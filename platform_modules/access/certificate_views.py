import json

from django.core.exceptions import PermissionDenied, RequestDataTooBig, ValidationError
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from . import certificate_possession as proof


def _reply(value, status):
    response = JsonResponse(value, status=status)
    response["Cache-Control"] = "no-store"
    if status == 429:
        response["Retry-After"] = "60"
    return response


def _read(request, fields):
    if request.content_type != "application/json":
        raise ValueError
    try:
        body = request.body
    except RequestDataTooBig as error:
        raise OverflowError from error
    if len(body) > 16384:
        raise OverflowError

    def pairs(items):
        result = dict(items)
        if len(result) != len(items):
            raise ValueError
        return result

    data = json.loads(body, object_pairs_hook=pairs)
    if not isinstance(data, dict) or set(data) != fields:
        raise ValueError
    return data


@csrf_exempt
@require_POST
def certificate_proof(request, object_id, *, challenge_only=False):
    if not request.is_secure():
        return _reply({"error": "https_required"}, 403)
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return _reply({"error": "unauthorized"}, 401)
    try:
        source = proof.consume_budget(header[7:])
        data = _read(
            request, set() if challenge_only else {"challenge", "certificate", "signature"}
        )
        if challenge_only:
            return _reply(proof.issue(source, object_id), 200)
        return _reply(
            proof.submit(
                source,
                object_id,
                **{
                    "challenge": data["challenge"],
                    "certificate": data["certificate"],
                    "signed": data["signature"],
                },
            ),
            201,
        )
    except proof.RateLimited:
        return _reply({"error": "rate_limited"}, 429)
    except PermissionDenied:
        return _reply({"error": "unauthorized"}, 401)
    except proof.Unavailable:
        return _reply({"error": "not_available"}, 404)
    except proof.Conflict:
        return _reply({"error": "already_verified"}, 409)
    except OverflowError:
        return _reply({"error": "payload_too_large"}, 413)
    except (ValueError, ValidationError, RecursionError):
        return _reply({"error": "invalid_proof"}, 400)
