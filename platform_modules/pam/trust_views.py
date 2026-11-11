"""Same-origin WebAuthn endpoints for independently commissioned PAM credentials."""

import json
import uuid

from cryptography.fernet import InvalidToken
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.http import require_http_methods, require_POST

from . import trust_auth
from .trust_auth_models import PAMTrustChallenge, PAMTrustEnrollment


def _json(request):
    if request.content_type != "application/json" or len(request.body) > 65536:
        raise ValueError
    value = json.loads(request.body, object_pairs_hook=trust_auth._unique_object)
    if not isinstance(value, dict):
        raise ValueError
    return value


def _reply(value, *, status=200):
    response = JsonResponse(value, status=status)
    response["Cache-Control"] = "no-store"
    return response


def _organization(request):
    if not getattr(request, "organization", None) or not request.user.is_active:
        raise PermissionDenied


def _visible(value):
    if isinstance(value, dict):
        return {
            key: "[masqué]" if key.casefold() in {
                "password", "private_key", "passphrase", "secret", "token", "client_secret",
            } else _visible(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_visible(item) for item in value]
    return value


def challenge_response(request, required):
    _organization(request)
    if request.method != "POST" or int(request.META.get("CONTENT_LENGTH") or 0) > 65536:
        raise PermissionDenied
    if not request.path.startswith("/") or request.path.startswith("//"):
        raise PermissionDenied
    replay = {
        "path": request.path,
        "fields": [
            [key, value] for key, values in request.POST.lists()
            if key not in {"csrfmiddlewaretoken", "_pam_trust_proof"} for value in values
        ],
    }
    ceremony = trust_auth.begin_action(
        request, required.action, required.payload, replay=replay,
    )
    ceremony.update(mode="get", endpoint=reverse("pam-trust-action"))
    response = render(request, "pam/trust_action.html", {
        "ceremony": ceremony, "action_name": required.action,
        "payload_display": json.dumps(_visible(required.payload), indent=2, ensure_ascii=False),
    })
    response["Cache-Control"] = "no-store"
    return response


@login_required
@require_POST
def authenticate(request):
    _organization(request)
    try:
        data = _json(request)
        operation = data.get("operation")
        if operation == "begin" and set(data) <= {"operation", "action", "payload", "credential"}:
            result = trust_auth.begin_action(
                request, data["action"], data["payload"], credential_id=data.get("credential"),
            )
        elif operation == "choose" and set(data) == {"operation", "challenge", "credential"}:
            result = trust_auth.choose_credential(
                request, uuid.UUID(data["challenge"]), data["credential"],
            )
        elif operation == "finish" and set(data) == {"operation", "challenge", "credential"}:
            result = trust_auth.finish_action(
                request, uuid.UUID(data["challenge"]), data["credential"],
            )
        else:
            raise ValueError
        return _reply(result)
    except PermissionDenied:
        return _reply({"error": "pam_authentication_refused"}, status=403)
    except (ValueError, TypeError, KeyError, ValidationError, InvalidToken, RecursionError,
            PAMTrustChallenge.DoesNotExist):
        return _reply({"error": "invalid_pam_authentication"}, status=400)


@login_required
@require_http_methods(["GET", "POST"])
def enrollment(request):
    _organization(request)
    if request.method == "GET":
        response = render(request, "pam/trust_action.html", {
            "ceremony": {"mode": "create", "endpoint": reverse("pam-trust-enrollment")},
            "action_name": "Enrôler un authentificateur PAM",
        })
        response["Cache-Control"] = "no-store"
        return response
    try:
        data = _json(request)
        operation = data.get("operation")
        if operation == "begin" and set(data) == {"operation"}:
            result = trust_auth.begin_enrollment(request)
        elif operation == "register" and set(data) == {"operation", "challenge", "credential"}:
            result = trust_auth.finish_registration(
                request, uuid.UUID(data["challenge"]), data["credential"],
            )
        elif operation == "finish" and set(data) == {"operation", "enrollment", "credential"}:
            result = trust_auth.finish_enrollment(
                request, uuid.UUID(data["enrollment"]), data["credential"],
            )
        else:
            raise ValueError
        return _reply(result)
    except PermissionDenied:
        return _reply({"error": "pam_enrollment_refused"}, status=403)
    except (ValueError, TypeError, KeyError, ValidationError, RecursionError,
            PAMTrustChallenge.DoesNotExist,
            PAMTrustEnrollment.DoesNotExist):
        return _reply({"error": "invalid_pam_enrollment"}, status=400)
