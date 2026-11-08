"""A versioned inbound API; a publisher can only read its own business facts."""

import json

from django import forms
from django.contrib import messages
from django.core.exceptions import PermissionDenied, RequestDataTooBig, ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from platform_core.security import ensure_recent
from platform_core.tenancy import organization_context
from platform_modules.access.ui import scoped

from .business import (
    BusinessConflict,
    BusinessRateLimited,
    configure_business_source,
    consume_business_budget,
    create_business_source,
    ingest_business_record,
    receipt_public,
)
from .business_models import BusinessReceipt, BusinessSource


class BusinessSourceForm(forms.Form):
    name = forms.CharField(label="Nom du système métier", max_length=180)
    key = forms.SlugField(
        label="Identifiant de cette intégration",
        max_length=80,
        help_text="Exemples : glpi-it, jira-projets, servicenow-production.",
    )
    freshness_seconds = forms.IntegerField(
        label="Lecture considérée récente pendant (secondes)",
        min_value=60,
        max_value=86400,
        initial=900,
    )


def source_page(request, form=None, token=""):
    sources = list(BusinessSource.objects.order_by("key")[:101])
    receipts = list(
        BusinessReceipt.objects.select_related("record__source").order_by("-received_at", "-pk")[
            :101
        ]
    )
    response = render(
        request,
        "connectors/business.html",
        dict(
            form=form or BusinessSourceForm(),
            token=token,
            sources=sources[:100],
            receipts=receipts[:100],
            sources_limited=len(sources) > 100,
            receipts_limited=len(receipts) > 100,
        ),
    )
    response["Cache-Control"] = "no-store"
    return response


@scoped("connectors", roles=("admin",))
def sources(request):
    form = BusinessSourceForm(request.POST or None)
    token = ""
    if request.method == "POST" and form.is_valid():
        try:
            _, token = create_business_source(
                form.cleaned_data, actor=request.user, organization=request.organization
            )
            form = BusinessSourceForm()
        except ValidationError as error:
            form.add_error(None, "; ".join(error.messages))
    return source_page(request, form, token)


@scoped("connectors", roles=("admin",))
@require_http_methods(["POST"])
def source_command(request, source_id):
    get_object_or_404(BusinessSource.objects, pk=source_id)
    command = request.POST.get("command")
    if command not in {"enable", "disable", "rotate"}:
        return JsonResponse({"error": "invalid_command"}, status=400)
    _, token = configure_business_source(
        source_id,
        actor=request.user,
        organization=request.organization,
        active=(command == "enable") if command != "rotate" else None,
        rotate=command == "rotate",
    )
    messages.success(request, "Configuration auditée. Les anciennes preuves sont conservées.")
    return source_page(request, token=token)


@scoped("connectors")
def receipt_detail(request, receipt_id):
    challenge = ensure_recent(request)
    if challenge is not None:
        return challenge
    obj = get_object_or_404(
        BusinessReceipt.objects.select_related("record__source__audit", "audit"), pk=receipt_id
    )
    try:
        data = receipt_public(obj)
    except ValidationError:
        return JsonResponse({"error": "evidence_invalid"}, status=409)
    response = render(
        request,
        "connectors/business_receipt.html",
        dict(
            receipt=obj,
            proof=data,
            serialized=json.dumps(data, ensure_ascii=False, indent=2),
        ),
    )
    response["Cache-Control"] = "no-store"
    return response


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Repeated JSON key")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("Nonfinite JSON number")


@csrf_exempt
@require_http_methods(["GET", "POST"])
def records_api(request):
    response = _records_api(request)
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _records_api(request):
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    try:
        source = consume_business_budget(token)
    except BusinessRateLimited:
        response = JsonResponse({"error": "rate_limited"}, status=429)
        response["Retry-After"] = "60"
        return response
    except PermissionDenied:
        return JsonResponse({"error": "unauthorized"}, status=401)
    try:
        if len(request.body) > 16384:
            raise RequestDataTooBig
        with organization_context(source.organization):
            if request.method == "GET":
                values = request.GET.getlist("external_id")
                if request.body or set(request.GET) != {"external_id"} or len(values) != 1:
                    raise ValueError
                external_id = values[0]
                if not external_id or len(external_id) > 180:
                    raise ValueError
                receipt = (
                    BusinessReceipt.objects.select_related("record__source__audit", "audit")
                    .filter(record__source=source, record__external_id=external_id)
                    .order_by("-sequence")
                    .first()
                )
                if receipt is None:
                    return JsonResponse({"error": "not_found"}, status=404)
                return JsonResponse(receipt_public(receipt))
            if request.GET or request.content_type != "application/json":
                return JsonResponse({"error": "application_json_required"}, status=415)
            data = json.loads(
                request.body, object_pairs_hook=unique_object, parse_constant=invalid_constant
            )
            receipt, created = ingest_business_record(
                data, token=token, organization=source.organization
            )
            return JsonResponse(
                dict(receipt_public(receipt), created=created), status=201 if created else 200
            )
    except RequestDataTooBig:
        return JsonResponse({"error": "payload_too_large"}, status=413)
    except BusinessConflict:
        return JsonResponse({"error": "sequence_conflict"}, status=409)
    except (ValidationError, ValueError, TypeError):
        return JsonResponse({"error": "invalid_business_record"}, status=400)
    except PermissionDenied:
        return JsonResponse({"error": "unauthorized"}, status=401)
