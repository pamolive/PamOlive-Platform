"""A versioned inbound API; a publisher can only read its own business facts."""

import json

from django import forms
from django.contrib import messages
from django.core.exceptions import PermissionDenied, RequestDataTooBig, ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from platform_core.security import ensure_recent
from platform_core.tenancy import organization_context
from platform_core.view_access import scoped
from platform_modules.access.models import AccessIntent

from .business import (
    BusinessConflict,
    BusinessRateLimited,
    canonical,
    configure_business_source,
    consume_business_budget,
    create_business_source,
    ingest_business_record,
    receipt_public,
)
from .business_associations import (
    association_body,
    authorize_association,
    intent_business_context,
    publish_business_association,
    verify_business_association,
)
from .business_models import BusinessAssociation, BusinessReceipt, BusinessSource


class AssociationForm(forms.Form):
    source = forms.ModelChoiceField(label="Système métier", queryset=BusinessSource.unscoped.none())
    external_id = forms.CharField(label="Identifiant stable dans ce système", max_length=180)
    receipt_id = forms.UUIDField(required=False, widget=forms.HiddenInput)
    rationale = forms.CharField(
        label="Pourquoi cette référence concerne-t-elle l’intention ?",
        max_length=500,
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["source"].queryset = BusinessSource.objects.order_by("key")


@scoped("access", roles=("admin", "operator"))
def associate_intent(request, intent_id):
    from platform_core.services import require_module

    require_module(request.organization, "connectors")
    intent = get_object_or_404(AccessIntent.objects, pk=intent_id)
    authorize_association(intent, actor=request.user, organization=request.organization)
    form = AssociationForm(request.POST or None)
    preview = None
    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        query = BusinessReceipt.objects.filter(
            record__source=data["source"], record__external_id=data["external_id"]
        )
        command = request.POST.get("command")
        receipt = (
            query.filter(pk=data["receipt_id"]).first()
            if command == "associate" and data["receipt_id"]
            else query.order_by("-sequence").first()
        )
        if receipt is None:
            form.add_error("external_id", "Aucune lecture correspondante dans cette source.")
        elif command == "preview":
            try:
                preview = receipt_public(receipt)
                form = AssociationForm(initial={**data, "receipt_id": receipt.pk})
            except ValidationError:
                form.add_error(None, "La preuve source doit être examinée avant tout rattachement.")
        elif command == "associate" and data["receipt_id"]:
            try:
                publish_business_association(
                    intent.pk,
                    receipt.pk,
                    data["rationale"],
                    actor=request.user,
                    organization=request.organization,
                )
                return redirect("intent-business-context", intent_id=intent.pk)
            except ValidationError as error:
                form.add_error(None, "; ".join(error.messages))
        else:
            form.add_error(None, "Affichez la lecture source avant de confirmer le rattachement.")
    response = render(
        request,
        "connectors/business_associate.html",
        dict(
            form=form,
            intent=intent,
            preview=preview,
        ),
    )
    response["Cache-Control"] = "no-store"
    return response


@scoped("access")
def intent_context(request, intent_id, export=False):
    intent = get_object_or_404(AccessIntent.objects, pk=intent_id)
    challenge = ensure_recent(request)
    if challenge is not None:
        return challenge
    data = intent_business_context(intent.pk)
    if export:
        response = JsonResponse(data)
        response["Content-Disposition"] = f'attachment; filename="intent-business-{intent.pk}.json"'
    else:
        history = []
        can_manage = False
        if data["available"]:
            history = list(
                BusinessAssociation.objects.filter(intent=intent)
                .select_related(
                    "intent", "record", "receipt__record__source", "receipt__audit", "audit"
                )
                .order_by("-published_at", "-pk")[:51]
            )
            for obj in history:
                obj.proof_valid = verify_business_association(obj)
            try:
                authorize_association(intent, actor=request.user, organization=request.organization)
                can_manage = True
            except PermissionDenied:
                pass
        response = render(
            request,
            "connectors/business_context.html",
            dict(
                intent=intent,
                business=data,
                history=history[:50],
                history_limited=len(history) > 50,
                can_manage=can_manage,
            ),
        )
    response["Cache-Control"] = "no-store"
    return response


@scoped("access", roles=("admin", "operator"))
@require_http_methods(["POST"])
def withdraw_association(request, association_id):
    obj = get_object_or_404(BusinessAssociation.objects, pk=association_id)
    try:
        publish_business_association(
            obj.intent_id,
            obj.receipt_id,
            request.POST.get("rationale", ""),
            actor=request.user,
            organization=request.organization,
            withdraw_association_id=obj.pk,
        )
    except ValidationError as error:
        messages.error(request, "; ".join(error.messages))
    return redirect("intent-business-context", intent_id=obj.intent_id)


@scoped("connectors")
def association_proof(request, association_id):
    obj = get_object_or_404(
        BusinessAssociation.objects.select_related(
            "intent", "record", "receipt__record__source", "receipt__audit", "audit"
        ),
        pk=association_id,
    )
    challenge = ensure_recent(request)
    if challenge is not None:
        return challenge
    if not verify_business_association(obj):
        response = JsonResponse({"error": "invalid_association_proof"}, status=409)
    else:
        response = JsonResponse(
            dict(
                schema="pamolive.business-association/1",
                body=json.loads(canonical(association_body(obj))),
                proof_verified=True,
                audit_id=str(obj.audit_id),
                audit_hash=obj.audit.event_hash,
                signature=obj.signature,
                local_access_approval=False,
            )
        )
        response["Content-Disposition"] = (
            f'attachment; filename="business-association-{obj.pk}.json"'
        )
    response["Cache-Control"] = "no-store"
    return response


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
    return _private_response(_records_api(request))


def _private_response(response):
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _authenticated_api_source(request):
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    try:
        source = consume_business_budget(token)
    except BusinessRateLimited:
        response = JsonResponse({"error": "rate_limited"}, status=429)
        response["Retry-After"] = "60"
        return None, None, response
    except PermissionDenied:
        return None, None, JsonResponse({"error": "unauthorized"}, status=401)
    return source, token, None


@require_http_methods(["GET"])
def source_api(request):
    source, _, error = _authenticated_api_source(request)
    if error is not None:
        return _private_response(error)
    if request.GET or request.body:
        return _private_response(JsonResponse({"error": "invalid_request"}, status=400))
    return _private_response(
        JsonResponse(
            dict(
                schema="pamolive.business-source/1",
                organization_id=str(source.organization_id),
                source_id=str(source.pk),
                source_key=source.key,
                source_revision=source.revision,
            )
        )
    )


def _records_api(request):
    source, token, error = _authenticated_api_source(request)
    if error is not None:
        return error
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
