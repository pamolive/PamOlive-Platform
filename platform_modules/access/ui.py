import json
from functools import wraps

from django import forms
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from platform_core.audit import record, verify_chain
from platform_core.models import AuditEvent, OrganizationMembership
from platform_core.security import ensure_recent
from platform_core.services import (
    authorize,
    disable_module,
    install_module,
    module_catalog,
    require_module,
)
from platform_core.tenancy import current_organization, organization_context
from platform_modules.approvals.services import decide
from platform_modules.connectors.models import EventSource
from platform_modules.connectors.services import create_source, source_from_token
from platform_modules.identity.models import Credential, ExternalAccount, Grant, Identity, Resource
from platform_modules.pam.models import SessionLease
from platform_modules.pam.services import open_lease
from platform_modules.recertification.models import Campaign, Review
from platform_modules.recertification.services import review_grant, start_campaign

from .models import AccessEvent, AccessIntent
from .services import create_record, ingest_event, revoke_identity

CATALOG = {
    "identity": ("Identités", Identity, ("name", "kind", "email", "owner", "department")),
    "resource": ("Ressources", Resource, ("name", "kind", "owner", "location", "critical")),
    "account": (
        "Comptes de connexion",
        ExternalAccount,
        ("identity", "username", "system", "kind", "active"),
    ),
    "credential": (
        "Certificats et badges",
        Credential,
        ("name", "identity", "resource", "kind", "fingerprint", "issuer", "expires_at", "usage"),
    ),
    "grant": (
        "Droits et rôles attribués",
        Grant,
        ("identity", "account", "resource", "entitlement", "justification", "expires_at"),
    ),
    "intent": (
        "Intentions d’accès",
        AccessIntent,
        (
            "identity",
            "account",
            "resource",
            "method",
            "location",
            "privilege",
            "reason",
            "reference",
            "starts_at",
            "ends_at",
        ),
    ),
    "event": (
        "Événements observés",
        AccessEvent,
        (
            "source",
            "external_id",
            "occurred_at",
            "identity",
            "account",
            "credential",
            "resource",
            "method",
            "action",
            "location",
            "privilege",
            "result",
            "evidence",
        ),
    ),
}


def scoped(module=None, roles=("admin", "operator", "reviewer", "auditor")):
    def decorator(view):
        @login_required
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            organization = current_organization()
            authorize(request.user, organization, roles=roles)
            if module:
                require_module(organization, module)
            if request.method == "POST":
                challenge = ensure_recent(request)
                if challenge is not None:
                    return challenge
            return view(request, *args, **kwargs)

        return wrapped

    return decorator


def model_form(model, fields, data=None):
    cls = forms.modelform_factory(model, fields=fields)
    form = cls(data)
    form.instance.organization = current_organization()
    for field in form.fields.values():
        if isinstance(field, forms.ModelChoiceField):
            field.queryset = field.queryset.model.objects.all()
        if isinstance(field, forms.DateTimeField):
            field.widget = forms.DateTimeInput(attrs={"type": "datetime-local"})
    return form


@login_required
def dashboard(request):
    if not request.organization:
        return render(request, "governance/empty.html")
    authorize(
        request.user, request.organization, roles=("admin", "operator", "reviewer", "auditor")
    )
    active = {d.key for d, state in module_catalog() if state and state.enabled}
    return render(
        request,
        "governance/dashboard.html",
        {
            "modules": [d for d, state in module_catalog() if state and state.enabled],
            "identity_count": Identity.objects.count() if "identity" in active else None,
            "resource_count": Resource.objects.count() if "identity" in active else None,
            "event_count": AccessEvent.objects.count() if "access" in active else None,
            "pending_count": AccessIntent.objects.filter(status="pending").count()
            if "access" in active
            else None,
            "events": AccessEvent.objects.order_by("-received_at")[:8]
            if "access" in active
            else [],
        },
    )


@login_required
@require_POST
def switch_organization(request):
    organizations = request.organizations
    organization = get_object_or_404(organizations, pk=request.POST.get("organization"))
    request.session["organization_id"] = str(organization.pk)
    return redirect("dashboard")


@scoped("identity")
def identity_home(request):
    return record_list(request, "identity")


@scoped()
def record_list(request, kind):
    if kind not in CATALOG:
        raise PermissionDenied
    title, model, fields = CATALOG[kind]
    require_module(request.organization, "access" if kind in ("intent", "event") else "identity")
    rows = list(model.objects.order_by("-pk")[:200])
    for obj in rows:
        obj.display_type = (
            obj.get_kind_display() if hasattr(obj, "kind") else getattr(obj, "method", "")
        )
        obj.display_status = (
            obj.get_status_display() if hasattr(obj, "status") else getattr(obj, "result", "")
        )
    return render(request, "governance/list.html", {"title": title, "rows": rows, "kind": kind})


@scoped(roles=("admin", "operator"))
def record_create(request, kind):
    if kind not in CATALOG:
        raise PermissionDenied
    title, model, fields = CATALOG[kind]
    require_module(request.organization, "access" if kind in ("intent", "event") else "identity")
    form = model_form(model, fields, request.POST or None)
    # Service supplies internal fields only after validation; they are never editable from HTTP.
    form._validate_unique = False
    if request.method == "POST" and form.is_valid():
        try:
            if kind == "event":
                obj, _ = ingest_event(
                    form.cleaned_data, actor=request.user, organization=request.organization
                )
            else:
                obj = create_record(
                    kind, form.cleaned_data, actor=request.user, organization=request.organization
                )
            messages.success(request, "Enregistrement créé et audité.")
            return redirect("record-detail", kind=kind, object_id=obj.pk)
        except ValidationError as error:
            form.add_error(None, error)
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": f"Nouveau · {title}", "section": title},
    )


@scoped()
def record_detail(request, kind, object_id):
    if kind not in CATALOG:
        raise PermissionDenied
    title, model, fields = CATALOG[kind]
    require_module(request.organization, "access" if kind in ("intent", "event") else "identity")
    obj = get_object_or_404(model.objects, pk=object_id)
    details = [(model._meta.get_field(f).verbose_name, getattr(obj, f)) for f in fields]
    return render(
        request,
        "governance/detail.html",
        {
            "title": title,
            "obj": obj,
            "kind": kind,
            "details": details,
            "accounts": ExternalAccount.objects.filter(identity=obj) if kind == "identity" else [],
            "grants": Grant.objects.filter(identity=obj) if kind == "identity" else [],
            "credentials": Credential.objects.filter(identity=obj) if kind == "identity" else [],
            "evaluation": obj.evaluations.order_by("-evaluated_at").first()
            if kind == "event"
            else None,
        },
    )


@scoped("access")
def access_home(request):
    return record_list(request, "event")


@scoped("approvals")
def approvals_home(request):
    return render(
        request,
        "governance/approvals.html",
        {
            "intents": AccessIntent.objects.select_related(
                "identity", "resource", "requested_by"
            ).order_by("-created_at")[:100]
        },
    )


@scoped("approvals", roles=("admin", "reviewer"))
@require_POST
def decision(request, object_id):
    get_object_or_404(AccessIntent.objects, pk=object_id)
    try:
        decide(
            object_id,
            actor=request.user,
            organization=request.organization,
            approved=request.POST.get("decision") == "approve",
            comment=request.POST.get("comment", ""),
        )
        messages.success(request, "Décision enregistrée.")
    except ValidationError as error:
        messages.error(request, "; ".join(error.messages))
    return redirect("approvals-home")


@scoped("identity", roles=("admin", "operator"))
@require_POST
def depart(request, object_id):
    get_object_or_404(Identity.objects, pk=object_id)
    try:
        revoke_identity(
            object_id,
            actor=request.user,
            organization=request.organization,
            reason=request.POST.get("reason", ""),
        )
        messages.success(
            request,
            "Départ enregistré ; droits locaux révoqués. "
            "L’exécution externe doit être confirmée par les systèmes cibles.",
        )
    except ValidationError as error:
        messages.error(request, "; ".join(error.messages))
    return redirect("record-detail", kind="identity", object_id=object_id)


@scoped("connectors", roles=("admin",))
def connectors_home(request):
    token = None
    form = forms.Form(request.POST or None)
    form.fields["name"] = forms.CharField(label="Nom de la source", max_length=180)
    if request.method == "POST" and form.is_valid():
        _, token = create_source(
            form.cleaned_data["name"], actor=request.user, organization=request.organization
        )
    return render(
        request,
        "governance/connectors.html",
        {"form": form, "sources": EventSource.objects.all(), "token": token},
    )


@scoped("recertification")
def recertification_home(request):
    form = forms.Form(request.POST or None)
    form.fields["name"] = forms.CharField(label="Campagne", max_length=180)
    form.fields["due_at"] = forms.DateTimeField(
        label="Échéance", widget=forms.DateTimeInput(attrs={"type": "datetime-local"})
    )
    if request.method == "POST" and form.is_valid():
        start_campaign(actor=request.user, organization=request.organization, **form.cleaned_data)
        return redirect("recertification-home")
    return render(
        request,
        "governance/recertification.html",
        {
            "form": form,
            "campaigns": Campaign.objects.order_by("-created_at"),
            "reviews": Review.objects.select_related("grant", "campaign").order_by(
                "campaign__due_at"
            )[:200],
        },
    )


@scoped("recertification", roles=("admin", "reviewer"))
@require_POST
def review(request, object_id):
    get_object_or_404(Review.objects, pk=object_id)
    try:
        review_grant(
            object_id,
            actor=request.user,
            organization=request.organization,
            keep=request.POST.get("decision") == "keep",
            comment=request.POST.get("comment", ""),
        )
    except ValidationError as error:
        messages.error(request, "; ".join(error.messages))
    return redirect("recertification-home")


@scoped("pam")
def pam_home(request):
    return render(
        request,
        "governance/pam.html",
        {
            "leases": SessionLease.objects.select_related("intent"),
            "intents": AccessIntent.objects.filter(status="approved", requested_by=request.user),
        },
    )


@scoped("pam", roles=("admin", "operator"))
@require_POST
def lease(request, object_id):
    get_object_or_404(AccessIntent.objects, pk=object_id)
    try:
        open_lease(object_id, actor=request.user, organization=request.organization)
    except ValidationError as error:
        messages.error(request, "; ".join(error.messages))
    return redirect("pam-home")


@scoped(roles=("admin",))
def modules(request):
    return render(request, "platform_core/modules.html", {"modules": module_catalog()})


@scoped(roles=("admin",))
@require_POST
def module_action(request, module_key, action):
    try:
        (install_module if action == "install" else disable_module)(
            module_key, actor=request.user, organization=request.organization
        )
    except (ValidationError, PermissionDenied) as error:
        messages.error(request, str(error))
    return redirect("module-list")


@scoped()
def audit(request):
    return render(
        request,
        "platform_core/audit_log.html",
        {
            "events": AuditEvent.objects.filter(organization=request.organization)
            .select_related("actor")
            .order_by("-sequence")[:200]
        },
    )


@scoped(roles=("admin",))
def system(request):
    form = forms.Form(request.POST or None)
    form.fields["username"] = forms.CharField(label="Compte PAM-olive", max_length=150)
    form.fields["role"] = forms.ChoiceField(
        label="Rôle dans l’organisation",
        choices=OrganizationMembership._meta.get_field("role").choices,
    )
    form.fields["password"] = forms.CharField(
        label="Mot de passe initial (nouveau compte)", required=False, widget=forms.PasswordInput
    )
    if request.method == "POST" and form.is_valid():
        try:
            with transaction.atomic():
                account = (
                    get_user_model().objects.filter(username=form.cleaned_data["username"]).first()
                )
                if not account:
                    password = form.cleaned_data["password"]
                    validate_password(password)
                    account = get_user_model().objects.create_user(
                        form.cleaned_data["username"], password=password
                    )
                member, _ = OrganizationMembership.objects.update_or_create(
                    organization=request.organization,
                    account=account,
                    defaults={"role": form.cleaned_data["role"], "active": True},
                )
                record(
                    action="core.membership.changed.v1",
                    summary=f"Appartenance : {account.username}",
                    actor=request.user,
                    organization=request.organization,
                    target=member,
                )
            return redirect("system-status")
        except ValidationError as error:
            form.add_error(None, error)
    return render(
        request,
        "governance/system.html",
        {
            "form": form,
            "members": OrganizationMembership.objects.filter(
                organization=request.organization
            ).select_related("account"),
            "database_vendor": connection.vendor,
            "audit_valid": verify_chain(request.organization),
        },
    )


@scoped("access")
def export_event(request, object_id):
    event = get_object_or_404(AccessEvent.objects, pk=object_id)
    evaluation = event.evaluations.order_by("-evaluated_at").first()
    response = JsonResponse(
        {
            "event_id": str(event.pk),
            "organization_id": str(request.organization.pk),
            "who": str(event.identity) if event.identity_id else None,
            "what": str(event.resource),
            "where": event.location or None,
            "when": event.occurred_at.isoformat(),
            "how": event.method,
            "source": event.source,
            "external_id": event.external_id,
            "evidence": event.evidence,
            "evaluation": {
                "verdict": evaluation.verdict,
                "rule_version": evaluation.rule_version,
                "findings": evaluation.findings,
            }
            if evaluation
            else None,
        }
    )
    response["Content-Disposition"] = f'attachment; filename="access-{event.pk}.json"'
    return response


@csrf_exempt
@require_POST
def api_events(request):
    if len(request.body) > 65536:
        return JsonResponse({"error": "payload_too_large"}, status=413)
    header = request.headers.get("Authorization", "")
    source = source_from_token(header[7:]) if header.startswith("Bearer ") else None
    if not source:
        return JsonResponse({"error": "unauthorized"}, status=401)
    try:
        data = json.loads(request.body)
        allowed = set(CATALOG["event"][2]) - {"source"}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError
        with organization_context(source.organization):
            form = model_form(AccessEvent, CATALOG["event"][2], {**data, "source": str(source.pk)})
            if not form.is_valid():
                return JsonResponse(
                    {"error": "invalid_event", "fields": form.errors.get_json_data()}, status=400
                )
            event, created = ingest_event(
                form.cleaned_data, source=source, organization=source.organization
            )
            return JsonResponse(
                {"event_id": str(event.pk), "created": created}, status=201 if created else 200
            )
    except (ValueError, ValidationError, PermissionDenied):
        return JsonResponse({"error": "invalid_event"}, status=400)


def health(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return JsonResponse({"status": "ok"})
    except Exception:
        return JsonResponse({"status": "unavailable"}, status=503)
