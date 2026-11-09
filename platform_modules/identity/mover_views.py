"""Native forms for business role publication, preparation and independent review."""

import hashlib

from django import forms
from django.contrib import messages
from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db.models import OuterRef, Q, Subquery
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from platform_core.attestations import canonical
from platform_core.models import ModuleActivation, OrganizationMembership
from platform_core.security import ensure_recent
from platform_core.services import require_module
from platform_modules.access.ui import scoped
from platform_modules.connectors.business_models import BusinessSource
from platform_modules.connectors.business_references import (
    MAX_REFERENCES,
    preview_references,
    reference_context,
)

from .models import ExternalAccount, Identity, Resource
from .mover import (
    current_move,
    decide_move,
    latest_role,
    proof_anchor,
    propose_move,
    publish_role,
    verified,
)
from .mover_models import MoveAccess, MoveDecision, MoveProposal, RoleRevision


def _latest():
    revision = (
        RoleRevision.objects.filter(key=OuterRef("key")).order_by("-revision").values("pk")[:1]
    )
    return RoleRevision.objects.filter(pk=Subquery(revision)).order_by("key")


def _can(request, *roles):
    return (
        request.user.is_superuser
        or OrganizationMembership.objects.filter(
            organization=request.organization,
            account=request.user,
            role__in=roles,
            active=True,
        ).exists()
    )


def _page(request, template, **context):
    response = render(request, f"mover/{template}.html", context)
    response["Cache-Control"] = "no-store"
    return response


@scoped("identity")
def home(request):
    page = Paginator(
        MoveProposal.objects.select_related("identity", "audit__actor", "movedecision").order_by(
            "-audit_id"
        ),
        30,
    ).get_page(request.GET.get("page"))
    return _page(request, "home", proposals=page, can_publish=_can(request, "admin"))


@scoped("identity")
def catalog(request):
    page = Paginator(_latest(), 30).get_page(request.GET.get("page"))
    return _page(request, "catalog", roles=page, can_publish=_can(request, "admin"))


class RoleForm(forms.Form):
    key = forms.SlugField(label="Identifiant stable", max_length=64)
    name = forms.CharField(label="Nom du rôle", max_length=160)
    enabled = forms.BooleanField(label="Disponible pour les nouvelles affectations", required=False)
    revision = forms.IntegerField(min_value=0, widget=forms.HiddenInput)


class EntryForm(forms.Form):
    resource = forms.ModelChoiceField(label="Ressource", queryset=Resource.unscoped.none())
    method = forms.CharField(label="Méthode", max_length=80)
    privilege = forms.CharField(label="Droit demandé", max_length=160)
    days = forms.IntegerField(label="Durée (jours)", min_value=1, max_value=365, initial=30)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["resource"].queryset = Resource.objects.order_by("name", "pk")


Entries = forms.formset_factory(
    EntryForm,
    extra=0,
    min_num=1,
    max_num=20,
    absolute_max=20,
    validate_min=True,
    validate_max=True,
    can_delete=True,
)


@scoped("identity", roles=("admin",))
def role_config(request, key=None):
    role = latest_role(key) if key else None
    if key and role is None:
        raise Http404
    if role and not verified(role):
        raise PermissionDenied("La preuve de ce rôle est invalide.")
    initial = dict(key=key or "", revision=0, enabled=True)
    if role:
        initial.update(name=role.body["name"], enabled=role.body["enabled"], revision=role.revision)
    data = request.POST if request.method == "POST" else None
    form = RoleForm(data, initial=initial)
    form.fields["key"].disabled = role is not None
    entries = Entries(data, initial=role.body["entries"] if role else [], prefix="entries")
    if request.method == "POST" and form.is_valid() and entries.is_valid():
        try:
            publish_role(
                key=form.cleaned_data["key"],
                name=form.cleaned_data["name"],
                enabled=form.cleaned_data["enabled"],
                expected_revision=form.cleaned_data["revision"],
                entries=[
                    dict(
                        resource=item["resource"].pk,
                        method=item["method"],
                        privilege=item["privilege"],
                        days=item["days"],
                    )
                    for item in entries.cleaned_data
                    if item and not item.get("DELETE")
                ],
                actor=request.user,
                organization=request.organization,
            )
            return redirect("mover-catalog")
        except ValidationError as error:
            form.add_error(None, "; ".join(error.messages))
    return _page(request, "role_form", form=form, entries=entries, role=role)


class MoveForm(forms.Form):
    department = forms.CharField(label="Nouvelle équipe ou fonction", max_length=180)
    reference = forms.CharField(label="Référence RH ou métier", max_length=180)
    reason = forms.CharField(
        label="Motif", max_length=2000, widget=forms.Textarea(attrs={"rows": 3})
    )
    roles = forms.ModelMultipleChoiceField(
        queryset=RoleRevision.unscoped.none(),
        required=False,
        widget=forms.MultipleHiddenInput,
    )

    def __init__(self, *args, available, selected, identity, previous, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["roles"].queryset = available
        accounts = ExternalAccount.objects.filter(identity=identity, active=True).order_by("system")
        self.assignments = {}
        for role in selected:
            if str(role.pk) in previous:
                self.assignments[str(role.pk)] = []
                continue
            if not verified(role):
                raise PermissionDenied("Preuve du rôle invalide.")
            keys = []
            for index, entry in enumerate(role.body["entries"]):
                resource = get_object_or_404(Resource.objects, pk=entry["resource"])
                name = f"account_{role.pk.hex}_{index}"
                self.fields[name] = forms.ModelChoiceField(
                    queryset=accounts,
                    label=f"{role} · {resource} · {entry['privilege']}",
                    help_text=f"Durée maximale proposée : {entry['days']} jours.",
                )
                keys.append(name)
            self.assignments[str(role.pk)] = keys


class SourceReferenceForm(forms.Form):
    source = forms.ModelChoiceField(
        label="Source métier",
        queryset=BusinessSource.unscoped.none(),
        required=False,
    )
    external_id = forms.CharField(
        label="Identifiant dans cette source", max_length=180, required=False
    )

    def __init__(self, *args, enabled, **kwargs):
        super().__init__(*args, **kwargs)
        if enabled:
            self.fields["source"].queryset = BusinessSource.objects.filter(active=True).order_by(
                "key"
            )
            self.fields["source"].label_from_instance = (
                lambda source: f"{source.name} · {source.key}"
            )

    def clean(self):
        data = super().clean()
        if not self.errors and bool(data.get("source")) != bool(data.get("external_id")):
            raise ValidationError("Indiquez la source et l’identifiant du même dossier.")
        return data


SourceReferences = forms.formset_factory(
    SourceReferenceForm,
    extra=MAX_REFERENCES,
    max_num=MAX_REFERENCES,
    absolute_max=MAX_REFERENCES,
    validate_max=True,
)
PREVIEW_SALT = "pamolive.mover.business.preview/1"
REVIEW_SALT = "pamolive.mover.business.review/1"


def _preview_scope(request, payload, references):
    normalized = dict(
        organization_id=request.organization.pk,
        actor_id=request.user.pk,
        move=payload,
        references=references,
    )
    return hashlib.sha256(canonical(normalized).encode()).hexdigest()


def _review_scope(request, proposal):
    return dict(
        actor_id=request.user.pk,
        organization_id=str(request.organization.pk),
        proposal_id=str(proposal.pk),
        signature=proposal.signature,
    )


def _submit_or_preview(request, identity, form, references):
    data = form.cleaned_data
    payload = dict(
        identity_id=identity.pk,
        department=data["department"],
        reason=data["reason"],
        reference=data["reference"],
        assignments={
            key: [data[name].pk for name in fields] for key, fields in form.assignments.items()
        },
    )
    command = request.POST.get("command", "submit")
    scope = _preview_scope(request, payload, references)
    if command == "preview":
        if not references:
            raise ValidationError("Sélectionnez au moins un dossier à examiner.")
        readings = preview_references(references, organization=request.organization)
        return (
            None,
            readings,
            signing.dumps(
                dict(scope=scope, receipts=[row["receipt_id"] for row in readings]),
                salt=PREVIEW_SALT,
            ),
        )
    if command != "submit":
        raise ValidationError("Commande de mobilité inconnue.")
    receipts = None
    if references:
        try:
            reviewed = signing.loads(
                request.POST.get("business_preview", ""),
                salt=PREVIEW_SALT,
                max_age=600,
            )
        except signing.BadSignature:
            raise ValidationError("Examinez les lectures métier avant de soumettre.") from None
        if reviewed["scope"] != scope:
            raise ValidationError("La demande a changé. Examinez à nouveau les lectures métier.")
        receipts = reviewed["receipts"]
    proposal = propose_move(
        **payload,
        business_receipts=receipts,
        actor=request.user,
        organization=request.organization,
    )
    return proposal, [], ""


@scoped("identity", roles=("admin", "operator"))
def prepare(request, identity_id):
    identity = get_object_or_404(
        Identity.objects, pk=identity_id, status="active", kind__in=("human", "external")
    )
    current = current_move(identity)
    previous = current.body["roles"] if current else {}
    available = RoleRevision.objects.filter(
        Q(pk__in=previous) | Q(pk__in=_latest().filter(body__enabled=True).values("pk"))
    ).order_by("key", "-revision")
    choice = forms.ModelMultipleChoiceField(
        queryset=available,
        required=False,
        label="Rôles à conserver ou à attribuer",
        widget=forms.CheckboxSelectMultiple,
    )
    step = request.POST if request.method == "POST" else request.GET
    picker = forms.Form(
        step if "choose" in step or request.method == "POST" else None,
        initial={"roles": list(previous)},
    )
    picker.fields["roles"] = choice
    form = None
    business_enabled = ModuleActivation.objects.filter(
        organization=request.organization,
        module_key="connectors",
        enabled=True,
    ).exists()
    references = SourceReferences(
        request.POST if any(key.startswith("business-") for key in request.POST) else None,
        prefix="business",
        form_kwargs={"enabled": business_enabled},
    )
    preview, preview_token = [], ""
    if picker.is_bound and picker.is_valid():
        selected = list(picker.cleaned_data["roles"])
        if len(selected) > 10:
            picker.add_error("roles", "Choisissez au plus dix rôles.")
        else:
            form = MoveForm(
                request.POST if request.method == "POST" else None,
                available=available,
                selected=selected,
                identity=identity,
                previous=previous,
                initial={
                    "department": identity.department,
                    "roles": [role.pk for role in selected],
                },
            )
            if (
                request.method == "POST"
                and form.is_valid()
                and (not references.is_bound or references.is_valid())
            ):
                try:
                    chosen = (
                        [
                            (item["source"].pk, item["external_id"])
                            for item in references.cleaned_data
                            if item.get("source")
                        ]
                        if references.is_bound
                        else []
                    )
                    proposal, preview, preview_token = _submit_or_preview(
                        request,
                        identity,
                        form,
                        chosen,
                    )
                    if proposal:
                        return redirect("mover-detail", proposal_id=proposal.pk)
                except ValidationError as error:
                    form.add_error(None, "; ".join(error.messages))
    return _page(
        request,
        "prepare",
        picker=picker,
        form=form,
        identity=identity,
        current=current,
        business_enabled=business_enabled,
        references=references,
        preview=preview,
        preview_token=preview_token,
    )


@scoped("identity")
def detail(request, proposal_id):
    proposal = get_object_or_404(
        MoveProposal.objects.select_related("identity", "audit__actor"), pk=proposal_id
    )
    decision = MoveDecision.objects.filter(proposal=proposal).first()
    valid = verified(proposal) and (not decision or verified(decision))
    target = []
    if valid:
        for role_id, accounts in proposal.body["target"].items():
            role = RoleRevision.objects.filter(pk=role_id).first()
            if not role or not verified(role):
                valid = False
                break
            rows = []
            if accounts:
                for entry, account_id in zip(role.body["entries"], accounts, strict=True):
                    rows.append(
                        dict(
                            entry=entry,
                            account=proposal.body["accounts"][account_id],
                            resource=Resource.objects.filter(pk=entry["resource"]).first(),
                        )
                    )
            target.append((role, rows))
    withdrawals = []
    if valid:
        for item in proposal.body["withdrawals"]:
            link = MoveAccess.objects.filter(pk=item["link"]).first()
            if not link or not verified(link):
                valid = False
                break
            withdrawals.append((item, link))
    requests = (
        MoveAccess.objects.filter(decision=decision).select_related("role", "intent")
        if decision
        else []
    )
    return _page(
        request,
        "detail",
        proposal=proposal,
        decision=decision,
        valid=valid,
        target=target,
        withdrawals=withdrawals,
        requests=requests,
        can_decide=_can(request, "admin", "reviewer")
        and request.user.pk != proposal.audit.actor_id,
    )


@scoped("identity")
def business_proof(request, proposal_id, *, export=False):
    require_module(request.organization, "connectors")
    proposal = get_object_or_404(MoveProposal.objects.select_related("audit"), pk=proposal_id)
    if not verified(proposal):
        raise PermissionDenied("Preuve de proposition invalide.")
    if "business" not in proposal.body:
        raise Http404
    challenge = ensure_recent(request)
    if challenge is not None:
        return challenge
    decision = MoveDecision.objects.filter(proposal=proposal).select_related("audit").first()
    if decision and (
        not verified(decision)
        or decision.body["proposal_signature"] != proposal.signature
        or decision.identity_id != proposal.identity_id
        or (decision.applied and "business_checked" not in decision.body)
    ):
        raise PermissionDenied("Preuve de décision invalide.")
    try:
        context = reference_context(
            proposal.body["business"],
            decision.body.get("business_checked") if decision else None,
            organization=request.organization,
        )
    except ValidationError:
        raise PermissionDenied("Preuves métier incomplètes ou invalides.") from None
    if export:
        context["proposal"] = proof_anchor(proposal)
        context["decision"] = proof_anchor(decision) if decision else None
        response = JsonResponse(context)
        response["Cache-Control"] = "no-store"
        return response
    can_review = (
        not decision
        and _can(request, "admin", "reviewer")
        and request.user.pk != proposal.audit.actor_id
        and all(
            row["same_context"] and row["latest"]["current_source_assertion"]
            for row in context["references"]
        )
    )
    return _page(
        request,
        "business_proof",
        proposal=proposal,
        context=context,
        review_token=signing.dumps(_review_scope(request, proposal), salt=REVIEW_SALT)
        if can_review
        else "",
    )


@scoped("identity", roles=("admin", "reviewer"))
@require_POST
def decision(request, proposal_id):
    proposal = get_object_or_404(MoveProposal.objects, pk=proposal_id)
    command = request.POST.get("decision")
    try:
        if command not in ("approve", "deny"):
            raise ValidationError("Décision inconnue.")
        if command == "approve" and "business" in proposal.body:
            try:
                reviewed = signing.loads(
                    request.POST.get("business_review", ""),
                    salt=REVIEW_SALT,
                    max_age=600,
                )
            except signing.BadSignature:
                reviewed = None
            if reviewed != _review_scope(request, proposal):
                raise ValidationError(
                    "Examinez les lectures métier avant d’approuver le transfert."
                )
        decide_move(
            proposal_id,
            approved=command == "approve",
            comment=request.POST.get("comment"),
            actor=request.user,
            organization=request.organization,
        )
    except ValidationError as error:
        messages.error(request, "; ".join(error.messages))
    return redirect(reverse("mover-detail", args=[proposal_id]))
