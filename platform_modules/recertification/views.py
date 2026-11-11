"""Native organization-scoped review screens; signed history is not live authority."""

import json

from django import forms
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from platform_core.attestations import canonical
from platform_core.models import OrganizationMembership
from platform_core.security import ensure_recent
from platform_core.view_access import scoped
from platform_modules.identity.models import ExternalAccount, Identity, Resource

from .evidence import (
    decision_body,
    publication_body,
    run_body,
    scope_body,
    verify_decision,
    verify_manifest,
    verify_publication,
    verify_scope,
)
from .models import Campaign, CampaignRun, Review, ReviewDecision, ReviewScope, Schedule
from .schedules import (
    current_publication,
    latest_publications,
    publish_schedule,
    set_schedule_enabled,
)
from .services import review_grant, start_campaign


def _owners():
    ids = OrganizationMembership.objects.filter(
        active=True, role__in=("admin", "reviewer"), account__is_active=True
    ).values("account_id")
    return get_user_model().objects.filter(pk__in=ids).order_by("username")


def _admin(request):
    return (
        request.user.is_superuser
        or OrganizationMembership.objects.filter(
            account=request.user, active=True, role="admin"
        ).exists()
    )


def _response(request, template, context):
    response = render(request, template, context)
    response["Cache-Control"] = "no-store"
    return response


class ManualForm(forms.Form):
    name = forms.CharField(label="Campagne", max_length=180)
    due_at = forms.DateTimeField(
        label="Échéance (fuseau de l’application)",
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
    )
    owner = forms.ModelChoiceField(
        label="Responsable (vous-même si vide)",
        queryset=get_user_model().objects.none(),
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["owner"].queryset = _owners()


class ScheduleForm(forms.Form):
    key = forms.SlugField(label="Identifiant stable", max_length=80)
    name = forms.CharField(label="Nom", max_length=140)
    first_at = forms.DateTimeField(
        label="Première échéance (fuseau de l’application)",
        widget=forms.DateTimeInput(format="%Y-%m-%dT%H:%M", attrs={"type": "datetime-local"}),
    )
    interval_days = forms.IntegerField(
        label="Période, en jours de 24 heures", min_value=1, max_value=3660
    )
    review_window_days = forms.IntegerField(
        label="Délai de revue, en jours", min_value=1, max_value=365
    )
    owner = forms.ModelChoiceField(label="Responsable", queryset=get_user_model().objects.none())
    resources = forms.ModelMultipleChoiceField(
        label="Ressources (vide : toutes)", queryset=Resource.unscoped.none(), required=False
    )
    identity_kinds = forms.MultipleChoiceField(
        label="Types d’identités (vide : tous)",
        choices=Identity._meta.get_field("kind").choices,
        required=False,
    )
    account_kinds = forms.MultipleChoiceField(
        label="Types de comptes (vide : tous)",
        choices=ExternalAccount._meta.get_field("kind").choices,
        required=False,
    )
    expected_revision = forms.IntegerField(required=False, min_value=1, widget=forms.HiddenInput)

    def __init__(self, *args, editing=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["owner"].queryset = _owners()
        self.fields["resources"].queryset = Resource.objects.order_by("name")
        self.fields["key"].disabled = editing

    def clean_resources(self):
        values = self.cleaned_data["resources"]
        if len(values) > 100:
            raise ValidationError("Sélectionnez 100 ressources maximum par règle.")
        return values

    def configuration(self):
        data = self.cleaned_data
        return {
            key: data[key]
            for key in ("name", "first_at", "interval_days", "review_window_days", "owner")
        } | {
            "scope": dict(
                resource_ids=[str(item.pk) for item in data["resources"]],
                identity_kinds=data["identity_kinds"],
                account_kinds=data["account_kinds"],
            )
        }


@scoped("recertification")
def index(request):
    form = ManualForm(request.POST or None)
    can_launch = (
        _admin(request)
        or OrganizationMembership.objects.filter(
            account=request.user, active=True, role="reviewer"
        ).exists()
    )
    if request.method == "POST":
        from platform_core.services import authorize

        authorize(request.user, request.organization, roles=("admin", "reviewer"))
        if form.is_valid():
            try:
                campaign = start_campaign(
                    actor=request.user, organization=request.organization, **form.cleaned_data
                )
                return redirect(
                    "recertification-run", run_id=CampaignRun.objects.get(campaign=campaign).pk
                )
            except ValidationError as error:
                form.add_error(None, error)
    plans = Paginator(
        latest_publications().select_related("schedule", "owner").order_by("name", "id"), 25
    )
    runs = Paginator(CampaignRun.objects.select_related("owner").order_by("-opened_at", "id"), 25)
    legacy = Campaign.objects.filter(campaignrun__isnull=True).order_by("-created_at")[:25]
    return _response(
        request,
        "recertification/index.html",
        dict(
            form=form,
            can_launch=can_launch,
            can_configure=_admin(request),
            plans=plans.get_page(request.GET.get("plans")),
            runs=runs.get_page(request.GET.get("runs")),
            legacy=legacy,
        ),
    )


@scoped("recertification", roles=("admin",))
def configure(request, schedule_id=None):
    schedule = get_object_or_404(Schedule.objects, pk=schedule_id) if schedule_id else None
    publication = current_publication(schedule) if schedule else None
    initial = {}
    if publication:
        initial = {
            key: getattr(publication, key)
            for key in ("name", "first_at", "interval_days", "review_window_days", "owner")
        } | dict(
            key=schedule.key,
            expected_revision=publication.revision,
            resources=publication.scope["resource_ids"],
            identity_kinds=publication.scope["identity_kinds"],
            account_kinds=publication.scope["account_kinds"],
        )
    form = ScheduleForm(request.POST or None, initial=initial, editing=bool(schedule))
    if request.method == "POST" and form.is_valid():
        try:
            result = publish_schedule(
                form.configuration(),
                key=form.cleaned_data["key"],
                schedule_id=schedule.pk if schedule else None,
                expected_revision=form.cleaned_data["expected_revision"],
                actor=request.user,
                organization=request.organization,
            )
            messages.success(
                request, "Règle enregistrée inactive. Vérifiez-la puis activez-la explicitement."
            )
            return redirect("recertification-schedule", schedule_id=result.schedule_id)
        except ValidationError as error:
            form.add_error(None, error)
    return _response(request, "recertification/configure.html", dict(form=form, schedule=schedule))


@scoped("recertification")
def schedule_detail(request, schedule_id):
    schedule = get_object_or_404(Schedule.objects, pk=schedule_id)
    pub = current_publication(schedule)
    return _response(
        request,
        "recertification/schedule.html",
        dict(
            schedule=schedule,
            publication=pub,
            proof_valid=bool(pub and verify_publication(pub)),
            can_configure=_admin(request),
            history=Paginator(schedule.schedulepublication_set.order_by("-revision"), 25).get_page(
                request.GET.get("history")
            ),
            runs=CampaignRun.objects.filter(schedule=schedule).order_by("-snapshot_at")[:25],
        ),
    )


@scoped("recertification", roles=("admin",))
@require_POST
def toggle(request, schedule_id):
    get_object_or_404(Schedule.objects, pk=schedule_id)
    command = request.POST.get("command")
    try:
        if command not in ("enable", "disable"):
            raise ValidationError("Commande inconnue : aucune modification.")
        try:
            revision = int(request.POST.get("expected_revision", ""))
        except (ValueError, TypeError):
            raise ValidationError("Rechargez la règle avant de la modifier.") from None
        set_schedule_enabled(
            schedule_id,
            command == "enable",
            expected_revision=revision,
            actor=request.user,
            organization=request.organization,
        )
    except ValidationError as error:
        messages.error(request, "; ".join(error.messages))
    return redirect("recertification-schedule", schedule_id=schedule_id)


@scoped("recertification")
def run_detail(request, run_id, *, export=False):
    run = get_object_or_404(
        CampaignRun.objects.select_related("owner", "audit", "publication"), pk=run_id
    )
    challenge = ensure_recent(request)
    if challenge is not None:
        return challenge
    manifest_valid = verify_manifest(run)
    scopes = ReviewScope.objects.filter(run=run).select_related("review").order_by("grant_id")
    page = Paginator(scopes, 25).get_page(request.GET.get("page"))
    decisions = {
        d.scope_id: d
        for d in ReviewDecision.objects.filter(scope__in=page.object_list).select_related("audit")
    }
    rows = []
    for item in page:
        decision = decisions.get(item.pk)
        rows.append(
            dict(
                scope=item,
                decision=decision,
                proof_valid=manifest_valid and verify_scope(item, run=run),
                decision_valid=bool(decision and verify_decision(decision, scope=item, run=run)),
                cache_consistent=(item.review.decision == ("keep" if decision.keep else "revoke"))
                if decision
                else item.review.decision == "pending",
            )
        )
    if export:

        def anchor(obj, body):
            return dict(
                body=json.loads(canonical(body)),
                signature=obj.signature,
                audit_id=str(obj.audit_id),
                audit_hash=obj.audit.event_hash,
            )

        response = JsonResponse(
            dict(
                schema="pamolive.recertification-evidence/1",
                run=anchor(run, run_body(run)),
                publication=anchor(run.publication, publication_body(run.publication))
                if run.publication_id
                else None,
                manifest_verified=manifest_valid,
                page=page.number,
                pages=page.paginator.num_pages,
                total_scopes=page.paginator.count,
                complete=page.paginator.num_pages == 1,
                scopes=[
                    dict(
                        body=scope_body(row["scope"]),
                        signature=row["scope"].signature,
                        verified=row["proof_valid"],
                        decision=anchor(
                            row["decision"], decision_body(row["decision"], row["scope"])
                        )
                        if row["decision"]
                        else None,
                        decision_verified=row["decision_valid"],
                        cache_consistent=row["cache_consistent"],
                    )
                    for row in rows
                ],
                local_decision_is_not_external_confirmation=True,
                historical_proof_is_not_current_authorization=True,
            )
        )
        response["Cache-Control"] = "no-store"
        return response
    return _response(
        request,
        "recertification/run.html",
        dict(
            run=run,
            rows=rows,
            page=page,
            manifest_valid=manifest_valid,
            can_decide=_admin(request) or run.owner_id == request.user.pk,
        ),
    )


@scoped("recertification", roles=("admin", "reviewer"))
@require_POST
def review(request, object_id):
    item = get_object_or_404(Review.objects, pk=object_id)
    scope = ReviewScope.objects.filter(review=item).first()
    try:
        command = request.POST.get("decision")
        if command not in ("keep", "revoke"):
            raise ValidationError("Décision inconnue : aucun droit modifié.")
        review_grant(
            object_id,
            actor=request.user,
            organization=request.organization,
            keep=command == "keep",
            comment=request.POST.get("comment", ""),
        )
    except ValidationError as error:
        messages.error(request, "; ".join(error.messages))
    return (
        redirect("recertification-run", run_id=scope.run_id)
        if scope
        else redirect("recertification-home")
    )
