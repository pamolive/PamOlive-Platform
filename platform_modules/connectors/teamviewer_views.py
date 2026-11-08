"""Native configuration, explicit mappings and raw evidence UI."""

import uuid

from cryptography.fernet import InvalidToken
from django import forms
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from platform_core.security import cipher, ensure_recent
from platform_modules.access.ui import scoped

from .scim import IntegrationFailure
from .teamviewer_collection import save_configuration, set_enabled, test_configuration
from .teamviewer_ingestion import verify_report
from .teamviewer_mapping import KINDS, publish_mapping, resolve_sighting, verify_mapping
from .teamviewer_mapping_models import TeamViewerMapping, TeamViewerSighting
from .teamviewer_models import TeamViewerCollector, TeamViewerReport, TeamViewerRun

MAPPING_LABELS = {
    "account": "Compte opérateur TeamViewer",
    "actor": "Identité explicitement attribuée",
    "device": "Machine cible",
}
MAPPING_STATES = {
    "mapped": "Correspondance sur toute la période",
    "unmapped": "Aucune correspondance",
    "withdrawn": "Correspondance retirée",
    "partial": "Période partiellement couverte",
    "ambiguous": "Affectation différente pendant la session",
    "invalid": "Preuve ou classification à examiner",
    "limit": "Historique trop complexe pour une résolution complète",
}


def _sighting(queryset, value):
    if not value:
        return None
    try:
        identifier = uuid.UUID(str(value))
    except (ValueError, TypeError):
        raise Http404 from None
    return get_object_or_404(queryset, pk=identifier)


class CollectorForm(forms.Form):
    name = forms.CharField(label="Nom du collecteur", max_length=180)
    token = forms.CharField(
        label="Jeton API TeamViewer en lecture seule",
        max_length=4096,
        widget=forms.PasswordInput,
        help_text="Ne le partagez pas dans une conversation. Sur une configuration existante, "
        "laissez vide pour tester le jeton déjà enregistré.",
    )
    start_at = forms.CharField(
        label="Première fin de session à collecter (ISO 8601 avec fuseau)",
        max_length=50,
        help_text="Exemple : 2026-11-01T00:00:00Z. Les sessions commencées avant cette date "
        "mais terminées après restent incluses.",
    )
    collect_notes = forms.BooleanField(
        label="Conserver les notes déclarées dans TeamViewer",
        required=False,
        help_text="Désactivé par défaut. Une note n’est ni un ticket vérifié "
        "ni une preuve de privilège.",
    )


def private_response(request, template, context):
    response = render(request, template, context)
    response["Cache-Control"] = "no-store"
    return response


@scoped("connectors", roles=("admin",))
def index(request):
    return private_response(
        request,
        "connectors/teamviewer.html",
        dict(
            collectors=TeamViewerCollector.objects.select_related("source").order_by("name")[:100],
            runs=TeamViewerRun.objects.select_related("collector").order_by("-finished_at")[:100],
            reports=TeamViewerReport.objects.select_related("collector").order_by("-observed_at")[
                :100
            ],
        ),
    )


@scoped("connectors", roles=("admin",))
def configure(request, collector_id=None):
    collector = (
        get_object_or_404(TeamViewerCollector.objects, pk=collector_id) if collector_id else None
    )
    form = CollectorForm(
        request.POST or None,
        initial=dict(
            name=collector.name,
            start_at=collector.start_at.isoformat(),
            collect_notes=collector.collect_notes,
        )
        if collector
        else {},
    )
    form.fields["token"].required = collector is None
    capsule, result = None, None
    if request.method == "POST":
        try:
            if request.POST.get("action") == "save":
                save_configuration(
                    request.POST.get("capsule", ""),
                    actor=request.user,
                    organization=request.organization,
                    browser_key=request.session.session_key,
                    collector_id=collector_id,
                )
                messages.success(
                    request,
                    "Configuration testée enregistrée inactive. "
                    "L’activation est une action séparée.",
                )
                return redirect("teamviewer-home")
            elif request.POST.get("action") == "test" and form.is_valid():
                values = form.cleaned_data.copy()
                if not values["token"] and collector:
                    values["token"] = cipher().decrypt(collector.encrypted_token.encode()).decode()
                capsule, result = test_configuration(
                    actor=request.user,
                    organization=request.organization,
                    browser_key=request.session.session_key,
                    collector_id=collector_id,
                    **values,
                )
            elif request.POST.get("action") not in {"test", "save"}:
                form.add_error(None, "Action de configuration inconnue.")
        except (ValidationError, IntegrationFailure) as error:
            if not form.is_bound or not hasattr(form, "cleaned_data"):
                form.is_valid()
            form.add_error(
                None,
                "; ".join(error.messages) if isinstance(error, ValidationError) else error.code,
            )
        except (InvalidToken, UnicodeError):
            form.is_valid()
            form.add_error(None, "Le jeton enregistré est illisible. Saisissez un nouveau jeton.")
    return private_response(
        request,
        "connectors/teamviewer_form.html",
        dict(
            form=form,
            collector=collector,
            capsule=capsule,
            result=result,
        ),
    )


@scoped("connectors", roles=("admin",))
@require_POST
def activation(request, collector_id):
    get_object_or_404(TeamViewerCollector.objects, pk=collector_id)
    try:
        action = request.POST.get("action")
        if action not in {"enable", "disable"}:
            raise ValidationError("Action d’activation inconnue.")
        set_enabled(
            collector_id, action == "enable", actor=request.user, organization=request.organization
        )
        messages.success(request, "État de collecte mis à jour.")
    except (ValidationError, IntegrationFailure) as error:
        messages.error(
            request, "; ".join(error.messages) if isinstance(error, ValidationError) else error.code
        )
    return redirect("teamviewer-home")


@scoped("connectors", roles=("admin",))
def report_detail(request, report_id):
    report = get_object_or_404(TeamViewerReport.objects.select_related("collector"), pk=report_id)
    challenge = ensure_recent(request)
    if challenge is not None:
        return challenge
    valid = verify_report(report)
    sightings = (
        TeamViewerSighting.objects.filter(report=report)
        .select_related("run__audit", "report")
        .order_by("-run__audit__sequence")
    )
    sighting = _sighting(sightings, request.GET.get("sighting")) or sightings.first()
    preview, preview_error = [], ""
    if valid and sighting:
        try:
            resolved = resolve_sighting(sighting, organization=request.organization)
            preview = [
                dict(
                    kind=kind,
                    label=MAPPING_LABELS[kind],
                    result=resolved[kind],
                    state_label=MAPPING_STATES[resolved[kind].state],
                )
                for kind in KINDS
            ]
        except ValidationError:
            preview_error = "L’observation n’est pas vérifiable. Aucune identité n’est attribuée."
    notes = (
        cipher().decrypt(report.encrypted_notes.encode()).decode()
        if valid and report.notes_included
        else None
    )
    return private_response(
        request,
        "connectors/teamviewer_report.html",
        dict(
            report=report,
            valid=valid,
            notes=notes,
            sighting=sighting,
            sightings=sightings[:20],
            preview=preview,
            preview_error=preview_error,
        ),
    )


@scoped("connectors", roles=("admin",))
def mappings(request, collector_id):
    collector = get_object_or_404(TeamViewerCollector.objects, pk=collector_id)
    rows = []
    for item in (
        TeamViewerMapping.objects.filter(collector=collector)
        .select_related("audit", "collector", "account", "identity", "resource")
        .order_by("-published_at")[:100]
    ):
        valid = verify_mapping(item)
        rows.append(
            dict(
                statement=item,
                verified=valid,
                target=item.target if valid and not item.withdrawn else None,
            )
        )
    return private_response(
        request, "connectors/teamviewer_mappings.html", dict(collector=collector, rows=rows)
    )


@scoped("connectors", roles=("admin",))
def mapping_create(request, collector_id, kind):
    if kind not in KINDS:
        raise Http404
    collector = get_object_or_404(TeamViewerCollector.objects, pk=collector_id)
    sighting_query = TeamViewerSighting.objects.filter(collector=collector).select_related(
        "run__audit", "report"
    )
    selected = _sighting(sighting_query, request.GET.get("sighting"))
    initial = {}
    if selected:
        initial = dict(
            source_sighting=selected.pk,
            remote_ref=selected.report.device_ref
            if kind == "device"
            else selected.report.account_ref,
            valid_from=selected.report.started_at.isoformat(),
            valid_until=selected.report.ended_at.isoformat()
            if selected.report.ended_at > selected.report.started_at
            else "",
        )
    targets = KINDS[kind].objects.all()
    if kind == "account":
        targets = targets.filter(system__iexact="TeamViewer")
    if kind == "device":
        targets = targets.filter(kind__in=["device", "server"])
    form = forms.Form(request.POST or None, initial=initial)
    form.fields["source_sighting"] = forms.ModelChoiceField(
        queryset=sighting_query, required=False, widget=forms.HiddenInput
    )
    form.fields["remote_ref"] = forms.CharField(
        label="Identifiant exact dans TeamViewer", max_length=180
    )
    form.fields["target"] = forms.ModelChoiceField(
        label=MAPPING_LABELS[kind],
        queryset=targets,
        required=False,
        empty_label="Aucune cible (retrait explicite)",
    )
    form.fields["withdrawn"] = forms.BooleanField(
        label="Retirer l’affectation sur cette période", required=False
    )
    form.fields["valid_from"] = forms.CharField(
        label="Début de validité avec fuseau (ISO 8601)", max_length=50
    )
    form.fields["valid_until"] = forms.CharField(
        label="Fin exclue avec fuseau (facultative)", required=False, max_length=50
    )
    form.fields["verification_reference"] = forms.CharField(
        label="Référence de vérification de l’affectation",
        max_length=255,
        help_text="Référence non secrète de ticket ou de document. "
        "Elle reste une attestation administrative, pas une preuve d’authentification TeamViewer.",
    )
    if request.method == "POST" and form.is_valid():
        values = form.cleaned_data.copy()
        source = values.pop("source_sighting")
        values["valid_until"] = values["valid_until"] or None
        try:
            publish_mapping(
                actor=request.user,
                organization=request.organization,
                collector_id=collector.pk,
                kind=kind,
                sighting_id=source.pk if source else None,
                **values,
            )
            messages.success(
                request,
                "Correspondance publiée. Les preuves et les anciennes affectations "
                "sont conservées.",
            )
            return redirect("teamviewer-mappings", collector_id=collector.pk)
        except ValidationError as error:
            form.add_error(None, error)
        except PermissionDenied:
            challenge = ensure_recent(request)
            if challenge is not None:
                return challenge
            raise
    return private_response(
        request,
        "connectors/teamviewer_mapping_form.html",
        dict(
            form=form,
            collector=collector,
            kind=kind,
            label=MAPPING_LABELS[kind],
            source_sighting=selected,
        ),
    )
