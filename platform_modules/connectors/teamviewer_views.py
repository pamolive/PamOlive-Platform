"""Native configuration and raw evidence UI; never an implicit identity mapping."""

from cryptography.fernet import InvalidToken
from django import forms
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from platform_core.security import cipher, ensure_recent
from platform_modules.access.ui import scoped

from .scim import IntegrationFailure
from .teamviewer_collection import save_configuration, set_enabled, test_configuration
from .teamviewer_ingestion import verify_report
from .teamviewer_models import TeamViewerCollector, TeamViewerReport, TeamViewerRun


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
    notes = (
        cipher().decrypt(report.encrypted_notes.encode()).decode()
        if valid and report.notes_included
        else None
    )
    return private_response(
        request, "connectors/teamviewer_report.html", dict(report=report, valid=valid, notes=notes)
    )
