from django import forms
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from platform_modules.access.ui import scoped
from platform_modules.identity.models import ExternalAccount, Resource

from .models import AccountBinding, ExternalChange, GroupBinding, ProvisioningConnector
from .outbound import (
    bind_account,
    bind_group,
    configure_connector,
    retry_change,
    set_connector_enabled,
    test_connector,
)
from .scim import IntegrationFailure


@scoped("connectors", roles=("admin",))
def index(request):
    return render(
        request,
        "connectors/index.html",
        {
            "connectors": ProvisioningConnector.objects.order_by("name"),
            "accounts": AccountBinding.objects.select_related("account", "connector"),
            "groups": GroupBinding.objects.select_related("resource", "connector"),
            "changes": ExternalChange.objects.select_related("account", "grant").order_by(
                "-created_at"
            )[:100],
        },
    )


@scoped("connectors", roles=("admin",))
def configure(request, connector_id=None):
    connector = (
        get_object_or_404(ProvisioningConnector.objects, pk=connector_id) if connector_id else None
    )
    form = forms.Form(
        request.POST or None,
        initial={"name": connector.name, "base_url": connector.base_url} if connector else {},
    )
    form.fields["name"] = forms.CharField(
        label="Nom", max_length=180, initial=connector.name if connector else ""
    )
    form.fields["base_url"] = forms.URLField(
        label="URL HTTPS de base SCIM",
        initial=connector.base_url if connector else "",
        help_text="Exemple : https://annuaire.example/scim/v2",
    )
    form.fields["token"] = forms.CharField(
        label="Jeton API",
        required=not bool(connector),
        widget=forms.PasswordInput,
        help_text="Laissez vide pour conserver le secret enregistré.",
    )
    if request.method == "POST" and form.is_valid():
        try:
            configure_connector(
                actor=request.user,
                organization=request.organization,
                connector_id=connector_id,
                **form.cleaned_data,
            )
            messages.success(
                request, "Configuration enregistrée en mode inactif. Testez-la avant activation."
            )
            return redirect("provisioning-home")
        except (ValidationError, IntegrationFailure) as error:
            form.add_error(None, str(error))
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": "Configurer SCIM", "section": "Connecteurs"},
    )


@scoped("connectors", roles=("admin",))
@require_POST
def connector_action(request, connector_id, action):
    get_object_or_404(ProvisioningConnector.objects, pk=connector_id)
    try:
        if action == "test":
            verified, code = test_connector(
                connector_id, actor=request.user, organization=request.organization
            )
            (messages.success if verified else messages.error)(
                request, f"Test de connexion : {code}"
            )
        else:
            set_connector_enabled(
                connector_id,
                actor=request.user,
                organization=request.organization,
                enabled=action == "enable",
            )
            messages.success(request, "État du connecteur mis à jour.")
    except (ValidationError, IntegrationFailure) as error:
        messages.error(request, str(error))
    return redirect("provisioning-home")


@scoped("connectors", roles=("admin",))
def binding_create(request, kind):
    form = forms.Form(request.POST or None)
    form.fields["connector"] = forms.ModelChoiceField(
        label="Connecteur", queryset=ProvisioningConnector.objects.all()
    )
    if kind == "account":
        form.fields["account"] = forms.ModelChoiceField(
            label="Compte local", queryset=ExternalAccount.objects.all()
        )
    else:
        form.fields["resource"] = forms.ModelChoiceField(
            label="Ressource locale", queryset=Resource.objects.all()
        )
        form.fields["entitlement"] = forms.CharField(label="Droit / rôle local", max_length=160)
    form.fields["remote_identifier"] = forms.CharField(
        label="Identifiant SCIM distant", max_length=180
    )
    if request.method == "POST" and form.is_valid():
        try:
            (bind_account if kind == "account" else bind_group)(
                actor=request.user, organization=request.organization, **form.cleaned_data
            )
            messages.success(
                request,
                "Correspondance enregistrée. Les opérations déjà en attente "
                "nécessitent une relance explicite.",
            )
            return redirect("provisioning-home")
        except (ValidationError, IntegrationFailure) as error:
            form.add_error(None, str(error))
    return render(
        request,
        "platform_core/form.html",
        {
            "form": form,
            "title": "Relier un compte SCIM"
            if kind == "account"
            else "Relier un droit à un groupe SCIM",
            "section": "Connecteurs",
        },
    )


@scoped("connectors")
def change_detail(request, change_id):
    change = get_object_or_404(
        ExternalChange.objects.select_related("account", "grant", "binding__connector", "group"),
        pk=change_id,
    )
    return render(
        request,
        "connectors/change.html",
        {"change": change, "proofs": change.proofs.order_by("recorded_at")},
    )


@scoped("connectors", roles=("admin",))
@require_POST
def retry(request, change_id):
    get_object_or_404(ExternalChange.objects, pk=change_id)
    try:
        retry_change(change_id, actor=request.user, organization=request.organization)
        messages.success(request, "Opération réexaminée avec les correspondances actuelles.")
    except ValidationError as error:
        messages.error(request, str(error))
    return redirect("external-change", change_id=change_id)
