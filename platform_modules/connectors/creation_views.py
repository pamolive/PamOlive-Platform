"""Native, MFA-protected initial account preparation; never Django admin."""

from cryptography.fernet import InvalidToken
from django import forms
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from platform_core.security import ensure_recent
from platform_core.view_access import scoped
from platform_modules.access.models import AccessIntent

from .business import sign
from .creation import (
    _initial_intent,
    creation_scope,
    dispatch_body,
    proof_body,
    request_body,
    request_creation,
    retry_creation,
    verify_dispatch,
    verify_proof,
    verify_request,
)
from .creation_models import ScimCreationDispatch, ScimCreationJob, ScimCreationProof
from .models import ExternalChange, GroupBinding, ProvisioningConnector
from .scim import USER_SCHEMA, IntegrationFailure, ScimAdapter
from .scim_credentials import connector_token


class CreationForm(forms.Form):
    intent = forms.ModelChoiceField(
        label="Intention IAM déjà approuvée", queryset=AccessIntent.unscoped.none()
    )
    connector = forms.ModelChoiceField(
        label="Connecteur SCIM testé et actif", queryset=ProvisioningConnector.unscoped.none()
    )
    activate_after_grant = forms.BooleanField(
        required=False,
        label="Activer après confirmation du droit approuvé",
        help_text="Sans cette option, le compte reste désactivé et aucun droit n’est envoyé.",
    )
    preview_signature = forms.CharField(required=False, max_length=64, widget=forms.HiddenInput)
    acknowledge = forms.BooleanField(
        required=False,
        label="Je confirme la création et j’ai vérifié les droits implicites du fournisseur.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["intent"].queryset = AccessIntent.objects.filter(
            status="approved", fulfillment="iam_group", account__isnull=False
        ).select_related("account", "identity", "resource")
        self.fields["connector"].queryset = ProvisioningConnector.objects.filter(enabled=True)


@scoped("connectors", roles=("admin",))
def configure(request):
    form, preview = CreationForm(request.POST or None), None
    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        try:
            intent, connector = data["intent"], data["connector"]
            if request.POST.get("command") == "confirm":
                if not data["preview_signature"] or not data["acknowledge"]:
                    raise ValidationError("Vérifiez la destination et confirmez le périmètre.")
                job = request_creation(
                    intent.pk,
                    connector.pk,
                    activate_after_grant=data["activate_after_grant"],
                    actor=request.user,
                    organization=request.organization,
                    preview_signature=data["preview_signature"],
                )
                messages.success(request, "Demande enregistrée ; aucun second POST automatique.")
                return redirect("scim-creation-detail", job_id=job.pk)
            _initial_intent(intent, request.organization)
            group = GroupBinding.objects.filter(
                connector=connector, resource=intent.resource, entitlement=intent.privilege
            ).first()
            if not group or connector.verified_revision != connector.revision:
                raise ValidationError("Testez le connecteur et reliez le droit à son groupe SCIM.")
            adapter = ScimAdapter(connector.base_url, connector_token(connector))
            adapter.creation_capabilities()
            if adapter.find_user("userName", intent.account.username):
                raise ValidationError(
                    "Ce nom existe déjà. Vérifiez puis reliez explicitement le compte."
                )
            preview = dict(
                username=intent.account.username,
                connector=connector.name,
                payload=dict(schemas=[USER_SCHEMA], userName=intent.account.username, active=False),
            )
            signature = sign(
                dict(
                    scope=creation_scope(intent, connector, group),
                    actor_id=request.user.pk,
                    activate_after_grant=data["activate_after_grant"],
                ),
                "scim-creation-preview",
            )
            form = CreationForm(initial={**data, "preview_signature": signature})
        except (ValidationError, IntegrationFailure) as error:
            form.add_error(None, str(error))
        except (InvalidToken, ValueError, OSError):
            form.add_error(None, "La configuration chiffrée du connecteur doit être examinée.")
    response = render(request, "connectors/creation_form.html", {"form": form, "preview": preview})
    response["Cache-Control"] = "no-store"
    return response


@scoped("connectors", roles=("admin",))
def detail(request, job_id, *, export=False):
    job = get_object_or_404(
        ScimCreationJob.objects.select_related(
            "account", "request__intent", "request__connector", "binding"
        ),
        pk=job_id,
    )
    challenge = ensure_recent(request)
    if challenge is not None:
        return challenge
    dispatch = ScimCreationDispatch.objects.filter(job=job).first()
    proof = ScimCreationProof.objects.filter(dispatch=dispatch).first() if dispatch else None
    if export:

        def evidence(obj, body, verify):
            return (
                dict(
                    body=body(obj),
                    signature=obj.signature,
                    verified=verify(obj),
                    audit_id=str(obj.audit_id),
                    audit_hash=obj.audit.event_hash,
                )
                if obj
                else None
            )

        response = JsonResponse(
            dict(
                schema="pamolive.scim-creation-evidence/1",
                request=evidence(job.request, request_body, verify_request),
                dispatch=evidence(dispatch, dispatch_body, verify_dispatch),
                inactive_read=evidence(proof, proof_body, verify_proof),
                current_state=dict(status=job.status, code=job.result_code, attempts=job.attempts),
                historical_proof_is_not_current_account_state=True,
            )
        )
    else:
        response = render(
            request,
            "connectors/creation_detail.html",
            dict(
                job=job,
                dispatch=dispatch,
                proof=proof,
                request_verified=verify_request(job.request),
                changes=ExternalChange.objects.filter(creation_proof=proof) if proof else [],
            ),
        )
    response["Cache-Control"] = "no-store"
    return response


@scoped("connectors", roles=("admin",))
@require_POST
def retry(request, job_id):
    get_object_or_404(ScimCreationJob.objects, pk=job_id)
    try:
        retry_creation(job_id, actor=request.user, organization=request.organization)
        messages.success(request, "Réexamen demandé. Un POST déjà réservé n’est jamais répété.")
    except ValidationError as error:
        messages.error(request, str(error))
    return redirect("scim-creation-detail", job_id=job_id)
