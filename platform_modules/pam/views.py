import time

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404, HttpResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_POST

from platform_core.audit import record
from platform_core.authorization import recent_authentication
from platform_core.security import ensure_recent
from platform_core.view_access import scoped
from platform_modules.identity.models import ExternalAccount, Resource

from .context import client_address
from .destination import TransportFailure
from .models import RelayConnection, SessionEndpoint
from .recordings import authorize_recording, issue_recording_grant, recording_page, validate_grant
from .sessions import (
    configure_endpoint,
    launch_session,
    probe_endpoint,
    set_endpoint_enabled,
    stop_session,
)


class SecretTextarea(forms.Textarea):
    def format_value(self, value):
        return ""


@scoped("pam", roles=("admin",))
def endpoints(request):
    return render(
        request,
        "pam/endpoints.html",
        {
            "endpoints": SessionEndpoint.objects.select_related("resource", "account").order_by(
                "name"
            ),
        },
    )


@sensitive_post_parameters("password", "private_key", "passphrase")
@scoped("pam", roles=("admin",))
def configure(request, endpoint_id=None):
    endpoint = get_object_or_404(SessionEndpoint.objects, pk=endpoint_id) if endpoint_id else None
    public = (
        "name",
        "resource",
        "account",
        "protocol",
        "hostname",
        "port",
        "domain",
        "auth_method",
    )
    form = forms.Form(
        request.POST or None,
        initial={key: getattr(endpoint, key) for key in public}
        if endpoint
        else {"protocol": "ssh", "port": 22, "auth_method": "password"},
    )
    form.fields.update(
        {
            "name": forms.CharField(label="Nom de la cible", max_length=180),
            "resource": forms.ModelChoiceField(
                label="Ressource",
                queryset=Resource.objects.filter(kind__in=("server", "device", "cloud")),
            ),
            "account": forms.ModelChoiceField(
                label="Compte privilégié",
                queryset=ExternalAccount.objects.filter(
                    active=True,
                    kind__in=("privileged", "service"),
                    identity__status="active",
                ),
            ),
            "protocol": forms.ChoiceField(
                label="Transport",
                choices=[
                    ("ssh", "SSH"),
                    ("rdp", "RDP — NLA et certificat épinglé"),
                ],
            ),
            "hostname": forms.CharField(label="DNS ou IP autorisé au déploiement", max_length=253),
            "port": forms.IntegerField(label="Port", min_value=1, max_value=65535),
            "domain": forms.CharField(
                label="Domaine RDP (facultatif)", max_length=180, required=False
            ),
            "auth_method": forms.ChoiceField(
                label="Authentification distante",
                choices=[
                    ("password", "Mot de passe"),
                    ("private_key", "Clé privée SSH"),
                ],
            ),
            "password": forms.CharField(
                label="Mot de passe distant",
                required=False,
                max_length=4096,
                widget=forms.PasswordInput,
            ),
            "private_key": forms.CharField(
                label="Clé privée SSH (si cette méthode est choisie)",
                required=False,
                max_length=16384,
                widget=SecretTextarea(attrs={"rows": 5}),
            ),
            "passphrase": forms.CharField(
                label="Phrase de déverrouillage de la nouvelle clé",
                required=False,
                max_length=1024,
                widget=forms.PasswordInput,
            ),
            "host_key": forms.CharField(
                label="Clé publique d’hôte SSH attendue",
                required=False,
                max_length=16384,
                initial=endpoint.ssh_host_key if endpoint else "",
            ),
            "rdp_pin": forms.CharField(
                label="Empreinte SHA-256 du certificat RDP attendu",
                required=False,
                max_length=103,
                initial=endpoint.certificate_pin if endpoint else "",
            ),
        }
    )
    if request.method == "POST" and form.is_valid():
        try:
            target = configure_endpoint(
                actor=request.user,
                organization=request.organization,
                endpoint_id=endpoint_id,
                **form.cleaned_data,
            )
            messages.success(
                request, "Cible enregistrée, inactive. Testez son identité avant activation."
            )
            return redirect("pam-endpoint-edit", endpoint_id=target.pk)
        except (ValidationError, TransportFailure) as error:
            form.add_error(None, str(error))
    return render(request, "pam/configure.html", {"form": form, "endpoint": endpoint})


@scoped("pam", roles=("admin",))
@require_POST
def endpoint_action(request, endpoint_id, action):
    if action not in ("test", "enable", "disable"):
        raise Http404
    get_object_or_404(SessionEndpoint.objects, pk=endpoint_id)
    try:
        if action == "test":
            verified, code = probe_endpoint(
                endpoint_id, actor=request.user, organization=request.organization
            )
            (messages.success if verified else messages.error)(request, f"Test d’identité : {code}")
        else:
            set_endpoint_enabled(
                endpoint_id,
                actor=request.user,
                organization=request.organization,
                enabled=action == "enable",
            )
            messages.success(request, "État de la cible mis à jour.")
    except (ValidationError, TransportFailure) as error:
        messages.error(request, str(error))
    return redirect("pam-endpoint-edit", endpoint_id=endpoint_id)


@scoped("pam", roles=("admin", "operator"))
@require_POST
def launch(request, intent_id):
    from platform_modules.access.models import AccessIntent

    get_object_or_404(AccessIntent.objects, pk=intent_id)
    try:
        ip = client_address(
            request.META.get("REMOTE_ADDR"), request.META.get("HTTP_X_FORWARDED_FOR", "")
        )
        item, ticket = launch_session(
            intent_id,
            actor=request.user,
            organization=request.organization,
            session_key=request.session.session_key,
            client_ip=ip,
        )
    except (ValidationError, TransportFailure, SessionEndpoint.DoesNotExist) as error:
        messages.error(
            request,
            "Aucune cible active compatible."
            if isinstance(error, SessionEndpoint.DoesNotExist)
            else str(error),
        )
        return redirect("pam-home")
    return render(
        request,
        "pam/session.html",
        {
            "connection": item,
            "player": {"mode": "live", "ticket": ticket, "websocket_path": f"/ws/pam/{item.pk}/"},
        },
    )


@scoped()
def detail(request, connection_id):
    item = get_object_or_404(
        RelayConnection.objects.select_related(
            "endpoint", "opened_by", "lease__intent", "organization"
        ),
        pk=connection_id,
    )
    if item.opened_by_id != request.user.pk:
        from platform_core.services import authorize

        authorize(request.user, request.organization, roles=("admin", "auditor"))
    return render(request, "pam/detail.html", {"connection": item})


@login_required
@require_POST
def stop(request, connection_id):
    item = get_object_or_404(RelayConnection.objects, pk=connection_id)
    if item.opened_by_id == request.user.pk:
        # Reducing one's own privilege never needs an in-session MFA challenge.
        stop_session(connection_id, actor=request.user, organization=request.organization)
    else:
        from platform_core.services import authorize

        authorize(request.user, request.organization, roles=("admin",))
        challenge = ensure_recent(request)
        if challenge:
            return challenge
        with recent_authentication(
            request.user, request.organization, request.session.get("mfa_verified_at", 0)
        ):
            stop_session(connection_id, actor=request.user, organization=request.organization)
    messages.success(request, "Fermeture demandée ; le relais applique le retrait d’autorisation.")
    return redirect("pam-connection", connection_id=connection_id)


@scoped()
@require_POST
def recording(request, connection_id):
    item = get_object_or_404(
        RelayConnection.objects.select_related("organization"), pk=connection_id
    )
    try:
        authorize_recording(item, request.user)
        if not item.recording_bytes:
            raise ValidationError("Aucun affichage distant n’a été capturé pour ce relais.")
    except ValidationError as error:
        messages.error(request, str(error))
        return redirect("pam-connection", connection_id=connection_id)
    grants = request.session.get("pam_recording_grants", {})
    grants = {key: value for key, value in grants.items() if value["expires_at"] > time.time()}
    if len(grants) >= 10:
        grants.pop(next(iter(grants)))
    grants[str(item.pk)] = issue_recording_grant(item, request.user, request.session.session_key)
    request.session["pam_recording_grants"] = grants
    record(
        action="pam.recording.viewed.v1",
        summary="Consultation d’une capture PAM",
        actor=request.user,
        organization=request.organization,
        target=item,
    )
    return render(
        request,
        "pam/session.html",
        {
            "connection": item,
            "player": {
                "mode": "recording",
                "url": reverse("pam-recording-data", args=[item.pk]),
                "bytes": item.recording_bytes,
            },
        },
    )


@scoped()
def recording_data(request, connection_id):
    from .broker import database

    if request.headers.get("Range"):
        return HttpResponse(status=416)
    item = get_object_or_404(
        RelayConnection.objects.select_related("organization"), pk=connection_id
    )
    grant = request.session.get("pam_recording_grants", {}).get(str(item.pk), {})
    if not grant or grant.get("expires_at", 0) <= time.time():
        raise PermissionDenied("Ouvrez la capture après une validation MFA.")
    validate_grant(item, request.user, request.session.session_key, grant)
    authorize_recording(item, request.user)
    key, organization = request.session.session_key, request.organization

    async def stream():
        sequence, previous, size = 0, "", 0
        while True:
            payloads, sequence, previous = await database(
                recording_page, item.pk, organization, key, grant, sequence, previous
            )
            if not payloads:
                if size != item.recording_bytes:
                    raise ValidationError("Taille finale de capture incohérente.")
                return
            for payload in payloads:
                size += len(payload)
                yield payload

    response = StreamingHttpResponse(stream(), content_type="application/octet-stream")
    response["Content-Disposition"] = f'inline; filename="pamolive-{item.pk}.guac"'
    response["X-Content-Type-Options"] = "nosniff"
    response["Cache-Control"] = "no-store"
    return response
