import json
import time
import uuid
from datetime import timedelta
from functools import wraps

from cryptography.fernet import InvalidToken
from django import forms
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from platform_core.audit import record
from platform_core.authorization import recent_authentication
from platform_core.security import MFALoginForm, cipher, ensure_recent, throttle, verify_mfa
from platform_core.services import authorize
from platform_core.tenancy import organization_context

from . import services
from .client import OIDCFailure, exchange
from .models import OIDCAttempt, OIDCLink, OIDCProvider


class PortalLogin(LoginView):
    template_name = "registration/login.html"
    authentication_form = MFALoginForm

    def get_context_data(self, **kwargs):
        data = super().get_context_data(**kwargs)
        data["oidc_providers"] = [
            item
            for item in OIDCProvider.unscoped.filter(enabled=True, organization__active=True)
            .select_related("organization")
            .order_by("organization__name", "name")
            if services.ready(item)
        ]
        return data


class ProviderForm(forms.Form):
    slug = forms.SlugField(label="Identifiant du domaine", max_length=50)
    name = forms.CharField(label="Nom affiché", max_length=100)
    issuer = forms.URLField(label="Émetteur OIDC exact (issuer)", max_length=500)
    client_id = forms.CharField(label="Client ID", max_length=255)
    client_secret = forms.CharField(
        label="Secret client",
        max_length=4096,
        required=False,
        widget=forms.PasswordInput,
        help_text="Vide : conserve le secret du brouillon ou du domaine existant.",
    )
    algorithm = forms.ChoiceField(
        label="Signature des ID tokens", choices=[("RS256", "RS256"), ("ES256", "ES256")]
    )
    auth_method = forms.ChoiceField(
        label="Authentification du client",
        choices=[
            ("client_secret_basic", "Secret par HTTP Basic"),
            ("client_secret_post", "Secret dans le POST"),
        ],
    )
    draft_id = forms.UUIDField(required=False, widget=forms.HiddenInput)


def protected(*, administrator=False, sensitive=False):
    def decorate(view):
        @login_required
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if request.organization is None:
                raise PermissionDenied
            if administrator:
                authorize(request.user, request.organization, roles=("admin",))
            else:
                services.member(request.user, request.organization)
            if sensitive or request.method == "POST":
                challenge = ensure_recent(request)
                if challenge is not None:
                    return challenge
                with recent_authentication(
                    request.user, request.organization, request.session.get("mfa_verified_at", 0)
                ):
                    try:
                        return view(request, *args, **kwargs)
                    except (OIDCFailure, InvalidToken, ValidationError):
                        return failed(request)
            try:
                return view(request, *args, **kwargs)
            except (OIDCFailure, InvalidToken, ValidationError):
                return failed(request)

        return wrapped

    return decorate


@protected(administrator=True)
@require_GET
def providers(request):
    return render(
        request,
        "oidc/providers.html",
        {
            "providers": OIDCProvider.objects.all(),
            "links": OIDCLink.objects.select_related("account", "provider").filter(
                revoked_at__isnull=True
            ),
        },
    )


@protected(administrator=True)
@require_http_methods(["GET", "POST"])
def configure(request, provider_id=None):
    provider = get_object_or_404(OIDCProvider.objects, pk=provider_id) if provider_id else None
    initial = (
        {
            field: getattr(provider, field)
            for field in ("slug", "name", "issuer", "client_id", "algorithm", "auth_method")
        }
        if provider
        else {"algorithm": "RS256", "auth_method": "client_secret_basic"}
    )
    draft, config, result = None, None, None
    draft_id = (
        request.POST.get("draft_id") if request.method == "POST" else request.GET.get("draft")
    )
    try:
        if draft_id:
            draft, config = services.read_draft(
                draft_id,
                actor=request.user,
                organization=request.organization,
                session=request.session,
            )
            if draft.provider_id != (provider.pk if provider else None):
                raise OIDCFailure("draft_provider_mismatch")
            initial = {
                key: value
                for key, value in config.items()
                if key not in {"client_secret", "redirect_uri"}
            }
            initial["draft_id"] = draft.pk
            if draft.encrypted_result:
                result = json.loads(cipher().decrypt(draft.encrypted_result.encode()).decode())
    except (ValueError, InvalidToken):
        messages.warning(request, "Brouillon expiré ou d’un autre navigateur. Relancez le test.")
        draft, config = None, None
    form = ProviderForm(request.POST if request.method == "POST" else None, initial=initial)
    if provider:
        for key in ("slug", "issuer", "client_id"):
            form.fields[key].disabled = True
    callback, callback_pattern = "", ""
    try:
        callback_pattern = services.callback_uri(request.organization, "__realm__")
    except OIDCFailure:
        messages.warning(
            request, "Configurez PAMOLIVE_OIDC_PUBLIC_ORIGIN avec l’URL HTTPS publique exacte."
        )
    if request.method == "POST" and form.is_valid():
        try:
            values = dict(form.cleaned_data)
            if not values["client_secret"]:
                values["client_secret"] = (
                    config["client_secret"]
                    if config
                    else services.provider_config(provider)["client_secret"]
                    if provider
                    else ""
                )
            fresh = services.configuration(values, request.organization)
            if request.POST.get("action") == "save":
                if not draft or fresh != config:
                    raise OIDCFailure("configuration_changed_retest_required")
                saved = services.save_provider(
                    draft.pk,
                    actor=request.user,
                    organization=request.organization,
                    session=request.session,
                    provider_id=provider.pk if provider else None,
                )
                messages.success(
                    request, "Domaine enregistré. Son activation reste une action séparée."
                )
                return redirect("oidc-provider-edit", provider_id=saved.pk)
            draft = services.probe(
                values,
                actor=request.user,
                organization=request.organization,
                session=request.session,
                provider=provider,
            )
            return redirect(
                reverse("oidc-provider-edit", kwargs={"provider_id": provider.pk})
                + "?draft="
                + str(draft.pk)
                if provider
                else reverse("oidc-provider-new") + "?draft=" + str(draft.pk)
            )
        except (OIDCFailure, ValidationError, InvalidToken) as error:
            form.add_error(
                None,
                "Test ou enregistrement refusé. Vérifiez l’émetteur, les hôtes autorisés, "
                "le callback et le secret. "
                + (str(error) if isinstance(error, OIDCFailure) else ""),
            )
    try:
        slug = form["slug"].value()
        if slug:
            callback = services.callback_uri(request.organization, slug)
    except OIDCFailure:
        pass
    return render(
        request,
        "oidc/configure.html",
        dict(
            form=form,
            provider=provider,
            draft=draft,
            callback=callback,
            callback_pattern=callback_pattern,
            result=result,
        ),
    )


@protected(administrator=True)
@require_POST
def activation(request, provider_id):
    provider = get_object_or_404(OIDCProvider.objects, pk=provider_id)
    try:
        services.set_enabled(
            provider,
            request.POST.get("action") == "enable",
            actor=request.user,
            organization=request.organization,
        )
    except (OIDCFailure, ValidationError) as error:
        messages.error(request, "Activation refusée : " + str(error))
    return redirect("oidc-providers")


@protected(administrator=True, sensitive=True)
@require_http_methods(["GET", "POST"])
def test_start(request, draft_id):
    if request.method == "POST":
        return render(request, "oidc/continue.html", {"continuation": request.path})
    draft, _ = services.read_draft(
        draft_id, actor=request.user, organization=request.organization, session=request.session
    )
    _, url = services.start(
        organization=request.organization,
        session=request.session,
        purpose="test",
        actor=request.user,
        draft=draft,
    )
    return redirect(url)


@protected()
@require_GET
def my_links(request):
    return render(
        request,
        "oidc/my_links.html",
        dict(
            providers=OIDCProvider.objects.filter(enabled=True),
            links=OIDCLink.objects.filter(
                account=request.user, revoked_at__isnull=True
            ).select_related("provider"),
        ),
    )


@protected(sensitive=True)
@require_http_methods(["GET", "POST"])
def link_start(request, provider_id):
    if request.method == "POST":
        return render(request, "oidc/continue.html", {"continuation": request.path})
    provider = get_object_or_404(OIDCProvider.objects, pk=provider_id, enabled=True)
    _, url = services.start(
        organization=request.organization,
        session=request.session,
        purpose="link",
        actor=request.user,
        provider=provider,
    )
    return redirect(url)


@protected()
@require_POST
def revoke(request, link_id):
    link = get_object_or_404(OIDCLink.objects, pk=link_id)
    services.revoke_link(link, actor=request.user, organization=request.organization)
    return redirect("oidc-my-links")


@require_GET
def login_start(request, provider_id):
    if request.user.is_authenticated:
        return redirect("dashboard")
    bucket = "oidc-start\0" + str(provider_id) + "\0" + request.META.get("REMOTE_ADDR", "unknown")
    if throttle(bucket, failure=True, limit=100):
        response = failed(request)
        response.status_code = 429
        return response
    provider = get_object_or_404(
        OIDCProvider.unscoped.select_related("organization"),
        pk=provider_id,
        enabled=True,
        organization__active=True,
    )
    try:
        with organization_context(provider.organization):
            _, url = services.start(
                organization=provider.organization,
                session=request.session,
                purpose="login",
                provider=provider,
            )
        return redirect(url)
    except (OIDCFailure, InvalidToken):
        return failed(request)


def failed(request):
    return render(request, "oidc/failed.html", status=400)


@transaction.atomic
def complete_login(request, attempt, link, *, mfa_at=None):
    attempt = OIDCAttempt.unscoped.select_for_update().get(pk=attempt.pk, completed_at__isnull=True)
    link = OIDCLink.unscoped.select_related("provider__organization", "account").get(pk=link.pk)
    provider = link.provider
    if (
        attempt.provider_id != provider.pk
        or attempt.config_hash != provider.config_hash
        or attempt.session_hash != services.session_hash(request.session)
        or attempt.expires_at <= timezone.now()
        or attempt.pending_link_id != link.pk
        or not attempt.pending_until
        or attempt.pending_until <= timezone.now()
        or not constant_time_compare(attempt.pending_proof, services.pending_proof(attempt))
        or not services.valid_link(link)
        or not provider.enabled
        or not services.ready(provider)
    ):
        raise OIDCFailure("login_authority_changed")
    services.member(link.account, provider.organization)
    profile = getattr(link.account, "accountsecurity", None)
    if profile and profile.encrypted_secret and mfa_at is None:
        raise OIDCFailure("local_mfa_required")
    attempt.completed_at = timezone.now()
    attempt.save(update_fields=["completed_at"])
    request.organization = provider.organization
    request.session.pop("mfa_verified_at", None)
    with organization_context(provider.organization):
        login(request, link.account, backend="django.contrib.auth.backends.ModelBackend")
    request.session["organization_id"] = str(provider.organization_id)
    request.session["oidc"] = dict(
        provider_id=str(provider.pk),
        link_id=str(link.pk),
        config_hash=provider.config_hash,
        organization_id=str(provider.organization_id),
    )
    if mfa_at is not None:
        request.session["mfa_verified_at"] = mfa_at
    request.session.pop("oidc_pending", None)


@require_GET
def callback(request, organization_id, slug):
    try:
        if any(len(request.GET.getlist(key)) != 1 for key in ("state",)):
            raise OIDCFailure("invalid_callback_parameters")
        attempt, flow = services.claim(
            request.GET.get("state"),
            organization_id=organization_id,
            slug=slug,
            session=request.session,
            actor=request.user,
        )
        if (
            "error" in request.GET
            or len(request.GET.getlist("code")) != 1
            or ("iss" in request.GET and request.GET.getlist("iss") != [flow["issuer"]])
        ):
            raise OIDCFailure("authorization_refused")
        with organization_context(attempt.organization):
            if attempt.purpose != "login" and request.organization != attempt.organization:
                raise OIDCFailure("organization_changed")
            if attempt.purpose == "test":
                authorize(request.user, attempt.organization, roles=("admin",))
                draft, _ = services.read_draft(
                    attempt.draft_id,
                    actor=request.user,
                    organization=attempt.organization,
                    session=request.session,
                )
                if draft.config_hash != attempt.config_hash:
                    raise OIDCFailure("draft_changed")
            else:
                provider = attempt.provider
                if (
                    not provider.enabled
                    or not services.ready(provider)
                    or provider.config_hash != attempt.config_hash
                ):
                    raise OIDCFailure("provider_changed")
            subject = exchange(flow, request.GET["code"])
            if attempt.purpose == "test":
                draft.verified_at = timezone.now()
                draft.encrypted_result = (
                    cipher().encrypt(json.dumps({"subject": subject}).encode()).decode()
                )
                draft.verification_proof = services.draft_proof(draft)
                draft.save(update_fields=["verified_at", "encrypted_result", "verification_proof"])
                record(
                    organization=attempt.organization,
                    actor=request.user,
                    target=draft,
                    action="core.oidc.login_tested.v1",
                    summary="Test complet OIDC validé sans connexion ni activation",
                )
                messages.success(
                    request,
                    "Test complet réussi : signature, issuer, audience, nonce et PKCE vérifiés. "
                    "Votre session locale est conservée.",
                )
                destination = (
                    reverse("oidc-provider-edit", kwargs={"provider_id": draft.provider_id})
                    if draft.provider_id
                    else reverse("oidc-provider-new")
                )
                return redirect(destination + "?draft=" + str(draft.pk))
            if attempt.purpose == "link":
                with recent_authentication(
                    request.user, attempt.organization, request.session.get("mfa_verified_at", 0)
                ):
                    services.associate(
                        provider, subject, actor=request.user, organization=attempt.organization
                    )
                messages.success(
                    request, "Votre compte est associé. La connexion locale reste disponible."
                )
                return redirect("oidc-my-links")
            link = (
                OIDCLink.objects.select_related("account")
                .filter(provider=provider, subject=subject, revoked_at__isnull=True)
                .first()
            )
            if not link or not services.valid_link(link):
                raise OIDCFailure("no_explicit_account_association")
            services.member(link.account, attempt.organization)
            attempt.pending_link = link
            attempt.pending_until = timezone.now() + timedelta(minutes=2)
            attempt.pending_proof = services.pending_proof(attempt)
            attempt.save(update_fields=["pending_link", "pending_until", "pending_proof"])
            profile = getattr(link.account, "accountsecurity", None)
            if profile and profile.encrypted_secret:
                request.session["oidc_pending"] = str(attempt.pk)
                return redirect("oidc-mfa")
            complete_login(request, attempt, link)
            return redirect("dashboard")
    except (
        OIDCFailure,
        InvalidToken,
        PermissionDenied,
        ValidationError,
        ValueError,
        OIDCLink.DoesNotExist,
        OIDCAttempt.DoesNotExist,
    ) as error:
        if "attempt" in locals():
            record(
                organization=attempt.organization,
                target=attempt,
                action="core.oidc.flow_refused.v1",
                summary="Parcours OIDC refusé",
                metadata={
                    "reason": str(error) if isinstance(error, OIDCFailure) else type(error).__name__
                },
            )
        return failed(request)


@require_http_methods(["GET", "POST"])
def mfa(request):
    pending = request.session.get("oidc_pending")
    if pending:
        try:
            pending = uuid.UUID(pending)
        except (TypeError, ValueError, AttributeError):
            return failed(request)
    attempt = (
        OIDCAttempt.unscoped.select_related("pending_link__account")
        .filter(
            pk=pending,
            purpose="login",
            session_hash=services.session_hash(request.session),
            completed_at__isnull=True,
            pending_until__gt=timezone.now(),
            expires_at__gt=timezone.now(),
        )
        .first()
        if pending
        else None
    )
    if (
        not attempt
        or not attempt.pending_link_id
        or not constant_time_compare(attempt.pending_proof, services.pending_proof(attempt))
    ):
        return failed(request)
    form = forms.Form(request.POST if request.method == "POST" else None)
    form.fields["code"] = forms.CharField(
        label="Code MFA ou récupération", max_length=64, widget=forms.PasswordInput
    )
    if request.method == "POST" and form.is_valid():
        if verify_mfa(attempt.pending_link.account, form.cleaned_data["code"].strip()):
            try:
                complete_login(request, attempt, attempt.pending_link, mfa_at=time.time())
                return redirect("dashboard")
            except (OIDCFailure, PermissionDenied, OIDCAttempt.DoesNotExist):
                return failed(request)
        form.add_error(None, "Code invalide, expiré ou déjà utilisé.")
    return render(request, "oidc/mfa.html", {"form": form})
