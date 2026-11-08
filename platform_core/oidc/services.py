import base64
import hashlib
import hmac
import json
import re
import secrets
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

from cryptography.fernet import InvalidToken
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac

from platform_core.audit import record
from platform_core.authorization import assurance_datetime, require_recent_authentication
from platform_core.models import Organization, OrganizationMembership
from platform_core.security import cipher
from platform_core.services import authorize
from platform_core.tenancy import current_organization

from .client import OIDCFailure, discover, endpoint
from .models import OIDCAttempt, OIDCDraft, OIDCLink, OIDCProvider


def tag(value, domain="config"):
    return hmac.new(
        settings.SECRET_KEY.encode(),
        ("pamolive.oidc." + domain + ".v1\0").encode()
        + json.dumps(value, sort_keys=True, separators=(",", ":")).encode(),
        "sha256",
    ).hexdigest()


def session_hash(session):
    if not session.session_key:
        session.create()
    return salted_hmac(
        "pamolive.oidc.browser.v1", session.session_key, algorithm="sha256"
    ).hexdigest()


def callback_uri(organization, slug):
    origin = settings.OIDC_PUBLIC_ORIGIN
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or "\\" in origin
        or not re.fullmatch(r"[a-zA-Z0-9_\-]{1,50}", slug)
    ):
        raise OIDCFailure("configure_exact_public_https_origin")
    return f"{origin}/accounts/oidc/{organization.pk}/{slug}/callback/"


def admin(actor, organization):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    authorize(actor, organization, roles=("admin",))
    require_recent_authentication(actor, organization)


def member(actor, organization):
    if (
        not organization
        or not actor
        or not actor.is_active
        or not organization.active
        or not OrganizationMembership.objects.filter(
            organization=organization, account=actor, active=True, account__is_active=True
        ).exists()
    ):
        raise PermissionDenied


def configuration(values, organization):
    result = {
        name: values[name]
        for name in (
            "slug",
            "name",
            "issuer",
            "client_id",
            "client_secret",
            "algorithm",
            "auth_method",
        )
    }
    if (
        result["algorithm"] not in {"RS256", "ES256"}
        or result["auth_method"] not in {"client_secret_basic", "client_secret_post"}
        or not 1 <= len(result["client_secret"]) <= 4096
        or any(ord(char) < 32 for char in result["client_id"] + result["client_secret"])
    ):
        raise ValidationError("Configuration de client confidentiel invalide.")
    result["redirect_uri"] = callback_uri(organization, result["slug"])
    endpoint(result["issuer"])
    return result


def provider_config(provider):
    return configuration(
        dict(
            slug=provider.slug,
            name=provider.name,
            issuer=provider.issuer,
            client_id=provider.client_id,
            client_secret=cipher().decrypt(provider.encrypted_secret.encode()).decode(),
            algorithm=provider.algorithm,
            auth_method=provider.auth_method,
        ),
        provider.organization,
    )


def ready(provider):
    try:
        config = provider_config(provider)
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            endpoint(provider.metadata[key])
        return (
            provider.organization.active
            and provider.verified_at <= timezone.now()
            and constant_time_compare(provider.verification_proof, provider_proof(provider))
            and constant_time_compare(
                provider.config_hash, tag({"config": config, "metadata": provider.metadata})
            )
        )
    except (ValueError, KeyError, TypeError, AttributeError, InvalidToken):
        return False


def draft_proof(draft):
    return tag(
        dict(
            id=str(draft.pk),
            organization=str(draft.organization_id),
            provider=str(draft.provider_id),
            owner=draft.owner_id,
            browser=draft.session_hash,
            config_hash=draft.config_hash,
            verified_at=draft.verified_at.isoformat(),
        ),
        "test",
    )


def provider_proof(provider):
    return tag(
        dict(
            id=str(provider.pk),
            organization=str(provider.organization_id),
            config_hash=provider.config_hash,
            verified_at=provider.verified_at.isoformat(),
        ),
        "provider",
    )


def read_draft(draft_id, *, actor, organization, session):
    draft = OIDCDraft.unscoped.filter(
        pk=draft_id,
        organization=organization,
        owner=actor,
        session_hash=session_hash(session),
        expires_at__gt=timezone.now(),
    ).first()
    if not draft or not draft.encrypted_config:
        raise OIDCFailure("draft_expired_or_wrong_browser")
    config = json.loads(cipher().decrypt(draft.encrypted_config.encode()).decode())
    if not constant_time_compare(
        draft.config_hash, tag({"config": config, "metadata": draft.metadata})
    ):
        raise OIDCFailure("draft_integrity")
    return draft, config


def probe(values, *, actor, organization, session, provider=None):
    admin(actor, organization)
    config = configuration(values, organization)
    if provider and (
        provider.organization_id != organization.pk
        or (provider.slug, provider.issuer, provider.client_id)
        != (config["slug"], config["issuer"], config["client_id"])
    ):
        raise PermissionDenied
    metadata = discover(config)
    with transaction.atomic():
        Organization.objects.select_for_update().get(pk=organization.pk, active=True)
        draft = OIDCDraft.objects.create(
            organization=organization,
            owner=actor,
            provider=provider,
            session_hash=session_hash(session),
            encrypted_config=cipher().encrypt(json.dumps(config).encode()).decode(),
            config_hash=tag({"config": config, "metadata": metadata}),
            metadata=metadata,
            expires_at=timezone.now() + timedelta(minutes=15),
        )
        record(
            organization=organization,
            actor=actor,
            target=draft,
            action="core.oidc.discovery_tested.v1",
            summary="Découverte OIDC vérifiée",
        )
        return draft


@transaction.atomic
def save_provider(draft_id, *, actor, organization, session, provider_id=None):
    admin(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    draft, config = read_draft(draft_id, actor=actor, organization=organization, session=session)
    if draft.provider_id != provider_id:
        raise OIDCFailure("draft_provider_mismatch")
    if (
        not draft.verified_at
        or draft.verified_at > timezone.now()
        or not constant_time_compare(draft.verification_proof, draft_proof(draft))
        or callback_uri(organization, config["slug"]) != config["redirect_uri"]
    ):
        raise OIDCFailure("complete_login_test_before_saving")
    provider = (
        OIDCProvider.objects.select_for_update().get(pk=provider_id)
        if provider_id
        else OIDCProvider(organization=organization)
    )
    if provider_id and (provider.slug, provider.issuer, provider.client_id) != (
        config["slug"],
        config["issuer"],
        config["client_id"],
    ):
        raise ValidationError(
            "L’identifiant, l’émetteur et le client sont immuables ; créez un nouveau domaine."
        )
    changed = provider.config_hash != draft.config_hash
    for field in (
        "slug",
        "name",
        "issuer",
        "client_id",
        "algorithm",
        "auth_method",
        "redirect_uri",
    ):
        setattr(provider, field, config[field])
    provider.encrypted_secret = cipher().encrypt(config["client_secret"].encode()).decode()
    provider.metadata, provider.config_hash, provider.verified_at = (
        draft.metadata,
        draft.config_hash,
        draft.verified_at,
    )
    provider.verification_proof = provider_proof(provider)
    if changed:
        provider.enabled = False
    provider.full_clean()
    provider.save()
    record(
        organization=organization,
        actor=actor,
        target=provider,
        action="core.oidc.saved.v1",
        summary="Domaine OIDC testé et enregistré inactif" if changed else "Test OIDC renouvelé",
    )
    return provider


@transaction.atomic
def set_enabled(provider, enabled, *, actor, organization):
    admin(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    provider = OIDCProvider.objects.select_for_update().get(pk=provider.pk)
    if enabled and (
        not ready(provider) or timezone.now() - provider.verified_at > timedelta(hours=1)
    ):
        raise OIDCFailure("fresh_complete_test_required")
    provider.enabled = enabled
    provider.save(update_fields=["enabled"])
    record(
        organization=organization,
        actor=actor,
        target=provider,
        action="core.oidc.enabled.v1" if enabled else "core.oidc.disabled.v1",
        summary="Domaine OIDC activé" if enabled else "Domaine OIDC désactivé",
    )


def link_signature(link):
    return tag(
        dict(
            id=str(link.pk),
            organization_id=str(link.organization_id),
            provider_id=str(link.provider_id),
            issuer=link.provider.issuer,
            client_id=link.provider.client_id,
            account_id=link.account_id,
            subject=link.subject,
            created_at=link.created_at.isoformat(),
            mfa_verified_at=link.mfa_verified_at.isoformat(),
            mfa_window_minutes=link.mfa_window_minutes,
        ),
        "link",
    )


def valid_link(link):
    return (
        not link.revoked_at
        and link.account.is_active
        and link.mfa_window_minutes in {2, 5, 10, 15}
        and 0
        <= (link.created_at - link.mfa_verified_at).total_seconds()
        < link.mfa_window_minutes * 60
        and constant_time_compare(link.signature, link_signature(link))
    )


@transaction.atomic
def associate(provider, subject, *, actor, organization):
    member(actor, organization)
    assurance = require_recent_authentication(actor, organization)
    if provider.organization_id != organization.pk:
        raise PermissionDenied
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    provider = (
        OIDCProvider.objects.select_for_update().select_related("organization").get(pk=provider.pk)
    )
    if provider.organization_id != organization.pk or not provider.enabled or not ready(provider):
        raise PermissionDenied
    if not re.fullmatch(r"[\x21-\x7e]{1,255}", subject):
        raise OIDCFailure("invalid_subject")
    existing = (
        OIDCLink.objects.filter(provider=provider, revoked_at__isnull=True)
        .filter(Q(subject=subject) | Q(account=actor))
        .first()
    )
    if existing:
        if existing.subject == subject and existing.account_id == actor.pk and valid_link(existing):
            return existing
        raise OIDCFailure("subject_or_account_already_associated")
    link = OIDCLink(
        organization=organization,
        provider=provider,
        subject=subject,
        account=actor,
        mfa_verified_at=assurance_datetime(assurance.verified_at),
        mfa_window_minutes=assurance.freshness_minutes,
    )
    link.signature = link_signature(link)
    link.full_clean()
    link.save()
    record(
        organization=organization,
        actor=actor,
        target=link,
        action="core.oidc.self_linked.v1",
        summary="Association OIDC confirmée par le titulaire",
    )
    return link


@transaction.atomic
def revoke_link(link, *, actor, organization):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    link = OIDCLink.objects.select_for_update().get(pk=link.pk)
    if actor.pk != link.account_id:
        authorize(actor, organization, roles=("admin",))
    else:
        member(actor, organization)
    require_recent_authentication(actor, organization)
    if not link.revoked_at:
        link.revoked_at = timezone.now()
        link.save(update_fields=["revoked_at"])
        record(
            organization=organization,
            actor=actor,
            target=link,
            action="core.oidc.link_revoked.v1",
            summary="Association OIDC révoquée",
        )


def federation(session_data, actor):
    value = session_data.get("oidc")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PermissionDenied
    try:
        link = OIDCLink.unscoped.select_related("provider__organization", "account").get(
            pk=value.get("link_id"),
            provider_id=value.get("provider_id"),
            account=actor,
            organization_id=value.get("organization_id"),
        )
    except (OIDCLink.DoesNotExist, ValueError, TypeError, ValidationError):
        raise PermissionDenied from None
    member(actor, link.provider.organization)
    if (
        not valid_link(link)
        or not link.provider.enabled
        or not ready(link.provider)
        or not constant_time_compare(value.get("config_hash", ""), link.provider.config_hash)
    ):
        raise PermissionDenied
    return link.organization_id


def start(*, organization, session, purpose, actor=None, provider=None, draft=None):
    if purpose == "test":
        admin(actor, organization)
        draft, config = read_draft(
            draft.pk, actor=actor, organization=organization, session=session
        )
        metadata, config_hash = draft.metadata, draft.config_hash
    else:
        if (
            not provider
            or provider.organization_id != organization.pk
            or not provider.enabled
            or not ready(provider)
        ):
            raise OIDCFailure("provider_inactive_or_unverified")
        config, metadata, config_hash = (
            provider_config(provider),
            provider.metadata,
            provider.config_hash,
        )
        if purpose == "link":
            member(actor, organization)
            assurance = require_recent_authentication(actor, organization)
        elif purpose != "login":
            raise OIDCFailure("invalid_flow_purpose")
    browser = session_hash(session)
    with transaction.atomic():
        Organization.objects.select_for_update().get(pk=organization.pk, active=True)
        if (
            OIDCAttempt.unscoped.filter(
                session_hash=browser, expires_at__gt=timezone.now(), used_at__isnull=True
            ).count()
            >= 5
        ):
            raise OIDCFailure("too_many_pending_flows")
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        flow = dict(config, metadata=metadata, nonce=nonce, verifier=verifier)
        if purpose == "link":
            flow.update(
                mfa_verified_at=assurance.verified_at,
                mfa_window_minutes=assurance.freshness_minutes,
            )
        attempt = OIDCAttempt(
            organization=organization,
            provider=provider,
            draft=draft,
            requester=actor,
            purpose=purpose,
            session_hash=browser,
            state_hash=hashlib.sha256(state.encode()).hexdigest(),
            config_hash=config_hash,
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        flow["binding"] = attempt_binding(attempt)
        attempt.encrypted_flow = cipher().encrypt(json.dumps(flow).encode()).decode()
        attempt.save()
    params = dict(
        response_type="code",
        client_id=config["client_id"],
        redirect_uri=config["redirect_uri"],
        scope="openid email profile",
        state=state,
        nonce=nonce,
        code_challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("="),
        code_challenge_method="S256",
    )
    return attempt, metadata["authorization_endpoint"] + "?" + urlencode(params)


@transaction.atomic
def claim(state, *, organization_id, slug, session, actor=None):
    if not isinstance(state, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", state):
        raise OIDCFailure("invalid_authorization_state")
    attempt = (
        OIDCAttempt.unscoped.select_for_update(of=("self",))
        .select_related("provider", "draft")
        .filter(
            organization_id=organization_id,
            state_hash=hashlib.sha256(state.encode()).hexdigest(),
            used_at__isnull=True,
            expires_at__gt=timezone.now(),
            session_hash=session_hash(session),
        )
        .first()
    )
    if not attempt or not attempt.encrypted_flow:
        raise OIDCFailure("expired_replayed_or_wrong_browser_state")
    flow = json.loads(cipher().decrypt(attempt.encrypted_flow.encode()).decode())
    if flow.get("binding") != attempt_binding(attempt):
        raise OIDCFailure("flow_integrity")
    if flow["slug"] != slug or callback_uri(attempt.organization, slug) != flow["redirect_uri"]:
        raise OIDCFailure("callback_mismatch")
    if attempt.purpose != "login" and (
        not actor or not actor.is_authenticated or actor.pk != attempt.requester_id
    ):
        raise OIDCFailure("wrong_test_or_link_owner")
    attempt.used_at = timezone.now()
    attempt.encrypted_flow = ""
    attempt.save(update_fields=["used_at", "encrypted_flow"])
    return attempt, flow


def cleanup_expired():
    now = timezone.now()
    for model, field in ((OIDCDraft, "encrypted_config"), (OIDCAttempt, "encrypted_flow")):
        ids = list(
            model.unscoped.filter(expires_at__lte=now)
            .exclude(**{field: ""})
            .values_list("pk", flat=True)[:100]
        )
        values = {field: ""}
        if model is OIDCDraft:
            values["encrypted_result"] = ""
        model.unscoped.filter(pk__in=ids).update(**values)


def attempt_binding(attempt):
    return dict(
        id=str(attempt.pk),
        organization=str(attempt.organization_id),
        provider=str(attempt.provider_id),
        draft=str(attempt.draft_id),
        requester=attempt.requester_id,
        purpose=attempt.purpose,
        browser=attempt.session_hash,
        state=attempt.state_hash,
        config_hash=attempt.config_hash,
        expires_at=attempt.expires_at.isoformat(),
    )


def pending_proof(attempt):
    return tag(
        dict(
            binding=attempt_binding(attempt),
            link=str(attempt.pending_link_id),
            until=attempt.pending_until.isoformat(),
            used_at=attempt.used_at.isoformat(),
        ),
        "pending",
    )
