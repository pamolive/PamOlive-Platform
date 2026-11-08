"""Attested TeamViewer configuration; domain services never inherit a view's trust."""

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import timedelta

from cryptography.fernet import InvalidToken
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import constant_time_compare

from platform_core.audit import record
from platform_core.authorization import assurance_datetime, require_recent_authentication
from platform_core.models import Organization
from platform_core.security import cipher
from platform_core.services import authorize, require_module
from platform_core.tenancy import current_organization

from .models import EventSource
from .scim import IntegrationFailure
from .teamviewer import TeamViewerClient, _json, _time
from .teamviewer_models import TeamViewerCollector


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def tag(value, domain):
    return hmac.new(
        settings.SECRET_KEY.encode(),
        ("pamolive.teamviewer." + domain + ".v1\0").encode() + canonical(value),
        "sha256",
    ).hexdigest()


def _admin(actor, organization):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    actor = get_user_model().objects.filter(pk=getattr(actor, "pk", None), is_active=True).first()
    if actor is None or not Organization.objects.filter(pk=organization.pk, active=True).exists():
        raise PermissionDenied
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "connectors")
    return actor, require_recent_authentication(actor, organization)


def config_values(*, name, token, start_at, collect_notes):
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 180
        or name != name.strip()
        or any(ord(char) < 32 for char in name)
        or type(collect_notes) is not bool
    ):
        raise ValidationError("Nom ou politique de notes TeamViewer invalide.")
    if isinstance(start_at, str):
        start_at = _time(start_at)
    if (
        not hasattr(start_at, "utcoffset")
        or start_at.utcoffset() is None
        or start_at.microsecond
        or start_at >= timezone.now()
    ):
        raise ValidationError(
            "La première date de fin doit être passée, avec fuseau et secondes entières."
        )
    # Constructor validates the deployment's fixed HTTPS origin and token syntax;
    # it does not perform a network call.
    TeamViewerClient(token)
    return dict(name=name, token=token, start_at=start_at.isoformat(), collect_notes=collect_notes)


def browser_binding(browser_key):
    if not isinstance(browser_key, str) or not 16 <= len(browser_key) <= 128:
        raise PermissionDenied
    return tag(browser_key, "browser")


def test_configuration(
    *,
    actor,
    organization,
    browser_key,
    name,
    token,
    start_at,
    collect_notes=False,
    collector_id=None,
):
    actor, _ = _admin(actor, organization)
    config = config_values(name=name, token=token, start_at=start_at, collect_notes=collect_notes)
    current = TeamViewerCollector.objects.get(pk=collector_id) if collector_id else None
    identifier = current.pk if current else uuid.uuid4()
    browser = browser_binding(browser_key)
    tested_at = timezone.now().replace(microsecond=0)
    # Validate an actual readable page, not the entirety of historical collection.
    batch = TeamViewerClient(token).fetch_completed(
        tested_at - timedelta(minutes=5),
        tested_at,
        max_pages=1,
    )
    if not batch.pagination_complete and batch.code != "page_limit":
        raise IntegrationFailure(batch.code)
    actor, _ = _admin(actor, organization)
    payload = dict(
        schema="teamviewer-draft/1",
        actor=actor.pk,
        organization=str(organization.pk),
        browser=browser,
        collector=str(identifier),
        new=current is None,
        revision=current.revision if current else 0,
        config=config,
        tested_at=tested_at.isoformat(),
    )
    capsule = cipher().encrypt(canonical(payload)).decode()
    record(
        organization=organization,
        actor=actor,
        action="connectors.teamviewer.tested.v1",
        summary="Lecture API TeamViewer vérifiée",
        metadata={
            "read_page_verified": True,
            "reports_in_recent_window": len(batch.reports),
            "pagination_complete": batch.pagination_complete,
            "imported": 0,
        },
    )
    return capsule, dict(
        read_page_verified=True,
        imported=0,
        collector_saved=False,
        reports_in_recent_window=len(batch.reports),
    )


def _draft(capsule, *, actor, organization, browser_key):
    try:
        if not isinstance(capsule, str) or len(capsule) > 16384:
            raise ValueError
        data = _json(cipher().decrypt(capsule.encode(), ttl=900))
        if (
            set(data)
            != {
                "schema",
                "actor",
                "organization",
                "browser",
                "collector",
                "new",
                "revision",
                "config",
                "tested_at",
            }
            or data["schema"] != "teamviewer-draft/1"
            or data["actor"] != actor.pk
            or data["organization"] != str(organization.pk)
            or not constant_time_compare(data["browser"], browser_binding(browser_key))
            or type(data["new"]) is not bool
            or type(data["revision"]) is not int
        ):
            raise ValueError
        data["collector"] = uuid.UUID(data["collector"])
        data["tested_at"] = _time(data["tested_at"])
        if not 0 <= (timezone.now() - data["tested_at"]).total_seconds() <= 900:
            raise ValueError
        data["config"] = config_values(**data["config"])
        return data
    except (InvalidToken, ValueError, TypeError, KeyError, AttributeError):
        raise ValidationError("Brouillon expiré, modifié ou lié à un autre navigateur.") from None


def collector_config(collector):
    return dict(
        name=collector.name,
        token=cipher().decrypt(collector.encrypted_token.encode()).decode(),
        start_at=collector.start_at.isoformat(),
        collect_notes=collector.collect_notes,
    )


def config_proof(collector):
    return tag(
        dict(
            id=str(collector.pk),
            organization=str(collector.organization_id),
            source=str(collector.source_id),
            config_hash=collector.config_hash,
            revision=collector.revision,
            tested_at=collector.tested_at.isoformat(),
            configured_at=collector.configured_at.isoformat(),
            actor=collector.configured_by_id,
            mfa_at=collector.mfa_verified_at.isoformat(),
            mfa_window=collector.mfa_window_minutes,
        ),
        "configuration",
    )


def verify_configuration(collector):
    try:
        config = collector_config(collector)
        return bool(
            collector.mfa_window_minutes in {2, 5, 10, 15}
            and 0
            <= (collector.configured_at - collector.mfa_verified_at).total_seconds()
            < collector.mfa_window_minutes * 60
            and collector.tested_at <= collector.configured_at <= timezone.now()
            and constant_time_compare(collector.config_hash, tag(config, "config"))
            and constant_time_compare(collector.config_proof, config_proof(collector))
        )
    except (InvalidToken, ValueError, TypeError, AttributeError):
        return False


def ready(collector):
    return bool(collector.organization.active and verify_configuration(collector))


def activation_proof(collector):
    return tag(
        dict(
            id=str(collector.pk),
            organization=str(collector.organization_id),
            source=str(collector.source_id),
            config_hash=collector.config_hash,
            revision=collector.revision,
            activation=collector.activation,
        ),
        "activation",
    )


def verify_activation(collector):
    try:
        proof = collector.activation
        if proof == {} and collector.activation_proof == "":
            return not collector.enabled
        at, mfa_at = _time(proof["at"]), _time(proof["mfa_at"])
        return bool(
            type(proof["actor"]) is int
            and type(proof["enabled"]) is bool
            and type(proof["window"]) is int
            and proof["window"] in {2, 5, 10, 15}
            and 0 <= (at - mfa_at).total_seconds() < proof["window"] * 60
            and at <= timezone.now()
            and constant_time_compare(collector.activation_proof, activation_proof(collector))
        )
    except (ValueError, TypeError, KeyError, AttributeError, IntegrationFailure):
        return False


def enabled_ready(collector):
    return bool(
        collector.enabled
        and ready(collector)
        and verify_activation(collector)
        and collector.activation.get("enabled") is True
        and EventSource.unscoped.filter(
            pk=collector.source_id, organization_id=collector.organization_id, active=True
        ).exists()
    )


def scan_proof(collector):
    return tag(
        dict(
            collector=str(collector.pk),
            organization=str(collector.organization_id),
            revision=collector.revision,
            activation_hash=collector.activation_proof,
            until=collector.scan_until.isoformat() if collector.scan_until else None,
            offset=str(collector.next_offset) if collector.next_offset else None,
            last_end=collector.scan_last_end.isoformat() if collector.scan_last_end else None,
        ),
        "scan",
    )


@transaction.atomic
def save_configuration(capsule, *, actor, organization, browser_key, collector_id=None):
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    actor, assurance = _admin(actor, organization)
    draft = _draft(capsule, actor=actor, organization=organization, browser_key=browser_key)
    config = draft["config"]
    if draft["new"]:
        if (
            collector_id is not None
            or TeamViewerCollector.unscoped.filter(pk=draft["collector"]).exists()
        ):
            raise ValidationError("Ce brouillon a déjà été enregistré ou vise un autre collecteur.")
        source = EventSource.objects.create(
            organization=organization,
            name=("TeamViewer · " + config["name"])[:180],
            active=False,
            token_hash=hashlib.sha256(secrets.token_bytes(48)).hexdigest(),
        )
        collector = TeamViewerCollector(
            id=draft["collector"], organization=organization, source=source
        )
    else:
        if str(collector_id) != str(draft["collector"]):
            raise PermissionDenied
        collector = TeamViewerCollector.objects.select_for_update().get(pk=collector_id)
        if collector.revision != draft["revision"]:
            raise ValidationError("La configuration a changé ; recommencez le test.")
        collector.revision += 1
    collector.name, collector.start_at = config["name"], _time(config["start_at"])
    collector.encrypted_token = cipher().encrypt(config["token"].encode()).decode()
    collector.collect_notes = config["collect_notes"]
    collector.config_hash = tag(collector_config(collector), "config")
    collector.tested_at, collector.configured_at = draft["tested_at"], timezone.now()
    collector.configured_by = actor
    collector.mfa_verified_at = assurance_datetime(assurance.verified_at)
    collector.mfa_window_minutes = assurance.freshness_minutes
    collector.config_proof = config_proof(collector)
    collector.enabled = False
    collector.activation, collector.activation_proof = {}, ""
    collector.scan_until = collector.next_offset = collector.scan_last_end = None
    collector.scan_proof = ""
    collector.claim_token = collector.claim_until = None
    collector.next_run_at, collector.last_code = timezone.now(), "configuration_saved_inactive"
    collector.full_clean()
    collector.save()
    EventSource.objects.filter(pk=collector.source_id).update(active=False)
    record(
        organization=organization,
        actor=actor,
        target=collector,
        action="connectors.teamviewer.saved.v1",
        summary="Collecteur TeamViewer enregistré inactif",
        metadata={
            "revision": collector.revision,
            "config_hash": collector.config_hash,
            "notes_included": collector.collect_notes,
        },
    )
    return collector


@transaction.atomic
def set_enabled(collector_id, enabled, *, actor, organization):
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    actor, assurance = _admin(actor, organization)
    collector = (
        TeamViewerCollector.objects.select_for_update()
        .select_related("organization")
        .get(pk=collector_id)
    )
    if type(enabled) is not bool:
        raise ValidationError("État de collecte invalide.")
    if enabled and (
        not ready(collector) or timezone.now() - collector.tested_at > timedelta(hours=1)
    ):
        raise ValidationError("Un test de lecture récent et valide est requis.")
    if enabled:
        TeamViewerClient(collector_config(collector)["token"])
    collector.enabled = enabled
    collector.activation = dict(
        actor=actor.pk,
        enabled=enabled,
        at=timezone.now().isoformat(),
        mfa_at=assurance_datetime(assurance.verified_at).isoformat(),
        window=assurance.freshness_minutes,
    )
    collector.activation_proof = activation_proof(collector)
    collector.scan_until = collector.next_offset = collector.scan_last_end = None
    collector.scan_proof = scan_proof(collector) if enabled else ""
    collector.next_run_at = timezone.now()
    collector.claim_token = collector.claim_until = None
    collector.save(
        update_fields=[
            "enabled",
            "claim_token",
            "claim_until",
            "activation",
            "activation_proof",
            "scan_until",
            "next_offset",
            "scan_last_end",
            "scan_proof",
            "next_run_at",
        ]
    )
    EventSource.objects.filter(pk=collector.source_id).update(active=enabled)
    record(
        organization=organization,
        actor=actor,
        target=collector,
        action="connectors.teamviewer.enabled.v1"
        if enabled
        else "connectors.teamviewer.disabled.v1",
        summary="État de collecte TeamViewer modifié",
        metadata={
            "enabled": enabled,
            "activation_hash": collector.activation_proof,
            "config_hash": collector.config_hash,
        },
    )
    return collector
