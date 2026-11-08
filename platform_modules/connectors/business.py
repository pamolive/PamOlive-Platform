"""Scoped inbound business facts; no approvals, identities or grants are created."""

import hashlib
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.validators import URLValidator
from django.db import connection, transaction
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.dateparse import parse_datetime

from platform_core.audit import digest, record
from platform_core.authorization import assurance_datetime, require_recent_authentication
from platform_core.models import Organization
from platform_core.services import authorize, require_module
from platform_core.tenancy import current_organization, organization_context

from .business_models import BusinessReceipt, BusinessRecord, BusinessSource

FORMAT = "pamolive.business-record/1"
KINDS = {"ticket", "incident", "change", "maintenance", "project", "emergency", "other"}
STATES = {"unknown", "open", "approved", "closed", "cancelled"}
FIELDS = {
    "schema",
    "external_id",
    "sequence",
    "kind",
    "reference",
    "state",
    "title",
    "url",
    "source_updated_at",
    "observed_at",
}


class BusinessConflict(ValidationError):
    pass


class BusinessRateLimited(PermissionDenied):
    pass


def canonical(data):
    def encode(value):
        if isinstance(value, datetime):
            return value.isoformat(timespec="microseconds")
        if isinstance(value, UUID):
            return str(value)
        raise TypeError("Unsupported business evidence value")

    return json.dumps(
        data,
        default=encode,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sign(body, purpose):
    return salted_hmac(
        "pamolive.business-reference/1/" + purpose,
        canonical(body),
        secret=settings.PAMOLIVE_ENCRYPTION_KEY,
        algorithm="sha256",
    ).hexdigest()


def source_body(source):
    return {
        key: getattr(source, key)
        for key in (
            "id",
            "organization_id",
            "key",
            "name",
            "token_hash",
            "revision",
            "active",
            "freshness_seconds",
            "configured_at",
            "configured_by_id",
            "mfa_verified_at",
            "mfa_window_minutes",
        )
    }


def anchored_signature(body, audit, purpose):
    return sign(dict(body=body, audit_id=audit.pk, audit_hash=audit.event_hash), purpose)


def anchor_valid(obj, body, purpose, action, actor_id):
    audit = obj.audit
    return bool(
        audit.organization_id == obj.organization_id
        and audit.actor_id == actor_id
        and audit.action == action
        and audit.object_type == obj._meta.label_lower
        and audit.object_id == str(obj.pk)
        and audit.event_hash == digest(audit)
        and audit.metadata.get("body_hash") == sign(body, purpose + "-body")
        and constant_time_compare(obj.signature, anchored_signature(body, audit, purpose))
    )


def verify_source(source):
    try:
        return anchor_valid(
            source,
            source_body(source),
            "source",
            "business.source.configured.v1",
            source.configured_by_id,
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False


def lock_organization(organization):
    try:
        return Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    except Organization.DoesNotExist:
        raise PermissionDenied from None


def seal_source(source, *, actor, organization):
    assurance = require_recent_authentication(actor, organization)
    source.configured_by = actor
    source.configured_at = timezone.now()
    source.mfa_verified_at = assurance_datetime(assurance.verified_at)
    source.mfa_window_minutes = assurance.freshness_minutes
    source.full_clean(exclude=["audit", "signature"])
    body = source_body(source)
    source.audit = record(
        action="business.source.configured.v1",
        summary="Configuration d’une source métier",
        actor=actor,
        organization=organization,
        target=source,
        metadata={"body_hash": sign(body, "source-body"), "revision": source.revision},
    )
    source.signature = anchored_signature(body, source.audit, "source")
    source.save()


@transaction.atomic
def create_business_source(data, *, actor, organization):
    if organization.pk != current_organization().pk:
        raise PermissionDenied
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "connectors")
    lock_organization(organization)
    if set(data) - {"key", "name", "freshness_seconds"}:
        raise ValidationError("Configuration de source inconnue.")
    token = "pobiz_" + secrets.token_urlsafe(48)
    source = BusinessSource(
        organization=organization, **data, token_hash=hashlib.sha256(token.encode()).hexdigest()
    )
    seal_source(source, actor=actor, organization=organization)
    return source, token


@transaction.atomic
def configure_business_source(source_id, *, actor, organization, active=None, rotate=False):
    if organization.pk != current_organization().pk:
        raise PermissionDenied
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "connectors")
    lock_organization(organization)
    if type(rotate) is not bool:
        raise ValidationError("Commande de rotation invalide.")
    source = BusinessSource.objects.select_for_update().get(pk=source_id)
    if not verify_source(source) or (active is not None and type(active) is not bool):
        raise ValidationError("Configuration de source invalide.")
    token = ""
    if rotate:
        token = "pobiz_" + secrets.token_urlsafe(48)
        source.token_hash = hashlib.sha256(token.encode()).hexdigest()
    if active is not None:
        source.active = active
    source.revision += 1
    seal_source(source, actor=actor, organization=organization)
    return source, token


def source_from_business_token(token):
    if not isinstance(token, str) or not re.fullmatch(r"pobiz_[A-Za-z0-9_-]{64}", token):
        raise PermissionDenied("Identifiant d’intégration invalide.")
    source = (
        BusinessSource.unscoped.select_related("organization", "audit")
        .filter(
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            active=True,
            organization__active=True,
        )
        .first()
    )
    if not source or not verify_source(source):
        raise PermissionDenied("Identifiant d’intégration invalide.")
    return source


def business_rate_bucket():
    # Shared PostgreSQL time prevents separate application VM clocks from
    # resetting a publisher's budget into different minute buckets.
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT date_trunc('minute', clock_timestamp())")
            return cursor.fetchone()[0]
    return timezone.now().replace(second=0, microsecond=0)


@transaction.atomic
def consume_business_budget(token):
    source = source_from_business_token(token)
    with organization_context(source.organization):
        lock_organization(source.organization)
        require_module(source.organization, "connectors")
        source = (
            BusinessSource.objects.select_for_update().select_related("audit").get(pk=source.pk)
        )
        if (
            not source.active
            or not verify_source(source)
            or not constant_time_compare(
                source.token_hash, hashlib.sha256(token.encode()).hexdigest()
            )
        ):
            raise PermissionDenied
        bucket = business_rate_bucket()
        count = source.rate_count if source.rate_bucket == bucket else 0
        if count >= 60:
            raise BusinessRateLimited("Limite de 60 appels par minute pour cette source.")
        source.rate_bucket, source.rate_count = bucket, count + 1
        source.save(update_fields=["rate_bucket", "rate_count"])
        return source


def normalize_payload(data, now):
    if not isinstance(data, dict) or set(data) - FIELDS or data.get("schema") != FORMAT:
        raise ValidationError("Format de référence métier invalide.")
    if type(data.get("sequence")) is not int or not 1 <= data["sequence"] <= 2147483647:
        raise ValidationError("La séquence doit être un entier positif.")
    payload = {}
    for key, maximum, required in (
        ("external_id", 180, True),
        ("reference", 180, True),
        ("title", 240, False),
        ("url", 500, False),
    ):
        value = data.get(key, "")
        if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value):
            raise ValidationError("Champ métier invalide : " + key)
        value = value.strip()
        if required and not value:
            raise ValidationError("Champ métier absent : " + key)
        payload[key] = value
    if (
        not isinstance(data.get("kind"), str)
        or data["kind"] not in KINDS
        or not isinstance(data.get("state"), str)
        or data["state"] not in STATES
    ):
        raise ValidationError("Type ou état métier invalide.")
    if payload["url"]:
        from urllib.parse import urlsplit

        URLValidator(schemes=["https"])(payload["url"])
        parsed = urlsplit(payload["url"])
        if parsed.username or parsed.password or parsed.fragment:
            raise ValidationError("Une référence URL ne contient ni identifiants ni fragment.")
    dates = {}
    for key in ("source_updated_at", "observed_at"):
        try:
            value = parse_datetime(data[key]) if isinstance(data.get(key), str) else None
        except (ValueError, TypeError):
            value = None
        if value is None or not timezone.is_aware(value) or value > now + timedelta(minutes=5):
            raise ValidationError("Date source invalide : " + key)
        dates[key] = value.astimezone(UTC).isoformat(timespec="microseconds")
    if parse_datetime(dates["source_updated_at"]) > parse_datetime(dates["observed_at"]):
        raise ValidationError("La lecture ne peut pas précéder la modification source.")
    payload.update(
        dates, schema=FORMAT, sequence=data["sequence"], kind=data["kind"], state=data["state"]
    )
    return payload


def receipt_body(receipt):
    return dict(
        id=receipt.pk,
        organization=receipt.organization_id,
        record=receipt.record_id,
        source=receipt.record.source_id,
        external_id=receipt.record.external_id,
        source_revision=receipt.source_revision,
        sequence=receipt.sequence,
        payload=receipt.payload,
        content_hash=receipt.content_hash,
        received_at=receipt.received_at,
    )


def verify_business_receipt(receipt):
    try:
        return bool(
            receipt.record.organization_id == receipt.organization_id
            and receipt.record.source.organization_id == receipt.organization_id
            and receipt.payload["external_id"] == receipt.record.external_id
            and receipt.payload["sequence"] == receipt.sequence
            and hashlib.sha256(canonical(receipt.payload).encode()).hexdigest()
            == receipt.content_hash
            and anchor_valid(
                receipt, receipt_body(receipt), "receipt", "business.record.received.v1", None
            )
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False


@transaction.atomic
def ingest_business_record(data, *, token, organization):
    if organization.pk != current_organization().pk:
        raise PermissionDenied
    lock_organization(organization)
    require_module(organization, "connectors")
    principal = source_from_business_token(token)
    if principal.organization_id != organization.pk:
        raise PermissionDenied
    source = BusinessSource.objects.select_for_update().select_related("audit").get(pk=principal.pk)
    if (
        not source.active
        or not verify_source(source)
        or not constant_time_compare(source.token_hash, hashlib.sha256(token.encode()).hexdigest())
    ):
        raise PermissionDenied
    now = timezone.now()
    payload = normalize_payload(data, now)
    content_hash = hashlib.sha256(canonical(payload).encode()).hexdigest()
    obj, _ = BusinessRecord.objects.get_or_create(
        organization=organization, source=source, external_id=payload["external_id"]
    )
    existing = BusinessReceipt.objects.filter(record=obj, sequence=payload["sequence"]).first()
    if existing:
        if (
            existing.content_hash != content_hash
            or existing.source_revision != source.revision
            or not verify_business_receipt(existing)
        ):
            raise BusinessConflict("Une séquence existante porte une autre preuve.")
        return existing, False
    latest = BusinessReceipt.objects.filter(record=obj).order_by("-sequence").first()
    if latest and (
        payload["sequence"] <= latest.sequence
        or not verify_business_receipt(latest)
        or any(
            parse_datetime(payload[key]) < parse_datetime(latest.payload[key])
            for key in ("source_updated_at", "observed_at")
        )
    ):
        raise BusinessConflict("La nouvelle lecture recule dans l’historique connu.")
    receipt = BusinessReceipt(
        organization=organization,
        record=obj,
        source_revision=source.revision,
        sequence=payload["sequence"],
        payload=payload,
        content_hash=content_hash,
        received_at=now,
    )
    body = receipt_body(receipt)
    receipt.audit = record(
        action="business.record.received.v1",
        summary="Lecture métier reçue",
        organization=organization,
        target=receipt,
        metadata={
            "body_hash": sign(body, "receipt-body"),
            "source_id": str(source.pk),
            "sequence": receipt.sequence,
        },
    )
    receipt.signature = anchored_signature(body, receipt.audit, "receipt")
    receipt.full_clean()
    receipt.save()
    return receipt, True


@transaction.atomic
def receipt_public(receipt):
    organization = current_organization()
    if organization.pk != receipt.organization_id:
        raise PermissionDenied
    lock_organization(organization)
    require_module(organization, "connectors")
    if not verify_business_receipt(receipt):
        raise ValidationError("Preuve métier invalide.")
    # Do not reuse a related-object cache from ingestion or a prior display:
    # an administrator may have revoked/rotated this source in the meantime.
    source = BusinessSource.objects.select_related("audit").get(pk=receipt.record.source_id)
    now = timezone.now()
    latest_sequence = (
        BusinessReceipt.objects.filter(record_id=receipt.record_id)
        .order_by("-sequence")
        .values_list("sequence", flat=True)
        .first()
    )
    return _receipt_snapshot(receipt, source=source, latest_sequence=latest_sequence, now=now)


def _receipt_snapshot(receipt, *, source, latest_sequence, now):
    """Internal bulk reader; callers hold the organization lock and loaded current sources."""
    if (
        source.pk != receipt.record.source_id
        or source.organization_id != receipt.organization_id
        or not verify_business_receipt(receipt)
    ):
        raise ValidationError("Preuve métier invalide.")
    observed = parse_datetime(receipt.payload["observed_at"])
    fresh = (
        0 <= (now - min(observed, receipt.received_at)).total_seconds() <= source.freshness_seconds
    )
    current = source.active and verify_source(source) and receipt.source_revision == source.revision
    latest = latest_sequence == receipt.sequence
    return dict(
        receipt_id=str(receipt.pk),
        record_id=str(receipt.record_id),
        source_id=str(source.pk),
        source_key=source.key,
        source_revision=receipt.source_revision,
        payload=receipt.payload,
        received_at=receipt.received_at.isoformat(timespec="microseconds"),
        as_of=now.isoformat(timespec="microseconds"),
        proof_verified=True,
        source_configuration_current=bool(current),
        source_read_recent=bool(fresh),
        latest_for_record=latest,
        current_source_assertion=bool(current and fresh and latest),
        authority="authenticated_source_assertion",
        local_access_approval=False,
        local_authorizations_modified=False,
    )


def verify_business_evidence():
    """Offline restoration only: inactive sources and old revisions remain evidence."""
    count = 0
    for source in BusinessSource.unscoped.select_related("audit").iterator():
        if not verify_source(source):
            raise RuntimeError("Invalid restored business-source configuration")
        count += 1
    for item in BusinessRecord.unscoped.select_related("source").iterator():
        if item.organization_id != item.source.organization_id or not (
            BusinessReceipt.unscoped.filter(record_id=item.pk).exists()
        ):
            raise RuntimeError("Invalid restored business-record scope or empty dossier")
    for receipt in BusinessReceipt.unscoped.select_related("record__source", "audit").iterator():
        if not verify_business_receipt(receipt):
            raise RuntimeError("Invalid restored business receipt")
        count += 1
    from .business_associations import verify_business_association
    from .business_models import BusinessAssociation

    for obj in BusinessAssociation.unscoped.select_related(
        "intent", "record", "receipt__record__source", "receipt__audit", "audit"
    ).iterator():
        if not verify_business_association(obj):
            raise RuntimeError("Invalid restored business association")
        count += 1
    return count
