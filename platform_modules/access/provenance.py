"""Versioned server acceptance receipts for access events.

The receipt proves that this PamOlive installation accepted an event under a
particular authenticated authority. It does not attest remote telemetry truth.
The historical V7 evaluation snapshot and signature remain unchanged.
"""

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.utils.crypto import constant_time_compare

from platform_core.audit import digest as audit_digest

FACTS_SCHEMA = "event-facts/8"
RECEIPT_VERSION = "event-provenance/8"
_FACTS_DOMAIN = b"pamolive.access.event-facts.v8\0"
_RECEIPT_DOMAIN = b"pamolive.access.provenance-receipt.v8\0"
_KEY_ID_DOMAIN = b"pamolive.access.provenance-key-id.v8\0"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

# Frozen schema. In particular, the server event UUID and receipt time are not
# content: retrying the same collector payload must yield the same digest.
_FACT_FIELDS = (
    "organization_id",
    "source",
    "external_id",
    "occurred_at",
    "ended_at",
    "identity_id",
    "account_id",
    "resource_id",
    "credential_id",
    "method",
    "action",
    "location",
    "privilege",
    "result",
    "contract_id",
    "country_code",
    "evidence",
    "domain",
    "network_switch_id",
    "network_port",
    "network_vlan",
    "credential_observation",
)


def _timestamp(value):
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValidationError("A provenance timestamp must have a timezone.")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _value(value):
    if isinstance(value, datetime):
        return _timestamp(value)
    if isinstance(value, UUID):
        return str(value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    raise ValidationError("Unsupported provenance fact type.")


def _canonical(document):
    try:
        return json.dumps(
            document, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValidationError("Invalid provenance document.") from error


def canonical_facts_v8(event):
    """Return the exact normalized event facts covered by V8 content hashing."""
    return {name: _value(getattr(event, name)) for name in _FACT_FIELDS}


def event_facts_digest(event):
    """Return (schema, SHA-256) over validated, normalized source facts."""
    return FACTS_SCHEMA, hashlib.sha256(
        _FACTS_DOMAIN + _canonical(canonical_facts_v8(event))
    ).hexdigest()


def _principal(event):
    channel = event.provenance_channel
    if channel == "collector":
        if not event.collector_source_id or event.manual_actor_id or event.internal_principal:
            raise ValidationError("Invalid collector provenance principal.")
        if event.collector_source.organization_id != event.organization_id:
            raise ValidationError("Collector belongs to another organization.")
        return str(event.collector_source_id)
    if channel == "manual":
        if not event.manual_actor_id or event.collector_source_id or event.internal_principal:
            raise ValidationError("Invalid manual provenance principal.")
        return str(event.manual_actor_id)
    if channel == "internal":
        if not event.internal_principal or event.collector_source_id or event.manual_actor_id:
            raise ValidationError("Invalid internal provenance principal.")
        return event.internal_principal
    raise ValidationError("Legacy events cannot receive a V8 provenance receipt.")


def _key_id(key):
    return hmac.new(key.encode("utf-8"), _KEY_ID_DOMAIN, hashlib.sha256).hexdigest()[:32]


def _sign(body, key):
    return hmac.new(
        key.encode("utf-8"), _RECEIPT_DOMAIN + _canonical(body), hashlib.sha256
    ).hexdigest()


def _verification_keys():
    keys = (
        settings.SECRET_KEY,
        *getattr(settings, "PAMOLIVE_EVIDENCE_VERIFICATION_KEYS", ()),
    )
    return tuple(dict.fromkeys(key for key in keys if isinstance(key, str) and key))


def _validate_audit(event, audit):
    return bool(
        audit.organization_id == event.organization_id
        and audit.action == "access.event.received.v1"
        and audit.object_type == event._meta.label_lower
        and audit.object_id == str(event.pk)
        and audit.event_hash == audit_digest(audit)
        and (
            audit.actor_id == event.manual_actor_id
            if event.provenance_channel == "manual"
            else audit.actor_id is None
        )
    )


def _body(receipt):
    return {
        "version": receipt.version,
        "organization": str(receipt.organization_id),
        "event": str(receipt.event_id),
        "channel": receipt.channel,
        "principal": receipt.principal_id,
        "credential_fingerprint": receipt.credential_fingerprint or None,
        "facts_schema": receipt.facts_schema,
        "facts_digest": receipt.facts_digest,
        "first_received_at": _timestamp(receipt.first_received_at),
        "audit": str(receipt.audit_id),
        "audit_hash": receipt.audit.event_hash,
        "key_id": receipt.key_id,
    }


def create_provenance_receipt(event, audit, credential_fingerprint=""):
    """Seal a newly stored event after its reception audit has been recorded."""
    from .models import AccessProvenanceReceipt

    if not event.pk or not _validate_audit(event, audit):
        raise ValidationError("Invalid provenance reception audit.")
    principal = _principal(event)
    schema, facts_hash = event_facts_digest(event)
    if event.facts_schema != schema or event.facts_digest != facts_hash:
        raise ValidationError("Event facts do not match the normalized V8 digest.")
    if event.provenance_channel == "collector":
        if not _HEX64.fullmatch(credential_fingerprint):
            raise ValidationError("Collector credential fingerprint is required.")
    elif credential_fingerprint:
        raise ValidationError("Only a collector can have a bearer credential fingerprint.")

    receipt = AccessProvenanceReceipt(
        organization=event.organization,
        event=event,
        audit=audit,
        version=RECEIPT_VERSION,
        channel=event.provenance_channel,
        principal_id=principal,
        credential_fingerprint=credential_fingerprint,
        facts_schema=schema,
        facts_digest=facts_hash,
        first_received_at=event.received_at,
        key_id=_key_id(settings.SECRET_KEY),
    )
    receipt.signature = _sign(_body(receipt), settings.SECRET_KEY)
    receipt.full_clean()
    receipt.save()
    return receipt


def verify_provenance_receipt(receipt):
    """Verify acceptance and stored facts; never infer remote telemetry truth."""
    try:
        event, audit = receipt.event, receipt.audit
        principal = _principal(event)
        schema, facts_hash = event_facts_digest(event)
        if not (
            receipt.version == RECEIPT_VERSION
            and receipt.organization_id == event.organization_id
            and receipt.channel == event.provenance_channel
            and receipt.principal_id == principal
            and receipt.facts_schema == schema == event.facts_schema
            and receipt.facts_digest == facts_hash == event.facts_digest
            and receipt.first_received_at == event.received_at
            and _validate_audit(event, audit)
            and (
                bool(_HEX64.fullmatch(receipt.credential_fingerprint))
                if receipt.channel == "collector"
                else not receipt.credential_fingerprint
            )
            and isinstance(receipt.signature, str)
            and bool(_HEX64.fullmatch(receipt.signature))
        ):
            return False
        body = _body(receipt)
        return any(
            receipt.key_id == _key_id(key)
            and constant_time_compare(receipt.signature, _sign(body, key))
            for key in _verification_keys()
        )
    except (AttributeError, KeyError, TypeError, ValueError, ObjectDoesNotExist, ValidationError):
        return False
