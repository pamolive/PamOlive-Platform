"""Domain-neutral signed evidence, with an audit anchor and explicit namespace."""

import json
from datetime import UTC, datetime
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.crypto import constant_time_compare, salted_hmac

from .audit import digest, record
from .tenancy import ScopedModel, TenantManager


def canonical(value):
    def encode(item):
        if isinstance(item, datetime):
            if item.tzinfo is None or item.utcoffset() is None:
                raise ValueError("Attestation timestamps must have a timezone")
            return item.astimezone(UTC).isoformat(timespec="microseconds")
        if isinstance(item, UUID):
            return str(item)
        raise TypeError("Unsupported attestation value")

    return json.dumps(
        value,
        default=encode,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def signature(namespace, purpose, body):
    return salted_hmac(
        namespace + "/" + purpose,
        canonical(body),
        secret=settings.PAMOLIVE_ENCRYPTION_KEY,
        algorithm="sha256",
    ).hexdigest()


def anchor_signature(obj, namespace, purpose, body):
    return signature(
        namespace,
        purpose,
        dict(body=body, audit_id=str(obj.audit_id), audit_hash=obj.audit.event_hash),
    )


def seal(obj, namespace, purpose, body, action, *, actor=None, summary="Publication signée"):
    obj.audit = record(
        action=action,
        summary=summary,
        actor=actor,
        organization=obj.organization,
        target=obj,
        metadata={"body_hash": signature(namespace, purpose + "-body", body)},
    )
    obj.signature = anchor_signature(obj, namespace, purpose, body)
    obj.full_clean()
    obj.save()
    return obj


def verify_anchor(obj, namespace, purpose, body, action, actor_id):
    audit = obj.audit
    return bool(
        audit.organization_id == obj.organization_id
        and audit.actor_id == actor_id
        and audit.action == action
        and audit.object_type == obj._meta.label_lower
        and audit.object_id == str(obj.pk)
        and audit.event_hash == digest(audit)
        and audit.metadata.get("body_hash") == signature(namespace, purpose + "-body", body)
        and constant_time_compare(obj.signature, anchor_signature(obj, namespace, purpose, body))
    )


class EvidenceQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError("Une attestation existante n’est pas réécrite.")

    def delete(self):
        raise ValidationError("Les attestations sont conservées.")


class ImmutableEvidence(ScopedModel):
    objects = TenantManager.from_queryset(EvidenceQuerySet)()
    unscoped = EvidenceQuerySet.as_manager()

    class Meta(ScopedModel.Meta):
        abstract = True

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Une attestation existante est immuable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Les attestations sont conservées.")
