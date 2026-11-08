"""Human evidence associations, separate from access authorization and signed evaluations."""

import hashlib
from datetime import UTC, datetime
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import F, Window
from django.db.models.functions import RowNumber
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from platform_core.audit import record
from platform_core.authorization import assurance_datetime, require_recent_authentication
from platform_core.services import authorize, require_module
from platform_core.tenancy import current_organization
from platform_modules.access.models import AccessIntent

from .business import (
    _receipt_snapshot,
    anchor_valid,
    anchored_signature,
    canonical,
    lock_organization,
    sign,
    verify_business_receipt,
)
from .business_models import BusinessAssociation, BusinessReceipt

SCOPE_FIELDS = (
    "identity_id",
    "resource_id",
    "account_id",
    "method",
    "location",
    "privilege",
    "reason",
    "reference",
    "contract_id",
    "country_code",
    "fulfillment",
    "starts_at",
    "ends_at",
    "requested_by_id",
    "requester_binding_id",
    "network_switch_id",
    "network_port",
    "network_vlan",
    "created_at",
)
ASSOCIATION_LIMIT = 20


def intent_scope(intent):
    data = {}
    for name in SCOPE_FIELDS:
        value = getattr(intent, name)
        if isinstance(value, datetime):
            value = value.astimezone(UTC).isoformat(timespec="microseconds")
        elif isinstance(value, UUID):
            value = str(value)
        data[name] = value
    return data


def association_body(obj):
    return dict(
        id=obj.pk,
        organization=obj.organization_id,
        intent=obj.intent_id,
        record=obj.record_id,
        receipt=obj.receipt_id,
        receipt_signature=obj.receipt.signature,
        sequence=obj.sequence,
        withdrawn=obj.withdrawn,
        rationale=obj.rationale,
        intent_scope=obj.intent_scope,
        published_at=obj.published_at,
        published_by=obj.published_by_id,
        mfa_verified_at=obj.mfa_verified_at,
        mfa_window_minutes=obj.mfa_window_minutes,
    )


def verify_business_association(obj):
    try:
        action = (
            "business.intent.withdrawn.v1" if obj.withdrawn else "business.intent.associated.v1"
        )
        return bool(
            obj.intent.organization_id == obj.organization_id
            and obj.record.organization_id == obj.organization_id
            and obj.receipt.organization_id == obj.organization_id
            and obj.receipt.record_id == obj.record_id
            and obj.mfa_window_minutes in {2, 5, 10, 15}
            and set(obj.intent_scope) == set(SCOPE_FIELDS)
            and verify_business_receipt(obj.receipt)
            and anchor_valid(obj, association_body(obj), "association", action, obj.published_by_id)
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False


def authorize_association(intent, *, actor, organization):
    authorize(actor, organization, roles=("admin", "operator"))
    try:
        authorize(actor, organization, roles=("admin",))
    except PermissionDenied:
        if intent.requested_by_id != actor.pk:
            raise PermissionDenied("Vous ne pouvez associer que vos propres intentions.") from None


@transaction.atomic
def publish_business_association(
    intent_id, receipt_id, rationale, *, actor, organization, withdraw_association_id=None
):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    lock_organization(organization)
    require_module(organization, "access")
    require_module(organization, "connectors")
    intent = AccessIntent.objects.filter(pk=intent_id).first()
    if intent is None:
        raise ValidationError("Intention introuvable dans cette organisation.")
    authorize_association(intent, actor=actor, organization=organization)
    assurance = require_recent_authentication(actor, organization)
    if (
        not isinstance(rationale, str)
        or not rationale.strip()
        or len(rationale) > 500
        or any(ord(c) < 32 and c not in "\n\t" for c in rationale)
    ):
        raise ValidationError("Précisez un motif de rattachement de 500 caractères maximum.")
    receipt = (
        BusinessReceipt.objects.select_related("record__source", "audit")
        .filter(pk=receipt_id)
        .first()
    )
    if receipt is None or not verify_business_receipt(receipt):
        raise ValidationError("Lecture source introuvable ou preuve invalide.")
    previous = (
        BusinessAssociation.objects.select_related(
            "intent", "record", "receipt__record__source", "receipt__audit", "audit"
        )
        .filter(intent=intent, record_id=receipt.record_id)
        .order_by("-sequence")
        .first()
    )
    if previous and not verify_business_association(previous):
        raise ValidationError("Le précédent rattachement doit être examiné avant toute correction.")
    withdrawn = withdraw_association_id is not None
    if withdrawn:
        try:
            withdraw_association_id = UUID(str(withdraw_association_id))
        except (ValueError, TypeError):
            raise ValidationError("Identifiant de retrait invalide.") from None
    if withdrawn and (not previous or previous.pk != withdraw_association_id or previous.withdrawn):
        raise ValidationError("Le rattachement a changé ; rechargez son état courant.")
    if withdrawn and previous.receipt_id != receipt.pk:
        raise ValidationError("Le retrait doit conserver la lecture du rattachement courant.")
    scope = intent_scope(intent)
    if len(canonical(scope).encode()) > 65536:
        raise ValidationError("Périmètre trop volumineux pour une attestation métier.")
    obj = BusinessAssociation(
        organization=organization,
        intent=intent,
        record=receipt.record,
        receipt=receipt,
        sequence=previous.sequence + 1 if previous else 1,
        withdrawn=withdrawn,
        rationale=rationale.strip(),
        intent_scope=scope,
        published_at=timezone.now(),
        published_by=actor,
        mfa_verified_at=assurance_datetime(assurance.verified_at),
        mfa_window_minutes=assurance.freshness_minutes,
    )
    body = association_body(obj)
    obj.audit = record(
        action="business.intent.withdrawn.v1" if withdrawn else "business.intent.associated.v1",
        summary="Retrait d’un rattachement métier" if withdrawn else "Rattachement métier déclaré",
        actor=actor,
        organization=organization,
        target=obj,
        metadata={"body_hash": sign(body, "association-body"), "sequence": obj.sequence},
    )
    obj.signature = anchored_signature(body, obj.audit, "association")
    obj.full_clean()
    obj.save()
    return obj


@transaction.atomic
def intent_business_context(intent_id, *, event_at=None, evaluated_at=None):
    organization = current_organization()
    lock_organization(organization)
    require_module(organization, "access")
    now = timezone.now()
    output = dict(
        schema="pamolive.business-context/1",
        intent_id=str(intent_id),
        as_of=now.isoformat(),
        available=False,
        rows=[],
        truncated=False,
        local_authorizations_modified=False,
        included_in_historical_evaluation=False,
        observed_interval_evaluated=False,
        authority="source_assertions_and_human_associations_not_access_approval",
        event_at=event_at.isoformat() if event_at else None,
        evaluated_at=evaluated_at.isoformat() if evaluated_at else None,
        event_knowledge_scope="at_start_only_not_full_session" if event_at else None,
    )
    try:
        require_module(organization, "connectors")
    except PermissionDenied:
        output["unavailable_reason"] = "connectors_module_disabled"
        return output
    intent = AccessIntent.objects.filter(pk=intent_id).first()
    if intent is None:
        raise PermissionDenied
    output["available"] = True
    output["local_intent_status"] = intent.status
    output["local_intent_status_label"] = intent.get_status_display()
    scope = canonical(intent_scope(intent))
    rows = list(
        BusinessAssociation.objects.filter(intent=intent)
        .annotate(
            latest=Window(RowNumber(), partition_by=[F("record_id")], order_by=F("sequence").desc())
        )
        .filter(latest=1)
        .select_related("record__source__audit", "receipt__audit", "audit")
        .order_by("-published_at", "-pk")[: ASSOCIATION_LIMIT + 1]
    )
    output["truncated"] = len(rows) > ASSOCIATION_LIMIT
    rows = rows[:ASSOCIATION_LIMIT]
    latest_receipts = list(
        BusinessReceipt.objects.filter(record_id__in=[obj.record_id for obj in rows])
        .annotate(
            latest=Window(RowNumber(), partition_by=[F("record_id")], order_by=F("sequence").desc())
        )
        .filter(latest=1)
        .select_related("record__source__audit", "audit")
    )
    by_record = {obj.record_id: obj for obj in latest_receipts}
    for obj in rows:
        obj.intent = intent
        if obj.receipt.record_id == obj.record_id:
            obj.receipt.record = obj.record
        item = dict(
            association_id=str(obj.pk),
            record_id=str(obj.record_id),
            receipt_id=str(obj.receipt_id),
            sequence=obj.sequence,
            published_at=obj.published_at.isoformat(),
            withdrawn=obj.withdrawn,
            proof_verified=False,
            usable_current_context=False,
        )
        output["rows"].append(item)
        if not verify_business_association(obj):
            item["state"] = "invalid_association_proof"
            continue
        item.update(
            proof_verified=True,
            rationale=obj.rationale,
            actor_id=obj.published_by_id,
            audit_id=str(obj.audit_id),
            signature=obj.signature,
            intent_scope_hash=hashlib.sha256(canonical(obj.intent_scope).encode()).hexdigest(),
        )
        latest = by_record.get(obj.record_id)
        if latest is None or not verify_business_receipt(latest):
            item["state"] = "invalid_current_source_proof"
            continue
        source = obj.record.source
        pinned = _receipt_snapshot(
            obj.receipt, source=source, latest_sequence=latest.sequence, now=now
        )
        current = _receipt_snapshot(latest, source=source, latest_sequence=latest.sequence, now=now)
        unchanged = canonical(obj.intent_scope) == scope
        stable_reference = all(
            obj.receipt.payload.get(key) == latest.payload.get(key) for key in ("reference", "kind")
        )
        item.update(
            pinned_read=pinned,
            latest_read=current,
            intent_scope_matches=unchanged,
            source_reference_unchanged=stable_reference,
            association_known_before_access=(obj.published_at <= event_at) if event_at else None,
            pinned_read_known_before_access=(
                obj.receipt.received_at <= event_at
                and parse_datetime(obj.receipt.payload["observed_at"]) <= event_at
                and parse_datetime(obj.receipt.payload["source_updated_at"]) <= event_at
            )
            if event_at
            else None,
            association_known_before_evaluation=(obj.published_at <= evaluated_at)
            if evaluated_at
            else None,
        )
        item["usable_current_context"] = bool(
            not obj.withdrawn
            and unchanged
            and stable_reference
            and current["current_source_assertion"]
        )
        item["state"] = (
            "withdrawn"
            if obj.withdrawn
            else "intent_scope_changed"
            if not unchanged
            else "source_reference_changed"
            if not stable_reference
            else "current_source_context"
            if item["usable_current_context"]
            else "historical_or_stale_source_context"
        )
    return output
