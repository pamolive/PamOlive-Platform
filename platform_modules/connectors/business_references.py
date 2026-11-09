"""Pinned business evidence for human-reviewed workflows, not source authorization."""

from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from platform_core.services import require_module
from platform_core.tenancy import current_organization

from .business import _receipt_snapshot, lock_organization, verify_business_receipt
from .business_models import BusinessReceipt

MAX_REFERENCES = 5


def _key(value):
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError):
        raise ValidationError("Identifiant de lecture métier invalide.") from None


def _list(values):
    if not isinstance(values, list) or len(values) > MAX_REFERENCES:
        raise ValidationError("Sélectionnez au plus cinq références métier.")
    return values


def _receipts(organization, *, offline=False):
    manager = BusinessReceipt.unscoped if offline else BusinessReceipt.objects
    return manager.filter(organization=organization).select_related(
        "record__source__audit", "audit"
    )


def _pin(receipt):
    return dict(
        receipt_id=str(receipt.pk),
        record_id=str(receipt.record_id),
        source_id=str(receipt.record.source_id),
        sequence=receipt.sequence,
        source_revision=receipt.source_revision,
        signature=receipt.signature,
    )


def _load(pins, organization, *, offline=False):
    receipts, seen = [], set()
    for pin in _list(pins):
        if not isinstance(pin, dict):
            raise ValidationError("Rattachement métier invalide.")
        receipt = (
            _receipts(organization, offline=offline).filter(pk=_key(pin.get("receipt_id"))).first()
        )
        if (
            not receipt
            or not verify_business_receipt(receipt)
            or _pin(receipt) != pin
            or receipt.record_id in seen
        ):
            raise ValidationError("Lecture métier manquante, répétée ou invalide.")
        seen.add(receipt.record_id)
        receipts.append(receipt)
    return receipts


def _facts(receipt):
    # A new observation of an unchanged dossier is useful. A changed source
    # modification time is a change even if the visible label stayed identical.
    return {
        key: value
        for key, value in receipt.payload.items()
        if key not in ("sequence", "observed_at")
    }


def _same_context(pinned, current):
    return (
        pinned.record_id == current.record_id
        and pinned.source_revision == current.source_revision
        and pinned.sequence <= current.sequence
        and _facts(pinned) == _facts(current)
    )


def _guard(organization):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    lock_organization(organization)
    require_module(organization, "connectors")


def _latest(receipt, organization, now):
    latest = (
        _receipts(organization).filter(record_id=receipt.record_id).order_by("-sequence").first()
    )
    if not latest:
        raise ValidationError("Lecture métier introuvable.")
    status = _receipt_snapshot(
        latest,
        source=latest.record.source,
        latest_sequence=latest.sequence,
        now=now,
    )
    return latest, status


@transaction.atomic
def preview_references(references, *, organization):
    """Internal reader after the caller's session/MFA check."""
    _guard(organization)
    now = timezone.now()
    output, seen = [], set()
    for source, external_id in _list(references):
        receipt = (
            _receipts(organization)
            .filter(
                record__source_id=_key(source),
                record__external_id=external_id,
            )
            .order_by("-sequence")
            .first()
        )
        if not receipt or receipt.record_id in seen:
            raise ValidationError("Dossier métier introuvable ou sélectionné plusieurs fois.")
        seen.add(receipt.record_id)
        status = _receipt_snapshot(
            receipt,
            source=receipt.record.source,
            latest_sequence=receipt.sequence,
            now=now,
        )
        if not status["current_source_assertion"]:
            raise ValidationError("Une lecture récente de la source active est nécessaire.")
        output.append(status)
    return output


def _check_current(selected, organization):
    now = timezone.now()
    checked = []
    for receipt in selected:
        latest, status = _latest(receipt, organization, now)
        if not status["current_source_assertion"] or not _same_context(receipt, latest):
            raise ValidationError(
                "Une référence métier a changé ou n’est plus récente. "
                "Examinez une nouvelle demande avec les lectures actuelles."
            )
        checked.append(latest)
    return checked


@transaction.atomic
def capture_references(receipt_ids, *, organization):
    if not _list(receipt_ids):
        return {}
    _guard(organization)
    keys = [_key(value) for value in receipt_ids]
    indexed = {str(item.pk): item for item in _receipts(organization).filter(pk__in=keys)}
    if len(indexed) != len(keys):
        raise ValidationError("Lecture métier introuvable ou sélectionnée plusieurs fois.")
    selected = _load([_pin(indexed[key]) for key in keys], organization)
    checked = _check_current(selected, organization)
    return dict(
        selected=[_pin(item) for item in selected], submitted=[_pin(item) for item in checked]
    )


def _historical(provenance, organization, *, offline=False):
    if not isinstance(provenance, dict) or set(provenance) != {"selected", "submitted"}:
        raise ValidationError("Historique de référence métier invalide.")
    selected = _load(provenance["selected"], organization, offline=offline)
    submitted = _load(provenance["submitted"], organization, offline=offline)
    if (
        not selected
        or len(selected) != len(submitted)
        or not all(
            _same_context(first, second) for first, second in zip(selected, submitted, strict=True)
        )
    ):
        raise ValidationError("Lectures métier soumises incohérentes.")
    return selected, submitted


@transaction.atomic
def recheck_references(provenance, *, organization):
    _guard(organization)
    _, submitted = _historical(provenance, organization)
    return [_pin(item) for item in _check_current(submitted, organization)]


def verify_reference_history(provenance, checked, *, organization):
    """Offline verification ignores current source availability and expiry."""
    _, submitted = _historical(provenance, organization, offline=True)
    if checked is None:
        return
    approved = _load(checked, organization, offline=True)
    if len(submitted) != len(approved) or not all(
        _same_context(first, last) for first, last in zip(submitted, approved, strict=True)
    ):
        raise ValidationError("Lectures métier de décision incohérentes.")


def _historical_snapshot(receipt):
    return dict(
        **_pin(receipt),
        source_key=receipt.record.source.key,
        payload=receipt.payload,
        received_at=receipt.received_at.isoformat(timespec="microseconds"),
        audit_id=str(receipt.audit_id),
        audit_hash=receipt.audit.event_hash,
    )


@transaction.atomic
def reference_context(provenance, checked, *, organization, tolerate_invalid_latest=False):
    _guard(organization)
    selected, submitted = _historical(provenance, organization)
    approved = _load(checked, organization) if checked is not None else []
    if checked is not None and (
        len(submitted) != len(approved)
        or not all(
            _same_context(first, last) for first, last in zip(submitted, approved, strict=True)
        )
    ):
        raise ValidationError("Lectures métier de décision incohérentes.")
    now = timezone.now()
    rows = []
    for index, receipt in enumerate(selected):
        try:
            latest, status = _latest(receipt, organization, now)
        except ValidationError:
            if not tolerate_invalid_latest:
                raise
            latest, status = None, None
        rows.append(
            dict(
                selected=_historical_snapshot(receipt),
                submitted=_historical_snapshot(submitted[index]),
                reviewed=_historical_snapshot(approved[index]) if approved else None,
                latest=status,
                same_context=_same_context(receipt, latest) if latest is not None else None,
            )
        )
    return dict(
        schema="pamolive.mover-business-context/1",
        references=rows,
        authority="authenticated_source_assertion",
        local_access_approval=False,
    )
