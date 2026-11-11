"""Signed, bounded risk tracking. This module never grants or bypasses a right."""

from datetime import datetime, timedelta

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from platform_core.attestations import seal, verify_anchor
from platform_core.authorization import assurance_datetime, require_recent_authentication
from platform_core.services import authorize, lock_authorized_actor, require_module

from .exception_models import ExceptionCase, ExceptionDecision

NAMESPACE = "pamolive.governance.exception/1"


def _body(obj):
    fields = (
        (
            "identity_id",
            "resource_id",
            "entitlement",
            "reason",
            "reference",
            "compensating_controls",
            "requested_by_id",
            "created_at",
            "expires_at",
        )
        if isinstance(obj, ExceptionCase)
        else ("case_id", "decision", "comment", "decided_by_id", "decided_at")
    )
    return {
        key: getattr(obj, key)
        for key in (
            "id",
            "organization_id",
            "mfa_verified_at",
            "mfa_window_minutes",
            *fields,
        )
    }


def _purpose(obj):
    return "request" if isinstance(obj, ExceptionCase) else "decision"


def verified(obj):
    try:
        at = obj.created_at if isinstance(obj, ExceptionCase) else obj.decided_at
        actor_id = obj.requested_by_id if isinstance(obj, ExceptionCase) else obj.decided_by_id
        purpose = _purpose(obj)
        return bool(
            obj.mfa_window_minutes in (2, 5, 10, 15)
            and 0 <= (at - obj.mfa_verified_at).total_seconds() < obj.mfa_window_minutes * 60
            and verify_anchor(
                obj, NAMESPACE, purpose, _body(obj), f"governance.exception.{purpose}.v1", actor_id
            )
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _text(value, maximum, label):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(c) < 32 and c not in "\n\t\r" for c in value)
    ):
        raise ValidationError(f"{label} obligatoire, {maximum} caractères maximum.")
    return value.strip()


def _seal(obj, actor):
    purpose = _purpose(obj)
    return seal(
        obj,
        NAMESPACE,
        purpose,
        _body(obj),
        f"governance.exception.{purpose}.v1",
        actor=actor,
        summary="Justification suivie sans dérogation aux contrôles d’accès",
    )


@transaction.atomic
def request_exception(
    *,
    actor,
    organization,
    identity_id,
    resource_id,
    entitlement,
    reason,
    reference,
    compensating_controls,
    expires_at,
):
    actor, organization = lock_authorized_actor(actor, organization)
    require_module(organization, "governance")
    assurance = require_recent_authentication(actor, organization)
    from platform_modules.identity.models import Identity, Resource

    identity = Identity.objects.get(pk=identity_id)
    resource = Resource.objects.get(pk=resource_id)
    now = timezone.now()
    if (
        not isinstance(expires_at, datetime)
        or timezone.is_naive(expires_at)
        or not now < expires_at <= now + timedelta(days=30)
    ):
        raise ValidationError("Une exception doit expirer dans les trente prochains jours.")
    obj = ExceptionCase(
        organization=organization,
        identity=identity,
        resource=resource,
        entitlement=_text(entitlement, 160, "Droit"),
        reason=_text(reason, 2000, "Motif"),
        reference=_text(reference, 180, "Référence"),
        compensating_controls=_text(compensating_controls, 2000, "Mesures compensatoires"),
        requested_by=actor,
        created_at=now,
        expires_at=expires_at,
        mfa_verified_at=assurance_datetime(assurance.verified_at),
        mfa_window_minutes=assurance.freshness_minutes,
    )
    return _seal(obj, actor)


@transaction.atomic
def decide_exception(case_id, *, actor, organization, decision, comment):
    actor, organization = lock_authorized_actor(
        actor, organization, roles=("admin", "operator", "reviewer")
    )
    require_module(organization, "governance")
    assurance = require_recent_authentication(actor, organization)
    case = ExceptionCase.objects.select_for_update().select_related("audit").get(pk=case_id)
    if not verified(case):
        raise ValidationError("La preuve de la demande est invalide.")
    if decision not in ("accepted", "rejected", "closed"):
        raise ValidationError("Décision inconnue.")
    rows = list(case.decisions.select_related("audit"))
    if any(not verified(row) for row in rows):
        raise ValidationError("Une preuve de décision est invalide.")
    if case.expires_at <= timezone.now() or any(row.decision == "closed" for row in rows):
        raise ValidationError("Cette exception est expirée ou clôturée.")
    if decision == "closed":
        if actor.pk != case.requested_by_id:
            authorize(actor, organization, roles=("admin", "reviewer"))
    else:
        authorize(actor, organization, roles=("admin", "reviewer"))
        if actor.pk == case.requested_by_id:
            raise PermissionDenied("Un autre compte doit examiner cette exception.")
        if any(row.decision in ("accepted", "rejected") for row in rows):
            raise ValidationError("Cette exception a déjà été examinée.")
    obj = ExceptionDecision(
        organization=organization,
        case=case,
        decision=decision,
        decided_by=actor,
        comment=_text(comment, 2000, "Commentaire"),
        mfa_verified_at=assurance_datetime(assurance.verified_at),
        mfa_window_minutes=assurance.freshness_minutes,
    )
    return _seal(obj, actor)


def case_state(case, decisions, *, at):
    """Expired, invalid and closed records can never look like active acceptance."""
    if not verified(case) or any(not verified(row) for row in decisions):
        return "invalid_evidence"
    if any(row.decision == "closed" for row in decisions):
        return "closed"
    if case.expires_at <= at:
        return "expired"
    return next((row.decision for row in decisions if row.decision != "closed"), "pending")


def verify_exceptions():
    """Verify restored history without reviving expired tracking or live authority.

    The guarded restoration caller owns database scope and read permissions.
    Historical actors need not retain their current membership/MFA enrollment.
    """
    from platform_core.models import AuditEvent

    checked = 0
    for case in ExceptionCase.unscoped.select_related("audit", "identity", "resource").iterator(
        chunk_size=100
    ):
        if (
            not verified(case)
            or case.identity.organization_id != case.organization_id
            or case.resource.organization_id != case.organization_id
            or not case.created_at < case.expires_at <= case.created_at + timedelta(days=30)
            or not all(
                isinstance(value, str) and value.strip()
                for value in (
                    case.entitlement,
                    case.reference,
                    case.reason,
                    case.compensating_controls,
                )
            )
        ):
            raise RuntimeError("Restored governance exception request is invalid.")
        checked += 1
        decisions = list(ExceptionDecision.unscoped.filter(case_id=case.pk).select_related("audit"))
        initial = [row for row in decisions if row.decision in ("accepted", "rejected")]
        closed = [row for row in decisions if row.decision == "closed"]
        if (
            len(initial) > 1
            or len(closed) > 1
            or len(initial) + len(closed) != len(decisions)
            or (initial and closed and initial[0].decided_at > closed[0].decided_at)
        ):
            raise RuntimeError("Restored governance exception history is inconsistent.")
        for decision in decisions:
            if (
                not verified(decision)
                or decision.organization_id != case.organization_id
                or not case.created_at <= decision.decided_at < case.expires_at
                or (
                    decision.decision != "closed" and decision.decided_by_id == case.requested_by_id
                )
                or not isinstance(decision.comment, str)
                or not decision.comment.strip()
            ):
                raise RuntimeError("Restored governance exception decision is invalid.")
            checked += 1
    anchored = AuditEvent.objects.filter(
        action__in=(
            "governance.exception.request.v1",
            "governance.exception.decision.v1",
        )
    ).count()
    if (
        checked != ExceptionCase.unscoped.count() + ExceptionDecision.unscoped.count()
        or checked != anchored
    ):
        raise RuntimeError("Restored governance exception history has unlinked evidence.")
    return checked
