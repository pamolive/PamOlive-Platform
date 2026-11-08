"""Gate a new role on evidence for previously attempted SCIM effects."""

from hashlib import sha256

from platform_core.attestations import canonical
from platform_core.audit import digest
from platform_core.models import AuditEvent
from platform_modules.identity.mover_models import MoveGrant

from .models import ExecutionEvidence, ExternalChange

WAITING = "waiting_for_mover_withdrawal"
TARGET_CHANGED = "mover_withdrawal_target_changed"
NEVER_ATTEMPTED = "mover_addition_not_attempted"


def is_role_effect(change):
    return (
        change.kind in ("add_membership", "remove_membership")
        and MoveGrant.objects.filter(grant_id=change.grant_id).exists()
    )


def membership_scope(change):
    if not change.binding_id or not change.group_id:
        return None
    connector = change.binding.connector
    return dict(
        connector=str(connector.pk),
        endpoint_sha256=sha256(connector.base_url.encode()).hexdigest(),
        account=change.binding.remote_id,
        group=change.group.remote_id,
    )


def _event_scope(event, proof=None):
    value = event.metadata.get("mover_membership")
    if (
        event.event_hash != digest(event)
        or not isinstance(event.sequence, int)
        or not isinstance(value, dict)
        or set(value) != {"connector", "endpoint_sha256", "account", "group"}
        or not all(isinstance(item, str) and item for item in value.values())
        or (
            proof
            and (
                event.metadata.get("change_id") != str(proof.change_id)
                or proof.observed.get("remote_account_id") != value["account"]
                or proof.observed.get("remote_group_id") != value["group"]
            )
        )
    ):
        return None
    return canonical(value)


def _outcomes(change, member):
    proofs = {
        str(item.pk): item
        for item in ExecutionEvidence.objects.filter(
            change=change,
            observed__member=member,
        )
    }
    return [
        (event, proofs[event.object_id])
        for event in AuditEvent.objects.filter(
            organization_id=change.organization_id,
            action__in=(
                "connectors.external_change.executed.v1",
                "connectors.external_change.late_result.v1",
            ),
            object_type=ExecutionEvidence._meta.label_lower,
            object_id__in=proofs,
        )
    ], len(proofs)


def _required(add):
    # A failed or interrupted attempt may still have changed the target. Require
    # a subsequent observation for every attempted endpoint, not only successes.
    if add.status == "running":
        return None
    starts = list(
        AuditEvent.objects.filter(
            organization_id=add.organization_id,
            action="connectors.external_change.started.v1",
            object_type=ExternalChange._meta.label_lower,
            object_id=str(add.pk),
        )
    )
    if {event.metadata.get("attempt") for event in starts} != set(range(1, add.attempts + 1)):
        return None
    positives, count = _outcomes(add, True)
    if len(positives) != count:
        return None
    required = {}
    for event, proof in [(event, None) for event in starts] + positives:
        key = _event_scope(event, proof)
        if not key:
            return None
        required[key] = max(required.get(key, 0), event.sequence)
    return required


def _uncovered(add, removals):
    required = _required(add)
    if required is None:
        return None
    from .outbound import _obsolete

    for removal in removals:
        for event, proof in _outcomes(removal, False)[0]:
            key = _event_scope(event, proof)
            if (
                proof.confirmed
                and event.metadata.get("confirmed") is True
                and proof.code == "read_after_write_confirmed"
                and key in required
                and event.sequence > required[key]
            ):
                del required[key]
        scope = membership_scope(removal)
        if scope and canonical(scope) in required and _obsolete(removal):
            # Another current IAM basis still authorizes this exact membership.
            # The normal local separation-of-duties checks see that other right.
            del required[canonical(scope)]
    return required


def removal_problem(change):
    if change.kind != "remove_membership" or not is_role_effect(change):
        return ""
    adds = ExternalChange.objects.filter(grant_id=change.grant_id, kind="add_membership")
    adds = list(adds.filter(attempts__gt=0))
    if not adds:
        return NEVER_ATTEMPTED
    scope = membership_scope(change)
    required = [_required(add) for add in adds]
    if not scope or any(item is None for item in required):
        return TARGET_CHANGED
    return "" if any(canonical(scope) in item for item in required) else TARGET_CHANGED


def can_reconcile(change):
    if (
        change.kind != "remove_membership"
        or not is_role_effect(change)
        or change.grant.status != "revoked"
    ):
        return False
    scope = membership_scope(change)
    if not scope:
        return False
    related = ExternalChange.objects.filter(grant_id=change.grant_id)
    removals = related.filter(kind="remove_membership").select_related(
        "binding__connector", "group"
    )
    return any(
        canonical(scope) in (_uncovered(add, removals) or {})
        for add in related.filter(kind="add_membership", attempts__gt=0)
    )


def withdrawals_ready(identity_id):
    withdrawn = MoveGrant.objects.filter(
        grant__identity_id=identity_id,
        grant__status="revoked",
    ).values("grant_id")
    positives = ExternalChange.objects.filter(
        grant_id__in=withdrawn,
        kind="add_membership",
        attempts__gt=0,
    )
    for add in positives:
        removals = ExternalChange.objects.filter(
            grant_id=add.grant_id,
            kind="remove_membership",
        ).select_related("binding__connector", "group")
        if _uncovered(add, removals) != {}:
            return False
    return True


def needs_handover(change):
    return (
        change.kind == "add_membership"
        and is_role_effect(change)
        and not withdrawals_ready(change.grant.identity_id)
    )


def effect_metadata(change):
    return {"mover_membership": membership_scope(change)} if is_role_effect(change) else {}
