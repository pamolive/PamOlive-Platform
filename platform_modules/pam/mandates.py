"""Person-bound, scoped authority to use an account; not transfer of ownership."""

import json
from datetime import UTC

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils.crypto import constant_time_compare, salted_hmac

from platform_core.authorization import require_recent_authentication
from platform_modules.identity.bindings import binding_valid, current_binding
from platform_modules.identity.models import LoginIdentityBinding

NON_HUMAN_KINDS = {"machine", "service", "workload", "application", "api"}
NATIVE_ACCOUNT_PRIVILEGE = "native_full_account"


def account_can_use_pam(account):
    return account.kind in ("privileged", "service")


def account_snapshot(account):
    return {
        "id": str(account.pk),
        "owner_identity_id": str(account.identity_id),
        "username": account.username,
        "system": account.system,
        "kind": account.kind,
        "state_revision": account.state_revision,
        "managed_contract_id": str(account.managed_contract_id or ""),
    }


def prepare_request(intent, *, actor, organization):
    require_recent_authentication(actor, organization)
    if intent.privilege and intent.privilege != NATIVE_ACCOUNT_PRIVILEGE:
        raise ValidationError(
            "Le relais PAM ouvre les droits natifs du compte, pas un profil de commandes limité. "
            "Utilisez le privilège native_full_account ou laissez ce champ vide pour le renseigner."
        )
    intent.privilege = NATIVE_ACCOUNT_PRIVILEGE
    binding = current_binding(actor, organization=organization, identity_id=intent.identity_id)
    intent.requester_binding = binding
    intent.account_snapshot = account_snapshot(intent.account) if intent.account_id else {}
    validate_request(intent, organization=organization, actor=actor)


def validate_request(intent, *, organization, actor=None):
    actor = actor or intent.requested_by
    if (
        intent.organization_id != organization.pk
        or intent.requested_by_id != actor.pk
        or intent.fulfillment != "pam"
        or not intent.requester_binding_id
        or not intent.account_id
        or not intent.account.active
        or intent.account.identity.status != "active"
        or intent.identity.status != "active"
        or intent.identity.kind not in ("human", "external")
        or not account_can_use_pam(intent.account)
        or intent.method.casefold() not in ("ssh", "rdp")
        or intent.privilege != NATIVE_ACCOUNT_PRIVILEGE
        or intent.account_snapshot != account_snapshot(intent.account)
        or not intent.reason.strip()
    ):
        raise ValidationError(
            "Le mandat PAM exige une personne liée, un compte actif précisément identifié "
            "et un protocole SSH/RDP. Une demande ancienne ou modifiée doit être recréée."
        )
    if intent.account.identity_id != intent.identity_id and (
        intent.account.identity.kind not in NON_HUMAN_KINDS
    ):
        raise ValidationError(
            "L’usage partagé PAM concerne un compte d’identité technique, "
            "pas l’emprunt du compte personnel d’un autre intervenant."
        )
    binding = current_binding(
        actor,
        organization=organization,
        identity_id=intent.identity_id,
        binding_id=intent.requester_binding_id,
    )
    if intent.created_at and binding.created_at > intent.created_at:
        raise ValidationError("La demande doit avoir été créée avec son lien de personne.")
    return binding


def _time(value):
    return value.astimezone(UTC).isoformat(timespec="microseconds") if value else None


def _hash(namespace, payload):
    return salted_hmac(
        namespace,
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        secret=settings.PAMOLIVE_ENCRYPTION_KEY,
        algorithm="sha256",
    ).hexdigest()


def scope_hash(intent):
    body = {
        "id": str(intent.pk),
        "organization": str(intent.organization_id),
        "requested_by": str(intent.requested_by_id),
        "identity": str(intent.identity_id),
        "binding": str(intent.requester_binding_id or ""),
        "account": str(intent.account_id or ""),
        "account_snapshot": intent.account_snapshot,
        "resource": str(intent.resource_id),
        "method": intent.method.casefold(),
        "privilege": intent.privilege,
        "location": intent.location,
        "reason": intent.reason,
        "reference": intent.reference,
        "contract": str(intent.contract_id or ""),
        "country": intent.country_code,
        "fulfillment": intent.fulfillment,
        "starts_at": _time(intent.starts_at),
        "ends_at": _time(intent.ends_at),
        "network_switch": str(intent.network_switch_id or ""),
        "network_port": intent.network_port,
        "network_vlan": intent.network_vlan,
    }
    return _hash("pamolive.pam.mandate-scope.v1", body)


def decision_signature(decision):
    return _hash(
        "pamolive.pam.person-decision.v1",
        {
            "id": str(decision.pk),
            "organization": str(decision.organization_id),
            "intent": str(decision.intent_id),
            "reviewer": str(decision.reviewer_id),
            "binding": str(decision.reviewer_binding_id or ""),
            "identity": str(decision.reviewer_identity_id or ""),
            "approved": decision.approved,
            "comment": decision.comment,
            "decided_at": _time(decision.decided_at),
            "mfa_verified_at": _time(decision.mfa_verified_at),
            "mfa_window_minutes": decision.mfa_window_minutes,
            "scope_hash": decision.scope_hash,
        },
    )


def binding_at(account_id, at):
    binding = (
        LoginIdentityBinding.objects.filter(
            login_account_id=account_id,
            created_at__lte=at,
        )
        .filter(Q(revoked_at__isnull=True) | Q(revoked_at__gt=at))
        .first()
    )
    return binding if binding and binding_valid(binding) else None


def valid_decisions(intent, at):
    """Historical attestations, not the approver's current job or login binding."""
    from platform_modules.access.services import identity_status_at

    expected_scope = scope_hash(intent)
    valid = []
    for decision in intent.decisions.filter(approved=True, decided_at__lte=at).select_related(
        "reviewer_binding", "reviewer_identity"
    ):
        binding = decision.reviewer_binding
        if (
            not binding
            or not binding_valid(binding)
            or not decision.reviewer_identity_id
            or decision.reviewer_id == intent.requested_by_id
            or decision.reviewer_identity_id == intent.identity_id
            or binding.organization_id != intent.organization_id
            or binding.login_account_id != decision.reviewer_id
            or binding.identity_id != decision.reviewer_identity_id
            or binding.created_at > decision.decided_at
            or (binding.revoked_at and binding.revoked_at <= decision.decided_at)
            or identity_status_at(decision.reviewer_identity, decision.decided_at) != "active"
            or not decision.mfa_verified_at
            or decision.mfa_window_minutes not in (2, 5, 10, 15)
            or not 0
            <= (decision.decided_at - decision.mfa_verified_at).total_seconds()
            < decision.mfa_window_minutes * 60
            or not constant_time_compare(decision.scope_hash, expected_scope)
            or not constant_time_compare(decision.signature, decision_signature(decision))
        ):
            continue
        valid.append(decision)
    return valid


def authorized_at(intent, at):
    """Historical event comparison must not apply a binding revoked before the event."""
    from platform_modules.governance.policy import approval_requirements

    binding = intent.requester_binding
    return bool(
        intent.approved_at
        and intent.approved_at <= at
        and binding
        and binding_valid(binding)
        and binding.organization_id == intent.organization_id
        and binding.identity_id == intent.identity_id
        and binding.login_account_id == intent.requested_by_id
        and binding.created_at <= intent.created_at
        and (not binding.revoked_at or binding.revoked_at > at)
        and approval_requirements(intent, at=intent.approved_at)["complete"]
    )
