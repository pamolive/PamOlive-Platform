"""Signed independent people are required for live PAM; history remains verifiable."""

import hashlib
from datetime import UTC, time

from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from platform_core.attestations import canonical
from platform_modules.governance.policy import policy_at


def contract_authority(contract, *, at=None):
    """Pin the immutable published terms, including resource and sponsor restrictions."""
    from platform_modules.governance.policy import revision_at

    revision = revision_at(contract, at or timezone.now())
    if not revision:
        raise ValidationError("Aucune révision contractuelle attestable.")
    fields = {field.attname: getattr(revision, field.attname) for field in revision._meta.fields}
    fields = {
        name: value.isoformat() if isinstance(value, time) else value
        for name, value in fields.items()
    }
    fields["scopes"] = sorted(
        [
            {"resource": str(s.resource_id), "privilege": s.privilege, "locations": s.locations}
            for s in revision.scopes.all()
        ],
        key=lambda row: (row["resource"], row["privilege"]),
    )
    return {
        "revision": str(revision.pk),
        "hash": hashlib.sha256(canonical(fields).encode()).hexdigest(),
    }


def _policy_snapshot():
    policy = policy_at(timezone.now())
    if not policy:
        return {
            "id": "baseline/1",
            "min_reviewers": 1,
            "critical_reviewers": 1,
            "supplier_sponsor_required": False,
            "require_external_contract": False,
        }
    return {
        "id": str(policy.pk),
        **{
            name: getattr(policy, name)
            for name in (
                "min_reviewers",
                "critical_reviewers",
                "supplier_sponsor_required",
                "require_external_contract",
            )
        },
    }


def request_payload(intent, policy):
    """Exclude the transient UUID: the form is recreated after its signed challenge."""
    return {
        "organization": str(intent.organization_id),
        "actor": str(intent.requested_by_id),
        "identity": str(intent.identity_id),
        "binding": str(intent.requester_binding_id),
        "account": str(intent.account_id),
        "account_snapshot": intent.account_snapshot,
        "resource": str(intent.resource_id),
        "destination": intent.pam_destination,
        "method": intent.method.casefold(),
        "privilege": intent.privilege,
        "location": intent.location,
        "reason": intent.reason,
        "reference": intent.reference,
        "contract": str(intent.contract_id or ""),
        "country": intent.country_code,
        "starts_at": intent.starts_at.astimezone(UTC).isoformat(timespec="microseconds"),
        "ends_at": intent.ends_at.astimezone(UTC).isoformat(timespec="microseconds"),
        "network_switch": str(intent.network_switch_id or ""),
        "network_port": intent.network_port,
        "network_vlan": intent.network_vlan,
        "policy": policy,
    }


def _target(registry, intent):
    from .mandates import mandate_endpoint
    from .trust_registry import protected_target

    endpoint = mandate_endpoint(intent)
    if not endpoint or not intent.pam_destination:
        raise ValidationError("Une cible PAM précise et attestée est obligatoire.")
    target = protected_target(registry, endpoint, intent=intent)
    if intent.contract_id and target.get("contract_authority") != contract_authority(
        intent.contract
    ):
        raise ValidationError("La révision contractuelle exige une nouvelle attestation PAM.")
    return endpoint, target


def prepare_trust(intent, *, actor, organization):
    from .trust_auth import authorization_evidence, require_action
    from .trust_registry import recognized_registry, registry_person

    registry = recognized_registry(organization)
    endpoint, target = _target(registry, intent)
    person, _ = registry_person(
        registry, actor, identity=intent.identity, role="requester", endpoint=endpoint
    )
    policy = _policy_snapshot()
    proof = require_action(actor, organization, "request", request_payload(intent, policy))
    intent.pam_trust = {
        "registry_hash": registry.revision_hash,
        "person": person,
        "request": authorization_evidence(proof),
        "target": target,
        "policy": policy,
    }


def _historical_registry(intent):
    from .trust_auth import verify_authorization_evidence
    from .trust_registry import historical_registry

    trust = intent.pam_trust
    if not trust or not trust.get("person"):
        raise ValidationError("Un mandat antérieur ne constitue pas une autorité PAM actuelle.")
    registry = historical_registry(intent.organization, trust["registry_hash"])
    target = registry.body["targets"][intent.pam_destination["endpoint"]]
    protected = {
        **target,
        "minimum": max(
            registry.body["policy"]["critical_min" if target["critical"] else "standard_min"],
            target.get("min_reviewers", 1),
        ),
        "contract_required": bool(target.get("contract_id")),
        "sponsor_required": bool(target.get("sponsor_person")),
    }
    if (
        trust["request"].get("registry_hash") != registry.revision_hash
        or protected != trust["target"]
        or target["scope"] != intent.pam_destination
    ):
        raise ValidationError("Le périmètre historique attesté est incohérent.")
    if not verify_authorization_evidence(
        trust["request"],
        actor=intent.requested_by,
        organization=intent.organization,
        action="request",
        payload=request_payload(intent, trust["policy"]),
    ):
        raise ValidationError("La signature personnelle du mandat PAM est invalide.")
    if trust["request"].get("person") != trust["person"]:
        raise ValidationError("La personne du mandat PAM est incohérente.")
    person = registry.body["persons"].get(trust["person"], {})
    if (
        not person.get("active")
        or "requester" not in person.get("roles", [])
        or str(intent.identity_id) not in person.get("identity_ids", [])
        or str(intent.requested_by_id) not in person.get("account_ids", [])
        or intent.pam_destination["endpoint"] not in person.get("endpoint_ids", [])
    ):
        raise ValidationError("La personne n’était pas habilitée pour cette cible PAM.")
    return registry


def require_live(intent, organization, actor=None):
    from .trust_registry import recognized_registry, registry_person

    _historical_registry(intent)
    registry = recognized_registry(organization)
    if (
        registry.revision_hash != intent.pam_trust["registry_hash"]
        or _policy_snapshot() != intent.pam_trust["policy"]
    ):
        raise ValidationError("La confiance ou la politique a changé : recréez le mandat PAM.")
    endpoint, target = _target(registry, intent)
    if target != intent.pam_trust["target"]:
        raise ValidationError("Le périmètre PAM attesté a changé.")
    person, _ = registry_person(
        registry,
        actor or intent.requested_by,
        identity=intent.identity,
        role="requester",
        endpoint=endpoint,
    )
    if person != intent.pam_trust["person"]:
        raise ValidationError("Le titulaire PAM indépendant a changé.")
    return registry


def vote_payload(intent, approved, comment):
    from .mandates import scope_hash

    return {
        "intent": str(intent.pk),
        "scope_hash": scope_hash(intent),
        "approved": bool(approved),
        "comment": comment,
    }


def authorize_vote(intent, *, actor, organization, approved, comment, binding):
    from .mandates import mandate_endpoint
    from .trust_auth import authorization_evidence, require_action
    from .trust_registry import registry_person

    registry = require_live(intent, organization)
    endpoint = mandate_endpoint(intent)
    person, _ = registry_person(registry, actor, identity=binding.identity, endpoint=endpoint)
    if person == intent.pam_trust["person"]:
        raise ValidationError("Une même personne ne peut pas approuver sa propre session.")
    sponsor = intent.pam_trust["target"].get("sponsor_person")
    action = "refuse" if not approved else "sponsor" if sponsor == person else "approve"
    registry_person(
        registry,
        actor,
        identity=binding.identity,
        endpoint=endpoint,
        role="sponsor" if action == "sponsor" else "reviewer",
    )
    if any(d.pam_trust.get("person") == person for d in intent.decisions.all()):
        raise ValidationError("Cette personne indépendante a déjà voté.")
    proof = require_action(actor, organization, action, vote_payload(intent, approved, comment))
    return {"person": person, "action": action, "proof": authorization_evidence(proof)}


def verified_vote(intent, decision):
    from .trust_auth import verify_authorization_evidence
    from .trust_registry import historical_registry

    evidence = decision.pam_trust
    if not evidence:
        return False
    registry = historical_registry(intent.organization, intent.pam_trust["registry_hash"])
    person = registry.body["persons"].get(evidence.get("person"), {})
    if (
        str(decision.reviewer_identity_id) not in person.get("identity_ids", [])
        or intent.pam_destination["endpoint"] not in person.get("endpoint_ids", [])
        or (
            evidence.get("action") == "sponsor"
            and evidence.get("person") != intent.pam_trust["target"].get("sponsor_person")
        )
    ):
        return False
    return bool(
        evidence
        and evidence.get("person") != intent.pam_trust.get("person")
        and evidence.get("person") == evidence.get("proof", {}).get("person")
        and evidence.get("action") in ("approve", "sponsor")
        and evidence.get("proof", {}).get("registry_hash") == intent.pam_trust["registry_hash"]
        and verify_authorization_evidence(
            evidence["proof"],
            actor=decision.reviewer,
            organization=intent.organization,
            action=evidence["action"],
            payload=vote_payload(intent, decision.approved, decision.comment),
        )
    )


def trusted_requirements(intent, at, legacy):
    """Add independent authority to all the existing restrictions."""
    from .mandates import valid_decisions

    try:
        registry = _historical_registry(intent)
        target = intent.pam_trust["target"]
        minimum = max(legacy["minimum"], target["minimum"], 2 if target["critical"] else 1)
        votes = [d for d in valid_decisions(intent, at) if verified_vote(intent, d)]
        people = {d.pam_trust["person"] for d in votes}
        sponsor = target.get("sponsor_person")
        sponsored = not sponsor or any(
            d.pam_trust["person"] == sponsor and d.pam_trust["action"] == "sponsor" for d in votes
        )
        eligible = {
            person for person in people if "reviewer" in registry.body["persons"][person]["roles"]
        }
        return {
            **legacy,
            "minimum": minimum,
            "approved": len(eligible),
            "unit": "personnes indépendantes attestées",
            "sponsor_person": sponsor,
            "sponsor_satisfied": legacy["sponsor_satisfied"] and sponsored,
            "complete": len(eligible) >= minimum and sponsored and legacy["sponsor_satisfied"],
        }
    except (PermissionDenied, ValidationError, KeyError, TypeError, ValueError):
        return {
            **legacy,
            "complete": False,
            "approved": 0,
            "unit": "personnes indépendantes attestées",
        }


def launch_payload(intent):
    from .mandates import scope_hash

    return {"intent": str(intent.pk), "scope_hash": scope_hash(intent)}


def authorize_launch(intent, *, actor, organization):
    from .trust_auth import authorization_evidence, require_action

    require_live(intent, organization, actor=actor)
    proof = require_action(actor, organization, "launch", launch_payload(intent))
    return authorization_evidence(proof)


def verify_launch(intent, evidence):
    from .trust_auth import verify_authorization_evidence

    return bool(
        evidence
        and evidence.get("person") == intent.pam_trust.get("person")
        and evidence.get("registry_hash") == intent.pam_trust.get("registry_hash")
        and verify_authorization_evidence(
            evidence,
            actor=intent.requested_by,
            organization=intent.organization,
            action="launch",
            payload=launch_payload(intent),
        )
    )
