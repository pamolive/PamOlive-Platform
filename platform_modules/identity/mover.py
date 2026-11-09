"""Business roles describe requests; only ordinary IAM approval can grant access."""

import json
from datetime import timedelta
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from platform_core.attestations import canonical, seal, verify_anchor
from platform_core.authorization import assurance_datetime, require_recent_authentication
from platform_core.events import publish_domain_event
from platform_core.models import Organization
from platform_core.services import authorize, require_module
from platform_core.tenancy import current_organization

from .bindings import current_binding
from .models import ExternalAccount, Identity, Resource
from .mover_models import MoveAccess, MoveDecision, MoveGrant, MoveProposal, RoleRevision
from .review_contract import grant_snapshot

NAMESPACE = "pamolive.identity.mover/1"
PROOFS = {
    RoleRevision: ("role", ("key", "revision")),
    MoveProposal: ("proposal", ("identity_id",)),
    MoveDecision: ("decision", ("identity_id", "proposal_id", "applied", "sequence")),
    MoveAccess: ("access", ("decision_id", "role_id", "intent_id")),
    MoveGrant: ("grant", ("access_id", "grant_id")),
}
INTENT_FIELDS = (
    "identity_id",
    "account_id",
    "resource_id",
    "requested_by_id",
    "requester_binding_id",
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
    "network_switch_id",
    "network_port",
    "network_vlan",
    "account_snapshot",
)


def _json(body):
    return json.loads(canonical(body))


def _scope(obj):
    _, fields = PROOFS[type(obj)]
    return dict(
        id=obj.pk,
        organization_id=obj.organization_id,
        data=obj.body,
        relations={key: getattr(obj, key) for key in fields},
    )


def _action(obj):
    return f"identity.mover.{PROOFS[type(obj)][0]}.v1"


def _attest(obj, actor, organization, **data):
    assurance = require_recent_authentication(actor, organization)
    obj.body = _json(
        dict(
            actor_id=actor.pk,
            at=timezone.now(),
            mfa_at=assurance_datetime(assurance.verified_at),
            mfa_window=assurance.freshness_minutes,
            **data,
        )
    )
    return seal(
        obj,
        NAMESPACE,
        PROOFS[type(obj)][0],
        _scope(obj),
        _action(obj),
        actor=actor,
        summary="Attestation de rôle métier ou de mobilité",
    )


def verified(obj):
    try:
        mfa, at = parse_datetime(obj.body["mfa_at"]), parse_datetime(obj.body["at"])
        window = obj.body["mfa_window"]
        return (
            window in (2, 5, 10, 15)
            and 0 <= (at - mfa).total_seconds() < 60 * window
            and verify_anchor(
                obj,
                NAMESPACE,
                PROOFS[type(obj)][0],
                _scope(obj),
                _action(obj),
                obj.body["actor_id"],
            )
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def _proof(obj):
    if obj is None or not verified(obj):
        raise ValidationError("Attestation de mobilité invalide.")
    return obj


def proof_anchor(obj):
    return dict(
        body=_json(_scope(_proof(obj))),
        signature=obj.signature,
        audit_id=str(obj.audit_id),
        audit_hash=obj.audit.event_hash,
    )


def business_origin(intent):
    link = MoveAccess.objects.filter(intent=intent).select_related("decision__proposal").first()
    if not link or "business" not in link.decision.proposal.body:
        return None
    try:
        _check_access(link)
        proposal = _proof(link.decision.proposal)
        if link.decision.body["proposal_signature"] == proposal.signature:
            return proposal.pk
    except ValidationError:
        pass
    return None


def _guard(actor, organization, roles, *, workflow=True):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    locked = Organization.objects.select_for_update().get(pk=organization.pk)
    authorize(actor, locked, roles=roles)
    require_module(locked, "identity")
    if workflow:
        require_module(locked, "access")
        require_module(locked, "approvals")
    require_recent_authentication(actor, locked)


def _text(value, maximum):
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise ValidationError("Texte requis ou longueur incorrecte.")
    return value.strip()


def _id(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise ValidationError("Identifiant de mobilité invalide.") from None


def latest_role(key):
    return RoleRevision.objects.filter(key=key).order_by("-revision").first()


@transaction.atomic
def publish_role(*, key, name, entries, enabled, expected_revision, actor, organization):
    _guard(actor, organization, ("admin",), workflow=False)
    key, name = _text(key, 64), _text(name, 160)
    latest = latest_role(key)
    number = _proof(latest).revision if latest else 0
    if type(expected_revision) is not int or expected_revision != number:
        raise ValidationError("Le rôle a changé. Rechargez le catalogue.")
    if type(enabled) is not bool or not isinstance(entries, list) or not 1 <= len(entries) <= 20:
        raise ValidationError("Un rôle doit définir de 1 à 20 accès.")
    normalized, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"resource", "method", "privilege", "days"}:
            raise ValidationError("Définition d’accès invalide.")
        resource = _id(entry["resource"])
        method, privilege = _text(entry["method"], 80), _text(entry["privilege"], 160)
        days = entry["days"]
        item = (resource, method, privilege)
        if (
            item in seen
            or type(days) is not int
            or not 1 <= days <= 365
            or not Resource.objects.filter(pk=resource).exists()
        ):
            raise ValidationError("Accès en double, ressource étrangère ou durée hors limites.")
        seen.add(item)
        normalized.append(dict(resource=resource, method=method, privilege=privilege, days=days))
    return _attest(
        RoleRevision(organization=organization, key=key, revision=number + 1),
        actor,
        organization,
        name=name,
        entries=normalized,
        enabled=enabled,
    )


def current_move(identity):
    decision = (
        MoveDecision.objects.filter(identity=identity, applied=True).order_by("-sequence").first()
    )
    return _proof(decision) if decision else None


def _state(identity):
    decision = current_move(identity)
    return dict(
        previous=str(decision.pk) if decision else None,
        roles=decision.body["roles"] if decision else {},
        department=identity.department,
    )


def intent_scope(intent):
    return _json({key: getattr(intent, key) for key in INTENT_FIELDS})


def _check_access(link):
    _proof(link)
    _proof(link.decision)
    _proof(link.role)
    if (
        not link.decision.applied
        or link.intent.identity_id != link.decision.identity_id
        or link.decision.body["roles"].get(str(link.role_id)) != str(link.decision_id)
        or str(link.intent_id) not in link.decision.body["requests"]
        or link.body["scope"] != intent_scope(link.intent)
        or link.body["intent_id"] != str(link.intent_id)
    ):
        raise ValidationError("La demande n’est plus conforme à sa provenance métier.")
    return link


def _check_grant(proof):
    _proof(proof)
    _check_access(proof.access)
    if (
        proof.access.intent.provisioned_grant_id != proof.grant_id
        or proof.body["authority"] != grant_snapshot(proof.grant)["authority"]
    ):
        raise ValidationError("L’attribution ne correspond plus à sa preuve de provenance.")
    return proof


def _withdrawals(before, target):
    query = Q(pk__in=[])
    for role, decision in before["roles"].items():
        if role not in target:
            query |= Q(role_id=role, decision_id=decision)
    result = []
    for link in MoveAccess.objects.filter(query).select_related("intent").order_by("pk"):
        _check_access(link)
        intent = link.intent
        proof = MoveGrant.objects.filter(access=link).select_related("grant").first()
        if proof:
            _check_grant(proof)
        if bool(proof) != bool(intent.provisioned_grant_id):
            raise ValidationError("Provenance d’attribution manquante.")
        grant = proof.grant if proof else None
        if intent.status in ("pending", "approved") or (grant and grant.status == "active"):
            result.append(
                dict(
                    link=str(link.pk),
                    intent=str(intent.pk),
                    status=intent.status,
                    grant=str(grant.pk) if grant else None,
                    grant_status=grant.status if grant else None,
                    grant_revision=grant.state_revision if grant else None,
                )
            )
    return result


def _selection(identity, before, assignments):
    if not isinstance(assignments, dict) or len(assignments) > 10:
        raise ValidationError("Choisissez au plus dix rôles métier.")
    result, seen = {}, set()
    for role_id, accounts in assignments.items():
        role_id = _id(role_id)
        role = RoleRevision.objects.filter(pk=role_id).first()
        if not role:
            raise ValidationError("Rôle inconnu dans cette organisation.")
        _proof(role)
        if role.key in seen:
            raise ValidationError("Deux révisions d’un même rôle ne sont pas cumulables.")
        seen.add(role.key)
        if role_id in before["roles"]:
            if accounts != []:
                raise ValidationError("Un rôle conservé ne change pas de compte implicitement.")
            result[role_id] = []
            continue
        latest = _proof(latest_role(role.key))
        if latest.pk != role.pk or not role.body["enabled"]:
            raise ValidationError("Choisissez la dernière révision active du rôle.")
        resources = {entry["resource"] for entry in role.body["entries"]}
        if Resource.objects.filter(pk__in=resources).count() != len(resources):
            raise ValidationError("Une ressource du rôle n’est plus disponible.")
        if not isinstance(accounts, list) or len(accounts) != len(role.body["entries"]):
            raise ValidationError("Sélectionnez un compte pour chaque nouvel accès.")
        result[role_id] = [_id(account_id) for account_id in accounts]
        if ExternalAccount.objects.filter(
            pk__in=result[role_id], identity=identity, active=True
        ).count() != len(set(result[role_id])):
            raise ValidationError(
                "Les comptes choisis doivent appartenir à l’identité et être actifs."
            )
    if sum(map(len, result.values())) > 40:
        raise ValidationError("Un changement peut demander au plus 40 nouveaux accès.")
    return result


def _binding_data(binding):
    return dict(binding=str(binding.pk), person=str(binding.identity_id))


def _account_scope(account):
    return _json(
        {
            key: getattr(account, key)
            for key in (
                "id",
                "identity_id",
                "username",
                "system",
                "kind",
                "active",
                "state_revision",
                "managed_contract_id",
            )
        }
    )


def _accounts(target):
    keys = {account for ids in target.values() for account in ids}
    return {
        str(item.pk): _account_scope(item) for item in ExternalAccount.objects.filter(pk__in=keys)
    }


@transaction.atomic
def propose_move(
    *,
    identity_id,
    department,
    assignments,
    reason,
    reference,
    actor,
    organization,
    business_receipts=None,
):
    _guard(actor, organization, ("admin", "operator"))
    binding = current_binding(actor, organization=organization)
    identity = (
        Identity.objects.select_for_update().filter(pk=_id(identity_id), status="active").first()
    )
    if not identity or identity.kind not in ("human", "external"):
        raise ValidationError("Choisissez une personne active de l’organisation.")
    before = _state(identity)
    department, reason, reference = (
        _text(department, 180),
        _text(reason, 2000),
        _text(reference, 180),
    )
    target = _selection(identity, before, assignments)
    if set(target) == set(before["roles"]) and department == before["department"]:
        raise ValidationError("Aucun changement de poste ou de rôle à examiner.")
    business = {}
    if business_receipts is not None:
        from platform_modules.connectors.business_references import capture_references

        provenance = capture_references(business_receipts, organization=organization)
        if provenance:
            business["business"] = provenance
    return _attest(
        MoveProposal(organization=organization, identity=identity),
        actor,
        organization,
        before=before,
        department=department,
        target=target,
        accounts=_accounts(target),
        reason=reason,
        reference=reference,
        withdrawals=_withdrawals(before, target),
        **business,
        **_binding_data(binding),
    )


@transaction.atomic
def decide_move(proposal_id, *, approved, comment, actor, organization):
    _guard(actor, organization, ("admin", "reviewer"))
    if type(approved) is not bool:
        raise ValidationError("Décision de mobilité invalide.")
    proposal = MoveProposal.objects.filter(pk=_id(proposal_id)).first()
    if not proposal:
        raise ValidationError("Demande de mobilité inconnue.")
    _proof(proposal)
    data = proposal.body
    if MoveDecision.objects.filter(proposal=proposal).exists():
        raise ValidationError("Cette demande a déjà reçu une décision.")
    binding = current_binding(actor, organization=organization)
    if actor.pk == data["actor_id"] or str(binding.identity_id) in (
        data["person"],
        str(proposal.identity_id),
    ):
        raise ValidationError("Le demandeur et la personne concernée ne peuvent pas décider.")
    comment = _text(comment, 2000)
    decision = MoveDecision(
        organization=organization,
        proposal=proposal,
        identity_id=proposal.identity_id,
        applied=approved,
    )
    facts = dict(comment=comment, proposal_signature=proposal.signature, **_binding_data(binding))
    if not approved:
        return _attest(decision, actor, organization, **facts)
    identity = Identity.objects.select_for_update().get(pk=proposal.identity_id)
    now = timezone.now()
    requester = proposal.audit.actor
    authorize(requester, organization)
    current_binding(
        requester,
        organization=organization,
        identity_id=UUID(data["person"]),
        binding_id=UUID(data["binding"]),
    )
    if identity.status != "active" or not timedelta(0) <= now - parse_datetime(
        data["at"]
    ) < timedelta(days=2):
        raise ValidationError("La demande a expiré ou l’identité n’est plus active.")
    before = _state(identity)
    if before != data["before"]:
        raise ValidationError("Le poste ou les rôles ont changé. Préparez une nouvelle demande.")
    target = _selection(identity, before, data["target"])
    if _accounts(target) != data["accounts"]:
        raise ValidationError("Un compte choisi a changé. Préparez une nouvelle demande.")
    withdrawals = _withdrawals(before, target)
    if withdrawals != data["withdrawals"]:
        raise ValidationError("Les accès à retirer ont changé. Préparez une nouvelle demande.")
    if "business" in data:
        from platform_modules.connectors.business_references import recheck_references

        facts["business_checked"] = recheck_references(data["business"], organization=organization)
    from platform_modules.access.models import AccessIntent
    from platform_modules.access.services import create_record

    from .services import revoke_grant

    for withdrawal in withdrawals:
        intent = AccessIntent.objects.get(pk=withdrawal["intent"])
        if intent.status in ("pending", "approved"):
            intent.status, intent.revoked_at = "revoked", now
            intent.save(update_fields=("status", "revoked_at"))
        if withdrawal["grant_status"] == "active":
            revoke_grant(
                intent.provisioned_grant,
                actor=actor,
                organization=organization,
                origin="identity.mover.withdrawn.v1",
            )
    identity.department = data["department"]
    identity.save(update_fields=("department",))
    previous = current_move(identity)
    decision.sequence = previous.sequence + 1 if previous else 1
    roles = {role_id: before["roles"].get(role_id, str(decision.pk)) for role_id in target}
    requests = []
    for role_id, accounts in target.items():
        if not accounts:
            continue
        role = _proof(RoleRevision.objects.get(pk=role_id))
        for entry, account_id in zip(role.body["entries"], accounts, strict=True):
            account = ExternalAccount.objects.get(pk=account_id)
            intent = create_record(
                "intent",
                dict(
                    identity=identity,
                    account=account,
                    resource_id=entry["resource"],
                    method=entry["method"],
                    privilege=entry["privilege"],
                    reason=data["reason"],
                    reference=data["reference"],
                    starts_at=now,
                    ends_at=now + timedelta(days=entry["days"]),
                    contract=account.managed_contract,
                    fulfillment="iam_group",
                ),
                actor=requester,
                organization=organization,
            )
            requests.append((role, intent))
    _attest(
        decision,
        actor,
        organization,
        **facts,
        roles=roles,
        department=identity.department,
        withdrawals=withdrawals,
        requests=[str(intent.pk) for _, intent in requests],
    )
    for role, intent in requests:
        _attest(
            MoveAccess(organization=organization, decision=decision, role=role, intent=intent),
            actor,
            organization,
            scope=intent_scope(intent),
            intent_id=str(intent.pk),
            account=data["accounts"][str(intent.account_id)],
        )
    publish_domain_event(
        organization=organization,
        emitter="identity",
        topic="identity.mover.applied.v1",
        actor=actor,
        target=decision,
        payload=dict(
            identity_id=str(identity.pk),
            decision_id=str(decision.pk),
            requested_count=len(requests),
            withdrawn_count=len(withdrawals),
        ),
    )
    return decision


def authorize_move_intent(intent, *, actor, organization, approved=True):
    """Return exact provenance and a person binding for this special IAM request."""
    link = MoveAccess.objects.filter(intent=intent).select_related("decision", "role").first()
    if not link:
        return None, None
    _guard(actor, organization, ("admin", "reviewer"))
    _check_access(link)
    if intent_scope(intent) != link.body["scope"]:
        raise ValidationError("La demande d’accès a changé.")
    binding = current_binding(actor, organization=organization)
    proposal = _proof(link.decision.proposal)
    if str(binding.identity_id) in (proposal.body["person"], str(intent.identity_id)):
        raise ValidationError("Le demandeur et le bénéficiaire ne peuvent pas approuver cet accès.")
    if not approved:
        return link, binding
    current = current_move(intent.identity)
    latest = _proof(latest_role(link.role.key))
    if (
        not current
        or current.body["roles"].get(str(link.role_id)) != str(link.decision_id)
        or not latest.body["enabled"]
        or intent.identity.status != "active"
        or link.body["account"] != _account_scope(intent.account)
    ):
        raise ValidationError("Cette affectation métier n’est plus active.")
    from platform_modules.connectors.mover_handover import withdrawals_ready

    if not withdrawals_ready(intent.identity_id):
        raise ValidationError(
            "Un ancien retrait SCIM reste à confirmer sur sa destination. "
            "Consultez les opérations du connecteur avant d’approuver ce nouvel accès."
        )
    return link, binding


def attest_grant(link, grant, *, actor, organization):
    return _attest(
        MoveGrant(organization=organization, access=link, grant=grant),
        actor,
        organization,
        authority=grant_snapshot(grant)["authority"],
    )


def verify_mover():
    from platform_modules.connectors.business_references import verify_reference_history

    count = 0
    for model in (RoleRevision, MoveProposal, MoveDecision, MoveAccess, MoveGrant):
        for obj in model.unscoped.select_related("audit").iterator():
            _proof(obj)
            if model is MoveProposal and "business" in obj.body:
                verify_reference_history(obj.body["business"], None, organization=obj.organization)
            if model is MoveDecision:
                _proof(obj.proposal)
                if (
                    obj.proposal.identity_id != obj.identity_id
                    or obj.proposal.signature != obj.body["proposal_signature"]
                    or set(obj.body.get("requests", []))
                    != {
                        str(key)
                        for key in MoveAccess.unscoped.filter(decision=obj).values_list(
                            "intent_id", flat=True
                        )
                    }
                ):
                    raise ValidationError("Provenance de décision de mobilité incomplète.")
                if obj.applied and "business" in obj.proposal.body:
                    verify_reference_history(
                        obj.proposal.body["business"],
                        obj.body["business_checked"],
                        organization=obj.organization,
                    )
            if model is MoveAccess:
                _check_access(obj)
                if (
                    bool(obj.intent.provisioned_grant_id)
                    != MoveGrant.unscoped.filter(access=obj).exists()
                ):
                    raise ValidationError("Provenance d’attribution manquante.")
            if model is MoveGrant:
                _check_grant(obj)
            count += 1
    return count
