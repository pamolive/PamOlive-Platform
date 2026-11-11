"""Bounded tenant-local identity inventory, never an authority to grant access."""

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Exists, OuterRef
from django.db.models.functions import Trim
from django.utils import timezone

from platform_core.models import AuditEvent
from platform_core.services import lock_authorized_actor, module_available, require_module
from platform_core.tenancy import current_organization

from .models import Credential, ExternalAccount, Grant, Identity, IdentityStateChange
from .mover import verified
from .mover_models import MoveDecision, RoleRevision

SCHEMA = "pamolive.identity360/1"
READ_ROLES = ("admin", "operator", "reviewer", "auditor")


def _time(value):
    return value.isoformat() if value else None


def _section(query, project, limit, *, available=True):
    if not available:
        return {"availability": "module_disabled", "items": [], "truncated": False}
    rows = list(query[: limit + 1])
    return {
        "availability": "available",
        "items": [project(row) for row in rows[:limit]],
        "truncated": len(rows) > limit,
    }


def _guard(actor, organization):
    if current_organization().pk != organization.pk:
        raise PermissionDenied("Contexte organisationnel incorrect.")
    actor, organization = lock_authorized_actor(actor, organization, roles=READ_ROLES)
    require_module(organization, "identity")
    return actor, organization


def _limit(limit):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValidationError("La limite doit être comprise entre 1 et 100.")


def _identity(row):
    return {
        "id": str(row.pk),
        "name": row.name,
        "kind": row.kind,
        "population": "human" if row.kind in ("human", "external") else "non_human",
        "status": row.status,
        "email": row.email,
        "department": row.department,
        "responsible_owner": row.owner.strip() or None,
        "owner_assurance": "declared_text" if row.owner.strip() else "missing",
        "created_at": _time(row.created_at),
        "provenance": "local_record_not_independently_attested",
    }


def _orphan_reasons(account):
    if account.identity.organization_id != account.organization_id:
        raise ValidationError("Rattachement d’identité inter-organisation invalide.")
    reasons = []
    if account.identity.status != "active":
        reasons.append("inactive_identity")
    if account.identity.kind not in ("human", "external") and not account.identity.owner.strip():
        reasons.append("missing_responsible_owner")
    return reasons


@transaction.atomic
def identity_inventory(*, actor, organization, limit=100, orphaned_only=False):
    """The schema requires an identity FK; orphan means missing active responsibility."""
    from django.db.models import Q

    _limit(limit)
    _, organization = _guard(actor, organization)
    identities = Identity.objects.order_by("name", "pk")
    accounts = ExternalAccount.objects.select_related("identity").filter(active=True)
    orphaned = (
        accounts.annotate(owner_trimmed=Trim("identity__owner"))
        .filter(
            ~Q(identity__status="active")
            | (~Q(identity__kind__in=("human", "external")) & Q(owner_trimmed=""))
        )
        .order_by("system", "username", "pk")
    )
    return {
        "schema": SCHEMA,
        "organization_id": str(organization.pk),
        "read_only": True,
        "generated_at": _time(timezone.now()),
        "identities": _section(
            identities.none() if orphaned_only else identities, _identity, limit
        ),
        "orphaned_accounts": _section(
            orphaned,
            lambda row: {
                "id": str(row.pk),
                "username": row.username,
                "system": row.system,
                "identity_id": str(row.identity_id),
                "identity_name": row.identity.name,
                "reasons": _orphan_reasons(row),
            },
            limit,
        ),
        "orphan_definition": (
            "active account with inactive identity or ownerless non-human identity"
        ),
    }


def _current_roles(identity, limit):
    decision = (
        MoveDecision.objects.filter(identity=identity, applied=True)
        .order_by("-sequence")
        .select_related("audit")
        .first()
    )
    if decision is None:
        return {
            "availability": "available",
            "items": [],
            "truncated": False,
            "assurance": "no_recorded_move",
        }
    if not verified(decision) or not isinstance(decision.body.get("roles"), dict):
        return {
            "availability": "unverifiable",
            "items": [],
            "truncated": False,
            "assurance": "invalid_move_proof",
        }
    keys = list(decision.body["roles"])
    try:
        roles = list(
            RoleRevision.objects.filter(pk__in=keys)
            .select_related("audit")
            .order_by("key", "revision")[: limit + 1]
        )
    except (ValueError, ValidationError):
        return {
            "availability": "unverifiable",
            "items": [],
            "truncated": False,
            "assurance": "invalid_role_reference",
        }
    if any(not verified(role) for role in roles):
        return {
            "availability": "unverifiable",
            "items": [],
            "truncated": False,
            "assurance": "invalid_role_proof",
        }
    if len(roles) != min(len(keys), limit + 1):
        return {
            "availability": "unverifiable",
            "items": [],
            "truncated": False,
            "assurance": "missing_role_reference",
        }
    return {
        "availability": "available",
        "truncated": len(roles) > limit,
        "assurance": "verified_local_move_not_provider_confirmation",
        "decision_id": str(decision.pk),
        "items": [
            {
                "id": str(role.pk),
                "key": role.key,
                "revision": role.revision,
                "name": role.body.get("name", role.key),
                "proof_verified": True,
            }
            for role in roles[:limit]
        ],
    }


@transaction.atomic
def build_identity360(identity_id, *, actor, organization, limit=100):
    _limit(limit)
    _, organization = _guard(actor, organization)
    identity = Identity.objects.get(pk=identity_id)
    now = timezone.now()
    accounts = (
        ExternalAccount.objects.filter(identity=identity)
        .select_related("identity")
        .order_by("system", "username", "pk")
    )
    grants = (
        Grant.objects.filter(identity=identity)
        .select_related("account", "resource")
        .order_by("-created_at", "pk")
    )

    def grant_projection(row):
        # Never follow an invalid relationship into another tenant, even if data
        # was inserted outside model validation by an installation owner.
        if row.resource.organization_id != organization.pk or (
            row.account_id
            and (
                row.account.organization_id != organization.pk
                or row.account.identity_id != identity.pk
            )
        ):
            raise ValidationError("Lien d’habilitation inter-organisation invalide.")
        return {
            "id": str(row.pk),
            "entitlement": row.entitlement,
            "method": row.method,
            "resource_id": str(row.resource_id),
            "resource_name": row.resource.name,
            "resource_owner": row.resource.owner or None,
            "account_id": str(row.account_id) if row.account_id else None,
            "status": row.status,
            "valid_from": _time(row.valid_from),
            "expires_at": _time(row.expires_at),
            "revoked_at": _time(row.revoked_at),
            "locally_effective": row.status == "active"
            and row.valid_from <= now
            and (row.expires_at is None or now < row.expires_at),
            "assurance": "local_grant_not_provider_membership",
        }

    result = {
        "schema": SCHEMA,
        "organization_id": str(organization.pk),
        "read_only": True,
        "generated_at": _time(now),
        "identity": _identity(identity),
        "accounts": _section(
            accounts,
            lambda row: {
                "id": str(row.pk),
                "username": row.username,
                "system": row.system,
                "kind": row.kind,
                "active": row.active,
                "state_revision": row.state_revision,
                "responsibility_warnings": _orphan_reasons(row),
                "provenance": "local_record_not_remote_inventory",
            },
            limit,
        ),
        "grants": _section(grants, grant_projection, limit),
        "business_roles": _current_roles(identity, limit),
        "credentials": _section(
            Credential.objects.filter(identity=identity).order_by("name", "pk"),
            lambda row: {
                "id": str(row.pk),
                "name": row.name,
                "kind": row.kind,
                "expires_at": _time(row.expires_at),
                "assurance": "registered_reference_not_possession_proof",
            },
            limit,
        ),
        "lifecycle": {
            "joiner": {"recorded_at": _time(identity.created_at), "assurance": "local_creation"},
            "state_changes": _section(
                IdentityStateChange.objects.filter(identity=identity).order_by(
                    "-effective_at", "pk"
                ),
                lambda row: {
                    "id": str(row.pk),
                    "from": row.previous_status,
                    "to": row.next_status,
                    "effective_at": _time(row.effective_at),
                },
                limit,
            ),
        },
        "history": _section(
            AuditEvent.objects.filter(
                organization=organization,
                object_type="identity.identity",
                object_id=str(identity.pk),
            ).order_by("-sequence"),
            lambda row: {
                "id": str(row.pk),
                "action": row.action,
                "sequence": row.sequence,
                "event_hash": row.event_hash,
            },
            limit,
        ),
        "limitations": [
            "This bounded reading is unsigned and does not authorize access.",
            "Local grants and role assignments do not prove current directory membership.",
            "Owner is a declared label, not an independently attested person.",
            "No email or name matching grants authority or establishes provenance.",
        ],
    }

    def move_projection(row):
        valid = verified(row)
        item = {"id": str(row.pk), "proof_verified": valid}
        if valid:
            item.update(
                {
                    "applied": row.applied,
                    "sequence": row.sequence,
                    "decided_at": row.body.get("at"),
                    "department": row.body.get("department"),
                }
            )
        return item

    result["lifecycle"]["moves"] = _section(
        MoveDecision.objects.filter(identity=identity)
        .select_related("audit")
        .order_by("-audit__sequence"),
        move_projection,
        limit,
    )
    available = module_available(organization, "access")
    from platform_modules.access.models import AccessIntent

    result["access_requests"] = _section(
        AccessIntent.objects.filter(identity=identity).order_by("-created_at", "pk"),
        lambda row: {
            "id": str(row.pk),
            "status": row.status,
            "fulfillment": row.fulfillment,
            "created_at": _time(row.created_at),
        },
        limit,
        available=available,
    )
    from platform_modules.connectors.models import AccountBinding, GroupBinding

    connectors_available = module_available(organization, "connectors")

    def source_projection(row):
        if row.connector.organization_id != organization.pk:
            raise ValidationError("Référence de source inter-organisation invalide.")
        return {
            "binding_id": str(row.pk),
            "account_id": str(row.account_id),
            "connector_id": str(row.connector_id),
            "remote_id": row.remote_id,
            "connector_revision": row.connector.revision,
            "assurance": "configured_reference_not_authenticated_observation",
        }

    result["sources"] = _section(
        AccountBinding.objects.filter(account__identity=identity)
        .select_related("connector")
        .order_by("pk"),
        source_projection,
        limit,
        available=connectors_available,
    )
    local_right = Grant.objects.filter(
        identity=identity, resource_id=OuterRef("resource_id"), entitlement=OuterRef("entitlement")
    )

    def group_projection(row):
        if (
            row.connector.organization_id != organization.pk
            or row.resource.organization_id != organization.pk
        ):
            raise ValidationError("Référence de groupe inter-organisation invalide.")
        return {
            "binding_id": str(row.pk),
            "connector_id": str(row.connector_id),
            "resource_id": str(row.resource_id),
            "entitlement": row.entitlement,
            "remote_group_id": row.remote_id,
            "assurance": "configured_group_mapping_not_membership_confirmation",
        }

    result["directory_groups"] = _section(
        GroupBinding.objects.annotate(matches_local_right=Exists(local_right))
        .filter(matches_local_right=True)
        .select_related("connector", "resource")
        .order_by("pk"),
        group_projection,
        limit,
        available=connectors_available,
    )
    return result
