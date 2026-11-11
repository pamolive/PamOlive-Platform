"""Versioned, tenant-scoped IGA workspace composed from the existing domains."""

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import OuterRef, Subquery
from django.utils import timezone

from platform_core.services import lock_authorized_actor, module_available, require_module
from platform_modules.access.models import AccessIntent
from platform_modules.identity.models import Grant, Resource, RoleRevision
from platform_modules.identity.mover import verified as role_verified

from .exception_models import ExceptionCase
from .exceptions import case_state
from .models import ApprovalPolicyRevision, SeparationRule

SCHEMA = "pamolive.governance-workspace/1"
READ_ROLES = ("admin", "operator", "reviewer", "auditor")


def _section(query, project, limit):
    rows = list(query[: limit + 1])
    return {
        "availability": "available",
        "items": [project(row) for row in rows[:limit]],
        "truncated": len(rows) > limit,
    }


def _disabled():
    return {"availability": "module_disabled", "items": [], "truncated": False}


def _iso(value):
    return value.isoformat() if value is not None else None


def _grant(row):
    return dict(
        id=str(row.pk),
        identity_id=str(row.identity_id),
        identity=row.identity.name,
        resource_id=str(row.resource_id),
        resource=row.resource.name,
        entitlement=row.entitlement,
        state=row.status,
        expires_at=_iso(row.expires_at),
        revoked_at=_iso(row.revoked_at),
        assurance="local_record",
    )


def _origin(row):
    if row.binding_id and row.binding.organization_id == row.organization_id:
        return dict(
            state="recorded_reference",
            binding_id=str(row.binding_id),
            connector_id=str(row.binding.connector_id),
            recorded_connector_revision=row.connector_revision,
        )
    return dict(state="unknown")


@transaction.atomic
def build_governance_workspace(*, actor, organization, limit=50):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValidationError("Limite de lecture comprise entre 1 et 100.")
    actor, organization = lock_authorized_actor(actor, organization, roles=READ_ROLES)
    require_module(organization, "governance")
    now = timezone.now()
    enabled = {
        key: module_available(organization, key)
        for key in ("identity", "access", "approvals", "connectors", "recertification")
    }
    result = dict(
        schema=SCHEMA,
        organization_id=str(organization.pk),
        generated_at=_iso(now),
        read_only=True,
        optional_sections=enabled,
        limitations=[
            "Une lecture locale n’est pas un inventaire actuel du fournisseur.",
            "L’éligibilité est réévaluée par le parcours de demande et ses politiques.",
            "Une exception acceptée est une justification suivie, sans dérogation SoD/PAM.",
            "Des comptes de revue distincts ne prouvent pas des personnes indépendantes.",
        ],
    )
    policy = ApprovalPolicyRevision.objects.order_by("-sequence").first()
    result["approval_policy"] = (
        dict(
            id=str(policy.pk),
            revision=policy.sequence,
            min_reviewers=policy.min_reviewers,
            critical_reviewers=policy.critical_reviewers,
        )
        if policy
        else None
    )
    result["separation_rules"] = _section(
        SeparationRule.objects.select_related("left_resource", "right_resource").order_by("pk"),
        lambda row: dict(
            id=str(row.pk),
            name=row.name,
            retired_at=_iso(row.retired_at),
            left_resource=row.left_resource.name,
            left_entitlement=row.left_entitlement,
            right_resource=row.right_resource.name,
            right_entitlement=row.right_entitlement,
        ),
        limit,
    )
    latest = RoleRevision.objects.filter(key=OuterRef("key")).order_by("-revision").values("pk")[:1]
    result["business_roles"] = _section(
        RoleRevision.objects.filter(pk=Subquery(latest)).select_related("audit").order_by("key"),
        lambda row: dict(
            id=str(row.pk),
            key=row.key,
            revision=row.revision,
            name=row.body.get("name", row.key),
            enabled=bool(row.body.get("enabled")) and role_verified(row),
            proof_verified=role_verified(row),
        ),
        limit,
    )
    entries = []
    catalog_truncated = result["business_roles"]["truncated"]
    # Only signed role definitions describe requestable entries. Existing grants
    # and remote group mappings alone must not become a request catalogue.
    role_ids = [row["id"] for row in result["business_roles"]["items"] if row["enabled"]]
    catalog_roles = list(RoleRevision.objects.filter(pk__in=role_ids).order_by("key"))
    resource_ids = {
        entry["resource"] for role in catalog_roles for entry in role.body.get("entries", [])
    }
    resources = {str(row.pk): row for row in Resource.objects.filter(pk__in=resource_ids)}
    for role in catalog_roles:
        for entry in role.body.get("entries", []):
            resource = resources.get(str(entry.get("resource")))
            if resource is None:
                continue
            entries.append(
                dict(
                    role_id=str(role.pk),
                    role=role.body["name"],
                    resource_id=str(resource.pk),
                    resource=resource.name,
                    entitlement=entry["privilege"],
                    method=entry["method"],
                    max_days=entry["days"],
                    owner=resource.owner,
                    risk="critical" if resource.critical else "not_classified",
                    eligibility="requires_request_policy_evaluation",
                    meaning=role.body["name"],
                    provenance="verified_role_revision",
                )
            )
            if len(entries) > limit:
                catalog_truncated = True
                break
        if len(entries) > limit:
            break
    result["entitlement_catalog"] = dict(
        availability="available",
        items=entries[:limit],
        truncated=catalog_truncated,
    )
    result["access_requests"] = _section(
        AccessIntent.objects.select_related("identity", "resource").order_by("-created_at", "pk"),
        lambda row: dict(
            id=str(row.pk),
            identity=row.identity.name,
            resource=row.resource.name,
            entitlement=row.privilege,
            status=row.status,
            fulfillment=row.fulfillment,
            starts_at=_iso(row.starts_at),
            ends_at=_iso(row.ends_at),
        ),
        limit,
    )
    result["revoked_grants"] = _section(
        Grant.objects.filter(status="revoked")
        .select_related("identity", "resource")
        .order_by("-revoked_at", "pk"),
        _grant,
        limit,
    )
    if enabled["approvals"]:
        from platform_modules.approvals.models import ApprovalDecision

        result["approval_decisions"] = _section(
            ApprovalDecision.objects.order_by("-decided_at", "pk"),
            lambda row: dict(
                id=str(row.pk),
                intent_id=str(row.intent_id),
                approved=row.approved,
                decided_at=_iso(row.decided_at),
                assurance="stored_decision_not_new_authorization",
            ),
            limit,
        )
    else:
        result["approval_decisions"] = _disabled()
    if enabled["connectors"]:
        from platform_modules.connectors.models import ExecutionEvidence, ExternalChange

        latest_confirmation = ExecutionEvidence.objects.filter(
            change_id=OuterRef("pk"),
            organization=organization,
            confirmed=True,
        ).order_by("-recorded_at", "pk")
        changes = (
            ExternalChange.objects.filter(kind__in=("remove_membership", "disable_account"))
            .select_related("binding")
            .annotate(
                confirmation_id=Subquery(latest_confirmation.values("pk")[:1]),
                confirmation_at=Subquery(latest_confirmation.values("recorded_at")[:1]),
            )
            .order_by("-created_at", "pk")
        )
        result["withdrawal_operations"] = _section(
            changes,
            lambda row: dict(
                id=str(row.pk),
                grant_id=str(row.grant_id) if row.grant_id else None,
                account_id=str(row.account_id) if row.account_id else None,
                kind=row.kind,
                status=row.status,
                result_code=row.result_code,
                attempts=row.attempts,
                origin=_origin(row),
                recorded_confirmation_id=(
                    str(row.confirmation_id) if row.confirmation_id else None
                ),
                confirmed_at=_iso(row.confirmation_at),
                current_provider_state="not_asserted",
                confirmation_state="historically_confirmed"
                if row.confirmation_id
                else "unconfirmed",
            ),
            limit,
        )
    else:
        result["withdrawal_operations"] = _disabled()
    if enabled["recertification"]:
        from platform_modules.recertification.models import Campaign, Review

        result["campaigns"] = _section(
            Campaign.objects.order_by("-created_at", "pk"),
            lambda row: dict(id=str(row.pk), name=row.name, due_at=_iso(row.due_at)),
            limit,
        )
        result["access_reviews"] = _section(
            Review.objects.select_related("grant__identity", "grant__resource").order_by(
                "-reviewed_at", "pk"
            ),
            lambda row: dict(
                id=str(row.pk),
                campaign_id=str(row.campaign_id),
                grant_id=str(row.grant_id),
                decision=row.decision,
                reviewed_at=_iso(row.reviewed_at),
                assurance="local_review_not_external_confirmation",
            ),
            limit,
        )
    else:
        result["campaigns"], result["access_reviews"] = _disabled(), _disabled()
    cases = (
        ExceptionCase.objects.select_related("audit", "identity", "resource")
        .prefetch_related("decisions__audit")
        .order_by("-created_at", "pk")
    )

    def exception_row(row):
        decisions = list(row.decisions.all())
        return dict(
            id=str(row.pk),
            identity=row.identity.name,
            resource=row.resource.name,
            entitlement=row.entitlement,
            reference=row.reference,
            reason=row.reason,
            compensating_controls=row.compensating_controls,
            expires_at=_iso(row.expires_at),
            requested_by_id=row.requested_by_id,
            state=case_state(row, decisions, at=now),
            grants_authority=False,
            audit_id=str(row.audit_id),
            decisions=[
                dict(
                    id=str(d.pk),
                    decision=d.decision,
                    comment=d.comment,
                    decided_by_id=d.decided_by_id,
                    decided_at=_iso(d.decided_at),
                )
                for d in decisions
            ],
        )

    result["exceptions"] = _section(cases, exception_row, limit)
    return result
