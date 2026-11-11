"""Versioned, read-only access story. A recorded decision is never an external effect."""

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from platform_modules.access.evidence import verify_evaluation
from platform_modules.access.models import AccessEvaluation, AccessIntent
from platform_modules.access.provenance_status import verified_origin_status
from platform_modules.approvals.models import ApprovalDecision
from platform_modules.connectors.models import ExecutionEvidence, ExternalChange
from platform_modules.identity.models import Grant
from platform_modules.pam.models import RelayConnection, SessionLease

from .models import Organization
from .product_modules import PRODUCT_MAPPING_VERSION
from .services import authorize, module_available, require_module
from .tenancy import current_organization, organization_context

SCHEMA = "pamolive.access-contract/1"
READ_ROLES = ("admin", "operator", "reviewer", "auditor")


def _id(value):
    return str(value) if value is not None else None


def _time(value):
    return value.isoformat() if value is not None else None


def _section(items=(), *, available=True, truncated=False):
    return {
        "availability": "available" if available else "module_disabled",
        "items": list(items),
        "truncated": truncated,
    }


def _bounded(query, limit):
    rows = list(query[: limit + 1])
    return rows[:limit], len(rows) > limit


def _origin(change, organization):
    """Expose only the recorded routing references, never today's account mapping."""
    binding = change.binding
    if binding is None:
        return {
            "state": "unknown", "binding_id": None, "connector_id": None,
            "recorded_connector_revision": change.connector_revision,
        }
    if (
        binding.organization_id != organization.pk
        or binding.connector.organization_id != organization.pk
    ):
        raise ValidationError("La référence de destination appartient à une autre organisation.")
    return {
        "state": "recorded_reference", "binding_id": str(binding.pk),
        "connector_id": str(binding.connector_id),
        "recorded_connector_revision": change.connector_revision,
    }


@transaction.atomic
def build_access_contract(intent_id, *, actor, organization, limit=100):
    """Return a bounded tenant-scoped projection without exercising any authority.

    Optional disabled domains are not queried. Callers must render the availability
    and truncation markers rather than interpreting an empty list as no activity.
    The organization lock serializes this projection with domain writes/activation.
    This contract is a reading, not a fresh signed proof or a permission to connect.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValidationError("La limite du contrat doit être comprise entre 1 et 100.")
    if current_organization().pk != organization.pk:
        raise PermissionDenied("Contexte organisationnel incorrect.")
    authorize(actor, organization, roles=READ_ROLES)
    organization = Organization.objects.select_for_update().filter(
        pk=organization.pk, active=True
    ).first()
    if organization is None:
        raise PermissionDenied("Organisation indisponible.")
    actor = get_user_model().objects.filter(pk=actor.pk, is_active=True).first()
    authorize(actor, organization, roles=READ_ROLES)
    require_module(organization, "access")
    require_module(organization, "identity")
    with organization_context(organization):
        intent = AccessIntent.objects.select_related("identity", "account", "resource").get(
            pk=intent_id
        )
        available = {
            key: module_available(organization, key) for key in ("approvals", "connectors", "pam")
        }
        result = {
            "schema": SCHEMA,
            "product_mapping_version": PRODUCT_MAPPING_VERSION,
            "organization_id": str(organization.pk),
            "generated_at": _time(timezone.now()),
            "read_only": True,
            "optional_sections": available,
            "intention": {
                "id": str(intent.pk), "status": intent.status,
                "identity_id": str(intent.identity_id), "account_id": _id(intent.account_id),
                "resource_id": str(intent.resource_id), "requested_by_id": intent.requested_by_id,
                "method": intent.method, "fulfillment": intent.fulfillment,
                "reason": intent.reason, "reference": intent.reference,
                "starts_at": _time(intent.starts_at), "ends_at": _time(intent.ends_at),
                "created_at": _time(intent.created_at), "approved_at": _time(intent.approved_at),
                "revoked_at": _time(intent.revoked_at),
            },
            "requested_right": {
                "state": "requested", "entitlement": intent.privilege,
                "method": intent.method,
                "resource_id": str(intent.resource_id), "account_id": _id(intent.account_id),
                "provider_confirmation": False,
            },
            "approval_decisions": _section(available=available["approvals"]),
            "local_grant": _section(),
            "provisioned_right": _section(available=available["connectors"]),
            "confirmed_executions": _section(available=available["connectors"]),
            "execution_attempts": _section(available=available["connectors"]),
            "pam_sessions": _section(available=available["pam"]),
            "observations": _section(),
            "evidence": _section(),
            "limitations": [
                "A local grant or approved intent does not confirm external provisioning.",
                "A provider confirmation is a point-in-time result, not current inventory.",
                "A V8 receipt attests acceptance by PamOlive, not remote telemetry truth.",
                "Observations are linked only by a verified historical evaluation, not inference.",
            ],
        }
        if available["approvals"]:
            decisions, truncated = _bounded(
                ApprovalDecision.objects.filter(intent=intent).order_by("decided_at", "pk"), limit
            )
            result["approval_decisions"] = _section(({
                "id": str(row.pk), "reviewer_id": row.reviewer_id,
                "reviewer_identity_id": _id(row.reviewer_identity_id),
                "approved": row.approved, "comment": row.comment,
                "decided_at": _time(row.decided_at), "assurance": "recorded_decision",
                "confers_execution": False,
            } for row in decisions), truncated=truncated)

        grant = None
        if intent.provisioned_grant_id:
            grant = Grant.objects.filter(
                pk=intent.provisioned_grant_id, identity_id=intent.identity_id,
                resource_id=intent.resource_id, account_id=intent.account_id,
                entitlement=intent.privilege,
            ).first()
            if grant is None or grant.method.casefold() != intent.method.casefold():
                raise ValidationError("Le droit lié ne correspond pas au périmètre de la demande.")
            result["local_grant"] = _section([{
                "id": str(grant.pk), "state": grant.status, "revision": grant.state_revision,
                "entitlement": grant.entitlement, "valid_from": _time(grant.valid_from),
                "method": grant.method,
                "expires_at": _time(grant.expires_at), "revoked_at": _time(grant.revoked_at),
                "assurance": "local_record", "provider_confirmation": False,
            }])

        evidence = []
        evidence_truncated = False
        if available["connectors"] and grant is not None:
            changes, truncated = _bounded(
                ExternalChange.objects.filter(grant=grant).select_related("binding__connector")
                .order_by("created_at", "pk"), limit
            )
            result["execution_attempts"] = _section(({
                "id": str(row.pk), "kind": row.kind, "status": row.status,
                "attempts": row.attempts, "result_code": row.result_code,
                "connector_revision": row.connector_revision,
                "origin": _origin(row, organization),
                "created_at": _time(row.created_at), "updated_at": _time(row.updated_at),
            } for row in changes), truncated=truncated)
            proofs, proof_limit = _bounded(
                ExecutionEvidence.objects.filter(change__in=changes, confirmed=True)
                .select_related("change__binding__connector").order_by("recorded_at", "pk"), limit
            )
            confirmed = [{
                "id": str(proof.pk), "change_id": str(proof.change_id),
                "kind": proof.change.kind, "attempt": proof.attempt, "code": proof.code,
                "recorded_at": _time(proof.recorded_at),
                "assurance": "provider_result_recorded",
                "current_provider_state": "not_asserted",
                "origin": _origin(proof.change, organization),
            } for proof in proofs]
            result["confirmed_executions"] = _section(
                confirmed, truncated=truncated or proof_limit
            )
            evidence_truncated = truncated or proof_limit
            result["provisioned_right"] = _section(({
                "grant_id": str(grant.pk), "entitlement": grant.entitlement,
                "effect": proof.change.kind, "execution_evidence_id": str(proof.pk),
                "confirmed_at": _time(proof.recorded_at),
                "current_provider_state": "not_asserted",
                "origin": _origin(proof.change, organization),
            } for proof in proofs if proof.change.kind in ("add_membership", "remove_membership")),
                truncated=truncated or proof_limit)
            evidence.extend({"kind": "execution", "id": row["id"],
                             "assurance": "provider_result_recorded"} for row in confirmed)

        if available["pam"]:
            leases, truncated = _bounded(
                SessionLease.objects.filter(intent=intent).order_by("started_at", "pk"), limit
            )
            connections, conn_limit = _bounded(
                RelayConnection.objects.filter(lease__in=leases).order_by("created_at", "pk"), limit
            )
            session_rows = [{
                "lease_id": str(row.pk), "state": row.status,
                "started_at": _time(row.started_at), "expires_at": _time(row.expires_at),
                "ended_at": _time(row.ended_at), "assurance": "local_lease_not_remote_login",
            } for row in leases] + [{
                "connection_id": str(row.pk), "lease_id": str(row.lease_id),
                "state": row.status, "connected_at": _time(row.connected_at),
                "ended_at": _time(row.ended_at), "assurance": "relay_state_recorded",
            } for row in connections]
            result["pam_sessions"] = _section(
                session_rows[:limit], truncated=truncated or conn_limit or len(session_rows) > limit
            )

        evaluations = AccessEvaluation.objects.filter(intent=intent)
        if not available["connectors"]:
            evaluations = evaluations.filter(
                event__provenance_channel__in=("manual", "legacy_unknown")
            )
            result["limitations"].append(
                "Collector/internal observations hidden: Connect disabled."
            )
        related = ["audit", "event__provenance_receipt__audit", "intent"]
        if available["connectors"]:
            related.append("event__collector_source")
        evaluations, truncated = _bounded(
            evaluations.select_related(*related)
            .order_by("evaluated_at", "pk"), limit
        )
        observations = []
        for evaluation in evaluations:
            if not verify_evaluation(evaluation):
                result["limitations"].append("An invalid evaluation was excluded.")
                continue
            event = evaluation.event
            provenance = verified_origin_status(event)
            receipt = getattr(event, "provenance_receipt", None)
            origin_valid = provenance not in ("legacy_unknown", "invalid_provenance")
            observations.append({
                "id": str(event.pk), "evaluation_id": str(evaluation.pk),
                "occurred_at": _time(event.occurred_at), "ended_at": _time(event.ended_at),
                "received_at": _time(event.received_at), "action": event.action,
                "result": event.result, "verdict": evaluation.verdict,
                "identity_id": _id(event.identity_id), "account_id": _id(event.account_id),
                "resource_id": _id(event.resource_id),
                "provenance": provenance,
                "provenance_receipt_id": str(receipt.pk) if receipt else None,
                "provenance_principal_id": receipt.principal_id
                if receipt and origin_valid else None,
                "provenance_verified": bool(receipt and origin_valid),
                "association": "verified_evaluation_reference_not_causality",
            })
            if receipt:
                evidence.append({"kind": "provenance_receipt", "id": str(receipt.pk),
                                 "version": receipt.version, "verified": origin_valid})
            evidence.append({"kind": "evaluation", "id": str(evaluation.pk),
                             "rule_version": evaluation.rule_version, "verified": True})
        result["observations"] = _section(observations, truncated=truncated)
        result["evidence"] = _section(
            evidence[:limit], truncated=evidence_truncated or truncated or len(evidence) > limit
        )
        return result
