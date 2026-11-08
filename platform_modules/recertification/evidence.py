"""recertification.evidence/1: frozen campaigns and decisions, not access renewals."""

import hashlib
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.utils.crypto import constant_time_compare

from platform_core.attestations import signature, verify_anchor

from .evidence_models import CampaignRun, ReviewDecision, ReviewScope, SchedulePublication

NAMESPACE = "pamolive.recertification/1"
PUBLICATION_ACTION = "recertification.schedule.published.v1"
RUN_ACTION = "recertification.campaign.opened.v2"
DECISION_ACTION = "recertification.review.decided.v2"


def publication_body(obj):
    return dict(
        {
            key: getattr(obj, key)
            for key in (
                "id",
                "organization_id",
                "schedule_id",
                "revision",
                "name",
                "active",
                "first_at",
                "interval_days",
                "review_window_days",
                "scope",
                "owner_id",
                "published_by_id",
                "published_at",
                "mfa_verified_at",
                "mfa_window_minutes",
            )
        },
        schedule_key=obj.schedule.key,
    )


def run_body(obj):
    return dict(
        {
            key: getattr(obj, key)
            for key in (
                "id",
                "organization_id",
                "campaign_id",
                "publication_id",
                "schedule_id",
                "scheduled_for",
                "next_due_at",
                "missed_periods",
                "capture_started_at",
                "snapshot_at",
                "opened_at",
                "due_at",
                "name",
                "owner_id",
                "opened_by_id",
                "mfa_verified_at",
                "mfa_window_minutes",
                "review_count",
                "selection_scope",
                "manifest_hash",
            )
        },
        publication_signature=obj.publication.signature if obj.publication_id else None,
    )


def scope_body(obj):
    return {
        key: getattr(obj, key)
        for key in (
            "id",
            "organization_id",
            "run_id",
            "campaign_id",
            "review_id",
            "grant_id",
            "snapshot",
        )
    }


def decision_body(obj, scope=None):
    return dict(
        {
            key: getattr(obj, key)
            for key in (
                "id",
                "organization_id",
                "scope_id",
                "decided_by_id",
                "decided_at",
                "mfa_verified_at",
                "mfa_window_minutes",
                "keep",
                "comment",
                "local_outcome",
                "grant_state",
            )
        },
        scope_signature=(scope or obj.scope).signature,
        external_confirmation=False,
    )


def mfa_valid(at, verified, minutes):
    return bool(
        minutes in (2, 5, 10, 15)
        and verified
        and 0 <= (at - verified).total_seconds() < minutes * 60
    )


def verify_publication(obj):
    try:
        return bool(
            obj.schedule.organization_id == obj.organization_id
            and obj.revision >= 1
            and 1 <= obj.interval_days <= 3660
            and 1 <= obj.review_window_days <= 365
            and set(obj.scope) == {"resource_ids", "identity_kinds", "account_kinds"}
            and all(
                type(values) is list
                and len(values) <= 100
                and all(type(value) is str for value in values)
                and values == sorted(set(values))
                for values in obj.scope.values()
            )
            and mfa_valid(obj.published_at, obj.mfa_verified_at, obj.mfa_window_minutes)
            and verify_anchor(
                obj,
                NAMESPACE,
                "publication",
                publication_body(obj),
                PUBLICATION_ACTION,
                obj.published_by_id,
            )
        )
    except (TypeError, ValueError, AttributeError, KeyError, ValidationError):
        return False


def verify_run(obj):
    try:
        if obj.publication_id:
            pub, period = obj.publication, timedelta(days=obj.publication.interval_days)
            valid_source = (
                verify_publication(pub)
                and pub.active
                and pub.organization_id == obj.organization_id
                and obj.schedule_id == pub.schedule_id
                and obj.owner_id == pub.owner_id
                and obj.selection_scope == pub.scope
                and obj.opened_by_id is None
                and obj.mfa_verified_at is None
                and obj.mfa_window_minutes is None
                and obj.scheduled_for >= pub.first_at
                and (obj.scheduled_for - pub.first_at) % period == timedelta(0)
                and obj.next_due_at == obj.scheduled_for + period
                and obj.scheduled_for <= obj.snapshot_at < obj.next_due_at
                and obj.due_at == obj.snapshot_at + timedelta(days=pub.review_window_days)
            )
        else:
            valid_source = (
                obj.schedule_id is None
                and obj.scheduled_for is None
                and obj.next_due_at is None
                and obj.missed_periods == 0
                and obj.opened_by_id
                and mfa_valid(obj.opened_at, obj.mfa_verified_at, obj.mfa_window_minutes)
            )
        return bool(
            valid_source
            and obj.campaign.organization_id == obj.organization_id
            and obj.capture_started_at <= obj.snapshot_at < obj.due_at
            and verify_anchor(obj, NAMESPACE, "run", run_body(obj), RUN_ACTION, obj.opened_by_id)
        )
    except (TypeError, ValueError, AttributeError, KeyError, ValidationError):
        return False


def verify_scope(obj, *, run=None):
    try:
        run = run or obj.run
        body, selection = obj.snapshot, run.selection_scope
        return bool(
            verify_run(run)
            and obj.organization_id == run.organization_id
            and obj.run_id == run.pk
            and obj.campaign_id == run.campaign_id
            and obj.review.organization_id == obj.organization_id
            and obj.review.campaign_id == obj.campaign_id
            and obj.review.grant_id == obj.grant_id
            and body["contract"] == "identity.review/1"
            and body["authority"]["id"] == str(obj.grant_id)
            and body["authority"]["organization_id"] == str(obj.organization_id)
            and body["state"]["status"] == "active"
            and (
                not selection["resource_ids"]
                or body["authority"]["resource_id"] in selection["resource_ids"]
            )
            and (
                not selection["identity_kinds"]
                or body["context"]["identity_kind"] in selection["identity_kinds"]
            )
            and (
                not selection["account_kinds"]
                or body["context"]["account_kind"] in selection["account_kinds"]
            )
            and constant_time_compare(obj.signature, signature(NAMESPACE, "scope", scope_body(obj)))
        )
    except (TypeError, ValueError, AttributeError, KeyError, ValidationError):
        return False


def manifest_hash(scopes):
    digest = hashlib.sha256(b"pamolive.recertification.manifest/1\n")
    for scope in scopes:
        digest.update(scope.signature.encode("ascii") + b"\n")
    return digest.hexdigest()


def run_scopes(run):
    return ReviewScope.unscoped.filter(run=run).select_related("review").order_by("grant_id")


def verify_manifest(run):
    if not verify_run(run):
        return False
    scopes = list(run_scopes(run))
    return bool(
        len(scopes) == run.review_count
        and all(verify_scope(item, run=run) for item in scopes)
        and constant_time_compare(manifest_hash(scopes), run.manifest_hash)
    )


def verify_decision(obj, *, scope=None, run=None):
    try:
        scope = scope or obj.scope
        state = obj.grant_state
        return bool(
            obj.organization_id == scope.organization_id
            and obj.scope_id == scope.pk
            and verify_scope(scope, run=run)
            and mfa_valid(obj.decided_at, obj.mfa_verified_at, obj.mfa_window_minutes)
            and (
                (obj.keep and obj.local_outcome == "kept" and state["status"] == "active")
                or (
                    not obj.keep
                    and obj.local_outcome in ("revoked", "already_revoked")
                    and state["status"] == "revoked"
                )
            )
            and verify_anchor(
                obj,
                NAMESPACE,
                "decision",
                decision_body(obj, scope),
                DECISION_ACTION,
                obj.decided_by_id,
            )
        )
    except (TypeError, ValueError, AttributeError, KeyError, ValidationError):
        return False


def verify_recertification():
    count = 0
    for item in SchedulePublication.unscoped.select_related("audit", "schedule").iterator():
        if not verify_publication(item):
            raise RuntimeError("Invalid restored recertification publication")
        count += 1
    for run in CampaignRun.unscoped.select_related(
        "audit", "campaign", "publication__audit", "publication__schedule"
    ).iterator():
        if not verify_manifest(run):
            raise RuntimeError("Invalid restored recertification manifest")
        count += run.review_count + 1
    for item in ReviewDecision.unscoped.select_related("audit").iterator():
        if not verify_decision(item):
            raise RuntimeError("Invalid restored recertification decision")
        count += 1
    return count
