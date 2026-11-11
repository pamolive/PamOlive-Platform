"""Read an observation without inventing a request-to-event causal link."""

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.dateparse import parse_datetime

from platform_core.access_contract import READ_ROLES, build_access_contract
from platform_core.services import lock_authorized_actor, module_available, require_module
from platform_core.tenancy import organization_context

from .evidence import verify_evaluation
from .models import AccessEvaluation, AccessEvent, AccessIntent
from .provenance_status import verified_origin_status

SCHEMA = "pamolive.observation-story/1"
VERDICTS = {"expected": "Conforme", "deviation": "Non conforme", "unknown": "Indéterminé"}


def _dimensions(event, intent):
    """A comparison is explanatory only; the signed evaluator decides compliance."""
    fields = ("identity_id", "account_id", "resource_id", "method", "privilege")
    rows = []
    for key in fields:
        expected, actual = getattr(intent, key), getattr(event, key)
        if expected in (None, "") or actual in (None, ""):
            state = "unknown"
        else:
            matches = (
                actual.casefold() == expected.casefold() if key == "method" else actual == expected
            )
            state = "match" if matches else "mismatch"
        rows.append({"dimension": key, "state": state})
    rows.append({"dimension": "window", "state": "match" if (
        intent.starts_at <= event.occurred_at < intent.ends_at
        and (event.ended_at is None or event.ended_at <= intent.ends_at)
    ) else "mismatch"})
    return rows


@transaction.atomic
def observation_story(event_id, *, actor, organization, comparison_intent_id=None, limit=25):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValidationError("La limite doit être comprise entre 1 et 100.")
    actor, organization = lock_authorized_actor(actor, organization, roles=READ_ROLES)
    for key in ("identity", "access", "intelligence"):
        require_module(organization, key)
    with organization_context(organization):
        event = AccessEvent.objects.select_related(
            "identity", "account", "resource", "provenance_receipt__audit"
        ).get(pk=event_id)
        if event.provenance_channel in ("collector", "internal"):
            require_module(organization, "connectors")
        origin = verified_origin_status(event)
        receipt = getattr(event, "provenance_receipt", None)
        evaluations = list(AccessEvaluation.objects.filter(event=event).select_related(
            "audit", "intent", "event"
        ).order_by("-evaluated_at", "-pk")[:limit + 1])
        latest = evaluations[0] if evaluations else None
        valid = bool(latest and verify_evaluation(latest))
        verdict = latest.verdict if valid and origin != "invalid_provenance" else "unknown"
        result = {
            "schema": SCHEMA, "organization_id": str(organization.pk), "read_only": True,
            "observation": {
                "id": str(event.pk), "external_id": event.external_id,
                "identity": event.identity.name if event.identity else None,
                "account": event.account.username if event.account else None,
                "resource": event.resource.name if event.resource else None,
                "method": event.method, "privilege": event.privilege, "result": event.result,
                "occurred_at": event.occurred_at.isoformat(),
                "ended_at": event.ended_at.isoformat() if event.ended_at else None,
            },
            "verdict": {"code": verdict, "label": VERDICTS.get(verdict, "Indéterminé"),
                        "scope": "recorded_evaluation_not_global_remote_truth"},
            "provenance": {
                "status": origin, "receipt_id": str(receipt.pk) if receipt else None,
                "principal_id": receipt.principal_id
                if receipt and origin in ("manual", "collector", "internal") else None,
                "verified": origin in ("manual", "collector", "internal"),
                "claim": "PamOlive acceptance, not independent truth of collector data",
            },
            "evaluation": {
                "id": str(latest.pk) if latest else None,
                "rule_version": latest.rule_version if latest else None,
                "verified": valid,
                "evaluated_at": latest.evaluated_at.isoformat() if latest else None,
                "findings": [{key: item.get(key, "") for key in (
                    "code", "state", "detail", "evidence")}
                             for item in latest.findings] if valid else [],
            },
            "evaluation_history": {
                "items": [{"id": str(row.pk), "verdict": row.verdict,
                           "verified": verify_evaluation(row),
                           "evaluated_at": row.evaluated_at.isoformat()}
                          for row in evaluations[:limit]],
                "truncated": len(evaluations) > limit,
            },
            "access_contract": None, "comparison": None,
            "timeline": [],
            "limitations": [
                "A matching scope does not prove that a request caused this activity.",
                "An out-of-scope comparison does not rule out another valid authorization.",
                "The verdict describes the saved evaluation, not a new policy assessment.",
                "Missing or invalid evidence is never promoted to compliance.",
            ],
        }
        if valid and origin != "invalid_provenance" and latest.intent_id:
            result["access_contract"] = build_access_contract(
                latest.intent_id, actor=actor, organization=organization, limit=limit
            )
        if comparison_intent_id:
            comparison = AccessIntent.objects.get(pk=comparison_intent_id)
            result["comparison"] = {
                "intent_id": str(comparison.pk), "reference": comparison.reference,
                "association": "explicit_comparison_not_causality_or_authorization",
                "dimensions": _dimensions(event, comparison),
            }
        timeline = [{"kind": "observation", "at": event.occurred_at.isoformat(),
                     "id": str(event.pk), "state": event.result}]
        if valid:
            timeline.append({"kind": "evaluation", "at": latest.evaluated_at.isoformat(),
                             "id": str(latest.pk), "state": verdict})
        contract = result["access_contract"]
        if contract:
            intent = contract["intention"]
            timeline.append({"kind": "intention", "at": intent["created_at"],
                             "id": intent["id"], "state": intent["status"]})
            for decision in contract["approval_decisions"]["items"]:
                timeline.append({"kind": "approval", "at": decision["decided_at"],
                                 "id": decision["id"], "state": str(decision["approved"])})
            for change in contract["execution_attempts"]["items"]:
                timeline.append({"kind": "provisioning", "at": change["created_at"],
                                 "id": change["id"], "state": change["status"]})
            for proof in contract["confirmed_executions"]["items"]:
                timeline.append({"kind": "execution", "at": proof["recorded_at"],
                                 "id": proof["id"], "state": proof["kind"]})
        result["timeline"] = sorted(
            timeline, key=lambda row: (parse_datetime(row["at"]), row["kind"], row["id"]))
        return result


@transaction.atomic
def observation_index(*, actor, organization, limit=100, verdict=None):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValidationError("La limite doit être comprise entre 1 et 100.")
    if verdict not in (None, "", *VERDICTS):
        raise ValidationError("Filtre de verdict inconnu.")
    actor, organization = lock_authorized_actor(actor, organization, roles=READ_ROLES)
    for key in ("identity", "access", "intelligence"):
        require_module(organization, key)
    with organization_context(organization):
        rows = AccessEvent.objects.select_related("resource").order_by("-received_at", "pk")
        if not module_available(organization, "connectors"):
            rows = rows.filter(provenance_channel__in=("manual", "legacy_unknown"))
        rows = list(rows[:limit + 1])
        items = []
        for row in rows[:limit]:
            latest = AccessEvaluation.objects.filter(event=row).select_related(
                "audit", "intent", "event"
            ).order_by("-evaluated_at", "-pk").first()
            code = latest.verdict if latest and verify_evaluation(latest) else "unknown"
            if verified_origin_status(row) == "invalid_provenance":
                code = "unknown"
            if not verdict or verdict == code:
                items.append({"id": str(row.pk),
                              "resource": str(row.resource) if row.resource else "?",
                              "occurred_at": row.occurred_at.isoformat(),
                              "verdict": code, "verdict_label": VERDICTS.get(code, "Indéterminé")})
        return {"items": items, "truncated": len(rows) > limit,
                "filter": verdict, "filter_window": "most_recent_100_or_limit"}
