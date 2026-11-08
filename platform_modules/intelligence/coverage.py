"""Bounded interval reasoning. Absence is scoped to the reporting sources, never universal."""

from datetime import timedelta

from django.db.models import Q

from platform_core.tenancy import current_organization
from platform_modules.access.temporal import overlapping_events

from .models import DOMAINS, CollectionReport, CollectionScope


def _segments(reports, start, end):
    boundaries = {start, end}
    for report in reports:
        boundaries.update((max(start, report.covered_from), min(end, report.covered_until)))
    ordered = sorted(value for value in boundaries if start <= value <= end)
    output = []
    for left, right in zip(ordered, ordered[1:]):
        candidates = [r for r in reports if r.covered_from <= left and r.covered_until >= right]
        winner = max(candidates, key=lambda r: r.sequence) if candidates else None
        output.append(
            {
                "start": left.isoformat(),
                "end": right.isoformat(),
                "state": winner.state if winner else "unknown",
                "report": str(winner.pk) if winner else None,
            }
        )
    return output


def collection_coverage(start, end, *, resource=None):
    from .services import validate_window

    validate_window(start, end)
    scopes = (
        CollectionScope.objects.filter(effective_at__lt=end)
        .filter(Q(retired_at__isnull=True) | Q(retired_at__gt=start))
        .select_related("source", "resource")
    )
    scopes = (
        scopes.filter(Q(resource__isnull=True) | Q(resource=resource))
        if resource
        else scopes.filter(resource__isnull=True)
    )
    by_domain = {
        key: {"domain": key, "label": label, "sources": [], "state": "unknown"}
        for key, label in DOMAINS
    }
    selected_scopes = list(scopes[:101])
    scope_limit = len(selected_scopes) > 100
    for scope in selected_scopes[:100]:
        reports = list(
            CollectionReport.objects.filter(
                scope=scope, covered_from__lt=end, covered_until__gt=start
            ).order_by("-sequence")[:501]
        )
        truncated = len(reports) > 500
        segments = _segments(reports[:500], start, end)
        # Responsibility must span the entire query window for a complete result.
        complete = (
            not truncated
            and scope.effective_at <= start
            and (not scope.retired_at or scope.retired_at >= end)
            and all(segment["state"] == "complete" for segment in segments)
        )
        by_domain[scope.domain]["sources"].append(
            {
                "source": scope.source.name,
                "source_id": str(scope.source_id),
                "scope": str(scope.pk),
                "state": "complete" if complete else "partial" if reports else "unknown",
                "segments": segments,
                "truncated": truncated,
                "currently_enabled": scope.source.active,
            }
        )
    for item in by_domain.values():
        sources = item["sources"]
        if sources:
            item["state"] = (
                "complete" if all(s["state"] == "complete" for s in sources) else "partial"
            )
        if scope_limit:
            item["state"] = "unknown"
            item["scope_limit"] = True
        item["explanation"] = (
            "Couverture déclarée complète sur ces sources uniquement. "
            "L’absence d’événement n’est pas une preuve universelle d’absence d’accès."
            if item["state"] == "complete"
            else "Collecte incomplète ou non configurée : aucune conclusion d’absence d’activité."
        )
    return list(by_domain.values())


def event_clock(event):
    if not event.domain:
        return None, None
    reports = (
        CollectionReport.objects.filter(
            scope__source_id=event.source,
            scope__domain=event.domain,
            covered_from__lte=event.occurred_at,
            covered_until__gt=event.occurred_at,
        )
        .filter(Q(scope__resource__isnull=True) | Q(scope__resource_id=event.resource_id))
        .order_by("scope_id", "-sequence")[:500]
        if _uuid(event.source)
        else []
    )
    latest = {}
    for report in reports:
        latest.setdefault(report.scope_id, report)
    if not latest or any(r.clock_uncertainty_seconds is None for r in latest.values()):
        return None, None
    report = max(latest.values(), key=lambda r: r.clock_uncertainty_seconds)
    return report.clock_uncertainty_seconds, str(report.pk)


def _uuid(value):
    import uuid

    try:
        uuid.UUID(value)
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def event_timeline(queryset, start, end):
    from .services import validate_window

    validate_window(start, end)
    events = list(
        overlapping_events(queryset.filter(organization=current_organization()), start, end)
        .select_related("identity", "account", "resource", "credential")
        .prefetch_related("evaluations__intent")
        .order_by("occurred_at", "pk")[:501]
    )
    rows, previous = [], None
    for event in events[:500]:
        uncertainty, report_id = event_clock(event)
        evaluations = list(event.evaluations.all())
        evaluation = max(evaluations, key=lambda value: value.evaluated_at) if evaluations else None
        overlap = previous is not None and (
            uncertainty is None
            or previous[1] is None
            or event.occurred_at - timedelta(seconds=uncertainty)
            <= previous[0] + timedelta(seconds=previous[1])
        )
        whys = [item for item in evaluation.findings if item["code"] == "why"] if evaluation else []
        references = list(
            dict.fromkeys(
                item.get("business_reference") for item in whys if item.get("business_reference")
            )
        )
        segment_count = (
            sum(item["code"] == "observed_interval" for item in evaluation.findings) or 1
            if evaluation
            else 1
        )
        reference_complete = (
            bool(whys)
            and len(whys) == segment_count
            and all(
                item["state"] == "confirmed" and item.get("business_reference") for item in whys
            )
        )
        reference = " · ".join(references)
        if evaluation and evaluation.rule_version != "access-context/6":
            reference = evaluation.intent.reference if evaluation.intent_id else ""
            reference_complete = bool(reference)
        completed_at = event.ended_at or event.occurred_at
        rows.append(
            {
                "event": event,
                "evaluation": evaluation,
                "reference": reference,
                "reference_complete": reference_complete,
                "clock_uncertainty": uncertainty,
                "clock_report": report_id,
                "order_uncertain": overlap,
                "arrived_late": event.received_at - completed_at > timedelta(minutes=5),
                "delay_seconds": round((event.received_at - completed_at).total_seconds(), 1),
            }
        )
        previous = completed_at, uncertainty
    return rows, len(events) > 500
