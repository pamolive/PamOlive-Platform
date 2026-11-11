"""Read-only, exact mobility provenance for a signed access interpretation."""

from uuid import UUID

from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from platform_modules.identity import business_port
from platform_modules.identity.mobility_contract import (
    MAX_ORIGINS,
    MobilityOriginKey,
    discover_origins,
    read_origins,
)


def candidates(event, evaluation, organization):
    """Caller verifies the evaluation and its interpretation under the organization lock."""
    if evaluation is None or not business_port.available(organization):
        return [], False

    matches = {}
    for finding in evaluation.findings:
        if not isinstance(finding, dict) or finding.get("state") != "confirmed":
            continue
        kind = finding.get("code")
        if kind not in ("intent", "grant"):
            continue
        try:
            target = UUID(str(finding["evidence"]))
            if event.ended_at is not None and event.ended_at != event.occurred_at:
                start = parse_datetime(finding["interval_start"])
                end = parse_datetime(finding["interval_end"])
                if not event.occurred_at <= start < end <= event.ended_at:
                    continue
            elif "interval_start" not in finding and "interval_end" not in finding:
                start, end = event.occurred_at, None
            else:
                continue
        except (ValueError, TypeError, KeyError):
            continue
        periods = matches.setdefault(MobilityOriginKey(kind, target), [])
        if (start, end) not in periods:
            periods.append((start, end))
    # The evaluator itself bounds a session to 32 segments. Do not return
    # partial evidence as complete if a future rule exceeds this bound.
    if sum(map(len, matches.values())) > MAX_ORIGINS:
        return [], True
    if not matches:
        return [], False
    existing = discover_origins(matches, organization=organization)
    return [(key, periods) for key, periods in matches.items() if key in existing], False


def _known_at(receipt, at):
    return all(
        parse_datetime(value) <= at
        for value in (
            receipt["received_at"],
            receipt["payload"]["observed_at"],
            receipt["payload"]["source_updated_at"],
        )
    )


def project(matches, *, organization, limited=False):
    """Caller must require fresh personal MFA before materializing any rows."""
    result = dict(
        schema="pamolive.event-mobility-context/1",
        as_of=timezone.now().isoformat(),
        rows=[],
        limited=limited,
        included_in_historical_evaluation=False,
        local_authorizations_modified=False,
        authority="business_provenance_not_access_approval",
    )
    if not matches:
        return result
    provider = business_port.active_provider(organization)
    origins = read_origins((key for key, _ in matches), organization=organization)
    contexts = {}
    for key, periods in matches:
        row = dict(basis=key.kind, matched_id=str(key.object_id), state="invalid_origin")
        result["rows"].append(row)
        origin = origins.get(key)
        if origin is None:
            continue
        try:
            if origin.decision_id not in contexts:
                contexts[origin.decision_id] = provider.reference_context(
                    origin.submitted_references,
                    origin.reviewed_references,
                    organization=organization,
                    tolerate_invalid_latest=True,
                )["references"]
            references = contexts[origin.decision_id]
            row.update(
                state="verified_origin",
                intent_id=str(origin.intent_id),
                proposal_id=str(origin.proposal_id),
                role=dict(
                    key=origin.role_key, revision=origin.role_revision, name=origin.role_name
                ),
                decided_at=origin.decided_at.isoformat(),
                proposal=origin.proposal_proof,
                decision=origin.decision_proof,
                role_proof=origin.role_proof,
                origin=origin.intent_proof,
                grant_origin=origin.grant_proof,
                references=references,
                matches=[
                    dict(
                        start=start.isoformat(),
                        end=end.isoformat() if end else None,
                        reviewed_provenance_known_at_start=origin.last_proof_at <= start
                        and all(_known_at(ref["reviewed"], start) for ref in references),
                    )
                    for start, end in periods
                ],
            )
        except (ValidationError, ValueError, TypeError, KeyError):
            # Do not export any unverified source contents or signed claim.
            continue
    return result
