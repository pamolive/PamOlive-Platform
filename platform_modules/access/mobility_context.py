"""Read-only, exact mobility provenance for a signed access interpretation."""

from uuid import UUID

from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from platform_core.models import ModuleActivation
from platform_modules.connectors.business_references import reference_context
from platform_modules.identity.mover import observed_business_origin, proof_anchor
from platform_modules.identity.mover_models import MoveAccess, MoveGrant


def candidates(event, evaluation, organization):
    """Caller verifies the evaluation and its interpretation under the organization lock."""
    if evaluation is None or not {"identity", "connectors"}.issubset(
        ModuleActivation.objects.filter(
            organization=organization, enabled=True, module_key__in=("identity", "connectors")
        ).values_list("module_key", flat=True)
    ):
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
        periods = matches.setdefault((kind, target), [])
        if (start, end) not in periods:
            periods.append((start, end))
    # The evaluator itself bounds a session to 32 segments. Do not return
    # partial evidence as complete if a future rule exceeds this bound.
    if sum(map(len, matches.values())) > 32:
        return [], True
    links = {
        link.intent_id: link
        for link in MoveAccess.objects.filter(
            intent_id__in=[pk for kind, pk in matches if kind == "intent"],
            decision__proposal__body__has_key="business",
        ).select_related(
            "intent", "audit", "role__audit", "decision__audit", "decision__proposal__audit"
        )
    }
    grants = {
        proof.grant_id: proof
        for proof in MoveGrant.objects.filter(
            grant_id__in=[pk for kind, pk in matches if kind == "grant"],
            access__decision__proposal__body__has_key="business",
        ).select_related(
            "audit",
            "grant__identity",
            "grant__account",
            "grant__resource",
            "access__intent",
            "access__audit",
            "access__role__audit",
            "access__decision__audit",
            "access__decision__proposal__audit",
        )
    }
    result = []
    for (kind, pk), periods in matches.items():
        proof = grants.get(pk) if kind == "grant" else None
        link = proof.access if proof else links.get(pk) if kind == "intent" else None
        if link is not None:
            result.append((kind, pk, periods, link, proof))
    return result, False


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
    contexts = {}
    for kind, pk, periods, link, grant in matches:
        row = dict(basis=kind, matched_id=str(pk), state="invalid_origin")
        result["rows"].append(row)
        try:
            proposal, decision = observed_business_origin(link, grant)
            if decision.pk not in contexts:
                contexts[decision.pk] = reference_context(
                    proposal.body["business"],
                    decision.body["business_checked"],
                    organization=organization,
                    tolerate_invalid_latest=True,
                )["references"]
            references = contexts[decision.pk]
            chronology = [
                parse_datetime(obj.body["at"])
                for obj in (proposal, decision, link, *((grant,) if grant else ()))
            ]
            if chronology != sorted(chronology):
                continue
            row.update(
                state="verified_origin",
                intent_id=str(link.intent_id),
                proposal_id=str(proposal.pk),
                role=dict(
                    key=link.role.key, revision=link.role.revision, name=link.role.body["name"]
                ),
                decided_at=chronology[1].isoformat(),
                proposal=proof_anchor(proposal),
                decision=proof_anchor(decision),
                role_proof=proof_anchor(link.role),
                origin=proof_anchor(link),
                grant_origin=proof_anchor(grant) if grant else None,
                references=references,
                matches=[
                    dict(
                        start=start.isoformat(),
                        end=end.isoformat() if end else None,
                        reviewed_provenance_known_at_start=chronology[-1] <= start
                        and all(_known_at(ref["reviewed"], start) for ref in references),
                    )
                    for start, end in periods
                ],
            )
        except (ValidationError, ValueError, TypeError, KeyError):
            # Do not export any unverified source contents or signed claim.
            continue
    return result
