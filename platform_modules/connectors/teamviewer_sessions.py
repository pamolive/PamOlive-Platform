"""Deduplicate source observations, never merge facts by account ownership."""

import logging
from dataclasses import dataclass

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import F, Window
from django.db.models.functions import RowNumber
from django.utils.crypto import constant_time_compare

from platform_core.audit import digest, record
from platform_core.models import Organization
from platform_core.services import require_module
from platform_core.tenancy import current_organization, organization_context

from .teamviewer_collection import tag
from .teamviewer_ingestion import verify_run
from .teamviewer_mapping import KINDS, MappingResolution, _resolve
from .teamviewer_mapping_models import TeamViewerSighting
from .teamviewer_models import TeamViewerReport, TeamViewerRun
from .teamviewer_session_models import TeamViewerSession, TeamViewerSessionEvidence
from .teamviewer_sightings import _verify_sighting_link, verify_sighting

MAX_VARIANTS = 64


def session_body(session):
    return dict(
        id=str(session.pk),
        organization=str(session.organization_id),
        remote_id=str(session.remote_id),
        origin=str(session.origin_id),
        origin_signature=session.origin.signature,
        registered_at=session.registered_at.isoformat(),
    )


def evidence_body(evidence):
    return dict(
        id=str(evidence.pk),
        organization=str(evidence.organization_id),
        session=str(evidence.session_id),
        session_signature=evidence.session.signature,
        sighting=str(evidence.sighting_id),
        sighting_signature=evidence.sighting.signature,
        registered_at=evidence.registered_at.isoformat(),
    )


def _proof(item, body, domain):
    return tag(dict(body=body, audit_id=item.audit_id, audit_hash=item.audit.event_hash), domain)


def _anchored(item, body, domain, action):
    return bool(
        item.audit.organization_id == item.organization_id
        and item.audit.actor_id is None
        and item.audit.action == action
        and item.audit.object_type == item._meta.label_lower
        and item.audit.object_id == str(item.pk)
        and item.audit.event_hash == digest(item.audit)
        and item.audit.metadata.get("body_hash") == tag(body, domain + "-body")
        and constant_time_compare(item.signature, _proof(item, body, domain))
    )


def verify_session(session):
    try:
        return bool(
            session.organization_id == session.origin.organization_id
            and session.remote_id == session.origin.report.remote_id
            and _anchored(
                session,
                session_body(session),
                "session",
                "connectors.teamviewer.session.registered.v1",
            )
            and verify_sighting(session.origin)
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False


def _verify_evidence_link(evidence):
    try:
        return bool(
            evidence.organization_id
            == evidence.session.organization_id
            == evidence.sighting.organization_id
            and evidence.session.remote_id == evidence.sighting.report.remote_id
            and _anchored(
                evidence,
                evidence_body(evidence),
                "session-evidence",
                "connectors.teamviewer.session.observed.v1",
            )
            and _verify_sighting_link(evidence.sighting)
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False


def verify_session_evidence(evidence):
    return bool(
        _verify_evidence_link(evidence)
        and verify_session(evidence.session)
        and verify_run(evidence.sighting.run)
    )


def _seal(item, body, domain, action, summary):
    item.audit = record(
        organization=item.organization,
        target=item,
        action=action,
        summary=summary,
        metadata=dict(body_hash=tag(body, domain + "-body")),
    )
    item.signature = _proof(item, body, domain)
    item.full_clean()
    item.save()


@transaction.atomic
def index_sessions(organization, *, limit=10):
    """Bounded existing worker job; source reads are never edited or dropped."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Invalid session index limit")
    organization = Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    with organization_context(organization):
        require_module(organization, "connectors")
        sightings = list(
            TeamViewerSighting.objects.filter(session_evidence__isnull=True)
            .select_related("run__audit", "report")
            .order_by("run__audit__sequence", "pk")[:limit]
        )
        verified_runs = set()
        for sighting in sightings:
            if not _verify_sighting_link(sighting) or (
                sighting.run_id not in verified_runs and not verify_run(sighting.run)
            ):
                raise ValidationError("Preuve source invalide : indexation de session refusée.")
            verified_runs.add(sighting.run_id)
            session = (
                TeamViewerSession.objects.filter(remote_id=sighting.report.remote_id)
                .select_related("audit", "origin__run__audit", "origin__report")
                .first()
            )
            if session is None:
                session = TeamViewerSession(
                    organization=organization, remote_id=sighting.report.remote_id, origin=sighting
                )
                _seal(
                    session,
                    session_body(session),
                    "session",
                    "connectors.teamviewer.session.registered.v1",
                    "Session TeamViewer identifiée dans les preuves collectées",
                )
            elif not verify_session(session):
                raise ValidationError("Preuve de session invalide : aucune association ajoutée.")
            evidence = TeamViewerSessionEvidence(
                organization=organization, session=session, sighting=sighting
            )
            _seal(
                evidence,
                evidence_body(evidence),
                "session-evidence",
                "connectors.teamviewer.session.observed.v1",
                "Observation source rattachée à la session TeamViewer",
            )
        return len(sightings)


def process_sessions(organization):
    try:
        return index_sessions(organization)
    except (PermissionDenied, Organization.DoesNotExist):
        return 0
    except ValidationError:
        logging.getLogger(__name__).warning("TeamViewer session index refused invalid evidence")
        return 0


def _variants(session):
    # Identical re-reads do not consume the semantic variant limit. Every reading
    # stays retained; offline restoration verifies all links, not only these.
    return list(
        TeamViewerSessionEvidence.objects.filter(session=session)
        .annotate(
            variant_rank=Window(
                expression=RowNumber(),
                partition_by=[
                    F("sighting__report_id"),
                    F("sighting__run__revision"),
                    F("sighting__run__config_hash"),
                ],
                order_by=F("audit__sequence").desc(),
            )
        )
        .filter(variant_rank=1)
        .select_related("audit", "sighting__run__audit", "sighting__report")
        .order_by("-audit__sequence")[: MAX_VARIANTS + 1]
    )


def _merge(results):
    states = {result.state for result in results}
    targets = {result.target.pk for result in results if result.target is not None}
    state = (
        "invalid"
        if "invalid" in states
        else "limit"
        if "limit" in states
        else "ambiguous"
        if "ambiguous" in states or len(targets) > 1 or targets and "withdrawn" in states
        else "mapped"
        if states == {"mapped"} and len(targets) == 1
        else "withdrawn"
        if states == {"withdrawn"}
        else "partial"
        if targets or "partial" in states or len(states) > 1
        else "unmapped"
    )
    return MappingResolution(
        state=state,
        target=results[0].target if state == "mapped" else None,
        statements=tuple(dict.fromkeys(key for result in results for key in result.statements)),
        segments=tuple(segment for result in results for segment in result.segments),
    )


@dataclass(frozen=True)
class SessionResolution:
    state: str
    facts: dict | None
    dimensions: dict
    variants: tuple
    observations: int
    detail: str


@transaction.atomic
def resolve_session(session, *, organization):
    if current_organization().pk != organization.pk or session.organization_id != organization.pk:
        raise PermissionDenied
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    require_module(organization, "connectors")
    empty = {kind: MappingResolution("unmapped", None, (), ()) for kind in KINDS}
    count = TeamViewerSessionEvidence.objects.filter(session=session).count()

    def refused(state, detail, variants=()):
        return SessionResolution(state, None, empty, tuple(variants), count, detail)

    if not verify_session(session):
        return refused("invalid", "La preuve de session ne peut pas être vérifiée.")
    if (
        TeamViewerSighting.objects.filter(
            report__remote_id=session.remote_id, session_evidence__isnull=True
        ).exists()
        or TeamViewerReport.objects.filter(
            remote_id=session.remote_id, sightings__isnull=True
        ).exists()
        or TeamViewerRun.objects.filter(status__in=["page", "complete"], sightings__isnull=True)
        .exclude(report_manifest=[])
        .exists()
    ):
        return refused(
            "pending",
            "Des observations collectées attendent encore leur indexation. "
            "La concordance de toutes les preuves connues n’est pas encore établie.",
        )
    variants = _variants(session)
    if not variants:
        return refused("invalid", "Aucune observation vérifiable n’est rattachée à la session.")
    if len(variants) > MAX_VARIANTS:
        return refused("limit", "Plus de 64 variantes de rapport ou de périmètre source.")
    verified_runs, structures, scopes, proofs = set(), set(), {}, []
    for evidence in variants:
        evidence.session = session
        sighting = evidence.sighting
        if not _verify_evidence_link(evidence) or (
            sighting.run_id not in verified_runs and not verify_run(sighting.run)
        ):
            return refused("invalid", "Une observation de cette session n’est pas vérifiable.")
        verified_runs.add(sighting.run_id)
        report = sighting.report
        structures.add((report.account_ref, report.device_ref, report.started_at, report.ended_at))
        scope = (sighting.collector_id, sighting.run.revision, sighting.run.config_hash)
        scopes.setdefault(scope, sighting)
        proofs.append(
            dict(
                evidence=str(evidence.pk),
                evidence_signature=evidence.signature,
                sighting=str(sighting.pk),
                report=str(report.pk),
                collector=str(sighting.collector_id),
                revision=sighting.run.revision,
                config_hash=sighting.run.config_hash,
            )
        )
    accounts = {item[0] for item in structures if item[0]}
    devices = {item[1] for item in structures if item[1]}
    periods = {(item[2], item[3]) for item in structures}
    if len(accounts) > 1 or len(devices) > 1 or len(periods) != 1:
        return refused(
            "conflict",
            "Les sources ou versions divergent sur le compte, la machine ou les horaires. "
            "Aucune version n’est choisie arbitrairement.",
            proofs,
        )
    dimensions = {}
    for kind in KINDS:
        results = []
        for sighting in scopes.values():
            ref = sighting.report.device_ref if kind == "device" else sighting.report.account_ref
            result = _resolve(sighting, kind, ref)
            results.append(
                MappingResolution(
                    state=result.state,
                    target=result.target,
                    statements=result.statements,
                    segments=tuple(
                        dict(segment, sighting=str(sighting.pk)) for segment in result.segments
                    ),
                )
            )
        dimensions[kind] = _merge(results)
    account = next(iter(accounts), "")
    device = next(iter(devices), "")
    start, end = next(iter(periods))
    return SessionResolution(
        state="resolved"
        if all(value.state == "mapped" for value in dimensions.values())
        else "unresolved",
        facts=dict(
            remote_id=str(session.remote_id),
            account_ref=account,
            device_ref=device,
            started_at=start.isoformat(),
            ended_at=end.isoformat(),
            method="TeamViewer",
            remote_os_privilege=None,
            observed_location=None,
        ),
        dimensions=dimensions,
        variants=tuple(proofs),
        observations=count,
        detail="Correspondances administratives datées, pas une preuve indépendante "
        "d’authentification. Aucune attribution par propriété ni aucun droit accordé.",
    )
