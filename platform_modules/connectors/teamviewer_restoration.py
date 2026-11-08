"""Offline recovery verification, including inactive collectors and old evidence."""

from django.utils.crypto import constant_time_compare

from .teamviewer_access import verify_observation
from .teamviewer_access_models import TeamViewerAccessObservation
from .teamviewer_collection import scan_proof, verify_activation, verify_configuration
from .teamviewer_ingestion import verify_report, verify_run
from .teamviewer_mapping import verify_mapping
from .teamviewer_mapping_models import TeamViewerMapping, TeamViewerSighting
from .teamviewer_models import TeamViewerCollector, TeamViewerReport, TeamViewerRun
from .teamviewer_session_models import TeamViewerSession, TeamViewerSessionEvidence
from .teamviewer_sessions import _verify_evidence_link, verify_session
from .teamviewer_sightings import _verify_sighting_link


def verify_evidence():
    encrypted, signed = 0, 0
    for collector in TeamViewerCollector.unscoped.iterator(chunk_size=100):
        if not verify_configuration(collector) or not verify_activation(collector):
            raise RuntimeError("Restored TeamViewer configuration proof is invalid.")
        encrypted += 1
        signed += 1 + bool(collector.activation_proof)
        if collector.scan_proof:
            if not constant_time_compare(collector.scan_proof, scan_proof(collector)):
                raise RuntimeError("Restored TeamViewer scan proof is invalid.")
            signed += 1
        elif collector.enabled:
            raise RuntimeError("Restored TeamViewer scan proof is missing.")
    for report in TeamViewerReport.unscoped.iterator(chunk_size=100):
        if not verify_report(report):
            raise RuntimeError("Restored TeamViewer report proof is invalid.")
        encrypted += report.notes_included
        signed += 1
    for run in TeamViewerRun.unscoped.select_related("audit").iterator(chunk_size=100):
        if not verify_run(run):
            raise RuntimeError("Restored TeamViewer collection run proof is invalid.")
        signed += 1
        for sighting in (
            TeamViewerSighting.unscoped.filter(run=run, organization_id=run.organization_id)
            .select_related("report")
            .iterator(chunk_size=100)
        ):
            sighting.run = run
            if not _verify_sighting_link(sighting):
                raise RuntimeError("Restored TeamViewer sighting proof is invalid.")
            signed += 1
    for mapping in TeamViewerMapping.unscoped.select_related("audit", "collector").iterator(
        chunk_size=100
    ):
        if not verify_mapping(mapping, check_target=False):
            raise RuntimeError("Restored TeamViewer mapping proof is invalid.")
        signed += 1
    for session in TeamViewerSession.unscoped.select_related(
        "audit", "origin__run__audit", "origin__report"
    ).iterator(chunk_size=100):
        if not verify_session(session):
            raise RuntimeError("Restored TeamViewer physical session proof is invalid.")
        if not TeamViewerSessionEvidence.unscoped.filter(
            session_id=session.pk,
            sighting_id=session.origin_id,
            organization_id=session.organization_id,
        ).exists():
            raise RuntimeError("Restored TeamViewer session origin link is missing.")
        signed += 1
    for evidence in TeamViewerSessionEvidence.unscoped.select_related(
        "audit", "session", "sighting__run__audit", "sighting__report"
    ).iterator(chunk_size=100):
        # All sessions/runs were checked above; still inspect every link, including
        # malformed tenant relations instead of filtering them out of verification.
        if not _verify_evidence_link(evidence):
            raise RuntimeError("Restored TeamViewer session observation proof is invalid.")
        signed += 1
    for link in TeamViewerAccessObservation.unscoped.select_related(
        "audit", "event", "session__audit", "session__origin__run__audit", "session__origin__report"
    ).iterator(chunk_size=100):
        if not verify_observation(link):
            raise RuntimeError("Restored TeamViewer normalized source link is invalid.")
        signed += 1
    return encrypted, signed
