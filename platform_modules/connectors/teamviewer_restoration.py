"""Offline recovery verification, including inactive collectors and old evidence."""

from django.utils.crypto import constant_time_compare

from .teamviewer_collection import scan_proof, verify_activation, verify_configuration
from .teamviewer_ingestion import verify_report, verify_run
from .teamviewer_models import TeamViewerCollector, TeamViewerReport, TeamViewerRun


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
    return encrypted, signed
