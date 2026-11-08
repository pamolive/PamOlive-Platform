"""Immutable links to the exact collection revision that observed a report version."""

import logging

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils.crypto import constant_time_compare

from platform_core.models import Organization
from platform_core.services import require_module
from platform_core.tenancy import organization_context

from .teamviewer_collection import tag
from .teamviewer_mapping_models import TeamViewerSighting
from .teamviewer_models import TeamViewerRun


def sighting_signature(sighting):
    return tag(
        dict(
            id=str(sighting.pk),
            organization=str(sighting.organization_id),
            collector=str(sighting.collector_id),
            run=str(sighting.run_id),
            run_signature=sighting.run.signature,
            report=str(sighting.report_id),
            report_signature=sighting.report.signature,
            indexed_at=sighting.indexed_at.isoformat(),
        ),
        "sighting",
    )


def _verify_sighting_link(sighting):
    try:
        return bool(
            sighting.organization_id
            == sighting.run.organization_id
            == sighting.report.organization_id
            and sighting.collector_id == sighting.run.collector_id == sighting.report.collector_id
            and sighting.run.status in {"page", "complete"}
            and any(
                item == dict(id=str(sighting.report_id), signature=sighting.report.signature)
                for item in sighting.run.report_manifest
            )
            and constant_time_compare(sighting.signature, sighting_signature(sighting))
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False


def verify_sighting(sighting):
    from .teamviewer_ingestion import verify_run

    return _verify_sighting_link(sighting) and verify_run(sighting.run)


def _retain_sightings(run, reports):
    """Private ingestion helper, in the same locked transaction as the signed run."""
    if not reports:
        return []
    if run.status not in {"page", "complete"} or len({report.pk for report in reports}) != len(
        reports
    ):
        raise ValidationError("Manifest d’observation TeamViewer incohérent.")
    if run.report_manifest != [
        dict(id=str(report.pk), signature=report.signature) for report in reports
    ]:
        raise ValidationError("Manifest d’observation TeamViewer incohérent.")
    output = []
    for report in reports:
        if report.organization_id != run.organization_id or report.collector_id != run.collector_id:
            raise ValidationError("Observation d’un autre périmètre.")
        item = TeamViewerSighting(
            organization=run.organization, collector=run.collector, run=run, report=report
        )
        item.signature = sighting_signature(item)
        output.append(item)
    TeamViewerSighting.objects.bulk_create(output)
    return output


@transaction.atomic
def backfill_sightings(organization, *, limit=1):
    """Index accepted historical run manifests without changing their timestamps/data."""
    from .teamviewer_ingestion import verify_run
    from .teamviewer_models import TeamViewerReport

    if type(limit) is not int or not 1 <= limit <= 10:
        raise ValueError("Invalid sighting index limit")
    organization = Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    with organization_context(organization):
        require_module(organization, "connectors")
        runs = list(
            TeamViewerRun.objects.filter(status__in=["page", "complete"], sightings__isnull=True)
            .exclude(report_manifest=[])
            .select_related("audit", "collector")
            .order_by("audit__sequence")[:limit]
        )
        for run in runs:
            if not verify_run(run):
                raise ValidationError("Preuve de collecte historique invalide.")
            reports = {
                str(item.pk): item
                for item in TeamViewerReport.objects.filter(
                    pk__in=[entry["id"] for entry in run.report_manifest]
                )
            }
            _retain_sightings(run, [reports[entry["id"]] for entry in run.report_manifest])
        return len(runs)


def process_sightings(organization):
    try:
        return backfill_sightings(organization)
    except (PermissionDenied, Organization.DoesNotExist):
        return 0
    except ValidationError:
        logging.getLogger(__name__).warning("TeamViewer historical index refused invalid evidence")
        return 0
