"""Durable, tenant-scoped raw collection; no inferred identity or access entitlement.

One HTTPS page per lease. A scan freezes its upper bound and resumes from its
signed cursor after process interruption. Periodic full rescans also retain source
corrections as new evidence versions. Finishing pagination is not a coverage claim.
"""

import re
import uuid
from datetime import timedelta

from cryptography.fernet import InvalidToken
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.crypto import constant_time_compare

from platform_core.audit import digest, record
from platform_core.models import Organization
from platform_core.security import cipher
from platform_core.services import require_module
from platform_core.tenancy import organization_context

from .scim import IntegrationFailure
from .teamviewer import TeamViewerClient
from .teamviewer_collection import collector_config, enabled_ready, scan_proof, tag
from .teamviewer_models import TeamViewerCollector, TeamViewerReport, TeamViewerRun


def report_content(report, notes):
    return dict(
        remote_id=str(report.remote_id),
        account_ref=report.account_ref,
        device_ref=report.device_ref,
        started_at=report.started_at.isoformat(),
        ended_at=report.ended_at.isoformat(),
        notes_included=report.notes_included,
        notes=notes,
    )


def report_signature(report):
    return tag(
        dict(
            id=str(report.pk),
            organization=str(report.organization_id),
            collector=str(report.collector_id),
            content_hash=report.content_hash,
            observed_at=report.observed_at.isoformat(),
            encrypted_notes=report.encrypted_notes,
        ),
        "report",
    )


def verify_report(report):
    try:
        notes = (
            cipher().decrypt(report.encrypted_notes.encode()).decode()
            if report.notes_included
            else ""
        )
        return bool(
            (report.notes_included or report.encrypted_notes == "")
            and report.started_at <= report.ended_at <= report.observed_at
            and constant_time_compare(
                report.content_hash, tag(report_content(report, notes), "content")
            )
            and constant_time_compare(report.signature, report_signature(report))
        )
    except (InvalidToken, UnicodeError, ValueError, TypeError, AttributeError):
        return False


def _retain_report(collector, source):
    # Called inside the collector's locked completion transaction. Unknown IDs are
    # retained verbatim; a device owner or account owner is never made the actor.
    report = TeamViewerReport(
        organization=collector.organization,
        collector=collector,
        remote_id=uuid.UUID(source.id),
        account_ref=source.account_ref or "",
        device_ref=source.device_ref or "",
        started_at=source.started_at,
        ended_at=source.ended_at,
        notes_included=collector.collect_notes,
    )
    notes = source.notes if collector.collect_notes else ""
    report.content_hash = tag(report_content(report, notes), "content")
    existing = TeamViewerReport.objects.filter(
        collector=collector, remote_id=report.remote_id, content_hash=report.content_hash
    ).first()
    if existing:
        if not verify_report(existing):
            raise ValidationError("Preuve TeamViewer altérée ; collecte suspendue.")
        return existing
    report.encrypted_notes = (
        cipher().encrypt(notes.encode()).decode() if collector.collect_notes else ""
    )
    report.signature = report_signature(report)
    report.save()
    return report


def run_content(run):
    return dict(
        id=str(run.pk),
        organization=str(run.organization_id),
        collector=str(run.collector_id),
        revision=run.revision,
        config_hash=run.config_hash,
        activation_hash=run.activation_hash,
        started_at=run.started_at.isoformat(),
        finished_at=run.finished_at.isoformat(),
        since=run.since.isoformat(),
        until=run.until.isoformat(),
        code=run.code,
        status=run.status,
        cursor_input=str(run.cursor_input) if run.cursor_input else None,
        cursor_output=str(run.cursor_output) if run.cursor_output else None,
        manifest_hash=run.manifest_hash,
    )


def run_signature(run):
    return tag(
        dict(body=run_content(run), audit_id=run.audit_id, audit_hash=run.audit.event_hash),
        "run",
    )


def verify_run(run):
    try:
        if (
            run.audit.organization_id != run.organization_id
            or run.audit.action != "connectors.teamviewer.page.v1"
            or run.audit.object_id != str(run.pk)
            or run.audit.object_type != run._meta.label_lower
            or run.audit.event_hash != digest(run.audit)
            or run.audit.metadata.get("run_hash") != tag(run_content(run), "run-body")
            or not constant_time_compare(run.signature, run_signature(run))
            or not constant_time_compare(run.manifest_hash, tag(run.report_manifest, "manifest"))
        ):
            return False
        if not isinstance(run.report_manifest, list) or len(run.report_manifest) > 1000:
            return False
        if any(set(item) != {"id", "signature"} for item in run.report_manifest):
            return False
        entries = {item["id"]: item["signature"] for item in run.report_manifest}
        if len(entries) != len(run.report_manifest):
            return False
        reports = list(
            TeamViewerReport.unscoped.filter(
                pk__in=entries,
                organization_id=run.organization_id,
                collector_id=run.collector_id,
            )
        )
        return len(reports) == len(entries) and all(
            report.signature == entries[str(report.pk)] and verify_report(report)
            for report in reports
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False


def _retain_run(claim, *, status, code, page=None, reports=()):
    code = code if re.fullmatch(r"[a-z0-9_]{1,80}", code) else "teamviewer_collection_failed"
    run = TeamViewerRun(
        organization=claim.organization,
        collector=claim,
        revision=claim.revision,
        config_hash=claim.config_hash,
        activation_hash=claim.activation_proof,
        started_at=claim.started_at,
        since=claim.start_at,
        until=claim.scan_until,
        code=code,
        status=status,
        cursor_input=claim.next_offset,
        cursor_output=uuid.UUID(page.next_offset) if page and page.next_offset else None,
        report_manifest=[dict(id=str(item.pk), signature=item.signature) for item in reports],
    )
    run.manifest_hash = tag(run.report_manifest, "manifest")
    run.audit = record(
        organization=claim.organization,
        target=run,
        action="connectors.teamviewer.page.v1",
        summary="Collecte TeamViewer · " + status,
        metadata=dict(
            run_hash=tag(run_content(run), "run-body"),
            records=len(reports),
            status=status,
            code=code,
            pagination_finished=bool(page and page.finished and status == "complete"),
            coverage_asserted=False,
            normalized_access_events=0,
        ),
    )
    run.signature = run_signature(run)
    run.save()
    from .teamviewer_sightings import _retain_sightings

    _retain_sightings(run, reports)
    return run


def _allowed(organization):
    if not organization.active:
        return False
    try:
        require_module(organization, "connectors")
        return True
    except PermissionDenied:
        return False


@transaction.atomic
def claim_page(organization):
    organization = Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        if not _allowed(organization):
            return None
        now = timezone.now()
        collector = (
            TeamViewerCollector.objects.select_for_update()
            .filter(enabled=True, next_run_at__lte=now)
            .filter(Q(claim_until__isnull=True) | Q(claim_until__lte=now))
            .order_by("next_run_at", "pk")
            .first()
        )
        if collector is None:
            return None
        collector.organization = organization
        if not enabled_ready(collector) or not constant_time_compare(
            collector.scan_proof, scan_proof(collector)
        ):
            collector.enabled, collector.last_code = False, "collection_proof_invalid"
            collector.save(update_fields=["enabled", "last_code"])
            collector.source.active = False
            collector.source.save(update_fields=["active"])
            record(
                organization=organization,
                target=collector,
                action="connectors.teamviewer.suspended.v1",
                summary="Collecte suspendue : preuve invalide",
            )
            return None
        if collector.scan_until is None:
            collector.scan_until = now.replace(microsecond=0)
            collector.next_offset = collector.scan_last_end = None
        if collector.scan_until <= collector.start_at:
            collector.next_run_at = now + timedelta(seconds=5)
            collector.save(update_fields=["next_run_at"])
            return None
        collector.scan_proof = scan_proof(collector)
        collector.claim_token = uuid.uuid4()
        collector.claim_until = now + timedelta(seconds=90)
        collector.save(
            update_fields=[
                "scan_until",
                "next_offset",
                "scan_last_end",
                "scan_proof",
                "claim_token",
                "claim_until",
            ]
        )
        collector.started_at = now
        return collector


@transaction.atomic
def finish_page(claim, *, page=None, error=None):
    if (page is None) == (error is None):
        raise ValueError("A single collection outcome is required")
    organization = Organization.objects.select_for_update().get(pk=claim.organization_id)
    with organization_context(organization):
        collector = TeamViewerCollector.objects.select_for_update().get(pk=claim.pk)
        collector.organization = organization
        valid = bool(
            _allowed(organization)
            and enabled_ready(collector)
            and collector.claim_token == claim.claim_token
            and collector.claim_until
            and collector.claim_until > timezone.now()
            and collector.revision == claim.revision
            and collector.activation_proof == claim.activation_proof
            and constant_time_compare(collector.scan_proof, claim.scan_proof)
            and constant_time_compare(collector.scan_proof, scan_proof(collector))
        )
        if not valid:
            return _retain_run(claim, status="discarded", code="late_or_revoked_result")
        if (
            page
            and page.next_offset
            and TeamViewerRun.objects.filter(
                collector=collector,
                until=claim.scan_until,
                revision=claim.revision,
                activation_hash=claim.activation_proof,
                cursor_output=page.next_offset,
            ).exists()
        ):
            page, error = None, IntegrationFailure("teamviewer_repeated_or_empty_cursor")
        try:
            with transaction.atomic():
                reports = (
                    tuple(_retain_report(collector, item) for item in page.reports) if page else ()
                )
        except ValidationError:
            page, reports = None, ()
            error = IntegrationFailure("teamviewer_evidence_invalid")
        code = (
            error.code if error else ("pagination_finished" if page.finished else "page_retained")
        )
        status = "failed" if error else ("complete" if page.finished else "page")
        run = _retain_run(claim, status=status, code=code, page=page, reports=reports)
        collector.last_code = run.code
        collector.claim_token = collector.claim_until = None
        if error:
            collector.next_run_at = timezone.now() + timedelta(minutes=1)
            if not error.retryable:
                collector.enabled = False
                collector.source.active = False
                collector.source.save(update_fields=["active"])
        elif page.finished:
            collector.scan_until = collector.next_offset = collector.scan_last_end = None
            collector.next_run_at = timezone.now() + timedelta(minutes=5)
        else:
            collector.next_offset = uuid.UUID(page.next_offset)
            collector.scan_last_end = page.last_end
            collector.next_run_at = timezone.now()
        collector.scan_proof = scan_proof(collector)
        collector.save(
            update_fields=[
                "enabled",
                "last_code",
                "claim_token",
                "claim_until",
                "scan_until",
                "next_offset",
                "scan_last_end",
                "next_run_at",
                "scan_proof",
            ]
        )
        return run


def process_collectors(organization, *, limit=1):
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("Invalid TeamViewer job limit")
    processed = 0
    for _ in range(limit):
        claim = claim_page(organization)
        if claim is None:
            break
        page, error = None, None
        try:
            page = TeamViewerClient(collector_config(claim)["token"]).read_page(
                claim.start_at,
                claim.scan_until,
                offset=claim.next_offset,
                previous_end=claim.scan_last_end,
            )
        except IntegrationFailure as failure:
            error = failure
        except (InvalidToken, ValueError, UnicodeError):
            error = IntegrationFailure("collector_configuration_invalid")
        finish_page(claim, page=page, error=error)
        processed += 1
    return processed
