"""P0-4 regressions for consumers that used an untrusted source label."""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from platform_core.services import install_module
from platform_modules.access.provenance_status import verified_origin_status
from platform_modules.access.services import ingest_event
from platform_modules.access.temporal import observation_segments
from platform_modules.connectors.services import create_source, source_from_token
from platform_modules.intelligence.coverage import event_clock
from platform_modules.intelligence.models import CollectionScope
from platform_modules.intelligence.services import ingest_report

from . import test_platform as baseline


class EventProvenanceConsumerTests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        self.source, self.token = create_source(
            "Synthetic collector for provenance consumers",
            actor=self.admin,
            organization=self.org,
        )
        install_module("intelligence", actor=self.admin, organization=self.org)

    def event_data(self, occurred_at, *, external_id, ended_at=None):
        return {
            "source": str(self.source.pk),
            "external_id": external_id,
            "occurred_at": occurred_at,
            "ended_at": ended_at,
            "method": "SSH",
            "action": "session.start",
            "domain": "pam",
            "result": "success",
        }

    def test_manual_uuid_cannot_borrow_collector_clock(self):
        now = timezone.now()
        scope = CollectionScope.objects.create(
            organization=self.org,
            source=self.source,
            domain="pam",
            effective_at=now - timedelta(minutes=2),
            published_by=self.admin,
        )
        report, _ = ingest_report(
            {
                "scope": scope.pk,
                "external_id": "synthetic-clock-v8",
                "covered_from": now - timedelta(minutes=1),
                "covered_until": now,
                "state": "complete",
                "clock_uncertainty_seconds": 0,
            },
            source=self.source,
            organization=self.org,
        )
        facts = self.event_data(
            now - timedelta(seconds=1), external_id="synthetic-same-id-v8"
        )
        manual, _ = ingest_event(facts, actor=self.operator, organization=self.org)
        collector, _ = ingest_event(
            facts, source=source_from_token(self.token), source_token=self.token,
            organization=self.org,
        )
        self.assertNotEqual(manual.pk, collector.pk)
        self.assertEqual(verified_origin_status(manual), "manual")
        self.assertEqual(verified_origin_status(collector), "collector")
        self.assertEqual(event_clock(manual), (None, None))
        self.assertEqual(event_clock(collector), (0, str(report.pk)))
        collector.provenance_receipt.signature = "0" * 64
        self.assertEqual(verified_origin_status(collector), "invalid_provenance")
        self.assertEqual(event_clock(collector), (None, None))

    def test_manual_uuid_cannot_add_collector_scope_boundaries(self):
        now = timezone.now()
        start, end = now - timedelta(minutes=2), now - timedelta(minutes=1)
        CollectionScope.objects.create(
            organization=self.org,
            source=self.source,
            domain="pam",
            effective_at=start + timedelta(seconds=20),
            published_by=self.admin,
        )
        facts = self.event_data(
            start, ended_at=end, external_id="synthetic-interval-v8"
        )
        manual, _ = ingest_event(facts, actor=self.operator, organization=self.org)
        collector, _ = ingest_event(
            facts, source=source_from_token(self.token), source_token=self.token,
            organization=self.org,
        )
        manual_segments, manual_issue = observation_segments(manual)
        collector_segments, collector_issue = observation_segments(collector)
        self.assertIsNone(manual_issue)
        self.assertIsNone(collector_issue)
        self.assertEqual(len(manual_segments), 1)
        self.assertEqual(len(collector_segments), 2)
        collector.provenance_receipt.signature = "0" * 64
        self.assertEqual(len(observation_segments(collector)[0]), 1)
