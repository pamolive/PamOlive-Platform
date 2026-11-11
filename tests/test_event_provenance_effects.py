"""P0-4 regressions: signed analysis and collector origin are separate facts."""

import json
from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.models import AuditEvent
from platform_core.services import install_module
from platform_modules.access.evidence import verify_evaluation
from platform_modules.access.models import AccessIntent
from platform_modules.access.services import create_record, ingest_event
from platform_modules.approvals.models import ApprovalDecision
from platform_modules.connectors.models import ExternalChange
from platform_modules.connectors.services import create_source, source_from_token
from platform_modules.identity.models import Grant
from platform_modules.intelligence.coverage import event_clock
from platform_modules.intelligence.models import CollectionScope
from platform_modules.intelligence.services import ingest_report
from platform_modules.pam.models import RelayConnection, SessionLease
from platform_modules.pam.trust_models import PAMTrustRevision

from . import test_platform as baseline


class EventProvenanceEffectsTests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        self.source, self.token = create_source(
            "Synthetic telemetry collector", actor=self.admin, organization=self.org
        )

    def event_fields(self, **changes):
        return {
            "source": str(self.source.pk),
            "external_id": "synthetic-event-42",
            "occurred_at": timezone.now(),
            "identity": self.identity,
            "account": self.account,
            "resource": self.resource,
            "method": "SSH",
            "privilege": "Administrator",
            "action": "session.start",
            "result": "success",
            "evidence": "Synthetic manually declared evidence",
            "domain": "pam",
            **changes,
        }

    def authority_state(self):
        return {
            model._meta.label: list(model.unscoped.values_list("pk", flat=True).order_by("pk"))
            for model in (
                Grant,
                AccessIntent,
                ApprovalDecision,
                SessionLease,
                RelayConnection,
                PAMTrustRevision,
                ExternalChange,
            )
        }

    def test_manual_signed_event_cannot_suppress_authentic_event_or_grant_authority(self):
        create_record(
            "grant",
            {
                "identity": self.identity,
                "account": self.account,
                "resource": self.resource,
                "entitlement": "Administrator",
                "method": "SSH",
                "justification": "Synthetic pre-existing authorized right",
            },
            actor=self.operator,
            organization=self.org,
        )
        before = self.authority_state()
        fields = self.event_fields()
        forged, created = ingest_event(fields, actor=self.operator, organization=self.org)
        self.assertTrue(created)
        evaluation = forged.evaluations.get()
        self.assertEqual(evaluation.verdict, "expected")
        self.assertTrue(verify_evaluation(evaluation))

        payload = {
            key: str(value.pk)
            if hasattr(value, "pk")
            else value.isoformat()
            if hasattr(value, "isoformat")
            else value
            for key, value in fields.items()
            if key != "source"
        }
        payload.update(
            result="failure",
            privilege="Different privilege",
            evidence="Synthetic authentic observation with divergent content",
        )
        response = self.client.post(
            reverse("api-events"),
            json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        self.assertEqual(response.status_code, 201)
        self.assertNotEqual(response.json()["event_id"], str(forged.pk))
        authentic = type(forged).objects.get(pk=response.json()["event_id"])
        self.assertEqual(authentic.provenance_channel, "collector")
        self.assertEqual(authentic.result, "failure")
        self.client.force_login(self.operator)
        exported = self.client.get(reverse("event-export", args=[forged.pk]))
        self.assertEqual(exported.status_code, 200)
        proof = exported.json()
        self.assertEqual(proof["source"], str(self.source.pk))
        self.assertEqual(proof["evidence"], fields["evidence"])
        forged.refresh_from_db()
        self.assertEqual(forged.result, "success")
        self.assertTrue(proof["evaluation"]["proof_verified"])
        self.assertEqual(proof["evaluation"]["verdict"], "expected")
        self.assertEqual(proof["provenance"]["channel"], "manual")
        self.assertTrue(verify_chain(self.org))
        receipt = AuditEvent.objects.get(
            action="access.event.received.v1", object_id=str(forged.pk)
        )
        self.assertEqual(receipt.actor_id, self.operator.pk)
        self.assertEqual(self.authority_state(), before)

    def test_manual_uuid_cannot_borrow_a_collectors_clock_report(self):
        install_module("intelligence", actor=self.admin, organization=self.org)
        now = timezone.now()
        scope = CollectionScope.objects.create(
            organization=self.org,
            source=self.source,
            domain="pam",
            resource=self.resource,
            effective_at=now - timedelta(minutes=2),
            published_by=self.admin,
        )
        report, _ = ingest_report(
            {
                "scope": scope.pk,
                "external_id": "synthetic-clock-report",
                "covered_from": now - timedelta(minutes=1),
                "covered_until": now,
                "state": "complete",
                "clock_uncertainty_seconds": 0,
            },
            source=self.source,
            organization=self.org,
        )
        forged, _ = ingest_event(
            self.event_fields(occurred_at=now - timedelta(seconds=1)),
            actor=self.operator,
            organization=self.org,
        )
        self.assertEqual(event_clock(forged), (None, None))
        authentic, created = ingest_event(
            self.event_fields(occurred_at=now - timedelta(seconds=1)),
            source=source_from_token(self.token),
            source_token=self.token,
            organization=self.org,
        )
        self.assertTrue(created)
        self.assertEqual(event_clock(authentic), (0, str(report.pk)))
        receipt = AuditEvent.objects.get(
            action="access.event.received.v1", object_id=str(forged.pk)
        )
        self.assertIsNotNone(receipt.actor_id)
