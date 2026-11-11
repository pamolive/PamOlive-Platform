"""An isolated restored copy must retain every V8 receipt and V7 evaluation."""

from unittest import skipUnless
from unittest.mock import patch

from django.db import DatabaseError, connection, transaction
from django.test import TestCase
from django.utils import timezone

from deploy.restore_application_check import verify_application
from platform_modules.access.evidence import verify_evaluation
from platform_modules.access.models import AccessProvenanceReceipt
from platform_modules.access.provenance import verify_provenance_receipt
from platform_modules.access.services import ingest_event
from platform_modules.connectors.services import create_source, source_from_token

from . import test_platform as baseline


class EventProvenanceRestoreTests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        self.source, self.token = create_source(
            "Synthetic restore collector", actor=self.admin, organization=self.org
        )

    def event(self):
        return ingest_event(
            {
                "external_id": "synthetic-restore-event",
                "occurred_at": timezone.now(),
                "method": "SSH",
                "action": "session.start",
            },
            source=source_from_token(self.token),
            source_token=self.token,
            organization=self.org,
        )[0]

    @skipUnless(connection.vendor == "sqlite", "PostgreSQL forbids deleting a V8 receipt")
    def test_restore_rejects_a_missing_v8_receipt_and_keeps_v7_verifiable(self):
        event = self.event()
        self.assertTrue(verify_evaluation(event.evaluations.get()))
        AccessProvenanceReceipt.unscoped.filter(event=event).delete()
        self.assertTrue(verify_evaluation(event.evaluations.get()))
        # The guarded production entry point checks the restored database and
        # its restricted login role. Only that prerequisite is mocked here;
        # the receipt inspection runs against this synthetic Django test DB.
        with patch("deploy.restore_application_check.database_guard"):
            with self.assertRaisesRegex(RuntimeError, "missing its provenance receipt"):
                verify_application()

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL receipt deletion trigger")
    def test_postgres_refuses_receipt_deletion_and_preserves_verification(self):
        event = self.event()
        receipt = event.provenance_receipt
        with self.assertRaises(DatabaseError), transaction.atomic():
            AccessProvenanceReceipt.unscoped.filter(pk=receipt.pk).delete()
        receipt.refresh_from_db()
        self.assertTrue(verify_provenance_receipt(receipt))
        self.assertTrue(verify_evaluation(event.evaluations.get()))
