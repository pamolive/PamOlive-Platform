"""Offline directory proofs remain verifiable, tenant-bound and non-authoritative."""

from copy import copy
from unittest import skipUnless
from unittest.mock import Mock, patch

from django.db import connection
from django.test import TestCase, override_settings

from deploy.prepare_restore_fixture import directory_corpus
from deploy.restore_application_check import (
    failure_code,
    model_fingerprints,
    verify_application,
    verify_directory_evidence,
)
from platform_core.tenancy import current_organization, organization_context
from platform_modules.connectors import directory_inventory as inventory
from platform_modules.connectors.directory_models import (
    DirectoryFact,
    DirectoryMapping,
    DirectoryRun,
    DirectorySource,
)

from .test_directory_inventory import DirectoryInventoryFixture


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class DirectoryRestoreTests(DirectoryInventoryFixture, TestCase):
    def test_disabled_rotated_source_retains_verifiable_history_without_live_authority(self):
        self.accept(records=[dict(self.records[0], enabled=None)])
        mapping = self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=self.account.pk,
        )
        self.mutate(inventory.revoke_directory_mapping, mapping.pk)
        self.mutate(
            inventory.rotate_directory_credential,
            self.source.pk,
            credential=dict(self.credential, password="different-synthetic-secret"),
        )
        self.mutate(inventory.set_directory_source_enabled, self.source.pk, enabled=False)
        before = model_fingerprints(transaction_started=True)
        result = verify_directory_evidence()
        self.assertEqual(result, dict(sources=1, runs=1, facts=1, mappings=2, encrypted_values=1))
        self.assertEqual(model_fingerprints(transaction_started=True), before)
        self.source.refresh_from_db()
        self.assertFalse(self.source.enabled)
        self.assertIsNone(DirectoryFact.objects.get().enabled)

    def test_offline_global_reader_uses_each_tenant_and_restores_outer_context(self):
        directory_corpus(self.admin, self.org)
        with organization_context(self.other):
            directory_corpus(self.admin, self.other)
        before = model_fingerprints(transaction_started=True)
        result = verify_directory_evidence()
        self.assertEqual(result, dict(sources=5, runs=6, facts=6, mappings=8, encrypted_values=5))
        self.assertEqual(current_organization().pk, self.org.pk)
        self.assertEqual(model_fingerprints(transaction_started=True), before)
        self.assertFalse(
            DirectorySource.objects.exclude(pk=self.source.pk).filter(enabled=True).exists()
        )

    def test_changed_restored_run_facts_cannot_verify_with_original_signature(self):
        self.accept()
        damaged = copy(DirectoryRun.objects.select_related("source__audit", "audit").get())
        damaged.facts_sha256 = "f" * 64
        query = Mock()
        query.select_related.return_value.iterator.return_value = iter([damaged])
        with patch.object(DirectoryRun.objects, "filter", return_value=query):
            with self.assertRaisesRegex(RuntimeError, "directory run evidence is invalid"):
                verify_directory_evidence()

    def test_lost_mapping_row_is_detected_by_retained_audit_anchor(self):
        self.accept()
        self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=self.account.pk,
        )
        empty = DirectoryMapping.unscoped.none()
        with (
            patch.object(DirectoryMapping.objects, "filter", return_value=empty),
            patch.object(DirectoryMapping.unscoped, "count", return_value=0),
        ):
            with self.assertRaisesRegex(RuntimeError, "directory history evidence is invalid"):
                verify_directory_evidence()

    def test_cross_tenant_run_cannot_be_hidden_in_global_reader(self):
        self.accept()
        damaged = copy(DirectoryRun.objects.select_related("source__audit", "audit").get())
        damaged.organization = self.other
        query = Mock()
        query.select_related.return_value.iterator.return_value = iter([damaged])
        with patch.object(DirectoryRun.objects, "filter", return_value=query):
            with self.assertRaisesRegex(RuntimeError, "directory run evidence is invalid"):
                verify_directory_evidence()

    def test_public_directory_failure_code_is_static(self):
        for kind in ("source", "credential", "run", "mapping", "history"):
            self.assertEqual(
                failure_code(RuntimeError("Restored directory " + kind + " evidence is invalid.")),
                "directory_evidence_invalid",
            )

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL full offline verifier")
    def test_full_application_verifier_counts_directory_proofs_and_preserves_all_rows(self):
        self.accept()
        self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=self.account.pk,
        )
        before = model_fingerprints(transaction_started=True)
        with patch("deploy.restore_application_check.database_guard"):
            result = verify_application()
        self.assertEqual(
            result["directory_evidence_checked"],
            dict(sources=1, runs=1, facts=1, mappings=1, encrypted_values=1),
        )
        self.assertGreaterEqual(result["signed_proofs_checked"], 4)
        self.assertTrue(result["postgresql_audit_guard"])
        self.assertEqual(model_fingerprints(transaction_started=True), before)
