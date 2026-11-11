"""Review projection refuses equivalence shortcuts and produces no external effects."""

import json
import secrets
from copy import copy
from unittest.mock import Mock, patch
from uuid import uuid4

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from deploy.prepare_restore_fixture import scim_creation_corpus, teamviewer_corpus
from platform_core.models import ModuleActivation
from platform_modules.connectors import directory_inventory as inventory
from platform_modules.connectors.directory_reconciliation import directory_account_review
from platform_modules.connectors.models import (
    AccountBinding,
    ExecutionEvidence,
    ExternalChange,
    GroupBinding,
)
from platform_modules.connectors.outbound import configure_connector
from platform_modules.identity.models import ExternalAccount, Identity

from .test_directory_inventory import DirectoryInventoryFixture


class ReconciliationFixture(DirectoryInventoryFixture):
    def setUp(self):
        super().setUp()
        self.accept()
        self.mapping = self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=self.account.pk,
        )

    def review(self, **kwargs):
        return directory_account_review(
            self.source.pk, actor=self.operator, organization=self.org, **kwargs
        )

    def operation(
        self,
        *,
        kind="disable_account",
        status="succeeded",
        confirmed=True,
        code="read_after_write_confirmed",
        host="scim-origin.invalid",
    ):
        token = secrets.token_urlsafe(32)
        with override_settings(CONNECTOR_ALLOWED_HOSTS=(f"{host}:443",)):
            connector = self.mutate(
                configure_connector,
                name="Synthetic SCIM origin",
                base_url=f"https://{host}/scim/v2",
                token=token,
            )
        binding = AccountBinding.objects.create(
            organization=self.org,
            connector=connector,
            account=self.account,
            remote_id="same-remote-id",
        )
        group = GroupBinding.objects.create(
            organization=self.org,
            connector=connector,
            resource=self.resource,
            entitlement="reader",
            remote_id="reader",
        )
        change = ExternalChange.objects.create(
            organization=self.org,
            account=self.account,
            binding=binding,
            group=group,
            kind=kind,
            status=status,
            connector_revision=1,
            attempts=1,
            idempotency_key=str(uuid4()),
        )
        proof = ExecutionEvidence.objects.create(
            organization=self.org,
            change=change,
            attempt=1,
            code=code,
            confirmed=confirmed,
            observed={"never_export": token},
        )
        return change, proof, connector, token


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class DirectoryReconciliationTests(ReconciliationFixture, TestCase):
    def test_run_metadata_and_association_are_verified_references_not_public_proofs(self):
        from platform_modules.connectors.directory_models import DirectoryRun

        result = self.review()
        self.assertEqual(result["schema"], "pamolive.directory-account-review/1")
        self.assertEqual(result["run"]["id"], str(DirectoryRun.objects.get().pk))
        self.assertIsNotNone(result["run"]["accepted_at"])
        self.assertIsNotNone(result["run"]["audit_id"])
        self.assertEqual(result["items"][0]["mapping"]["id"], str(self.mapping.pk))
        self.assertNotIn("signature", result["items"][0]["mapping"])
        self.assertTrue(result["read_only"])
        self.assertFalse(result["can_apply"])
        self.assertEqual(result["same_destination_relation"], "not_established")

    def test_scim_confirmation_is_dated_record_not_current_directory_state(self):
        change, proof, connector, token = self.operation(kind="remove_membership")
        result = self.review()
        row = result["scim_history"]["results"]["items"][0]
        self.assertEqual(row["change_id"], str(change.pk))
        self.assertEqual(row["id"], str(proof.pk))
        self.assertTrue(row["confirmation_recorded"])
        self.assertEqual(row["current_provider_state"], "not_asserted")
        self.assertEqual(row["origin"]["connector_id"], str(connector.pk))
        self.assertEqual(row["origin"]["base_url"], connector.base_url)
        self.assertEqual(row["origin"]["same_destination_relation"], "not_established")
        output = json.dumps(result)
        self.assertNotIn(token, output)
        self.assertNotIn("never_export", output)
        self.assertNotIn("encrypted_token", output)
        self.assertNotIn("token_hash", output)

    def test_late_discarded_and_pending_results_never_become_effective_rights(self):
        self.operation(status="retry", confirmed=True, code="late_result_discarded")
        result = self.review()
        proof = result["scim_history"]["results"]["items"][0]
        self.assertFalse(proof["confirmation_recorded"])
        self.assertEqual(proof["outcome"], "late_result_discarded")
        reasons = result["items"][0]["review_reasons"]
        self.assertIn("scim_operation_not_confirmed", reasons)
        self.assertIn("late_scim_result_discarded", reasons)
        self.assertNotIn("provisioned_right", result)

    def test_historical_origin_does_not_lookup_the_current_account_binding(self):
        change, _, connector, _ = self.operation()
        with patch.object(
            AccountBinding.objects,
            "filter",
            side_effect=AssertionError("Current binding must not route historical operations"),
        ):
            result = self.review()
        origin = result["scim_history"]["operations"]["items"][0]["origin"]
        self.assertEqual(origin["binding_id"], str(change.binding_id))
        self.assertEqual(origin["connector_id"], str(connector.pk))

    def test_renaming_a_sealed_connector_preserves_the_recorded_origin_revision(self):
        change, _, connector, _ = self.operation()
        with override_settings(CONNECTOR_ALLOWED_HOSTS=("scim-origin.invalid:443",)):
            renamed = self.mutate(
                configure_connector,
                connector_id=connector.pk,
                name="Renamed synthetic connector",
                base_url=connector.base_url,
            )
        self.assertGreater(renamed.revision, change.connector_revision)
        origin = self.review()["scim_history"]["operations"]["items"][0]["origin"]
        self.assertEqual(origin["state"], "recorded_operation_origin")
        self.assertEqual(origin["base_url"], connector.base_url)
        self.assertEqual(origin["recorded_connector_revision"], change.connector_revision)

    def test_current_owner_reassignment_does_not_authenticate_a_historical_person(self):
        owner = Identity.objects.create(organization=self.org, name="Replacement owner")
        self.account.identity = owner
        self.account.save(update_fields=["identity"])
        result = self.review()["items"][0]
        self.assertEqual(result["local_account"]["current_identity_id"], str(owner.pk))
        self.assertEqual(
            result["local_account"]["identity_relation"],
            "current_owner_not_historical_person_authentication",
        )
        self.assertNotIn("authenticated_person_id", json.dumps(result))

    def test_unmapped_and_revoked_objects_do_not_query_execution_histories(self):
        self.mutate(inventory.revoke_directory_mapping, self.mapping.pk)
        with CaptureQueriesContext(connection) as queries:
            result = self.review()
        self.assertIsNone(result["items"][0]["local_account"])
        self.assertEqual(
            result["scim_history"]["operations"]["availability"], "no_explicit_account_link"
        )
        self.assertFalse(any("connectors_externalchange" in row["sql"] for row in queries))
        self.assertFalse(any("connectors_teamviewer" in row["sql"] for row in queries))

    def test_nullable_enabled_and_missing_even_complete_do_not_disable_or_create_effects(self):
        self.accept(records=[dict(self.records[0], enabled=None)], key="unknown-state")
        result = self.review()
        self.assertIn("source_enabled_state_unknown", result["items"][0]["review_reasons"])
        self.accept(records=[], key="missing", complete=True)
        result = self.review()
        self.assertEqual(result["items"][0]["observation_state"], "not_observed")
        self.assertIn("missing_observation_is_not_deletion", result["items"][0]["review_reasons"])
        self.account.refresh_from_db()
        self.assertTrue(self.account.active)

    def test_local_source_state_differences_are_only_review_reasons(self):
        self.accept(records=[dict(self.records[0], enabled=False)], key="disabled-source-row")
        result = self.review()
        self.assertIn("local_active_source_reports_disabled", result["items"][0]["review_reasons"])
        self.account.refresh_from_db()
        self.assertTrue(self.account.active)

    def test_unsigned_scim_history_is_bounded_with_explicit_truncation(self):
        change, _, _, _ = self.operation()
        ExecutionEvidence.objects.create(
            organization=self.org,
            change=change,
            attempt=2,
            code="read_after_write_confirmed",
            confirmed=True,
        )
        result = self.review(history_limit=1)
        self.assertEqual(len(result["scim_history"]["results"]["items"]), 1)
        self.assertTrue(result["scim_history"]["results"]["truncated"])
        self.assertIn("related_history_truncated", result["items"][0]["review_reasons"])

    def test_role_or_module_revocation_prevents_queries_into_hidden_domains(self):
        self.operator.__class__.objects.filter(pk=self.operator.pk).update(is_active=False)
        with self.assertRaises(PermissionDenied):
            self.review()
        self.operator.__class__.objects.filter(pk=self.operator.pk).update(is_active=True)
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        with CaptureQueriesContext(connection) as queries, self.assertRaises(PermissionDenied):
            self.review()
        self.assertFalse(any("connectors_" in row["sql"] for row in queries))

    def test_identical_foreign_remote_ids_cannot_select_foreign_operations(self):
        from platform_core.tenancy import organization_context

        other = self.create_source(name="Other source same UUIDs")
        self.mutate(inventory.set_directory_source_enabled, other.pk, enabled=True)
        self.mutate(
            inventory.import_directory_fixture,
            other.pk,
            records=self.records,
            idempotency_key="same-uuid-other-source",
            operator=True,
        )
        with organization_context(self.other):
            identity = Identity.objects.create(organization=self.other, name="Foreign")
            account = ExternalAccount.objects.create(
                organization=self.other,
                identity=identity,
                username=self.account.username,
                system="same",
            )
            ExternalChange.objects.create(
                organization=self.other,
                account=account,
                kind="disable_account",
                idempotency_key=str(uuid4()),
            )
        self.assertEqual(self.review()["scim_history"]["operations"]["items"], [])
        unlinked = directory_account_review(other.pk, actor=self.operator, organization=self.org)
        self.assertEqual(unlinked["items"][0]["observation"]["remote_id"], self.remote_id)
        self.assertIsNone(unlinked["items"][0]["local_account"])
        self.assertEqual(unlinked["scim_history"]["operations"]["items"], [])

    def test_account_page_pagination_is_inherited_and_wrong_source_cursor_refused(self):
        self.accept(records=[self.fact(username=str(number)) for number in range(3)], key="pages")
        first = self.review(limit=1)
        second = self.review(limit=1, cursor=first["next_cursor"])
        self.assertNotEqual(
            first["items"][0]["observation"]["remote_id"],
            second["items"][0]["observation"]["remote_id"],
        )
        other = self.create_source(name="Cursor-other")
        with self.assertRaises(ValidationError):
            directory_account_review(
                other.pk, actor=self.operator, organization=self.org, cursor=first["next_cursor"]
            )

    def test_signed_creation_only_confirms_initial_inactive_account(self):
        from platform_modules.connectors.creation_models import ScimCreationProof

        scim_creation_corpus(self.admin, self.operator, self.org)
        proof = ScimCreationProof.objects.select_related("binding").get()
        self.mutate(inventory.revoke_directory_mapping, self.mapping.pk)
        self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=proof.binding.account_id,
        )
        result = self.review()["scim_history"]["creations"]["items"][0]
        self.assertEqual(result["state"], "created_inactive_recorded")
        self.assertEqual(result["assurance"], "signed_creation_proof_verified")
        self.assertFalse(result["active_right_asserted"])
        self.assertEqual(result["current_provider_state"], "not_asserted")

    def test_invalid_creation_proof_is_flagged_without_exporting_payload(self):
        from platform_modules.connectors.creation_models import ScimCreationProof

        scim_creation_corpus(self.admin, self.operator, self.org)
        proof = ScimCreationProof.objects.select_related("binding").get()
        self.mutate(inventory.revoke_directory_mapping, self.mapping.pk)
        self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=proof.binding.account_id,
        )
        bad = copy(proof)
        bad.signature = "invalid"
        rows = Mock()
        rows.select_related.return_value.order_by.return_value = [bad]
        with patch.object(ScimCreationProof.objects, "filter", return_value=rows):
            result = self.review()
        self.assertEqual(
            result["scim_history"]["creations"]["items"][0]["state"], "invalid_creation_proof"
        )
        self.assertIn("invalid_scim_creation_proof", result["items"][0]["review_reasons"])

    def test_creation_origin_uses_its_signed_scope_not_a_present_connector_url(self):
        from platform_modules.connectors.creation_models import ScimCreationProof

        scim_creation_corpus(self.admin, self.operator, self.org)
        proof = ScimCreationProof.objects.select_related("binding__connector").get()
        original_url = proof.dispatch.request.scope["connector"]["base_url"]
        self.mutate(inventory.revoke_directory_mapping, self.mapping.pk)
        self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=proof.binding.account_id,
        )
        historic = copy(proof)
        historic.binding.connector = copy(proof.binding.connector)
        historic.binding.connector.base_url = "https://not-the-original.invalid/scim/v2"
        rows = Mock()
        rows.select_related.return_value.order_by.return_value = [historic]
        with patch.object(ScimCreationProof.objects, "filter", return_value=rows):
            result = self.review()["scim_history"]["creations"]["items"][0]
        self.assertEqual(result["state"], "created_inactive_recorded")
        self.assertEqual(result["origin"]["base_url"], original_url)

    def test_teamviewer_uses_explicit_operator_mapping_never_directory_os_equivalence(self):
        teamviewer_corpus(self.admin, self.org)
        operator = ExternalAccount.objects.get(system="TeamViewer")
        self.mutate(inventory.revoke_directory_mapping, self.mapping.pk)
        self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=operator.pk,
        )
        result = self.review()
        session = result["teamviewer_history"]["items"][0]
        self.assertEqual(session["association"], "operator_account_reference")
        self.assertEqual(session["account_id"], str(operator.pk))
        self.assertEqual(session["os_account"], "not_asserted")
        self.assertEqual(session["historical_person_authentication"], "not_asserted")
        self.assertEqual(session["provenance_link"], "verified")

    def test_reading_never_calls_transport_or_changes_business_rows(self):
        from django.apps import apps

        labels = [
            "identity.Grant",
            "connectors.ExternalChange",
            "connectors.ExecutionEvidence",
            "connectors.ScimCreationRequest",
            "access.AccessEvent",
            "approvals.ApprovalDecision",
            "pam.SessionLease",
            "platform_core.AuditEvent",
        ]

        def counts():
            return {label: apps.get_model(label)._base_manager.count() for label in labels}

        before = counts()
        with patch("socket.create_connection", side_effect=AssertionError("No egress in reader")):
            self.review()
        self.assertEqual(counts(), before)
