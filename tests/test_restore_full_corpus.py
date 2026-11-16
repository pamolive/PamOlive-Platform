"""The exact populated offline CI corpus must verify before archive transport."""

import io
import os
from copy import copy
from unittest import SkipTest
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TransactionTestCase, override_settings

from deploy.prepare_restore_fixture import directory_corpus, teamviewer_corpus
from deploy.prepare_restore_fixture import main as prepare_corpus
from deploy.restore_application_check import FORMAT, model_fingerprints, verify_application
from platform_core.models import Organization
from platform_core.services import install_module
from platform_core.tenancy import current_organization, organization_context
from platform_modules.connectors.teamviewer_access_models import TeamViewerAccessObservation
from platform_modules.connectors.teamviewer_restoration import verify_evidence as verify_teamviewer


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class CompleteRestoreCorpusTests(TransactionTestCase):
    def test_public_fixture_guards_refuse_private_or_live_inputs_and_boolean_counts(self):
        import json

        from deploy.check_restore_ci import public_trust_environment, require_extended_corpus

        organization = "00000000-0000-4000-8000-000000000483"
        anchors = {
            "PAM_TRUST_INSTALLATION_ID": "synthetic-isolated-installation",
            "PAM_TRUST_RP_ID": "pam.example.test",
            "PAM_TRUST_ORIGIN": "https://pam.example.test",
            "PAM_TRUST_COMMISSIONING_KEYS": json.dumps({organization: {"commissioner": "A" * 43}}),
            "PAM_TRUST_CHECKPOINT_KEYS": json.dumps({organization: {"witness": "B" * 43}}),
        }
        self.assertEqual(public_trust_environment(json.dumps(anchors).encode()), anchors)
        for extra in ({"PRIVATE_KEY": "must-refuse"}, {"PAM_TRUST_CHECKPOINT_DIRECTORY": "/live"}):
            with self.assertRaises(RuntimeError):
                public_trust_environment(json.dumps({**anchors, **extra}).encode())
        counts = dict(
            pam_trust_registries_verified=1,
            pam_personal_authorizations_verified=2,
            governance_exception_proofs_checked=3,
            legacy_events_checked=1,
            legacy_v7_evaluations_checked=1,
            provenance_receipts_checked=3,
        )
        require_extended_corpus(counts)
        for name in counts:
            for invalid in (None, True, False, 0, "1"):
                with self.assertRaises(RuntimeError):
                    require_extended_corpus({**counts, name: invalid})

    def test_nonempty_application_source_refuses_before_MigrationExecutor(self):
        from deploy.prepare_restore_fixture import prepare_historical_v7_source

        Organization.objects.create(key="must-retain", name="Preexisting synthetic row")
        with (
            patch.dict(os.environ, PAMOLIVE_RESTORE_FIXTURE="1"),
            patch("django.db.migrations.executor.MigrationExecutor") as executor,
            self.assertRaisesRegex(RuntimeError, "already contains application data"),
        ):
            prepare_historical_v7_source()
        executor.assert_not_called()
        self.assertTrue(Organization.objects.filter(key="must-retain").exists())

    def test_historical_V7_upgrade_keeps_bytes_and_post_V8_insertion_is_refused(self):
        from django.db import DatabaseError, transaction

        from deploy.prepare_restore_fixture import prepare_historical_v7_source
        from platform_modules.access.evidence import verify_evaluation
        from platform_modules.access.models import AccessEvaluation, AccessEvent
        from platform_modules.access.provenance_status import verified_origin_status

        with (
            patch.dict(os.environ, PAMOLIVE_RESTORE_FIXTURE="1"),
            patch("socket.create_connection", side_effect=AssertionError("No remote network")),
        ):
            prepare_historical_v7_source()
        event = AccessEvent.unscoped.get(source="synthetic-pre-v8-restore")
        evaluation = AccessEvaluation.unscoped.select_related("event", "audit").get(event=event)
        self.assertEqual(verified_origin_status(event), "legacy_unknown")
        self.assertTrue(verify_evaluation(evaluation))
        self.assertEqual((event.facts_schema, event.facts_digest), ("", ""))
        before = model_fingerprints()
        with patch("deploy.restore_application_check.database_guard"):
            report = verify_application()
        self.assertEqual(report["legacy_events_checked"], 1)
        self.assertEqual(report["legacy_v7_evaluations_checked"], 1)
        self.assertEqual(report["pam_trust_registries_verified"], 0)
        self.assertEqual(report["governance_exception_proofs_checked"], 0)
        with self.assertRaises(DatabaseError), transaction.atomic():
            AccessEvent.unscoped.bulk_create(
                [
                    AccessEvent(
                        organization=event.organization,
                        source="forbidden-post-V8",
                        external_id="must-not-insert",
                        occurred_at=event.occurred_at,
                        method="SSH",
                        action="session.start",
                        provenance_channel="legacy_unknown",
                    )
                ]
            )
        damaged = copy(evaluation)
        damaged.context_hash = "0" * 64
        self.assertFalse(verify_evaluation(damaged))
        rows = Mock()
        rows.iterator.return_value = iter([damaged])
        with (
            patch("deploy.restore_application_check.database_guard"),
            patch.object(AccessEvaluation.unscoped, "select_related", return_value=rows),
            self.assertRaisesRegex(RuntimeError, "interpretation proof is invalid"),
        ):
            verify_application()
        self.assertEqual(model_fingerprints(), before)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if (
            connection.vendor != "postgresql"
            or connection.settings_dict["NAME"] != "test_pamolive_restore_source"
        ):
            raise SkipTest("Dedicated PostgreSQL test_pamolive_restore_source corpus gate")

    def test_complete_ci_fixture_preserves_all_evidence_and_fingerprints(self):
        with (
            patch.dict(os.environ, {"PAMOLIVE_RESTORE_FIXTURE": "1"}),
            patch("sys.stdout", new_callable=io.StringIO),
            patch("socket.create_connection", side_effect=AssertionError("No remote network")),
        ):
            public_anchors = prepare_corpus()
            # A second tenant proves that the offline global reader does not
            # depend on an ambient tenant or pick one tenant for the whole file.
            actor = get_user_model().objects.get(username="admin")
            other = Organization.objects.create(key="restore-other", name="Synthetic other tenant")
            for module in ("identity", "access"):
                install_module(module, actor=actor, organization=other)
            with organization_context(other):
                teamviewer_corpus(actor, other)
                directory_corpus(actor, other)
        before = model_fingerprints()
        with (
            patch("deploy.restore_application_check.database_guard"),
            override_settings(**public_anchors, PAM_TRUST_CHECKPOINT_DIRECTORY=""),
        ):
            report = verify_application(
                expected_manifest={"format": FORMAT, "fingerprints": before}
            )
        self.assertEqual(report["certificate_possession_proofs_checked"], 1)
        from deploy.check_restore_ci import require_extended_corpus

        require_extended_corpus(report)
        self.assertEqual(report["pam_trust_registries_verified"], 1)
        self.assertGreaterEqual(report["pam_personal_authorizations_verified"], 2)
        self.assertEqual(report["governance_exception_proofs_checked"], 3)
        self.assertEqual(report["legacy_events_checked"], 1)
        self.assertEqual(report["legacy_v7_evaluations_checked"], 1)
        from django.core.exceptions import PermissionDenied

        from platform_modules.pam.trust_registry import recognized_registry

        with override_settings(**public_anchors, PAM_TRUST_CHECKPOINT_DIRECTORY=""):
            with self.assertRaises(PermissionDenied):
                recognized_registry(Organization.objects.get(key="test"))
        with (
            patch("deploy.restore_application_check.database_guard"),
            override_settings(
                **{**public_anchors, "PAM_TRUST_COMMISSIONING_KEYS": {}},
                PAM_TRUST_CHECKPOINT_DIRECTORY="",
            ),
            self.assertRaises(PermissionDenied),
        ):
            verify_application()

        self.assertGreater(report["provenance_receipts_checked"], 0)
        self.assertGreater(report["sealed_captures_verified"], 0)
        self.assertTrue(report["postgresql_audit_guard"])
        self.assertEqual(
            report["directory_evidence_checked"],
            dict(sources=4, runs=6, facts=6, mappings=8, encrypted_values=4),
        )
        self.assertEqual(model_fingerprints(), before)
        with organization_context(other):
            self.assertGreater(verify_teamviewer()[1], 0)
            self.assertEqual(current_organization().pk, other.pk)
        self.assertEqual(TeamViewerAccessObservation.unscoped.count(), 2)
        original = (
            TeamViewerAccessObservation.unscoped.exclude(organization=other)
            .select_related("organization", "session", "event")
            .get()
        )
        damaged = copy(original)
        damaged.organization = other
        rows = Mock()
        rows.iterator.return_value = iter([damaged])
        with (
            patch.object(TeamViewerAccessObservation.unscoped, "select_related", return_value=rows),
            self.assertRaisesRegex(RuntimeError, "normalized source link is invalid"),
        ):
            verify_teamviewer()
        self.assertEqual(model_fingerprints(), before)
