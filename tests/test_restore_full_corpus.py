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
            prepare_corpus()
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
        with patch("deploy.restore_application_check.database_guard"):
            report = verify_application(
                expected_manifest={"format": FORMAT, "fingerprints": before}
            )
        self.assertEqual(report["certificate_possession_proofs_checked"], 1)
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
