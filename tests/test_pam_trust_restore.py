"""Archived independent authority survives expiry without becoming live again."""

from datetime import timedelta
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import PermissionDenied
from django.db import connection
from django.test import TestCase, override_settings
from django.utils import timezone

from deploy.restore_application_check import model_fingerprints, verify_application
from platform_modules.pam.sessions import append_recording, finish_session
from platform_modules.pam.trust_registry import recognized_registry

from .test_pam_sessions import PamSessionFixtureMixin


@skipUnless(connection.vendor == "postgresql", "PostgreSQL restoration evidence verifier")
@override_settings(PAM_ALLOWED_HOSTS={"ssh.example.test:22"})
class PAMTrustRestoreTests(PamSessionFixtureMixin, TestCase):
    def test_full_restore_verifier_accepts_archive_after_expiry_without_reviving_live_access(self):
        item, owner = self.claimed()
        append_recording(item.pk, self.org, owner, b"3.nop;", 0)
        finish_session(item.pk, self.org, owner, reason="native_closed", complete=True)
        before = model_fingerprints(transaction_started=True)
        with patch(
            "platform_modules.pam.trust_registry.timezone.now",
            return_value=timezone.now() + timedelta(days=2),
        ):
            with self.assertRaises(PermissionDenied):
                recognized_registry(self.org)
            # The runner already owns an isolated test database. Only the CLI
            # name guard is bypassed; cryptographic and SQL guards remain real.
            with patch("deploy.restore_application_check.database_guard"):
                result = verify_application()
            self.assertEqual(result["pam_trust_registries_verified"], 1)
            self.assertGreaterEqual(result["signed_proofs_checked"], 3)
            self.assertEqual(result["sealed_captures_verified"], 1)
            self.assertTrue(result["postgresql_audit_guard"])
            with self.assertRaises(PermissionDenied):
                recognized_registry(self.org)
        self.assertEqual(model_fingerprints(transaction_started=True), before)
