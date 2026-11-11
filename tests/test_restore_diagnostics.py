"""Only statically approved failure labels may escape the private restore checker."""

import io
import json
import subprocess
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from cryptography.fernet import InvalidToken

from deploy.check_restore import RestoreQualification, RestoreVerificationFailure
from deploy.check_restore import main as restore_main
from deploy.restore_application_check import failure_code, public_failure_code


class RestoreDiagnosticsTests(TestCase):
    def report(self, **changes):
        return json.dumps({
            "result": "failed", "phase": "offline application verification",
            "error": "RuntimeError", "code": "teamviewer_evidence_invalid", **changes,
        }).encode()

    def test_child_known_failure_becomes_static_code_and_unknown_messages_do_not_escape(self):
        self.assertEqual(failure_code(RuntimeError(
            "Restored TeamViewer normalized source link is invalid."
        )), "teamviewer_evidence_invalid")
        self.assertEqual(failure_code(InvalidToken()), "decryption_failed")
        self.assertEqual(failure_code(RuntimeError("synthetic-private-value")),
                         "unclassified_verification_failure")

    def test_parent_rejects_unknown_values_extra_fields_duplicates_and_raw_output(self):
        self.assertEqual(public_failure_code(self.report()), "teamviewer_evidence_invalid")
        for value in (
            self.report(code="synthetic-private-value"),
            self.report(error="synthetic-private-value"),
            self.report(phase="synthetic-private-value"),
            self.report(extra="synthetic-private-value"),
            b"synthetic-private-value", b"x" * 4097,
            self.report()[:-1] + b',"code":"synthetic-private-value"}',
            b'{"result":"failed","phase":[],"error":{},"code":[]}',
        ):
            with self.subTest(size=len(value)):
                self.assertEqual(public_failure_code(value), "unclassified_verification_failure")

    def test_positive_verification_failure_exposes_only_recognized_code(self):
        check = RestoreQualification(SimpleNamespace())
        error = subprocess.CalledProcessError(
            1, ["fixed-checker"], output=self.report(), stderr=b"synthetic-private-stderr"
        )
        with (
            patch.object(check, "application", side_effect=error),
            self.assertRaises(RuntimeError) as got,
        ):
            check.verify_copy({})
        self.assertEqual(str(got.exception),
                         "Offline restore verification failed: teamviewer_evidence_invalid")
        self.assertNotIn("synthetic-private", str(got.exception))

    def test_wrong_key_and_wrong_password_keep_the_original_subprocess_failure(self):
        check = RestoreQualification(SimpleNamespace())
        for field in ("wrong_key", "wrong_password"):
            error = subprocess.CalledProcessError(1, ["fixed"], output=self.report())
            with (
                self.subTest(probe=field),
                patch.object(check, "application_command", return_value=(["fixed"], {})),
                patch.object(check, "command", side_effect=error),
                self.assertRaises(subprocess.CalledProcessError) as got,
            ):
                check.application("verify", **{field: True})
            self.assertIs(got.exception, error)

    def test_public_cli_keeps_only_the_validated_code_without_exception_contents(self):
        for code in ("teamviewer_evidence_invalid", "synthetic-private-value"):
            failure = RestoreVerificationFailure(code)
            # The public boundary revalidates even a modified exception object.
            failure.code = code
            check = RestoreQualification(SimpleNamespace())
            check.phase = "offline application verification"
            output = io.StringIO()
            with (
                self.subTest(code=code),
                patch("argparse.ArgumentParser.parse_args", return_value=SimpleNamespace()),
                patch("deploy.check_restore.RestoreQualification", return_value=check),
                patch.object(check, "execute", side_effect=failure),
                patch.object(check, "cleanup"), patch("sys.stdout", output),
                self.assertRaises(SystemExit) as exit_status,
            ):
                restore_main()
            self.assertEqual(exit_status.exception.code, 1)
            report = json.loads(output.getvalue())
            self.assertEqual(report["code"], code if code == "teamviewer_evidence_invalid"
                             else "unclassified_verification_failure")
            self.assertNotIn("synthetic-private", output.getvalue())

    def test_cleanup_cannot_replace_primary_failure_and_is_fatal_on_its_own(self):
        for primary_fails, cleanup_fails in ((True, False), (True, True), (False, True)):
            check = RestoreQualification(SimpleNamespace())
            check.phase = "offline application verification"
            primary = RestoreVerificationFailure("teamviewer_evidence_invalid")
            cleanup = subprocess.CalledProcessError(
                1, ["synthetic-private-command"], output=b"synthetic-private-stdout",
                stderr=b"synthetic-private-stderr",
            )
            output = io.StringIO()
            with (
                self.subTest(primary=primary_fails, cleanup=cleanup_fails),
                patch("argparse.ArgumentParser.parse_args", return_value=SimpleNamespace()),
                patch("deploy.check_restore.RestoreQualification", return_value=check),
                patch.object(check, "execute", side_effect=primary if primary_fails else None,
                             return_value={"result": "OK"}),
                patch.object(check, "cleanup", side_effect=cleanup if cleanup_fails else None),
                patch("sys.stdout", output), self.assertRaises(SystemExit) as exit_status,
            ):
                restore_main()
            self.assertEqual(exit_status.exception.code, 1)
            report = json.loads(output.getvalue())
            self.assertEqual(report["result"], "failed")
            if primary_fails:
                self.assertEqual(report["phase"], "offline application verification")
                self.assertEqual(report["code"], "teamviewer_evidence_invalid")
            else:
                self.assertEqual(report["phase"], "isolated copy cleanup")
                self.assertEqual(report["error"], "RestoreCleanupFailure")
            if cleanup_fails:
                self.assertEqual(report["cleanup_code"], "isolated_copy_cleanup_failed")
            else:
                self.assertNotIn("cleanup_code", report)
            self.assertNotIn("synthetic-private", output.getvalue())
