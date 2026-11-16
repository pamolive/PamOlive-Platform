"""Pure cleanup ownership/liveness models; never connect PostgreSQL or Docker."""

import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from deploy import check_restore as restore
from deploy import check_restore_ci as ci
from deploy import restore_application_check as checker


class DrainTests(unittest.TestCase):
    def late_zero(self, late_observation):
        check, calls, observations = self.check([0, 0])
        original = check.sql.side_effect
        clock = [0.0]

        def delayed(statement):
            result = original(statement)
            if "pg_stat_activity" in statement and len(observations) == late_observation:
                clock[0] = 4.0
            return result

        check.sql.side_effect = delayed
        with (
            patch.object(restore.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(restore.time, "sleep"),
            self.assertRaisesRegex(RuntimeError, "drain budget exceeded"),
        ):
            check.cleanup()
        self.assertFalse(any(statement.startswith("DROP ") for statement in calls))
        self.assertTrue(check.database_created and check.role_created)

    def test_late_first_zero_retains_sealed_copy(self):
        self.late_zero(1)

    def test_late_final_zero_retains_sealed_copy(self):
        self.late_zero(2)

    def check(self, sessions, *, seals=None):
        check = restore.RestoreQualification(SimpleNamespace())
        check.role_created = check.database_created = True
        check.role_oid, check.database_oid = 10, 20
        calls, observations = [], []
        counts = iter(sessions)
        states = iter(seals or [])
        last = sessions[-1]

        def sql(statement):
            nonlocal last
            calls.append(statement)
            if "FROM pg_roles r, pg_database d" in statement:
                return next(states, "10:20:10:0")
            if "rolcanlogin::int FROM pg_roles WHERE" in statement:
                return "10:0"
            if statement.startswith("SELECT oid FROM pg_roles"):
                return "10"
            if "SELECT oid || ':' || datdba" in statement:
                return "20:10"
            if "pg_stat_activity" in statement:
                last = next(counts, last)
                observations.append(last)
                return str(last)
            return ""

        check.sql = Mock(side_effect=sql)
        return check, calls, observations

    def run_cleanup(self, check):
        clock = [0.0]

        def advance(seconds):
            clock[0] += seconds

        with (
            patch.object(restore.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(restore.time, "sleep", side_effect=advance),
        ):
            return check.cleanup()

    def test_session_one_then_zero_drains_without_terminating(self):
        check, calls, observations = self.check([1, 0, 0])
        self.run_cleanup(check)
        self.assertEqual(observations, [1, 0, 0])
        self.assertEqual(sum(s.startswith("DROP DATABASE ") for s in calls), 1)
        self.assertEqual(sum(s.startswith("DROP ROLE ") for s in calls), 1)
        self.assertFalse(check.database_created or check.role_created)
        self.assertFalse(any("TERMINATE" in s.upper() or "FORCE" in s.upper() for s in calls))

    def test_permanent_active_session_is_finite_and_retained(self):
        check, calls, observations = self.check([1])
        with self.assertRaisesRegex(RuntimeError, "session is still active"):
            self.run_cleanup(check)
        self.assertLessEqual(len(observations), 20)
        self.assertFalse(any(s.startswith("DROP ") for s in calls))
        self.assertTrue(check.database_created and check.role_created)

    def test_changed_or_unknown_identity_or_reopened_role_never_deletes(self):
        for state in ("11:20:10:0", "10:21:10:0", "10:20:99:0", "10:20:10:1", ""):
            check, calls, _ = self.check([1, 0], seals=["10:20:10:0", state])
            with (
                self.subTest(state=state),
                self.assertRaisesRegex(RuntimeError, "sealed role changed"),
            ):
                self.run_cleanup(check)
            self.assertFalse(any(s.startswith("DROP ") for s in calls))

    def test_new_session_or_identity_change_after_first_zero_is_not_dropped(self):
        check, calls, _ = self.check([0, 1])
        with self.assertRaisesRegex(RuntimeError, "session is still active"):
            self.run_cleanup(check)
        self.assertFalse(any(s.startswith("DROP ") for s in calls))
        check, calls, _ = self.check([0], seals=["10:20:10:0", "10:20:10:1"])
        with self.assertRaisesRegex(RuntimeError, "sealed role changed"):
            self.run_cleanup(check)
        self.assertFalse(any(s.startswith("DROP ") for s in calls))

    def test_unknown_session_observation_is_not_zero(self):
        for value in ("unknown", -1):
            check, calls, _ = self.check([value])
            with self.subTest(value=value), self.assertRaises((RuntimeError, ValueError)):
                self.run_cleanup(check)
            self.assertFalse(any(s.startswith("DROP ") for s in calls))

    def test_role_change_after_database_drop_does_not_drop_foreign_role(self):
        check, calls, _ = self.check([0, 0])
        original = check.sql.side_effect

        def changed(statement):
            if "rolcanlogin::int FROM pg_roles WHERE" in statement:
                calls.append(statement)
                return "99:0"
            return original(statement)

        check.sql.side_effect = changed
        with self.assertRaisesRegex(RuntimeError, "role retained"):
            self.run_cleanup(check)
        self.assertEqual(sum(s.startswith("DROP DATABASE ") for s in calls), 1)
        self.assertFalse(any(s.startswith("DROP ROLE ") for s in calls))
        self.assertFalse(check.database_created)
        self.assertTrue(check.role_created)

    def test_shared_cleanup_report_preserves_primary_and_safe_code(self):
        check = restore.RestoreQualification(SimpleNamespace())
        check.phase = "offline application verification"
        primary = restore.RestoreVerificationFailure("signature_invalid")
        check.execute = Mock(side_effect=primary)
        check.cleanup = Mock(side_effect=RuntimeError("SYNTHETIC_PRIVATE"))
        report, failed = restore.qualify_and_cleanup(check)
        self.assertTrue(failed)
        self.assertEqual(report["code"], "signature_invalid")
        self.assertEqual(report["error"], "RestoreVerificationFailure")
        self.assertEqual(report["cleanup_code"], "isolated_copy_cleanup_failed")
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(report))

    def test_shared_success_deferred_report_avoids_exclusive_file_collision(self):
        check = restore.RestoreQualification(SimpleNamespace())
        check.directory_created = True
        check.execute = Mock(return_value={"result": "OK"})
        check.cleanup = Mock()
        check.json_file = Mock()
        report, failed = restore.qualify_and_cleanup(check, record_report=False)
        self.assertFalse(failed)
        self.assertEqual(report["result"], "OK")
        check.json_file.assert_not_called()


class CheckerCloseTests(unittest.TestCase):
    def run_checker(self, *, primary=None, closing=None, action="connection"):
        events, output = [], io.StringIO()
        django, db = types.ModuleType("django"), types.ModuleType("django.db")
        django.setup = Mock()

        def close():
            events.append("close")
            if closing:
                raise closing

        db.connections = SimpleNamespace(close_all=close)
        args = SimpleNamespace(action=action, database="copy", role="role", archive_sha256="")
        with (
            patch.dict(sys.modules, {"django": django, "django.db": db}),
            patch.dict(
                "os.environ",
                {"DATABASE_URL": "synthetic", "PAMOLIVE_RESTORE_PASSWORD": "synthetic"},
            ),
            patch("argparse.ArgumentParser.parse_args", return_value=args),
            patch.object(checker, "restore_url", return_value="synthetic"),
            patch.object(checker, "database_guard", side_effect=primary),
            patch.object(
                checker, "snapshot_session", side_effect=lambda: events.append("snapshot")
            ),
            patch("sys.stdout", output),
        ):
            try:
                checker.main()
                exit_code = 0
            except SystemExit as error:
                exit_code = error.code
        return events, output.getvalue(), exit_code

    def test_connection_closes_before_success_output(self):
        events, output, code = self.run_checker()
        self.assertEqual(events, ["close"])
        self.assertEqual(json.loads(output), {"scope_verified": True})
        self.assertEqual(code, 0)

    def test_primary_checker_failure_survives_close_failure(self):
        events, output, code = self.run_checker(
            primary=RuntimeError("Restored signed evidence cannot be verified."),
            closing=ValueError("SYNTHETIC_PRIVATE"),
        )
        self.assertEqual(events, ["close"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output)["code"], "signature_invalid")
        self.assertNotIn("SYNTHETIC_PRIVATE", output)

    def test_close_failure_alone_cannot_print_success(self):
        _, output, code = self.run_checker(closing=ValueError("SYNTHETIC_PRIVATE"))
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output)["result"], "failed")
        self.assertNotIn("scope_verified", output)
        self.assertNotIn("SYNTHETIC_PRIVATE", output)

    def test_snapshot_protocol_has_no_added_json_and_closes_after_release(self):
        events, output, code = self.run_checker(action="snapshot-session")
        self.assertEqual(events, ["snapshot", "close"])
        self.assertEqual(output, "")
        self.assertEqual(code, 0)


class CiFailureTests(unittest.TestCase):
    def run_ci(self, *, primary=None, copy_cleanup=None, source_sessions="0"):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            admin = restore.RestoreQualification(SimpleNamespace())
            check = restore.RestoreQualification(SimpleNamespace())
            check.phase = "offline application verification"
            statements, events = [], []
            check.command = Mock(return_value=b"")

            def execute():
                check.directory = root / "result"
                check.directory.mkdir()
                check.directory_created = check.database_created = check.role_created = True
                if primary:
                    raise primary
                check.command(["pamolive-snapshot-backup"])
                return {
                    "result": "OK",
                    "certificate_possession_proofs_checked": 1,
                    "pam_trust_registries_verified": 1,
                    "pam_personal_authorizations_verified": 2,
                    "governance_exception_proofs_checked": 3,
                    "legacy_events_checked": 1,
                    "legacy_v7_evaluations_checked": 1,
                    "provenance_receipts_checked": 3,
                }

            def cleanup():
                if copy_cleanup:
                    raise copy_cleanup
                check.database_created = check.role_created = False

            check.execute, check.cleanup = execute, cleanup

            def sql(statement):
                statements.append(statement)
                if "SELECT oid FROM pg_roles" in statement:
                    return "10"
                if "SELECT oid FROM pg_database" in statement:
                    return "20"
                if "SELECT oid || ':' || datdba" in statement:
                    return "20:10"
                if "pg_stat_activity" in statement:
                    return source_sessions
                if statement.startswith("DROP DATABASE "):
                    events.append("source-drop")
                return ""

            admin.sql = Mock(side_effect=sql)
            config = {
                "services": {
                    "node-a": {
                        "image": "synthetic-image",
                        "environment": {
                            "DATABASE_URL": "postgresql://owner:synthetic@db/pamolive",
                            "SECRET_KEY": "synthetic",
                            "PAMOLIVE_ENCRYPTION_KEY": "synthetic",
                        },
                    }
                },
                "networks": {"database": {"name": "synthetic-network"}},
            }

            def command(args, **kwargs):
                if "config" in args:
                    body = json.dumps(config).encode()
                elif any("runpy.run_path('/qualification.py'" in arg for arg in args):
                    organization = "00000000-0000-4000-8000-000000000483"
                    body = json.dumps(
                        {
                            "PAM_TRUST_INSTALLATION_ID": "synthetic-isolated-installation",
                            "PAM_TRUST_RP_ID": "pam.example.test",
                            "PAM_TRUST_ORIGIN": "https://pam.example.test",
                            "PAM_TRUST_COMMISSIONING_KEYS": json.dumps(
                                {organization: {"commissioner": "A" * 43}}
                            ),
                            "PAM_TRUST_CHECKPOINT_KEYS": json.dumps(
                                {organization: {"witness": "B" * 43}}
                            ),
                        }
                    ).encode()
                elif any("print('present')" in arg for arg in args):
                    body = b"present\n"
                else:
                    body = b""
                return SimpleNamespace(stdout=body)

            args = SimpleNamespace(
                docker="docker",
                postgres_container="synthetic",
                ha_env_file=root / "env",
                compose_file=root / "compose",
                public_report=None,
            )

            class Output(io.StringIO):
                def write(self, value):
                    if '"result": "OK"' in value:
                        events.append("positive-print")
                    return super().write(value)

            output = Output()
            with (
                patch("argparse.ArgumentParser.parse_args", return_value=args),
                patch.object(ci.tempfile, "mkdtemp", return_value=str(root)),
                patch.object(ci, "RestoreQualification", side_effect=[admin, check]),
                patch.object(ci, "validate_configuration"),
                patch.object(ci, "compose_client", return_value=(["synthetic"], {})),
                patch.object(ci.subprocess, "run", side_effect=command),
                patch("sys.stdout", output),
            ):
                try:
                    ci.main()
                    exit_code = 0
                except SystemExit as error:
                    exit_code = error.code
            records = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertNotIn("SYNTHETIC_PRIVATE", output.getvalue())
            path = root / "result/report.json"
            report_file = json.loads(path.read_bytes()) if path.exists() else None
            return exit_code, records, statements, events, report_file

    def test_actual_ci_path_keeps_primary_when_both_cleanups_fail(self):
        code, records, statements, _, report = self.run_ci(
            primary=restore.RestoreVerificationFailure("signature_invalid"),
            copy_cleanup=RuntimeError("SYNTHETIC_PRIVATE"),
            source_sessions="1",
        )
        self.assertEqual(code, 1)
        self.assertEqual(records[0]["code"], "signature_invalid")
        self.assertEqual(records[0]["cleanup_code"], "isolated_copy_cleanup_failed")
        self.assertEqual(records[1]["cleanup_code"], "source_cleanup_failed")
        self.assertEqual(report["code"], "signature_invalid")
        self.assertFalse(any(s.startswith("DROP DATABASE ") for s in statements))

    def test_ci_success_report_is_fresh_and_only_after_source_cleanup(self):
        code, records, _, events, report = self.run_ci()
        self.assertEqual(code, 0)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["result"], "OK")
        self.assertTrue(report["concurrent_source_write_isolated"])
        self.assertTrue(report["synthetic_source_removed"])
        self.assertEqual(events, ["source-drop", "positive-print"])

    def test_source_cleanup_failure_cannot_leave_positive_terminal_report(self):
        code, records, statements, events, report = self.run_ci(source_sessions="1")
        self.assertEqual(code, 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["cleanup_code"], "source_cleanup_failed")
        self.assertEqual(events, [])
        self.assertIsNone(report)
        self.assertFalse(any(s.startswith("DROP DATABASE ") for s in statements))
