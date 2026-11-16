"""Adversarial tests of the public projection, not restore or cryptography tests."""

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from deploy.restore_public_report import (
    public_restore_report,
    write_public_restore_report,
)


def synthetic_report():
    return {
        "application_image": "sha256:" + "a" * 64,
        "archive_bytes": 1000,
        "archive_sha256": "b" * 64,
        "audit_valid": True,
        "certificate_possession_proofs_checked": 1,
        "concurrent_source_write_isolated": True,
        "directory_evidence_checked": {
            "encrypted_values": 2,
            "facts": 3,
            "mappings": 4,
            "runs": 3,
            "sources": 2,
        },
        "encrypted_values_checked": 15,
        "full_managed_model_manifest": True,
        "governance_exception_proofs_checked": 3,
        "isolated_copy_removed": True,
        "key_companion_verified": True,
        "models_compared": 106,
        "pam_live_trust_requires_independent_current_checkpoint": True,
        "pam_trust_registries_verified": 1,
        "pam_personal_authorizations_verified": 2,
        "legacy_events_checked": 1,
        "legacy_v7_evaluations_checked": 1,
        "pending_migrations": 0,
        "permanent_containers_added": 0,
        "postgresql_audit_guard": True,
        "production_database_replaced": False,
        "provenance_receipts_checked": 3,
        "result": "OK",
        "safe_to_serve": False,
        "sealed_captures_verified": 1,
        "seconds": 14.37,
        "signed_proofs_checked": 75,
        "source_archive_unchanged": True,
        "temporary_role_removed": True,
        "unsealed_captures": 0,
        "wrong_database_password_refused": True,
        "wrong_key_refused": True,
        "synthetic_source_removed": True,
    }


class PublicRestoreReportTests(unittest.TestCase):
    def test_closed_roundtrip_does_not_mutate_input_or_infer_live_trust(self):
        original = synthetic_report()
        before = copy.deepcopy(original)
        projected = public_restore_report(original)
        self.assertEqual(original, before)
        self.assertFalse(projected["safe_to_serve"])
        self.assertEqual(projected["qualification_scope"], "synthetic_restore_only")
        self.assertEqual(projected["schema"], "pamolive.synthetic-restore-report/1")
        projected["directory_evidence_checked"]["facts"] = 900
        self.assertEqual(original["directory_evidence_checked"]["facts"], 3)

    def test_unknown_private_fields_and_missing_fields_fail_closed_without_stringification(
        self,
    ):
        class Private:
            def __str__(self):
                raise AssertionError("must_not_stringify_private_value")

        for field in ("error", "password", "private_key", "environment", "raw_stdout"):
            report = synthetic_report()
            report[field] = Private()
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "_fields$"),
            ):
                public_restore_report(report)
        for field in synthetic_report():
            report = synthetic_report()
            del report[field]
            with (
                self.subTest(missing=field),
                self.assertRaisesRegex(ValueError, "_fields$"),
            ):
                public_restore_report(report)

    def test_count_types_bounds_and_boolean_numeric_confusion_are_rejected(self):
        for value in (True, False, -1, 1.0, "1", None, 2**63):
            report = synthetic_report()
            report["models_compared"] = value
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "_count$"),
            ):
                public_restore_report(report)

    def test_cleanup_key_refusal_and_scope_flags_are_exact_booleans(self):
        for field in (
            "synthetic_source_removed",
            "temporary_role_removed",
            "isolated_copy_removed",
            "wrong_key_refused",
            "wrong_database_password_refused",
            "key_companion_verified",
            "audit_valid",
            "concurrent_source_write_isolated",
            "full_managed_model_manifest",
            "pam_live_trust_requires_independent_current_checkpoint",
            "postgresql_audit_guard",
            "source_archive_unchanged",
            "safe_to_serve",
            "production_database_replaced",
        ):
            for value in (0, 1, None, "true"):
                report = synthetic_report()
                report[field] = value
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    public_restore_report(report)
            report = synthetic_report()
            report[field] = not report[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                public_restore_report(report)

    def test_incomplete_or_failed_qualification_does_not_create_positive_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.json"
            for field, value in (
                ("result", "failed"),
                ("synthetic_source_removed", False),
                ("pending_migrations", 1),
                ("unsealed_captures", 1),
                ("permanent_containers_added", 1),
            ):
                report = synthetic_report()
                report[field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    write_public_restore_report(report, path)
                self.assertFalse(path.exists())

    def test_digests_are_only_fixed_public_identities(self):
        for field in ("archive_sha256", "application_image"):
            for value in (
                None,
                "https://host/private",
                "c" * 63,
                "A" * 64,
                "\n" + "a" * 64,
            ):
                report = synthetic_report()
                report[field] = value
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    public_restore_report(report)

    def test_nonfinite_or_unbounded_seconds_are_rejected(self):
        for value in (
            True,
            None,
            "1",
            -1,
            float("nan"),
            float("inf"),
            10**1000,
            -float("inf"),
            86401,
        ):
            report = synthetic_report()
            report["seconds"] = value
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "_seconds$"),
            ):
                public_restore_report(report)

    def test_nested_projection_rejects_unknown_data_and_types(self):
        for directory in (
            {"password": "synthetic"},
            {"encrypted_values": 1},
            dict(synthetic_report()["directory_evidence_checked"], facts=True),
            dict(synthetic_report()["directory_evidence_checked"], facts=-1),
        ):
            report = synthetic_report()
            report["directory_evidence_checked"] = directory
            with (
                self.subTest(directory=directory),
                self.assertRaisesRegex(ValueError, "_directory$"),
            ):
                public_restore_report(report)

    def test_exclusive_public_file_contains_only_typed_json_and_does_not_overwrite(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.json"
            write_public_restore_report(synthetic_report(), path)
            original = path.read_bytes()
            self.assertLess(len(original), 16384)
            self.assertTrue(original.endswith(b"\n"))
            self.assertEqual(json.loads(original), public_restore_report(synthetic_report()))
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_public_restore_report(synthetic_report(), path)
            self.assertEqual(path.read_bytes(), original)

    def test_writer_never_creates_directories_or_copies_private_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private.dump"
            private.write_bytes(b"synthetic-private-canary")
            with self.assertRaises(FileNotFoundError):
                write_public_restore_report(synthetic_report(), root / "absent" / "public.json")
            self.assertEqual(private.read_bytes(), b"synthetic-private-canary")
            self.assertEqual({p.name for p in root.iterdir()}, {"private.dump"})

    def test_ci_public_export_command_has_closed_shell_quoting_and_no_private_tree(
        self,
    ):
        import shlex

        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
        lines = workflow.read_text(encoding="utf-8").splitlines()
        commands = [line.strip() for line in lines if "python -m deploy.check_restore_ci " in line]
        self.assertEqual(len(commands), 1)
        tokens = shlex.split(commands[0], posix=True)
        self.assertEqual(tokens[:3], ["python", "-m", "deploy.check_restore_ci"])
        self.assertEqual(tokens.count("--public-report"), 1)
        self.assertEqual(
            tokens[tokens.index("--public-report") + 1],
            "$RUNNER_TEMP/pamolive-image-security/restore-qualification.json",
        )
        self.assertEqual(
            tokens[-1],
            "$RUNNER_TEMP/pamolive-image-security/restore-qualification.json",
        )
