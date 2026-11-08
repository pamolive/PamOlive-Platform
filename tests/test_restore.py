import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
from urllib.parse import urlsplit

from cryptography.fernet import InvalidToken
from django.contrib.auth import get_user_model
from django.test import TransactionTestCase, override_settings

from deploy.check_restore import RestoreQualification, compose_client, identifier, scram_verifier
from deploy.restore_application_check import (
    FORMAT,
    compare_manifest,
    database_guard,
    key_probe,
    model_fingerprints,
    restore_url,
    verify_application,
)
from platform_core.models import BusinessRole
from platform_core.security import cipher

DATABASE = "pamolive_restore_check_0123456789abcdef"


class RestoreGuardTests(TestCase):
    def test_application_client_uses_deployment_env_parser_without_host_control_overrides(self):
        from pathlib import Path

        with patch.dict("os.environ", {"DOCKER_HOST": "operator-selected-daemon"}):
            command, environment = compose_client(
                "docker",
                "image",
                Path("private.env"),
                "private-network",
                Path("reviewed.py"),
                "pamolive-restore-test",
            )
        self.assertEqual(command[:2], ["docker", "compose"])
        self.assertIn("--env-file", command)
        self.assertIn("compose.restore-check.yml", " ".join(command))
        self.assertEqual(environment["DOCKER_HOST"], "operator-selected-daemon")
        self.assertNotIn("SECRET_KEY", " ".join(command))

    def test_sql_identifiers_and_temporary_scram_verifiers_are_bounded(self):
        self.assertEqual(identifier(DATABASE), '"' + DATABASE + '"')
        for value in ("postgres; DROP DATABASE postgres", "test-name", "a" * 64, "../live"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                identifier(value)
        password = "temporary-test-only-password"
        verifier = scram_verifier(password)
        self.assertTrue(verifier.startswith("SCRAM-SHA-256$4096:"))
        self.assertNotIn(password, verifier)

    def test_cleanup_requires_created_object_identity_and_no_live_session(self):
        for state in ("different_role", "different_owner", "active_session", "unconfirmed"):
            check = RestoreQualification(SimpleNamespace())
            check.role_created = check.database_created = True
            check.role_oid, check.database_oid = 10, 20
            replies = {
                "different_role": ["11"],
                "different_owner": ["10", "", "20:99"],
                "active_session": ["10", "", "20:10", "1"],
                "unconfirmed": [],
            }
            if state == "unconfirmed":
                check.role_oid = None
            with patch.object(check, "sql", side_effect=replies[state]) as sql:
                with self.subTest(state=state), self.assertRaises(RuntimeError):
                    check.cleanup()
                self.assertFalse(any("DROP " in call.args[0] for call in sql.call_args_list))
            self.assertTrue(check.database_created)

    def test_cleanup_only_drops_its_verified_fresh_copy_and_role(self):
        check = RestoreQualification(SimpleNamespace())
        check.role_created = check.database_created = True
        check.role_oid, check.database_oid = 10, 20
        with patch.object(check, "sql", side_effect=["10", "", "20:10", "0", "", ""]) as sql:
            check.cleanup()
        commands = [call.args[0] for call in sql.call_args_list]
        self.assertIn("DROP DATABASE " + identifier(check.database) + ";", commands)
        self.assertIn("DROP ROLE " + identifier(check.role) + ";", commands)
        self.assertFalse(
            any("DROP OWNED" in command or "TERMINATE" in command for command in commands)
        )
        self.assertFalse(check.database_created or check.role_created)

    def test_restore_uri_never_keeps_source_credentials_or_database_routing(self):
        uri = restore_url(
            "postgresql://live:private@[::1]:5432/pamolive?sslmode=verify-full",
            DATABASE,
            DATABASE + "_role",
            "temporary$secret",
        )
        parsed = urlsplit(uri)
        self.assertEqual(parsed.path, "/" + DATABASE)
        self.assertEqual(parsed.username, DATABASE + "_role")
        self.assertEqual(parsed.hostname, "::1")
        self.assertEqual(parsed.query, "sslmode=verify-full")
        self.assertNotIn("live:private", uri)
        for target, role in (
            ("pamolive_platform", "admin"),
            (DATABASE, "postgres"),
            (DATABASE, "pamolive_restore_check_ffffffffffffffff_role"),
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                restore_url("postgresql://x:y@host/live", target, role, "test")
        for suffix in ("?dbname=live", "?service=live", "?servicefile=/secret"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                restore_url(
                    "postgresql://x:y@host/live" + suffix, DATABASE, DATABASE + "_role", "test"
                )

    def test_live_database_is_refused_before_any_probe_write(self):
        with self.assertRaises(RuntimeError):
            database_guard("pamolive_platform", restored=True)
        with self.assertRaises(RuntimeError):
            verify_application()

    def test_archive_bound_key_companion_fails_with_a_different_key(self):
        probe = key_probe("a" * 64)
        value = cipher().decrypt(probe["ciphertext"].encode())
        self.assertTrue(value.startswith(b"pamolive.restore-key.v1\0" + b"a" * 64))
        with override_settings(PAMOLIVE_ENCRYPTION_KEY="deliberately-wrong-qualification-key"):
            with self.assertRaises(InvalidToken):
                cipher().decrypt(probe["ciphertext"].encode())

    def test_manifest_mismatch_is_never_reported_as_success(self):
        with patch(
            "deploy.restore_application_check.model_fingerprints", return_value={"a": {"count": 2}}
        ):
            with self.assertRaises(RuntimeError):
                compare_manifest({"format": FORMAT, "fingerprints": {"a": {"count": 1}}})
            self.assertEqual(
                compare_manifest({"format": FORMAT, "fingerprints": {"a": {"count": 2}}}),
                {"models_compared": 1, "full_managed_model_manifest": True},
            )
        with self.assertRaises(RuntimeError):
            compare_manifest({"format": "unrecognized"})


class RestoreManifestTests(TransactionTestCase):
    def test_implicit_memberships_and_migration_rows_are_in_the_manifest(self):
        user = get_user_model().objects.create_user("restore-membership-fixture")
        role = BusinessRole.objects.create(key="restore-role", name="Restore role")
        before = model_fingerprints()
        role.members.add(user)
        after = model_fingerprints()
        label = BusinessRole.members.through._meta.label
        self.assertIn(label, before)
        self.assertIn("migrations.Migration", before)
        self.assertEqual(before[label]["count"], 0)
        self.assertEqual(after[label]["count"], 1)
        self.assertNotEqual(before[label]["sha256"], after[label]["sha256"])
        self.assertEqual(before["platform_core.BusinessRole"], after["platform_core.BusinessRole"])
        self.assertNotIn("restore-membership-fixture", json.dumps(after))

    def test_historical_manifest_is_explicitly_partial_not_silently_upgraded(self):
        label = "platform_core.BusinessRole"
        expected = model_fingerprints(legacy_labels={label})
        result = compare_manifest({"format": "pamolive-preservation/1", "fingerprints": expected})
        self.assertEqual(result, {"models_compared": 1, "full_managed_model_manifest": False})
        with self.assertRaises(RuntimeError):
            model_fingerprints(legacy_labels={"unrecognized.Model"})
