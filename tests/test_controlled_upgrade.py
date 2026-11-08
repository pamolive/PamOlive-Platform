import copy
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import patch

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import SimpleTestCase, TransactionTestCase

from deploy import controlled_upgrade as upgrade
from deploy.prepare_upgrade_fixture import seed


class PreservationPrimitiveTests(SimpleTestCase):
    def test_microseconds_and_numeric_scale_are_not_silently_rounded(self):
        stamp = datetime(2026, 1, 1, microsecond=123456, tzinfo=UTC)
        self.assertNotEqual(
            upgrade.digest(stamp), upgrade.digest(stamp + timedelta(microseconds=1))
        )
        self.assertNotEqual(upgrade.digest(Decimal("1.00")), upgrade.digest(Decimal("1.0")))
        self.assertNotIn(b"private-binary", upgrade.canonical(b"private-binary"))

    def test_only_catalog_appends_are_allowed(self):
        original = {
            "identity_identity": dict(count=1, sha256="a", rows={}),
            "auth_permission": dict(count=1, sha256="b", rows={"1": "one"}),
        }
        after = copy.deepcopy(original)
        after["auth_permission"] = dict(count=2, sha256="c", rows={"1": "one", "2": "two"})
        upgrade.assert_preserved(original, after)
        for table, change in (
            ("identity_identity", dict(count=2)),
            ("auth_permission", dict(rows={"1": "changed"})),
        ):
            altered = copy.deepcopy(after)
            altered[table].update(change)
            with self.assertRaises(upgrade.UpgradeRefused):
                upgrade.assert_preserved(original, altered)

    def test_backward_unreviewed_and_nonatomic_migrations_are_rejected(self):
        loader = SimpleNamespace(graph=SimpleNamespace(leaf_nodes=lambda: []))
        for app, name, atomic, backwards in (
            ("other", "0001", True, False),
            ("access", "0010_observed_intervals", False, False),
            ("access", "0010_observed_intervals", True, True),
        ):
            migration = SimpleNamespace(app_label=app, name=name, atomic=atomic, operations=[])
            executor = SimpleNamespace(
                loader=loader, migration_plan=lambda _: [(migration, backwards)]
            )
            with self.assertRaises(upgrade.UpgradeRefused):
                upgrade.reviewed_plan(executor, "pamolive_platform")

    def test_upgrade_requires_explicit_offline_ack_before_any_database_call(self):
        with (
            self.assertRaises(upgrade.UpgradeRefused),
            patch.object(upgrade, "guard_database") as guard,
        ):
            upgrade.upgrade("pamolive_platform", {}, offline=False)
        guard.assert_not_called()

    def test_normal_schema_operations_do_not_escape_an_atomic_migration(self):
        from django.db import migrations

        migration = SimpleNamespace(
            app_label="access",
            name="0010_observed_intervals",
            atomic=True,
            operations=[migrations.AddField("accessevent", "example", None)],
            __module__="platform_modules.access.migrations.0010_observed_intervals",
        )
        self.assertFalse(migration.operations[0].atomic)
        executor = SimpleNamespace(
            loader=SimpleNamespace(graph=SimpleNamespace(leaf_nodes=lambda: [])),
            migration_plan=lambda _: [(migration, False)],
        )
        plan = upgrade.reviewed_plan(executor, "pamolive_platform")
        self.assertEqual(plan["migrations"][0]["migration"], migration.name)
        self.assertEqual(len(plan["migrations"][0]["sha256"]), 64)


@skipUnless(connection.vendor == "postgresql", "Transactional PostgreSQL DDL and preservation")
class ControlledUpgradeTests(TransactionTestCase):
    def setUp(self):
        self.latest = MigrationExecutor(connection).loader.graph.leaf_nodes()
        self.fixture_env = patch.dict("os.environ", PAMOLIVE_UPGRADE_FIXTURE="1")
        self.fixture_env.start()
        self.addCleanup(self.fixture_env.stop)
        seed()
        self.database = connection.settings_dict["NAME"]
        # Functional tests run on Django's disposable database. The independent
        # Docker gate uses an actual dedicated NOSUPERUSER login without this mock.
        self.guard = patch.object(upgrade, "guard_database")
        self.guard.start()
        self.addCleanup(self.guard.stop)
        self.approved = upgrade.make_plan(self.database)
        self.old_specs = upgrade.historical_specs(MigrationExecutor(connection))
        self.before = upgrade.snapshot(self.old_specs)
        self.schema_before = upgrade.schema_hash()

    def tearDown(self):
        MigrationExecutor(connection).migrate(self.latest)
        super().tearDown()

    def test_probe_rolls_back_schema_rows_journal_and_then_real_commit_preserves_history(self):
        probe = upgrade.upgrade(self.database, self.approved, offline=True, rollback_probe=True)
        self.assertFalse(probe["committed"])
        self.assertTrue(probe["rollback_schema_and_rows_verified"])
        self.assertEqual(upgrade.schema_hash(), self.schema_before)
        self.assertEqual(upgrade.snapshot(self.old_specs), self.before)
        report = upgrade.upgrade(self.database, self.approved, offline=True)
        self.assertTrue(report["committed"])
        self.assertEqual(report["migrations"], 8)
        self.assertEqual(report["new_models"], 12)
        upgrade.assert_preserved(self.before, upgrade.snapshot(self.old_specs, after=True))
        from platform_modules.access.models import AccessEvaluation, AccessEvent

        source = AccessEvent.unscoped.get()
        self.assertEqual(source.occurred_at.microsecond, 123456)
        self.assertIsNone(source.ended_at)
        old = AccessEvaluation.unscoped.get()
        self.assertEqual(
            (old.context, old.context_hash, old.signature, old.audit_id), ({}, "", "", None)
        )
        self.assertEqual(old.rule_version, "access-context/5")

    def test_changed_plan_is_refused_without_schema_or_data_changes(self):
        forged = copy.deepcopy(self.approved)
        forged["migrations"][0]["sha256"] = "0" * 64
        with self.assertRaises(upgrade.UpgradeRefused) as error:
            upgrade.upgrade(self.database, forged, offline=True)
        self.assertEqual(error.exception.code, "reviewed_plan_changed")
        self.assertEqual(upgrade.schema_hash(), self.schema_before)
        self.assertEqual(upgrade.snapshot(self.old_specs), self.before)

    def test_corruption_at_the_gate_rolls_back_the_whole_migration(self):
        from django.core.management import call_command

        from platform_core.models import Organization

        def migrate_then_corrupt(*args, **kwargs):
            call_command(*args, **kwargs)
            Organization.objects.filter(key="upgrade-fixture").update(name="Unapproved rewrite")

        with patch("django.core.management.call_command", side_effect=migrate_then_corrupt):
            with self.assertRaises(upgrade.UpgradeRefused) as error:
                upgrade.upgrade(self.database, self.approved, offline=True)
        self.assertEqual(error.exception.code, "historical_data_changed")
        self.assertTrue(error.exception.rollback_verified)
        self.assertEqual(upgrade.snapshot(self.old_specs), self.before)
        self.assertEqual(upgrade.schema_hash(), self.schema_before)

    def test_old_catalog_changes_are_not_confused_with_authorized_new_permissions(self):
        from django.contrib.auth.models import Permission
        from django.core.management import call_command

        def migrate_then_corrupt(*args, **kwargs):
            call_command(*args, **kwargs)
            Permission.objects.filter(pk=Permission.objects.order_by("pk").first().pk).update(
                name="Rewritten"
            )

        with patch("django.core.management.call_command", side_effect=migrate_then_corrupt):
            with self.assertRaises(upgrade.UpgradeRefused) as error:
                upgrade.upgrade(self.database, self.approved, offline=True)
        self.assertEqual(error.exception.code, "historical_catalog_changed")
        self.assertTrue(error.exception.rollback_verified)
        self.assertEqual(upgrade.snapshot(self.old_specs), self.before)

    def test_incorrect_historical_default_expectation_blocks_commit_and_preserves_old_schema(self):
        defaults = copy.deepcopy(upgrade.NEW_DEFAULTS)
        defaults["access_accessevent"]["ended_at"] = "not-null"
        with patch.object(upgrade, "NEW_DEFAULTS", defaults):
            with self.assertRaises(upgrade.UpgradeRefused) as error:
                upgrade.upgrade(self.database, self.approved, offline=True)
        self.assertEqual(error.exception.code, "historical_default_changed")
        self.assertTrue(error.exception.rollback_verified)
        self.assertEqual(upgrade.schema_hash(), self.schema_before)
