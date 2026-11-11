"""PostgreSQL races and non-destructive migration rehearsal for directory evidence."""

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings

from platform_core.models import ModuleActivation, Organization
from platform_core.tenancy import organization_context
from platform_modules.connectors import directory_inventory as inventory
from platform_modules.connectors.directory_adapters import ReadResult
from platform_modules.connectors.directory_models import DirectoryRun

from .test_directory_inventory import DirectoryInventoryFixture


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL directory row locks")
@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class DirectoryInventoryConcurrencyTests(DirectoryInventoryFixture, TransactionTestCase):
    def independently(self, function):
        close_old_connections()
        try:
            with organization_context(self.org):
                return function()
        finally:
            connections.close_all()

    def test_duplicate_concurrent_snapshot_has_one_run(self):
        barrier = Barrier(2)

        def accept():
            barrier.wait(5)
            return self.accept().pk

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.independently, accept)
            second = pool.submit(self.independently, accept)
            self.assertEqual(first.result(timeout=15), second.result(timeout=15))
        self.assertEqual(DirectoryRun.objects.count(), 1)

    def test_rotation_during_network_read_refuses_acceptance(self):
        fetched, resume = Event(), Event()

        def adapter(**kwargs):
            kwargs["before_auth"]()
            fetched.set()
            if not resume.wait(10):
                raise RuntimeError("Synthetic read synchronization timeout")
            return ReadResult(self.records, False, 1, True, {}, ())

        def collect():
            try:
                return self.mutate(
                    inventory.collect_directory_inventory,
                    self.source.pk,
                    idempotency_key="network-race",
                    operator=True,
                )
            except PermissionDenied:
                return "denied"

        with (
            patch(
                "platform_modules.connectors.directory_adapters.read_directory", side_effect=adapter
            ),
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            future = pool.submit(self.independently, collect)
            self.assertTrue(fetched.wait(5))
            changed = dict(self.credential, password="synthetic-replacement-password")
            self.mutate(inventory.rotate_directory_credential, self.source.pk, credential=changed)
            resume.set()
            self.assertEqual(future.result(timeout=15), "denied")
        self.assertFalse(DirectoryRun.objects.exists())

    def test_waiting_reader_rechecks_committed_module_disablement(self):
        started, pid = Event(), []

        def read():
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                pid.append(cursor.fetchone()[0])
            started.set()
            try:
                return self.read()
            except PermissionDenied:
                return "denied"

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.pk)
                ModuleActivation.objects.filter(
                    organization=self.org, module_key="connectors"
                ).update(enabled=False)
                future = pool.submit(self.independently, read)
                self.assertTrue(started.wait(5))
                blocked, deadline = False, time.monotonic() + 5
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", [pid[0]]
                        )
                        row = cursor.fetchone()
                    if row and row[0] == "Lock":
                        blocked = True
                        break
                    Event().wait(0.02)
                self.assertTrue(blocked)
            self.assertEqual(future.result(timeout=15), "denied")

    def test_populated_executor_reverse_refused_before_any_schema_or_row_loss(self):
        self.accept()
        with self.assertRaises(RuntimeError):
            MigrationExecutor(connection).migrate([("connectors", "0011_scim_destination_binding")])
        self.assertIn("connectors_directoryrun", connection.introspection.table_names())
        self.assertEqual(DirectoryRun.objects.count(), 1)
        self.assertTrue(
            inventory.verify_directory_run(
                DirectoryRun.objects.select_related("source__audit", "audit").get()
            )
        )


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL directory migration guards")
class DirectoryInventoryMigrationTests(TransactionTestCase):
    def test_empty_downgrade_and_upgrade_preserves_prior_organization(self):
        org = Organization.objects.create(key="historical-directory", name="Historical synthetic")
        before = (org.pk, org.key, org.name)
        try:
            MigrationExecutor(connection).migrate([("connectors", "0011_scim_destination_binding")])
            self.assertNotIn("connectors_directoryrun", connection.introspection.table_names())
            self.assertEqual(
                tuple(
                    Organization.objects.filter(pk=org.pk).values_list("id", "key", "name").get()
                ),
                before,
            )
        finally:
            MigrationExecutor(connection).migrate([("connectors", "0012_directory_inventory")])
        self.assertIn("connectors_directoryrun", connection.introspection.table_names())
        self.assertEqual(
            tuple(Organization.objects.filter(pk=org.pk).values_list("id", "key", "name").get()),
            before,
        )
