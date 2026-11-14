"""PostgreSQL ordering of review reads against administrative authority changes."""

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest import skipUnless

from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase, override_settings

from platform_core.models import ModuleActivation, Organization, OrganizationMembership
from platform_core.tenancy import organization_context
from platform_modules.connectors import directory_inventory as inventory

from .test_directory_reconciliation import ReconciliationFixture


@skipUnless(connection.vendor == "postgresql", "Directory review PostgreSQL row-lock races")
@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class DirectoryReconciliationConcurrencyTests(ReconciliationFixture, TransactionTestCase):
    def waiting_read(self, mutation):
        started, pid = Event(), []

        def read():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    pid.append(cursor.fetchone()[0])
                started.set()
                with organization_context(self.org):
                    try:
                        return self.review()
                    except PermissionDenied:
                        return "denied"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.pk)
                mutation()
                future = pool.submit(read)
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
            return future.result(timeout=15)

    def test_waiting_review_refuses_committed_connect_module_disable(self):
        result = self.waiting_read(
            lambda: ModuleActivation.objects.filter(
                organization=self.org, module_key="connectors"
            ).update(enabled=False)
        )
        self.assertEqual(result, "denied")

    def test_waiting_review_refuses_committed_identity_module_disable(self):
        result = self.waiting_read(
            lambda: ModuleActivation.objects.filter(
                organization=self.org, module_key="identity"
            ).update(enabled=False)
        )
        self.assertEqual(result, "denied")

    def test_waiting_review_refuses_committed_membership_revocation(self):
        result = self.waiting_read(
            lambda: OrganizationMembership.objects.filter(
                organization=self.org, account=self.operator
            ).update(active=False)
        )
        self.assertEqual(result, "denied")

    def test_waiting_review_refuses_committed_account_deactivation(self):
        result = self.waiting_read(
            lambda: self.operator.__class__.objects.filter(pk=self.operator.pk).update(
                is_active=False
            )
        )
        self.assertEqual(result, "denied")

    def test_waiting_review_uses_new_revocation_without_inheriting_old_scim_links(self):
        result = self.waiting_read(
            lambda: self.mutate(inventory.revoke_directory_mapping, self.mapping.pk)
        )
        self.assertIsNone(result["items"][0]["local_account"])
        self.assertEqual(
            result["scim_history"]["operations"]["availability"], "no_explicit_account_link"
        )
