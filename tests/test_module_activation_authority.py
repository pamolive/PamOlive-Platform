"""Module administration cannot retain stale account or membership authority."""

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase

from platform_core.models import ModuleActivation, Organization, OrganizationMembership
from platform_core.services import disable_module, install_module


class ActivationFixture:
    def setUp(self):
        self.actor = get_user_model().objects.create_user("synthetic-module-admin")
        self.org = Organization.objects.create(key="module-authority", name="Synthetic authority")
        self.member = OrganizationMembership.objects.create(
            organization=self.org, account=self.actor, role="admin"
        )
        install_module("identity", actor=self.actor, organization=self.org)

    def operation(self, enable):
        return (install_module if enable else disable_module)(
            "identity", actor=self.actor, organization=self.org
        )


class ModuleActivationAuthorityTests(ActivationFixture, TestCase):
    def test_disabled_cached_account_cannot_enable_or_disable(self):
        get_user_model().objects.filter(pk=self.actor.pk).update(is_active=False)
        self.assertTrue(self.actor.is_active)
        for enable in (True, False):
            with self.subTest(enable=enable), self.assertRaises(PermissionDenied):
                self.operation(enable)
        self.assertTrue(ModuleActivation.objects.get(organization=self.org).enabled)


@skipUnless(connection.vendor == "postgresql", "PostgreSQL lock race requires PostgreSQL")
class ModuleActivationRaceTests(ActivationFixture, TransactionTestCase):
    def waiting_operation(self, enable):
        started, worker_pid = Event(), []

        def worker():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    worker_pid.append(cursor.fetchone()[0])
                started.set()
                try:
                    self.operation(enable)
                except PermissionDenied:
                    return "denied"
                return "committed"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.pk)
                future = pool.submit(worker)
                self.assertTrue(started.wait(5))
                deadline = time.monotonic() + 5
                blocked = False
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s",
                                       [worker_pid[0]])
                        row = cursor.fetchone()
                    if row and row[0] == "Lock":
                        blocked = True
                        break
                    Event().wait(0.02)
                self.assertTrue(blocked)
                OrganizationMembership.objects.filter(pk=self.member.pk).update(role="auditor")
            self.assertEqual(future.result(timeout=10), "denied")
        self.assertTrue(ModuleActivation.objects.get(organization=self.org).enabled)

    def test_waiting_enable_rechecks_revoked_admin_role(self):
        self.waiting_operation(True)

    def test_waiting_disable_rechecks_revoked_admin_role(self):
        self.waiting_operation(False)
