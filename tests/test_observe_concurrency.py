"""A reader waiting on the tenant lock must lose revoked Observe authority."""

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest import skipUnless

from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase, override_settings

from platform_core.models import ModuleActivation, Organization, OrganizationMembership
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.access.observe import observation_story

from . import test_platform as baseline


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row locks require PostgreSQL")
@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class ObserveConcurrencyTests(TransactionTestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        install_module("intelligence", actor=self.admin, organization=self.org)
        self.event = baseline.PlatformTests.event(self)

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
                        observation_story(self.event.pk, actor=self.operator, organization=self.org)
                    except PermissionDenied:
                        return "denied"
                return "read"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.pk)
                if mutation == "module":
                    ModuleActivation.objects.filter(
                        organization=self.org, module_key="intelligence"
                    ).update(enabled=False)
                else:
                    OrganizationMembership.objects.filter(
                        organization=self.org, account=self.operator
                    ).update(active=False)
                future = pool.submit(read)
                self.assertTrue(started.wait(5))
                deadline, locked = time.monotonic() + 5, False
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", [pid[0]]
                        )
                        row = cursor.fetchone()
                    if row and row[0] == "Lock":
                        locked = True
                        break
                    Event().wait(.02)
                self.assertTrue(locked)
            self.assertEqual(future.result(timeout=10), "denied")

    def test_module_disabled_while_waiting_denies_read(self):
        self.waiting_read("module")

    def test_membership_revoked_while_waiting_denies_read(self):
        self.waiting_read("membership")
