"""Real row-lock races for Identity 360 and synthetic reconciliation readers."""

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase, override_settings

from platform_core.models import Organization, OrganizationMembership
from platform_core.services import disable_module, install_module
from platform_core.tenancy import organization_context
from platform_modules.identity.directory_simulation import preview_reconciliation
from platform_modules.identity.identity360 import build_identity360
from platform_modules.identity.models import Identity


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row locks require PostgreSQL")
@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class Identity360ConcurrencyTests(TransactionTestCase):
    def waiting_read(self, mutation, *, preview=False):
        admin = get_user_model().objects.create_superuser("identity360-race-admin")
        actor = get_user_model().objects.create_user("identity360-race-reader")
        organization = Organization.objects.create(key="identity360-race", name="Synthetic race")
        membership = OrganizationMembership.objects.create(
            organization=organization, account=actor, role="auditor"
        )
        for module in (("identity", "access", "connectors") if preview else ("identity",)):
            install_module(module, actor=admin, organization=organization)
        with organization_context(organization):
            identity = Identity.objects.create(organization=organization, name="Synthetic subject")
        started, pid = Event(), []

        def read():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    pid.append(cursor.fetchone()[0])
                started.set()
                with organization_context(organization):
                    try:
                        if preview:
                            preview_reconciliation(
                                provider="ad",
                                source_id="synthetic-source",
                                records=[],
                                mapping={},
                                synthetic=True,
                                actor=actor,
                                organization=organization,
                            )
                        else:
                            build_identity360(identity.pk, actor=actor, organization=organization)
                    except PermissionDenied:
                        return "denied"
                return "read"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=organization.pk)
                if mutation == "identity":
                    disable_module("identity", actor=admin, organization=organization)
                elif mutation == "connectors":
                    disable_module("connectors", actor=admin, organization=organization)
                elif mutation == "membership":
                    OrganizationMembership.objects.filter(pk=membership.pk).update(active=False)
                else:
                    get_user_model().objects.filter(pk=actor.pk).update(is_active=False)
                future = pool.submit(read)
                self.assertTrue(started.wait(5))
                locked = False
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", [pid[0]]
                        )
                        row = cursor.fetchone()
                    if row and row[0] == "Lock":
                        locked = True
                        break
                    Event().wait(0.02)
                self.assertTrue(locked)
            self.assertEqual(future.result(timeout=10), "denied")

    def test_identity_module_disable_while_read_waits(self):
        self.waiting_read("identity")

    def test_membership_revocation_while_read_waits(self):
        self.waiting_read("membership")

    def test_account_deactivation_while_read_waits(self):
        self.waiting_read("account")

    def test_connect_disable_while_preview_waits(self):
        self.waiting_read("connectors", preview=True)
