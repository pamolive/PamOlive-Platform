"""A waiting reader cannot retain module authority across disablement."""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase
from django.utils import timezone

from platform_core.access_contract import build_access_contract
from platform_core.models import Organization, OrganizationMembership
from platform_core.services import disable_module, install_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.identity.models import Identity, Resource


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row locks require PostgreSQL")
class AccessContractConcurrencyTests(TransactionTestCase):
    def waiting_read(self, mutation):
        admin = get_user_model().objects.create_superuser("p1-read-admin")
        actor = get_user_model().objects.create_user("p1-read-race")
        org = Organization.objects.create(key="p1-read-race", name="Synthetic read race")
        membership = OrganizationMembership.objects.create(
            organization=org, account=actor, role="auditor"
        )
        for key in ("identity", "access"):
            install_module(key, actor=admin, organization=org)
        with organization_context(org):
            identity = Identity.objects.create(organization=org, name="Synthetic subject")
            resource = Resource.objects.create(organization=org, name="Synthetic target")
            intent = AccessIntent.objects.create(
                organization=org, identity=identity, resource=resource, method="SSH",
                reason="Synthetic concurrency", requested_by=actor, starts_at=timezone.now(),
                ends_at=timezone.now() + timedelta(minutes=5),
            )
        started, pid = Event(), []

        def read():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    pid.append(cursor.fetchone()[0])
                started.set()
                with organization_context(org):
                    try:
                        build_access_contract(intent.pk, actor=actor, organization=org)
                    except PermissionDenied:
                        return "denied"
                return "read"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=org.pk)
                if mutation == "module":
                    disable_module("access", actor=admin, organization=org)
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
                    Event().wait(.02)
                self.assertTrue(locked)
            self.assertEqual(future.result(timeout=10), "denied")

    def test_waiting_read_denies_after_module_disable_commits(self):
        self.waiting_read("module")

    def test_waiting_read_denies_after_membership_revocation_commits(self):
        self.waiting_read("membership")

    def test_waiting_read_denies_after_account_deactivation_commits(self):
        self.waiting_read("account")
