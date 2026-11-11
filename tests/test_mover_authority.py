"""A cached portal account must never retain business-role/JML authority."""

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings

from platform_core.authorization import recent_authentication
from platform_core.models import (
    AccountSecurity,
    ModuleActivation,
    Organization,
    OrganizationMembership,
)
from platform_core.tenancy import organization_context
from platform_modules.identity.mover import publish_role
from platform_modules.identity.mover_models import MoveDecision, MoveProposal, RoleRevision

from . import test_mover
from . import test_platform as fixture


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class MoverAuthorityTests(test_mover.MoverFixture, TestCase):
    def test_stale_disabled_administrator_cannot_publish_verified_role(self):
        get_user_model().objects.filter(pk=self.admin.pk).update(is_active=False)
        self.assertTrue(self.admin.is_active)
        with self.assertRaises(PermissionDenied):
            self.role()
        self.assertFalse(RoleRevision.objects.exists())

    def test_stale_superuser_cannot_keep_removed_platform_authority(self):
        get_user_model().objects.filter(pk=self.admin.pk).update(is_superuser=False)
        OrganizationMembership.objects.filter(organization=self.org, account=self.admin).update(
            role="auditor"
        )
        self.assertTrue(self.admin.is_superuser)
        with self.assertRaises(PermissionDenied):
            self.role()
        self.assertFalse(RoleRevision.objects.exists())

    def test_inactive_organization_cannot_publish_role_through_cached_context(self):
        Organization.objects.filter(pk=self.org.pk).update(active=False)
        self.assertTrue(self.org.active)
        with self.assertRaises(PermissionDenied):
            self.role()

    def test_deactivated_requester_cannot_propose_a_move(self):
        role = self.role()
        get_user_model().objects.filter(pk=self.operator.pk).update(is_active=False)
        with self.assertRaises(PermissionDenied):
            self.proposal({role.pk: [self.account.pk]})
        self.assertFalse(MoveProposal.objects.exists())

    def test_deactivated_reviewer_cannot_apply_a_move(self):
        role = self.role()
        proposal = self.proposal({role.pk: [self.account.pk]})
        get_user_model().objects.filter(pk=self.reviewer.pk).update(is_active=False)
        with self.assertRaises(PermissionDenied):
            self.apply(proposal)
        self.assertFalse(MoveDecision.objects.exists())

    def test_publication_keeps_recent_mfa_requirement(self):
        with self.assertRaises(PermissionDenied):
            publish_role(
                key="no-assurance",
                name="Synthetic no assurance",
                enabled=True,
                expected_revision=0,
                entries=[dict(resource=self.resource.pk, method="SSO", privilege="read", days=1)],
                actor=self.admin,
                organization=self.org,
            )
        self.assertFalse(RoleRevision.objects.exists())


@skipUnless(connection.vendor == "postgresql", "PostgreSQL mover row-lock races")
@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class MoverAuthorityConcurrencyTests(TransactionTestCase):
    def setUp(self):
        fixture.PlatformTests.setUp(self)
        self.publisher = get_user_model().objects.create_user("synthetic-mover-publisher")
        self.membership = OrganizationMembership.objects.create(
            organization=self.org, account=self.publisher, role="admin"
        )
        AccountSecurity.objects.create(
            account=self.publisher, encrypted_secret="synthetic-factor-reference"
        )

    def waiting_publication(self, mutation):
        started, pid = Event(), []

        def publish():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    pid.append(cursor.fetchone()[0])
                started.set()
                with (
                    organization_context(self.org),
                    recent_authentication(self.publisher, self.org, time.time()),
                ):
                    try:
                        publish_role(
                            key="waiting-publisher",
                            name="Synthetic waiting role",
                            enabled=True,
                            expected_revision=0,
                            entries=[
                                dict(
                                    resource=self.resource.pk,
                                    method="SSO",
                                    privilege="read",
                                    days=1,
                                )
                            ],
                            actor=self.publisher,
                            organization=self.org,
                        )
                    except PermissionDenied:
                        return "denied"
                return "published"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.pk)
                if mutation == "role":
                    OrganizationMembership.objects.filter(pk=self.membership.pk).update(
                        role="auditor"
                    )
                elif mutation == "module":
                    ModuleActivation.objects.filter(
                        organization=self.org, module_key="identity"
                    ).update(enabled=False)
                else:
                    get_user_model().objects.filter(pk=self.publisher.pk).update(is_active=False)
                future = pool.submit(publish)
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
        self.assertFalse(RoleRevision.objects.exists())

    def test_publisher_role_revocation_while_waiting_is_enforced(self):
        self.waiting_publication("role")

    def test_publisher_account_deactivation_while_waiting_is_enforced(self):
        self.waiting_publication("account")

    def test_identity_disablement_while_publisher_waits_is_enforced(self):
        self.waiting_publication("module")
