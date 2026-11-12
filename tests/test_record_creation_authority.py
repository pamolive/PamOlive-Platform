"""A record writer waiting on PostgreSQL must lose revoked authority."""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from platform_core.models import AuditEvent, ModuleActivation, Organization, OrganizationMembership
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.access.services import create_record
from platform_modules.connectors.models import ExternalChange
from platform_modules.identity.models import ExternalAccount, Grant, Identity, Resource


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock proof requires PostgreSQL")
@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class RecordCreationAuthorityTests(TransactionTestCase):
    def exercise(self, kind, revocation):
        admin = get_user_model().objects.create_superuser("synthetic-record-admin")
        actor = get_user_model().objects.create_user("synthetic-record-operator")
        org = Organization.objects.create(key="synthetic-record-race", name="Synthetic race")
        member = OrganizationMembership.objects.create(
            organization=org, account=actor, role="operator"
        )
        for module in ("identity", "access", "connectors"):
            install_module(module, actor=admin, organization=org)
        with organization_context(org):
            identity = Identity.objects.create(organization=org, name="Synthetic subject")
            resource = Resource.objects.create(organization=org, name="Synthetic target")
            account = ExternalAccount.objects.create(
                organization=org, identity=identity, username="synthetic", system="Fixture"
            )
            now = timezone.now()
            data = dict(identity=identity, account=account, resource=resource, method="HTTPS")
            if kind == "intent":
                data.update(reason="Synthetic request", starts_at=now,
                            ends_at=now + timedelta(minutes=5), fulfillment="observe")
            else:
                data.update(entitlement="synthetic-reader", justification="Synthetic test",
                            valid_from=now, expires_at=now + timedelta(minutes=5))
            before = (AuditEvent.objects.count(), AccessIntent.objects.count(),
                      Grant.objects.count(), ExternalChange.objects.count())
        started, backend_pid = Event(), []

        def writer():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    backend_pid.append(cursor.fetchone()[0])
                started.set()
                with organization_context(org):
                    try:
                        return create_record(kind, data, actor=actor, organization=org).status
                    except PermissionDenied:
                        return "denied"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=org.pk)
                future = pool.submit(writer)
                self.assertTrue(started.wait(5))
                waited = False
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s",
                            [backend_pid[0]],
                        )
                        row = cursor.fetchone()
                    if row and row[0] == "Lock":
                        waited = True
                        break
                    Event().wait(.02)
                self.assertTrue(waited, "Writer must actually wait before revocation commits")
                if revocation == "actor":
                    get_user_model().objects.filter(pk=actor.pk).update(is_active=False)
                elif revocation == "membership":
                    OrganizationMembership.objects.filter(pk=member.pk).update(active=False)
                elif revocation == "module":
                    ModuleActivation.objects.filter(
                        organization=org, module_key="access" if kind == "intent" else "identity"
                    ).update(enabled=False)
                elif revocation == "organization":
                    Organization.objects.filter(pk=org.pk).update(active=False)
                else:
                    self.assertIsNone(revocation)
            result = future.result(timeout=10)
        with organization_context(org):
            after = (AuditEvent.objects.count(), AccessIntent.objects.count(),
                     Grant.objects.count(), ExternalChange.objects.count())
        if revocation is not None:
            self.assertEqual(result, "denied")
            self.assertEqual(after, before, "No record, effect or creation audit after denial")
        else:
            self.assertEqual(result, "pending" if kind == "intent" else "active")
            self.assertEqual(after[1 if kind == "intent" else 2],
                             before[1 if kind == "intent" else 2] + 1)

    def test_waiting_intent_denies_deactivated_actor(self):
        self.exercise("intent", "actor")

    def test_waiting_intent_denies_revoked_membership(self):
        self.exercise("intent", "membership")

    def test_waiting_intent_denies_disabled_access(self):
        self.exercise("intent", "module")

    def test_waiting_intent_denies_inactive_organization(self):
        self.exercise("intent", "organization")

    def test_waiting_grant_denies_deactivated_actor(self):
        self.exercise("grant", "actor")

    def test_waiting_grant_denies_revoked_membership(self):
        self.exercise("grant", "membership")

    def test_waiting_grant_denies_disabled_identity(self):
        self.exercise("grant", "module")

    def test_waiting_grant_denies_inactive_organization(self):
        self.exercise("grant", "organization")

    def test_waiting_authorized_intent_still_succeeds(self):
        self.exercise("intent", None)

    def test_waiting_authorized_grant_still_succeeds(self):
        self.exercise("grant", None)

    def tenant_isolation(self, revocation):
        admin = get_user_model().objects.create_superuser("synthetic-tenant-admin")
        actor = get_user_model().objects.create_user("synthetic-tenant-operator")
        orgs, data = [], []
        now = timezone.now()
        for label in ("a", "b"):
            org = Organization.objects.create(key="synthetic-tenant-" + label, name=label)
            orgs.append(org)
            OrganizationMembership.objects.create(
                organization=org, account=actor, role="operator"
            )
            for module in ("identity", "access"):
                install_module(module, actor=admin, organization=org)
            with organization_context(org):
                identity = Identity.objects.create(organization=org, name="Synthetic subject")
                resource = Resource.objects.create(organization=org, name="Synthetic target")
                data.append(dict(identity=identity, resource=resource, method="HTTPS",
                                 reason="Synthetic isolation", starts_at=now,
                                 ends_at=now + timedelta(minutes=5), fulfillment="observe"))
        if revocation == "membership":
            OrganizationMembership.objects.filter(organization=orgs[0], account=actor).update(
                active=False
            )
        else:
            ModuleActivation.objects.filter(organization=orgs[0], module_key="access").update(
                enabled=False
            )
        with organization_context(orgs[0]):
            with self.assertRaises(PermissionDenied):
                create_record("intent", data[0], actor=actor, organization=orgs[0])
            self.assertFalse(AccessIntent.objects.exists())
        with organization_context(orgs[1]):
            intent = create_record("intent", data[1], actor=actor, organization=orgs[1])
            self.assertEqual(intent.status, "pending")
            self.assertEqual(intent.organization_id, orgs[1].pk)
            self.assertEqual(intent.requested_by_id, actor.pk)
            self.assertEqual(AccessIntent.objects.count(), 1)
            self.assertFalse(Grant.objects.exists())
            self.assertFalse(ExternalChange.objects.exists())

    def test_membership_revocation_is_local_to_its_organization(self):
        self.tenant_isolation("membership")

    def test_module_revocation_is_local_to_its_organization(self):
        self.tenant_isolation("module")
