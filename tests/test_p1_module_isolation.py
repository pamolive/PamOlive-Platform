"""P1-B1 capability isolation without suppressing mandatory safety withdrawal."""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.authorization import recent_authentication
from platform_core.events import process_events, publish_domain_event
from platform_core.memberships import set_membership
from platform_core.models import (
    AccountSecurity,
    ModuleActivation,
    ModuleEvent,
    Organization,
    OrganizationMembership,
)
from platform_core.services import disable_module, install_module, lock_authorized_actor
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.approvals.models import ApprovalDecision
from platform_modules.approvals.services import decide
from platform_modules.connectors.models import ExternalChange
from platform_modules.identity.models import ExternalAccount, Grant, Identity, Resource
from platform_modules.identity.services import expire_grants, grant_from_approval
from platform_modules.recertification.models import Review
from platform_modules.recertification.services import review_grant, start_campaign

from . import test_module_events as event_baseline


class ModuleCapabilityIsolationTests(TestCase):
    def setUp(self):
        users = get_user_model()
        self.admin = users.objects.create_superuser("p1-isolation-admin")
        self.requester = users.objects.create_user("p1-isolation-requester")
        self.reviewer = users.objects.create_user("p1-isolation-reviewer")
        self.first = Organization.objects.create(key="p1-isolation-a", name="A")
        self.second = Organization.objects.create(key="p1-isolation-b", name="B")
        OrganizationMembership.objects.create(
            organization=self.first, account=self.reviewer, role="reviewer"
        )
        for org in (self.first, self.second):
            for key in ("identity", "access", "approvals", "connectors"):
                install_module(key, actor=self.admin, organization=org)
        self.context = organization_context(self.first)
        self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)

    def approved_intent(self, org):
        with organization_context(org):
            identity = Identity.objects.create(organization=org, name="Synthetic person")
            resource = Resource.objects.create(organization=org, name="Synthetic resource")
            account = ExternalAccount.objects.create(
                organization=org, identity=identity, username="synthetic-account", system="fixture"
            )
            intent = AccessIntent.objects.create(
                organization=org, identity=identity, account=account, resource=resource,
                method="SSH", privilege="read", reason="Synthetic scope", fulfillment="iam_group",
                starts_at=timezone.now() - timedelta(minutes=1),
                ends_at=timezone.now() + timedelta(minutes=5),
                requested_by=self.requester, status="approved", approved_at=timezone.now(),
            )
            ApprovalDecision.objects.create(
                organization=org, intent=intent, reviewer=self.admin,
                approved=True, comment="Synthetic approval",
            )
            return intent

    def test_direct_grant_service_cannot_bypass_disabled_approval_capability(self):
        first, second = self.approved_intent(self.first), self.approved_intent(self.second)
        disable_module("approvals", actor=self.admin, organization=self.first)
        with self.assertRaises(PermissionDenied):
            grant_from_approval(first, actor=self.admin, organization=self.first)
        with organization_context(self.second):
            grant = grant_from_approval(second, actor=self.admin, organization=self.second)
            self.assertEqual(grant.organization_id, self.second.pk)
        self.assertFalse(Grant.objects.exists())

    def test_membership_in_one_tenant_does_not_authorize_grant_service_in_another(self):
        intent = self.approved_intent(self.second)
        with organization_context(self.second), self.assertRaises(PermissionDenied):
            grant_from_approval(intent, actor=self.reviewer, organization=self.second)
        self.assertFalse(Grant.unscoped.exists())

    def test_stale_account_and_organization_objects_cannot_preserve_authority(self):
        intent = self.approved_intent(self.first)
        get_user_model().objects.filter(pk=self.admin.pk).update(is_active=False)
        with self.assertRaises(PermissionDenied):
            grant_from_approval(intent, actor=self.admin, organization=self.first)
        get_user_model().objects.filter(pk=self.admin.pk).update(is_active=True, is_superuser=False)
        with self.assertRaises(PermissionDenied):
            grant_from_approval(intent, actor=self.admin, organization=self.first)
        get_user_model().objects.filter(pk=self.admin.pk).update(is_superuser=True)
        Organization.objects.filter(pk=self.first.pk).update(active=False)
        with self.assertRaises(PermissionDenied):
            grant_from_approval(intent, actor=self.admin, organization=self.first)
        self.assertFalse(Grant.unscoped.exists())

    def test_disabled_review_module_denies_direct_service_before_reading_scope(self):
        install_module("recertification", actor=self.admin, organization=self.first)
        disable_module("recertification", actor=self.admin, organization=self.first)
        with self.assertRaises(PermissionDenied):
            review_grant(
                uuid4(), actor=self.admin, organization=self.first,
                keep=True, comment="Synthetic decision",
            )

    def test_disabled_connector_does_not_leak_execution_rows_through_identity_detail(self):
        intent = self.approved_intent(self.first)
        change = ExternalChange.objects.create(
            organization=self.first, account=intent.account, kind="disable_account",
            idempotency_key="p1-synthetic-pending", status="blocked",
        )
        self.client.force_login(self.admin)
        session = self.client.session
        session["organization_id"] = str(self.first.pk)
        session.save()
        url = reverse("record-detail", args=["identity", intent.identity_id])
        self.assertEqual(list(self.client.get(url).context["external_changes"]), [change])
        disable_module("connectors", actor=self.admin, organization=self.first)
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(list(result.context["external_changes"]), [])
        self.assertTrue(ExternalChange.objects.filter(pk=change.pk).exists())
        self.assertEqual(self.client.get(reverse("connectors-home")).status_code, 403)
        self.assertEqual(
            self.client.get(reverse("record-detail", args=["identity", self.approved_intent(
                self.second
            ).identity_id])).status_code,
            404,
        )

    def test_safety_expiry_still_revokes_when_identity_capability_is_disabled(self):
        intent = self.approved_intent(self.first)
        grant = Grant.objects.create(
            organization=self.first, identity=intent.identity, account=intent.account,
            resource=intent.resource, entitlement="read", justification="Synthetic expired grant",
            valid_from=timezone.now() - timedelta(minutes=1),
            expires_at=timezone.now() - timedelta(seconds=1),
        )
        # Existing dependents cannot be disabled via the public admin operation;
        # a restored/stale disabled activation must still not suspend expiry.
        ModuleActivation.objects.filter(
            organization=self.first, module_key="identity"
        ).update(enabled=False)
        expire_grants(self.first)
        grant.refresh_from_db()
        self.assertEqual(grant.status, "revoked")

    def test_builtin_notification_publication_is_tenant_scoped_and_activation_guarded(self):
        ModuleActivation.objects.filter(
            organization=self.first, module_key="identity"
        ).update(enabled=False)
        with self.assertRaises(PermissionDenied):
            publish_domain_event(
                organization=self.first, emitter="identity", topic="identity.identity.created.v1",
                payload={"external_id": "same-synthetic-id"},
            )
        with organization_context(self.second):
            event = publish_domain_event(
                organization=self.second, emitter="identity", topic="identity.identity.created.v1",
                payload={"external_id": "same-synthetic-id"},
            )
        self.assertEqual(event.organization_id, self.second.pk)
        self.assertFalse(ModuleEvent.objects.exists())


class NotificationWorkerIsolationTests(TestCase):
    setUp = event_baseline.ModuleEventTests.setUp
    publish = event_baseline.ModuleEventTests.publish
    project = event_baseline.ModuleEventTests.project

    def test_disabled_dependency_pauses_worker_without_loading_handler_or_losing_queue(self):
        self.publish()
        ModuleActivation.objects.filter(
            organization=self.org, module_key="identity"
        ).update(enabled=False)
        with patch("platform_core.events.import_string") as imported:
            self.assertEqual(process_events(self.org), 0)
        imported.assert_not_called()
        from platform_core.models import EventDelivery

        self.assertEqual(EventDelivery.objects.get().attempts, 0)
        ModuleActivation.objects.filter(
            organization=self.org, module_key="identity"
        ).update(enabled=True)
        with patch("platform_core.events.import_string", return_value=self.project):
            self.assertEqual(process_events(self.org), 1)


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock concurrency")
class ModulePublicationConcurrencyTests(TransactionTestCase):
    def test_waiting_publisher_rechecks_activation_after_disable_commits(self):
        admin = get_user_model().objects.create_superuser("p1-publication-admin")
        org = Organization.objects.create(key="p1-publication-race", name="Synthetic race")
        install_module("identity", actor=admin, organization=org)
        started = Event()
        worker_pid = []

        def publish():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    worker_pid.append(cursor.fetchone()[0])
                started.set()
                with organization_context(org):
                    try:
                        publish_domain_event(
                            organization=org, emitter="identity",
                            topic="identity.identity.created.v1", payload={"fixture": True},
                        )
                    except PermissionDenied:
                        return "denied"
                return "published"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=org.pk)
                disable_module("identity", actor=admin, organization=org)
                future = pool.submit(publish)
                self.assertTrue(started.wait(5))
                observed_lock = False
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s",
                            [worker_pid[0]],
                        )
                        state = cursor.fetchone()
                    if state and state[0] == "Lock":
                        observed_lock = True
                        break
                    Event().wait(0.02)
                self.assertTrue(observed_lock)
            self.assertEqual(future.result(timeout=10), "denied")
        self.assertFalse(ModuleEvent.unscoped.filter(organization=org).exists())


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock concurrency")
class ModuleGrantConcurrencyTests(TransactionTestCase):
    setUp = ModuleCapabilityIsolationTests.setUp
    approved_intent = ModuleCapabilityIsolationTests.approved_intent

    def test_waiting_grant_rechecks_membership_after_revocation_commits(self):
        intent = self.approved_intent(self.first)
        ApprovalDecision.objects.create(
            organization=self.first, intent=intent, reviewer=self.reviewer,
            approved=True, comment="Synthetic independent reviewer",
        )
        AccountSecurity.objects.create(
            account=self.admin, encrypted_secret="synthetic-local-mfa-enabled",
        )
        started = Event()
        worker_pid = []

        def grant():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    worker_pid.append(cursor.fetchone()[0])
                started.set()
                with organization_context(self.first):
                    try:
                        grant_from_approval(
                            intent, actor=self.reviewer, organization=self.first
                        )
                    except PermissionDenied:
                        return "denied"
                return "granted"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.first.pk)
                with recent_authentication(self.admin, self.first, time.time()):
                    set_membership(
                        actor=self.admin, organization=self.first,
                        username=self.reviewer.username, role="reviewer", active=False,
                    )
                future = pool.submit(grant)
                self.assertTrue(started.wait(5))
                observed_lock = False
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s",
                            [worker_pid[0]],
                        )
                        state = cursor.fetchone()
                    if state and state[0] == "Lock":
                        observed_lock = True
                        break
                    Event().wait(0.02)
                self.assertTrue(observed_lock)
            self.assertEqual(future.result(timeout=10), "denied")
        self.assertFalse(Grant.unscoped.exists())


class AuthorizedActorTransactionTests(TransactionTestCase):
    def test_lock_authorization_requires_caller_transaction(self):
        actor = get_user_model().objects.create_superuser("p1-lock-helper")
        org = Organization.objects.create(key="p1-lock-helper", name="Synthetic helper")
        with organization_context(org), self.assertRaises(PermissionDenied):
            lock_authorized_actor(actor, org)


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock concurrency")
class ModuleDecisionConcurrencyTests(TransactionTestCase):
    approved_intent = ModuleCapabilityIsolationTests.approved_intent

    def setUp(self):
        ModuleCapabilityIsolationTests.setUp(self)
        install_module("recertification", actor=self.admin, organization=self.first)
        for actor in (self.admin, self.reviewer):
            AccountSecurity.objects.create(
                account=actor, encrypted_secret="synthetic-local-mfa-enabled",
            )

    def pending_intent(self):
        source = self.approved_intent(self.first)
        return AccessIntent.objects.create(
            organization=self.first, identity=source.identity, resource=source.resource,
            account=source.account, method="SSH", privilege="read", reason="Synthetic pending",
            starts_at=source.starts_at, ends_at=source.ends_at, requested_by=self.requester,
        )

    def pending_review(self):
        intent = self.approved_intent(self.first)
        grant_from_approval(intent, actor=self.admin, organization=self.first)
        with recent_authentication(self.admin, self.first, time.time()):
            campaign = start_campaign(
                actor=self.admin, organization=self.first, name="Synthetic scope",
                owner=self.reviewer, due_at=timezone.now() + timedelta(days=1),
            )
        return Review.objects.get(campaign=campaign)

    def assert_waiting_mutation_denied(self, operation, *, disable=None):
        started = Event()
        worker_pid = []

        def worker():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    worker_pid.append(cursor.fetchone()[0])
                started.set()
                with organization_context(self.first):
                    try:
                        with recent_authentication(self.reviewer, self.first, time.time()):
                            operation()
                    except PermissionDenied:
                        return "denied"
                return "committed"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.first.pk)
                if disable:
                    disable_module(disable, actor=self.admin, organization=self.first)
                else:
                    with recent_authentication(self.admin, self.first, time.time()):
                        set_membership(
                            actor=self.admin, organization=self.first,
                            username=self.reviewer.username, role="reviewer", active=False,
                        )
                future = pool.submit(worker)
                self.assertTrue(started.wait(5))
                deadline = time.monotonic() + 5
                observed_lock = False
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s",
                            [worker_pid[0]],
                        )
                        row = cursor.fetchone()
                    if row and row[0] == "Lock":
                        observed_lock = True
                        break
                    Event().wait(0.02)
                self.assertTrue(observed_lock)
            self.assertEqual(future.result(timeout=10), "denied")

    def test_waiting_vote_rechecks_disabled_approval_module(self):
        intent = self.pending_intent()
        self.assert_waiting_mutation_denied(lambda: decide(
            intent.pk, actor=self.reviewer, organization=self.first,
            approved=True, comment="Synthetic observation approval",
        ), disable="approvals")
        intent.refresh_from_db()
        self.assertEqual(intent.status, "pending")
        self.assertFalse(intent.decisions.exists())

    def test_waiting_vote_rechecks_revoked_membership(self):
        intent = self.pending_intent()
        self.assert_waiting_mutation_denied(lambda: decide(
            intent.pk, actor=self.reviewer, organization=self.first,
            approved=True, comment="Synthetic observation approval",
        ))
        intent.refresh_from_db()
        self.assertEqual(intent.status, "pending")
        self.assertFalse(intent.decisions.exists())

    def test_waiting_review_rechecks_disabled_recertification_module(self):
        review = self.pending_review()
        self.assert_waiting_mutation_denied(lambda: review_grant(
            review.pk, actor=self.reviewer, organization=self.first,
            keep=True, comment="Synthetic review",
        ), disable="recertification")
        review.refresh_from_db()
        self.assertEqual(review.decision, "pending")

    def test_waiting_review_rechecks_revoked_membership(self):
        review = self.pending_review()
        self.assert_waiting_mutation_denied(lambda: review_grant(
            review.pk, actor=self.reviewer, organization=self.first,
            keep=True, comment="Synthetic review",
        ))
        review.refresh_from_db()
        self.assertEqual(review.decision, "pending")
