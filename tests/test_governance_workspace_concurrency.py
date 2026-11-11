"""PostgreSQL serializes IGA reading, exception review and revocations."""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import close_old_connections, connection, connections, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from platform_core.authorization import recent_authentication
from platform_core.models import (
    AccountSecurity,
    ModuleActivation,
    Organization,
    OrganizationMembership,
)
from platform_core.tenancy import organization_context
from platform_modules.governance.exception_models import ExceptionCase, ExceptionDecision
from platform_modules.governance.exceptions import decide_exception, verified
from platform_modules.governance.services import publish_policy
from platform_modules.governance.workspace import build_governance_workspace
from platform_modules.identity.models import Identity
from platform_modules.recertification.schedules import publish_schedule, set_schedule_enabled
from platform_modules.recertification.services import start_campaign

from .test_governance_workspace import GovernanceFixture


@skipUnless(connection.vendor == "postgresql", "PostgreSQL exception row-lock concurrency")
@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class GovernanceWorkspaceConcurrencyTests(GovernanceFixture, TransactionTestCase):
    def independent(self, operation):
        close_old_connections()
        try:
            with organization_context(self.org):
                return operation()
        finally:
            connections.close_all()

    def wait_for_lock(self, backend_pid):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", [backend_pid]
                )
                row = cursor.fetchone()
            if row and row[0] == "Lock":
                return
            Event().wait(0.02)
        self.fail("The reader/reviewer did not wait on the organization lock.")

    def waiting_operation(self, operation, mutation):
        started, backend_pid = Event(), []

        def run():
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pid.append(cursor.fetchone()[0])
            started.set()
            try:
                operation()
            except PermissionDenied:
                return "denied"
            return "completed"

        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.pk)
                mutation()
                future = executor.submit(self.independent, run)
                self.assertTrue(started.wait(5))
                self.wait_for_lock(backend_pid[0])
            self.assertEqual(future.result(timeout=10), "denied")

    def test_waiting_workspace_refuses_committed_module_disablement(self):
        self.waiting_operation(
            lambda: build_governance_workspace(actor=self.operator, organization=self.org),
            lambda: ModuleActivation.objects.filter(
                organization=self.org,
                module_key="governance",
            ).update(enabled=False),
        )

    def test_waiting_exception_review_refuses_committed_reviewer_revocation(self):
        case = self.exception()

        def review():
            with recent_authentication(self.reviewer, self.org, time.time()):
                decide_exception(
                    case.pk,
                    actor=self.reviewer,
                    organization=self.org,
                    decision="accepted",
                    comment="Synthetic race review",
                )

        self.waiting_operation(
            review,
            lambda: OrganizationMembership.objects.filter(
                organization=self.org,
                account=self.reviewer,
            ).update(active=False),
        )
        self.assertFalse(ExceptionDecision.objects.exists())

    def waiting_policy_publication(self, mutation):
        OrganizationMembership.objects.filter(account=self.operator, organization=self.org).update(
            role="admin",
        )

        def publish():
            with recent_authentication(self.operator, self.org, time.time()):
                publish_policy(
                    dict(
                        min_reviewers=1,
                        critical_reviewers=1,
                        require_external_contract=False,
                        supplier_sponsor_required=False,
                    ),
                    actor=self.operator,
                    organization=self.org,
                )

        self.waiting_operation(publish, mutation)

    def test_waiting_policy_publication_refuses_committed_administrator_role_removal(self):
        self.waiting_policy_publication(
            lambda: OrganizationMembership.objects.filter(
                organization=self.org,
                account=self.operator,
            ).update(role="auditor")
        )

    def test_waiting_policy_publication_refuses_committed_module_disablement(self):
        self.waiting_policy_publication(
            lambda: ModuleActivation.objects.filter(
                organization=self.org,
                module_key="governance",
            ).update(enabled=False)
        )

    def waiting_schedule_change(self, mutation, *, enable=False):
        publication = self.schedule_draft() if enable else None
        OrganizationMembership.objects.filter(account=self.operator, organization=self.org).update(
            role="admin",
        )

        def change():
            with recent_authentication(self.operator, self.org, time.time()):
                if enable:
                    set_schedule_enabled(
                        publication.schedule_id,
                        True,
                        expected_revision=1,
                        actor=self.operator,
                        organization=self.org,
                    )
                else:
                    publish_schedule(
                        self.schedule_data(),
                        key="synthetic-race-review",
                        actor=self.operator,
                        organization=self.org,
                    )

        self.waiting_operation(change, mutation)

    def test_waiting_schedule_publication_refuses_committed_role_removal(self):
        self.waiting_schedule_change(
            lambda: OrganizationMembership.objects.filter(
                organization=self.org,
                account=self.operator,
            ).update(role="auditor")
        )

    def test_waiting_schedule_publication_refuses_committed_module_disablement(self):
        self.waiting_schedule_change(
            lambda: ModuleActivation.objects.filter(
                organization=self.org,
                module_key="recertification",
            ).update(enabled=False)
        )

    def test_waiting_schedule_activation_refuses_committed_role_removal(self):
        self.waiting_schedule_change(
            lambda: OrganizationMembership.objects.filter(
                organization=self.org,
                account=self.operator,
            ).update(role="auditor"),
            enable=True,
        )

    def test_waiting_schedule_activation_refuses_committed_module_disablement(self):
        self.waiting_schedule_change(
            lambda: ModuleActivation.objects.filter(
                organization=self.org,
                module_key="recertification",
            ).update(enabled=False),
            enable=True,
        )

    def waiting_manual_campaign(self, mutation):
        def start():
            with recent_authentication(self.reviewer, self.org, time.time()):
                start_campaign(
                    actor=self.reviewer,
                    organization=self.org,
                    name="Synthetic waiting campaign",
                    due_at=timezone.now() + timedelta(days=1),
                )

        self.waiting_operation(start, mutation)

    def test_waiting_manual_campaign_refuses_committed_account_deactivation(self):
        self.waiting_manual_campaign(
            lambda: get_user_model()
            .objects.filter(
                pk=self.reviewer.pk,
            )
            .update(is_active=False)
        )

    def test_waiting_manual_campaign_refuses_committed_role_removal(self):
        self.waiting_manual_campaign(
            lambda: OrganizationMembership.objects.filter(
                organization=self.org,
                account=self.reviewer,
            ).update(role="auditor")
        )

    def test_waiting_manual_campaign_refuses_committed_module_disablement(self):
        self.waiting_manual_campaign(
            lambda: ModuleActivation.objects.filter(
                organization=self.org,
                module_key="recertification",
            ).update(enabled=False)
        )

    def test_two_independent_review_attempts_create_exactly_one_decision(self):
        case = self.exception()
        other = get_user_model().objects.create_user("synthetic-other-risk-reviewer")
        OrganizationMembership.objects.create(
            organization=self.org,
            account=other,
            role="reviewer",
        )
        AccountSecurity.objects.create(account=other, encrypted_secret="synthetic-factor-reference")
        ready = Barrier(2)

        def review(actor):
            ready.wait(timeout=5)
            try:
                with recent_authentication(actor, self.org, time.time()):
                    decide_exception(
                        case.pk,
                        actor=actor,
                        organization=self.org,
                        decision="accepted",
                        comment="Synthetic concurrent review",
                    )
            except ValidationError:
                return "already_reviewed"
            return "accepted"

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(self.independent, lambda a=a: review(a))
                for a in (self.reviewer, other)
            ]
            self.assertCountEqual(
                [f.result(timeout=10) for f in futures], ["accepted", "already_reviewed"]
            )
        self.assertEqual(ExceptionDecision.objects.count(), 1)
        self.assertTrue(verified(ExceptionDecision.objects.get()))


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class GovernanceExceptionMigrationTests(GovernanceFixture, TransactionTestCase):
    old = ("governance", "0002_policy_database_boundaries")
    new = ("governance", "0003_exception_register")

    def test_empty_register_reverses_and_reapplies_without_changing_old_rows(self):
        before = list(Identity.objects.values("id", "name", "kind", "status"))
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.old])
            self.assertNotIn("governance_exceptioncase", connection.introspection.table_names())
        finally:
            MigrationExecutor(connection).migrate([self.new])
        self.assertEqual(before, list(Identity.objects.values("id", "name", "kind", "status")))
        self.assertFalse(ExceptionCase.objects.exists())

    def test_populated_register_refuses_destructive_reverse_and_keeps_proof(self):
        case = self.exception()
        self.decision(case)
        with self.assertRaisesRegex(RuntimeError, "explicit restoration"):
            MigrationExecutor(connection).migrate([self.old])
        self.assertTrue(verified(ExceptionCase.objects.get(pk=case.pk)))
        self.assertTrue(verified(ExceptionDecision.objects.get(case=case)))
