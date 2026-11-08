"""Upgrade existing immutable evidence; never infer or retro-sign a person."""

from datetime import timedelta
from unittest import skipUnless

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

from platform_core.audit import record, verify_chain
from platform_core.models import Organization
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.governance.policy import approval_requirements
from platform_modules.identity.models import LoginIdentityBinding
from platform_modules.pam.mandates import validate_request


@skipUnless(connection.vendor == "postgresql", "PostgreSQL immutable-evidence upgrade gate")
class PersonMandateUpgradeTests(TransactionTestCase):
    def test_old_votes_facts_and_audit_survive_without_inferred_person_attestations(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        previous = [
            ("access", "0006_observed_actor_is_not_account_owner"),
            ("identity", "0005_credential_registered_at_resource_environment"),
            ("approvals", "0002_alter_approvaldecision_intent_and_more"),
        ]
        try:
            executor.migrate(previous)
            old = MigrationExecutor(connection).loader.project_state(previous).apps
            org = old.get_model("platform_core", "Organization").objects.create(
                key="upgrade-fixture", name="Upgrade fixture"
            )
            user_model = old.get_model(*settings.AUTH_USER_MODEL.split("."))
            requester = user_model.objects.create(username="legacy-requester")
            reviewer = user_model.objects.create(username="legacy-reviewer")
            person = old.get_model("identity", "Identity").objects.create(
                organization_id=org.pk, name="Legacy person", kind="human"
            )
            resource = old.get_model("identity", "Resource").objects.create(
                organization_id=org.pk, name="Legacy target", kind="server"
            )
            account = old.get_model("identity", "ExternalAccount").objects.create(
                organization_id=org.pk,
                identity=person,
                username="legacy-admin",
                system="fixture",
                kind="privileged",
            )
            now = timezone.now()
            intent = old.get_model("access", "AccessIntent").objects.create(
                organization_id=org.pk,
                identity=person,
                resource=resource,
                account=account,
                requested_by=requester,
                method="SSH",
                privilege="Administrator",
                reason="Pre-existing approved request",
                fulfillment="pam",
                status="approved",
                approved_at=now,
                starts_at=now - timedelta(minutes=1),
                ends_at=now + timedelta(minutes=20),
            )
            vote = old.get_model("approvals", "ApprovalDecision").objects.create(
                organization_id=org.pk,
                intent=intent,
                reviewer=reviewer,
                approved=True,
                comment="Pre-existing immutable vote",
            )
            event = old.get_model("access", "AccessEvent").objects.create(
                organization_id=org.pk,
                source="upgrade-fixture",
                external_id="legacy-1",
                occurred_at=now,
                identity=person,
                account=account,
                resource=resource,
                method="SSH",
                action="login",
                evidence="Preserve original fact",
            )
            evaluation = old.get_model("access", "AccessEvaluation").objects.create(
                organization_id=org.pk,
                event=event,
                intent=intent,
                verdict="expected",
                rule_version="access-context/4",
                findings=[{"legacy": "preserved"}],
            )
            objects = [intent, vote, event, evaluation]
            original = [
                (type(obj), obj.pk, type(obj).objects.filter(pk=obj.pk).values().get())
                for obj in objects
            ]
            audit = record(
                action="upgrade.fixture.v1",
                summary="Evidence predates person bindings",
                # Django's migration-state models are distinct Python classes.
                # Core schema is unchanged; pass its runtime model to its service.
                organization=Organization.objects.get(pk=org.pk),
                metadata={"immutable": True},
            )
            audit_digest = audit.event_hash
            # Existing proof guards remain enabled throughout migration.
            with self.assertRaises(DatabaseError), transaction.atomic():
                type(vote).objects.filter(pk=vote.pk).update(comment="forbidden")
            MigrationExecutor(connection).migrate(latest)
            for model, pk, before in original:
                after = model.objects.filter(pk=pk).values(*before).get()
                self.assertEqual(after, before)
            audit.refresh_from_db()
            self.assertEqual(audit.event_hash, audit_digest)
            organization = Organization.objects.get(pk=org.pk)
            self.assertTrue(verify_chain(organization))
            self.assertFalse(LoginIdentityBinding.unscoped.exists())
            with organization_context(organization):
                upgraded = AccessIntent.objects.get(pk=intent.pk)
                self.assertEqual(upgraded.status, "approved")
                self.assertIsNone(upgraded.requester_binding_id)
                self.assertEqual(upgraded.account_snapshot, {})
                self.assertFalse(approval_requirements(upgraded)["complete"])
                with self.assertRaises(ValidationError):
                    validate_request(upgraded, organization=organization)
            with self.assertRaises(DatabaseError), transaction.atomic():
                type(vote).objects.filter(pk=vote.pk).update(comment="still forbidden")
        finally:
            # Restore schema before Django flushes this disposable test database.
            MigrationExecutor(connection).migrate(latest)
