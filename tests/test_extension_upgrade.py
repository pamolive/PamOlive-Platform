"""The extension schema must preserve existing tenants, security and audit evidence."""

from unittest import skipUnless

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from platform_core.audit import record, verify_chain
from platform_core.models import (
    AuditEvent,
    EventAttempt,
    EventDelivery,
    ExtensionDeployment,
    ModuleActivation,
    ModuleEvent,
    Organization,
)
from platform_core.security import cipher
from platform_core.services import require_module


@skipUnless(
    connection.vendor == "postgresql" and not settings.PAMOLIVE_EXTENSIONS,
    "Built-in-only PostgreSQL extension-schema upgrade gate",
)
class ExtensionSchemaUpgradeTests(TransactionTestCase):
    def test_event_schema_adds_no_backfill_and_preserves_existing_evidence(self):
        latest = MigrationExecutor(connection).loader.graph.leaf_nodes()
        previous = [
            (label, "0006_extension_deployment") if label == "platform_core" else (label, name)
            for label, name in latest
        ]
        try:
            MigrationExecutor(connection).migrate(previous)
            org = Organization.objects.create(key="event-upgrade", name="Existing organization")
            proof = record(
                action="upgrade.event_fixture.v1",
                summary="Before notification schema",
                organization=org,
                metadata={"retained": True},
            )
            before = AuditEvent.objects.filter(pk=proof.pk).values().get()
            org_before = Organization.objects.filter(pk=org.pk).values().get()
            MigrationExecutor(connection).migrate(latest)
            self.assertEqual(AuditEvent.objects.filter(pk=proof.pk).values().get(), before)
            self.assertEqual(Organization.objects.filter(pk=org.pk).values().get(), org_before)
            self.assertFalse(ModuleEvent.unscoped.exists())
            self.assertFalse(EventDelivery.unscoped.exists())
            self.assertFalse(EventAttempt.unscoped.exists())
            self.assertTrue(verify_chain(org))
            self.assert_audit_protected(proof.pk)
        finally:
            MigrationExecutor(connection).migrate(latest)

    def assert_audit_protected(self, event_id):
        with self.assertRaises(ValidationError):
            AuditEvent.objects.filter(pk=event_id).update(summary="forbidden upgrade fixture")
        # Bypass the ORM guard deliberately to verify the PostgreSQL trigger too.
        with self.assertRaises(DatabaseError), transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE platform_core_auditevent SET summary = %s WHERE id = %s",
                    ["forbidden upgrade fixture", event_id],
                )

    def test_existing_activations_security_and_audit_survive_without_implicit_delivery(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        previous = [
            (label, "0005_loginthrottle_accountsecurity")
            if label == "platform_core"
            else (label, name)
            for label, name in latest
        ]
        try:
            executor.migrate(previous)
            old = MigrationExecutor(connection).loader.project_state(previous).apps
            old_org = old.get_model("platform_core", "Organization")
            old_user = old.get_model(*settings.AUTH_USER_MODEL.split("."))
            old_membership = old.get_model("platform_core", "OrganizationMembership")
            old_activation = old.get_model("platform_core", "ModuleActivation")
            old_security = old.get_model("platform_core", "AccountSecurity")
            actor = old_user.objects.create(username="extension-upgrade-fixture", is_active=True)
            first = old_org.objects.create(key="extension-upgrade-a", name="Upgrade A")
            second = old_org.objects.create(key="extension-upgrade-b", name="Upgrade B")
            for organization in (first, second):
                old_membership.objects.create(
                    organization=organization, account=actor, role="admin", active=True
                )
                for key, enabled in (("identity", True), ("pam", organization.pk == first.pk)):
                    old_activation.objects.create(
                        organization=organization,
                        module_key=key,
                        version="0.1.0" if key == "identity" else "0.2.0",
                        enabled=enabled,
                    )
            old_security.objects.create(
                account=actor,
                encrypted_secret=cipher().encrypt(b"synthetic-upgrade-mfa-secret").decode(),
                last_counter=4242,
                freshness_minutes=10,
                recovery_hashes=["synthetic-upgrade-recovery-hash"],
                failures=2,
            )
            proof = record(
                action="upgrade.extension_fixture.v1",
                summary="Existing module state before signed extension delivery",
                organization=Organization.objects.get(pk=first.pk),
                metadata={"fixture": True},
            )
            # Capture the complete old columns, including timestamps and MFA replay state.
            originals = [
                (model, list(model.objects.order_by("pk").values()))
                for model in (old_org, old_membership, old_activation, old_security)
            ]
            audit_before = AuditEvent.objects.filter(pk=proof.pk).values().get()
            self.assert_audit_protected(proof.pk)

            MigrationExecutor(connection).migrate(latest)

            for model, rows in originals:
                fields = [field.attname for field in model._meta.concrete_fields]
                self.assertEqual(list(model.objects.order_by("pk").values(*fields)), rows)
            self.assertEqual(AuditEvent.objects.filter(pk=proof.pk).values().get(), audit_before)
            self.assertEqual(ExtensionDeployment.objects.count(), 0)
            self.assertEqual(ModuleActivation.objects.count(), 4)
            self.assertFalse(ModuleActivation.objects.exclude(release_hash="").exists())
            for organization in Organization.objects.all():
                self.assertTrue(verify_chain(organization))
                require_module(organization, "identity")
            require_module(Organization.objects.get(pk=first.pk), "pam")
            with self.assertRaises(PermissionDenied):
                require_module(Organization.objects.get(pk=second.pk), "pam")
            self.assert_audit_protected(proof.pk)
        finally:
            MigrationExecutor(connection).migrate(latest)
