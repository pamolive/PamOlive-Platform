"""The extension schema must preserve existing tenants, security and audit evidence."""

from unittest import skipUnless

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from platform_core.audit import record, verify_chain
from platform_core.models import AuditEvent, ExtensionDeployment, ModuleActivation, Organization
from platform_core.security import cipher
from platform_core.services import require_module


@skipUnless(
    connection.vendor == "postgresql" and not settings.PAMOLIVE_EXTENSIONS,
    "Built-in-only PostgreSQL extension-schema upgrade gate",
)
class ExtensionSchemaUpgradeTests(TransactionTestCase):
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
            with self.assertRaises(DatabaseError), transaction.atomic():
                AuditEvent.objects.filter(pk=proof.pk).update(summary="forbidden before upgrade")

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
            with self.assertRaises(DatabaseError), transaction.atomic():
                AuditEvent.objects.filter(pk=proof.pk).update(summary="forbidden after upgrade")
        finally:
            MigrationExecutor(connection).migrate(latest)
