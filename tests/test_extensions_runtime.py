"""Executed with a real wheel installed by deploy.check_extensions, never by a view."""

import io
import time
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import patch

import pyotp
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase
from django.urls import reverse

from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.extensions import api
from platform_core.models import (
    AccountSecurity,
    ExtensionDeployment,
    ModuleActivation,
    Organization,
    OrganizationMembership,
)
from platform_core.registry import get_module
from platform_core.security import cipher
from platform_core.services import disable_module, install_module, require_module
from platform_core.tenancy import organization_context

INSTALLED = any(item.manifest.key == "example_notes" for item in settings.PAMOLIVE_EXTENSIONS)


@skipUnless(INSTALLED, "Requires the signed, installed extension image gate")
class ExtensionRuntimeTests(TestCase):
    def setUp(self):
        from pamolive_ext_notes import services
        from pamolive_ext_notes.models import Note

        self.Note, self.services = Note, services
        User = get_user_model()
        self.admin = User.objects.create_superuser("extension-admin", password="fixture-password")
        self.operator = User.objects.create_user("extension-operator", password="fixture-password")
        self.auditor = User.objects.create_user("extension-auditor", password="fixture-password")
        self.unassigned = User.objects.create_user(
            "extension-no-organization", password="fixture-password"
        )
        self.org = Organization.objects.create(key="extension-a", name="Extension A")
        self.other = Organization.objects.create(key="extension-b", name="Extension B")
        for actor, role in [(self.operator, "operator"), (self.auditor, "auditor")]:
            OrganizationMembership.objects.create(organization=self.org, account=actor, role=role)
        for actor in (self.admin, self.operator, self.auditor):
            AccountSecurity.objects.create(
                account=actor,
                encrypted_secret=cipher().encrypt(pyotp.random_base32().encode()).decode(),
            )
        self.context = organization_context(self.org)
        self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        install_module("identity", actor=self.admin, organization=self.org)
        self.home = reverse("ext-example_notes:home")
        self.create_url = reverse("ext-example_notes:create")

    def deliver(self):
        call_command(
            "pamolive_extensions", "deliver", actor=self.admin.username, stdout=io.StringIO()
        )

    def activate(self, organization=None):
        organization = organization or self.org
        with (
            organization_context(organization),
            recent_authentication(self.admin, organization, time.time()),
        ):
            install_module("example_notes", actor=self.admin, organization=organization)

    def enabled(self):
        self.deliver()
        self.activate()

    def test_real_entry_point_registers_routes_without_core_source_edits(self):
        self.assertEqual(get_module("example_notes").version, "1.0.0")
        self.assertEqual(self.home, "/extensions/example_notes/")
        output = io.StringIO()
        call_command("pamolive_extensions", "verify", stdout=output)
        self.assertIn("example_notes 1.0.0", output.getvalue())
        self.assertFalse(ExtensionDeployment.objects.exists())

    def test_package_cannot_activate_before_reviewed_delivery(self):
        with self.assertRaises(ValidationError):
            self.activate()
        self.assertFalse(ExtensionDeployment.objects.exists())

    def test_deliver_refuses_pending_migrations_without_marking_ready(self):
        with patch(
            "platform_core.management.commands.pamolive_extensions.MigrationExecutor"
        ) as executor:
            executor.return_value.migration_plan.return_value = [(object(), False)]
            with self.assertRaises(CommandError):
                self.deliver()
        self.assertFalse(ExtensionDeployment.objects.exists())

    def test_delivery_refuses_unmigrated_model_changes(self):
        from django.db.migrations.operations import AddField

        pending = SimpleNamespace(operations=[AddField("note", "new_field", None)])
        with patch(
            "platform_core.management.commands.pamolive_extensions.MigrationAutodetector"
        ) as detector:
            detector.return_value.changes.return_value = {"example_notes": [pending]}
            with self.assertRaises(CommandError):
                self.deliver()
        self.assertFalse(ExtensionDeployment.objects.exists())

    def test_service_activation_requires_personal_recent_mfa(self):
        self.deliver()
        with self.assertRaises(PermissionDenied):
            install_module("example_notes", actor=self.admin, organization=self.org)

    def test_activation_is_independent_per_organization(self):
        self.enabled()
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(self.home).status_code, 200)
        session = self.client.session
        session["organization_id"] = str(self.other.pk)
        session.save()
        self.assertEqual(self.client.get(self.home).status_code, 403)
        with self.assertRaises(PermissionDenied):
            require_module(self.other, "example_notes")

    def test_writes_need_service_mfa_not_only_a_protected_button(self):
        self.enabled()
        with self.assertRaises(PermissionDenied):
            self.services.create_note(
                actor=self.operator, organization=self.org, title="denied", body="no MFA"
            )
        self.assertFalse(self.Note.objects.exists())
        with recent_authentication(self.operator, self.org, time.time()):
            note = self.services.create_note(
                actor=self.operator, organization=self.org, title="allowed", body="audited"
            )
        self.assertEqual(note.organization_id, self.org.pk)
        self.assertTrue(verify_chain(self.org))

    def test_service_refuses_another_tenant_even_for_a_superuser(self):
        self.enabled()
        with self.assertRaises(PermissionDenied):
            self.services.list_notes(actor=self.admin, organization=self.other)
        with organization_context(self.other):
            install_module("identity", actor=self.admin, organization=self.other)
        self.activate(self.other)
        with (
            organization_context(self.other),
            recent_authentication(self.admin, self.other, time.time()),
        ):
            self.services.create_note(
                actor=self.admin, organization=self.other, title="private B", body="never in A"
            )
        self.assertFalse(self.services.list_notes(actor=self.admin, organization=self.org).exists())

    def test_read_only_role_cannot_write_even_with_recent_mfa(self):
        self.enabled()
        with (
            recent_authentication(self.auditor, self.org, time.time()),
            self.assertRaises(PermissionDenied),
        ):
            self.services.create_note(
                actor=self.auditor, organization=self.org, title="denied", body="role"
            )

    def test_stale_mfa_redirects_and_preserves_the_post_without_writing(self):
        self.enabled()
        self.client.force_login(self.operator)
        self.assertEqual(self.client.get(self.home).status_code, 200)
        response = self.client.post(self.create_url, {"title": "resume me", "body": "draft"})
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("account-security"), response.url)
        self.assertTrue(self.client.session.get("post_mfa_action"))
        self.assertFalse(self.Note.objects.exists())

    def test_actual_http_post_and_escaped_list_are_audited(self):
        self.enabled()
        self.client.force_login(self.operator)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        response = self.client.post(
            self.create_url, {"title": "<script>bad</script>", "body": "sample"}
        )
        self.assertEqual(response.status_code, 302)
        response = self.client.get(self.home)
        self.assertContains(response, "&lt;script&gt;bad&lt;/script&gt;")
        self.assertNotContains(response, "<script>bad</script>")
        self.assertTrue(verify_chain(self.org))

    def test_csrf_wrong_methods_and_no_organization_do_not_execute(self):
        self.enabled()
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        self.assertEqual(
            client.post(self.create_url, {"title": "bad", "body": "csrf"}).status_code, 403
        )
        self.assertEqual(client.get(self.create_url).status_code, 405)
        client.get(self.home)
        self.assertEqual(
            client.delete(
                self.home, HTTP_X_CSRFTOKEN=client.cookies[settings.CSRF_COOKIE_NAME].value
            ).status_code,
            405,
        )
        client.force_login(self.unassigned)
        self.assertEqual(client.get(self.home).status_code, 403)
        self.assertFalse(self.Note.objects.exists())

    def test_disabling_preserves_data_and_reactivation_restores_access(self):
        self.enabled()
        with recent_authentication(self.operator, self.org, time.time()):
            self.services.create_note(
                actor=self.operator, organization=self.org, title="keep", body="history"
            )
        with recent_authentication(self.admin, self.org, time.time()):
            disable_module("example_notes", actor=self.admin, organization=self.org)
        with self.assertRaises(PermissionDenied):
            self.services.list_notes(actor=self.operator, organization=self.org)
        self.assertEqual(self.Note.objects.count(), 1)
        self.activate()
        self.assertEqual(
            self.services.list_notes(actor=self.operator, organization=self.org).count(), 1
        )

    def test_changed_delivery_fingerprint_stops_the_extension(self):
        self.enabled()
        ExtensionDeployment.objects.filter(module_key="example_notes").update(release_hash="0" * 64)
        with self.assertRaises(PermissionDenied):
            self.services.list_notes(actor=self.operator, organization=self.org)

    def test_activation_is_bound_to_release_hash_not_only_version(self):
        self.enabled()
        ModuleActivation.objects.filter(organization=self.org, module_key="example_notes").update(
            release_hash="0" * 64
        )
        with self.assertRaises(PermissionDenied):
            self.services.list_notes(actor=self.operator, organization=self.org)
        self.activate()
        self.assertEqual(
            self.services.list_notes(actor=self.operator, organization=self.org).count(), 0
        )

    def test_module_cannot_use_undeclared_permissions_or_foreign_audit_names(self):
        self.enabled()
        with self.assertRaises(PermissionDenied):
            api.authorize(self.admin, self.org, "example_notes.secret.reveal")
        with self.assertRaises(ValueError):
            api.audit(
                actor=self.admin,
                organization=self.org,
                permission_code="example_notes.note.view",
                action="identity.person.created.v1",
                summary="forged source",
            )
