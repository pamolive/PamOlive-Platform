"""Native directory UI/API contracts with synthetic identities and no network."""

import json
import secrets
import time
from html.parser import HTMLParser

from django.test import Client, TestCase, override_settings
from django.urls import reverse

from platform_core.models import ModuleActivation
from platform_modules.connectors.directory_models import DirectoryRun

from .test_directory_inventory import DirectoryInventoryFixture


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class DirectoryViewTests(DirectoryInventoryFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.login(self.admin)

    def login(self, user, *, fresh=True):
        self.client.force_login(user)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time() if fresh else 0
        session.save()

    def url(self, name, source_id=None):
        return reverse(name, args=[source_id or self.source.pk])

    def post(self, name, data, source_id=None):
        return self.client.post(
            self.url(name, source_id), data=json.dumps(data), content_type="application/json"
        )

    def test_readers_get_private_inventory_and_role_sensitive_controls(self):
        self.accept()
        for user, admin, collect in (
            (self.admin, True, True),
            (self.operator, False, True),
            (self.reviewer, False, False),
        ):
            self.login(user)
            response = self.client.get(self.url("directory-detail"))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response["Cache-Control"], "no-store")
            self.assertContains(response, "Correspondance explicite", count=1 if admin else 0)
            self.assertContains(response, "Collecter des faits", count=1 if collect else 0)
            self.assertNotContains(response, self.credential["password"])
            self.assertNotContains(response, "encrypted_credential")

    def test_json_replays_are_200_and_conflict_is_409(self):
        payload = {"records": self.records, "idempotency_key": "ui-import", "complete": True}
        first = self.post("directory-import", payload)
        self.assertEqual(first.status_code, 200, first.content)
        again = self.post("directory-import", payload)
        self.assertEqual(again.status_code, 200)
        self.assertEqual(first.json()["run_id"], again.json()["run_id"])
        payload["records"] = [self.fact(self.remote_id, "other-name")]
        conflict = self.post("directory-import", payload)
        self.assertEqual(conflict.status_code, 409, conflict.content)
        self.assertEqual(DirectoryRun.objects.count(), 1)

    def test_export_is_bounded_private_and_contains_no_secret(self):
        self.accept()
        response = self.client.get(self.url("directory-export"), {"limit": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertEqual(len(response.json()["items"]), 1)
        self.assertNotIn(self.credential["password"], response.content.decode())
        self.assertFalse(response.json()["can_apply"])

    def test_export_link_keeps_the_reviewed_page_size(self):
        class Links(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = []

            def handle_starttag(self, tag, attrs):
                if tag == "a":
                    self.links.append(dict(attrs).get("href", ""))

        self.accept(
            key="bounded-export", records=[self.fact(username=f"user-{i}") for i in range(3)]
        )
        response = self.client.get(self.url("directory-detail"), {"limit": 1})
        self.assertEqual(response.status_code, 200)
        parser = Links()
        parser.feed(response.content.decode())
        target = next(
            link for link in parser.links if link.startswith(self.url("directory-export"))
        )
        exported = self.client.get(target)
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(len(exported.json()["items"]), 1)
        self.assertContains(response, "Exporter l’état actualisé")
        self.assertContains(response, "Les données sont relues au moment de l’export")

    def test_ordinary_input_cannot_supply_authority_or_weak_boolean(self):
        for extra in ({"provenance": "collector"}, {"complete": "false"}):
            response = self.post(
                "directory-import",
                {
                    "records": self.records,
                    "idempotency_key": "bad-schema",
                    **extra,
                },
            )
            self.assertEqual(response.status_code, 400)
        duplicate = self.client.post(
            self.url("directory-import"),
            data='{"records":[],"records":[]}',
            content_type="application/json",
        )
        self.assertEqual(duplicate.status_code, 400)
        self.assertFalse(DirectoryRun.objects.exists())

    def test_cross_organization_source_is_not_visible(self):
        from platform_core.services import install_module
        from platform_core.tenancy import organization_context

        for key in ("identity", "access", "connectors"):
            install_module(key, actor=self.admin, organization=self.other)
        with organization_context(self.other):
            original = self.org
            self.org = self.other
            try:
                foreign = self.create_source(name="Other inaccessible source")
            finally:
                self.org = original
        for name in ("api-directory-inventory", "directory-export", "directory-detail"):
            self.assertEqual(self.client.get(self.url(name, foreign.pk)).status_code, 404)

    def test_disabled_dependency_blocks_ui_api_export_and_write(self):
        for module in ("connectors", "identity"):
            ModuleActivation.objects.filter(organization=self.org, module_key=module).update(
                enabled=False
            )
            for name in ("directory-detail", "api-directory-inventory", "directory-export"):
                self.assertEqual(self.client.get(self.url(name)).status_code, 403)
            self.assertEqual(
                self.post(
                    "directory-import",
                    {
                        "records": self.records,
                        "idempotency_key": "blocked",
                    },
                ).status_code,
                403,
            )
            ModuleActivation.objects.filter(organization=self.org, module_key=module).update(
                enabled=True
            )
        self.assertFalse(DirectoryRun.objects.exists())

    def test_operator_cannot_configure_rotate_enable_or_map(self):
        self.login(self.operator)
        self.assertEqual(self.client.get(reverse("directory-configure")).status_code, 403)
        for name in ("directory-enabled", "directory-map", "directory-rotate"):
            self.assertEqual(self.post(name, {}).status_code, 403)

    def test_fresh_mfa_and_csrf_are_required_for_mutations(self):
        self.login(self.admin, fresh=False)
        response = self.post(
            "directory-import",
            {
                "records": self.records,
                "idempotency_key": "no-mfa",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(DirectoryRun.objects.exists())
        self.client = Client(enforce_csrf_checks=True)
        self.login(self.admin)
        self.assertEqual(self.post("directory-enabled", {"enabled": False}).status_code, 403)

    def test_oversized_or_malformed_length_rejected_before_mfa(self):
        self.login(self.admin, fresh=False)
        for length, status in (("999999", 413), ("-1", 400), ("01", 400)):
            response = self.client.generic(
                "POST",
                self.url("directory-import"),
                b"{}",
                content_type="application/json",
                CONTENT_LENGTH=length,
            )
            self.assertEqual(response.status_code, status)

    def test_mapping_and_revoke_are_audited_explicit_actions(self):
        self.accept()
        response = self.post(
            "directory-map",
            {
                "remote_id": self.remote_id,
                "account_id": str(self.account.pk),
            },
        )
        self.assertEqual(response.status_code, 201, response.content)
        mapping_id = response.json()["mapping_id"]
        response = self.client.post(
            reverse("directory-unmap", args=[mapping_id]),
            data="{}",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["kind"], "revoke")

    def test_rotation_form_never_echoes_secret_and_preserves_destination(self):
        self.source.refresh_from_db()
        before_revision = self.source.credential_revision
        old_destination = self.source.destination
        response = self.client.get(self.url("directory-rotate"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.credential["password"])
        new_secret = secrets.token_urlsafe(32)
        response = self.client.post(self.url("directory-rotate"), {"secret": new_secret})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertNotIn(new_secret, response.content.decode())
        self.source.refresh_from_db()
        self.assertEqual(self.source.destination, old_destination)
        self.assertEqual(self.source.credential_revision, before_revision + 1)

    def test_escaped_remote_names_in_html(self):
        self.accept(records=[self.fact(self.remote_id, '<script>alert("x")</script>')])
        response = self.client.get(self.url("directory-detail"))
        self.assertNotContains(response, '<script>alert("x")</script>')
        self.assertContains(response, "&lt;script&gt;")
