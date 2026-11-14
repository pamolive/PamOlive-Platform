"""Independent HTTP/ASGI input, MFA and tenant checks for directory readers."""
import json
import secrets
import time

from django.test import AsyncRequestFactory, Client, TestCase, override_settings
from django.urls import reverse

from platform_core.models import AuditEvent, ModuleActivation
from platform_core.services import install_module
from platform_modules.connectors import directory_views
from platform_modules.connectors.directory_models import (
    DirectoryFact,
    DirectoryRun,
    DirectorySource,
)

from . import test_directory_redteam as fixtures


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class DirectoryViewsRedTeamTests(TestCase):
    source = fixtures.DirectoryInventoryRedTeamTests.source
    row = fixtures.DirectoryInventoryRedTeamTests.row
    ingest = fixtures.DirectoryInventoryRedTeamTests.ingest

    def setUp(self):
        fixtures.DirectoryInventoryRedTeamTests.setUp(self)
        self.client.force_login(self.admin)
        self.assure()
        self.directory = self.source()

    def assure(self):
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time()
        session.save()

    def post(self, name, data, identifier=None):
        route = reverse(name, args=[identifier or self.directory.pk])
        return self.client.post(route, json.dumps(data), content_type="application/json")

    def test_non_list_fixture_values_cannot_silently_become_an_empty_complete_snapshot(self):
        for kind, value in (("object", {}), ("null", None), ("false", False), ("zero", 0)):
            with self.subTest(kind=kind):
                response = self.post("directory-import", {
                    "idempotency_key": "bad-shape-"+kind, "records": value, "complete": True})
                self.assertEqual(response.status_code, 400)
        response = self.post("directory-import", {
            "idempotency_key": "missing-records", "complete": True})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(DirectoryRun.unscoped.count(), 0)
        self.assertEqual(DirectoryFact.unscoped.count(), 0)

    def test_explicit_empty_array_remains_a_valid_snapshot_with_declared_fixture_provenance(self):
        response = self.post("directory-import", {
            "idempotency_key": "explicit-empty", "records": [], "complete": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["provenance"], "synthetic_fixture")
        self.assertEqual(DirectoryRun.unscoped.get().record_count, 0)

    def test_duplicate_json_properties_are_rejected_without_creating_a_run(self):
        route = reverse("directory-import", args=[self.directory.pk])
        body = '{"idempotency_key":"duplicate","records":[],"complete":false,"complete":true}'
        response = self.client.post(route, body, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(DirectoryRun.unscoped.count(), 0)

    def test_deep_json_within_byte_budget_is_a_client_error_not_a_server_exception(self):
        route = reverse("directory-import", args=[self.directory.pk])
        body = (b'{"idempotency_key":"deep","records":' + b'['*1200 + b'0' + b']'*1200
                + b'}')
        self.client.raise_request_exception = False
        response = self.client.post(route, body, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(DirectoryRun.unscoped.count(), 0)

    def test_chunked_asgi_request_cannot_bypass_byte_budget_with_missing_content_length(self):
        route = reverse("directory-configure")
        body = b'{"unexpected":"' + b'x'*131073 + b'"}'
        request = AsyncRequestFactory().post(route, body, content_type="application/json")
        # ASGI supplies a stream after chunk decoding; Content-Length may be absent.
        request.META.pop("CONTENT_LENGTH", None)
        request.user, request.organization = self.admin, self.org
        request.session = self.client.session
        response = directory_views.configure(request)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(DirectorySource.unscoped.count(), 1)

    def test_input_budget_precedes_expired_mfa_post_preservation(self):
        session = self.client.session
        session.pop("mfa_verified_at", None)
        session.save()
        response = self.post("directory-import", {"records": ["x"*131073]})
        self.assertEqual(response.status_code, 413)
        self.assertNotIn("post_mfa_action", self.client.session)

    def test_valid_mutation_without_recent_mfa_is_challenged_without_side_effect(self):
        session = self.client.session
        session.pop("mfa_verified_at", None)
        session.save()
        response = self.post("directory-import", {
            "idempotency_key": "no-mfa", "records": [self.row()]})
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("account-security"), response.url)
        self.assertEqual(DirectoryRun.unscoped.count(), 0)

    def test_disabled_module_refuses_html_api_export_and_mutation(self):
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False)
        for name in ("directory-detail", "api-directory-inventory", "directory-export"):
            with self.subTest(route=name):
                response = self.client.get(reverse(name, args=[self.directory.pk]))
                self.assertEqual(response.status_code, 403)
        self.assertEqual(self.post("directory-import", {
            "idempotency_key": "disabled", "records": []}).status_code, 403)
        self.assertEqual(DirectoryRun.unscoped.count(), 0)

    def test_foreign_source_uuid_is_hidden_after_switch_to_another_enabled_tenant(self):
        for key in ("identity", "access", "connectors"):
            install_module(key, actor=self.admin, organization=self.other)
        session = self.client.session
        session["organization_id"] = str(self.other.pk)
        session.save()
        for name in ("directory-detail", "api-directory-inventory", "directory-export"):
            with self.subTest(route=name):
                response = self.client.get(reverse(name, args=[self.directory.pk]))
                self.assertEqual(response.status_code, 404)
                self.assertNotContains(response, self.secret, status_code=404)

    def test_operator_cannot_enable_map_revoke_or_rotate_even_with_recent_mfa(self):
        self.client.force_login(self.operator)
        self.assure()
        for name, data in (("directory-enabled", {"enabled": False}),
                           ("directory-map", {"remote_id": str(self.account.pk),
                                              "account_id": str(self.account.pk)}),
                           ("directory-rotate", {"credential": {
                               "bind_dn": "cn=reader,dc=example,dc=invalid",
                               "password": secrets.token_urlsafe(32)}})):
            with self.subTest(route=name):
                self.assertEqual(self.post(name, data).status_code, 403)
        self.directory.refresh_from_db()
        self.assertTrue(self.directory.enabled)

    def test_replay_conflict_is_409_audited_original_unchanged_and_has_no_secret(self):
        row = self.row()
        payload = {"idempotency_key": "http-replay", "records": [row]}
        first = self.post("directory-import", payload)
        self.assertEqual(first.status_code, 200)
        again = self.post("directory-import", payload)
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.json()["run_id"], first.json()["run_id"])
        before = AuditEvent.objects.filter(action="directory.import_conflict").count()
        response = self.post("directory-import", {
            "idempotency_key": "http-replay", "records": [dict(row, enabled=False)]})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json(), {"error": "directory_idempotency_conflict"})
        self.assertNotIn(self.secret, response.content.decode())
        self.assertEqual(DirectoryRun.unscoped.count(), 1)
        self.assertTrue(DirectoryFact.unscoped.get().enabled)
        self.assertEqual(
            AuditEvent.objects.filter(action="directory.import_conflict").count(), before+1)

    def test_json_cannot_supply_an_organization_or_authenticated_provenance(self):
        response = self.post("directory-import", {"idempotency_key": "spoof",
            "records": [], "organization": str(self.other.pk),
            "provenance": "authenticated_lab_directory"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(DirectoryRun.unscoped.count(), 0)

    def test_rotation_response_does_not_disclose_new_or_old_credentials(self):
        updated = secrets.token_urlsafe(32)
        response = self.post("directory-rotate", {"credential": {
            "bind_dn": "cn=reader,dc=example,dc=invalid", "password": updated}})
        self.assertEqual(response.status_code, 200)
        text = response.content.decode()
        self.assertNotIn(updated, text)
        self.assertNotIn(self.secret, text)
        self.directory.refresh_from_db()
        for name in ("api-directory-inventory", "directory-export"):
            response = self.client.get(reverse(name, args=[self.directory.pk]))
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(updated, response.content.decode())
            self.assertNotIn(self.directory.encrypted_credential, response.content.decode())

    def test_csrf_is_still_required_for_directory_mutations(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        response = client.post(reverse("directory-enabled", args=[self.directory.pk]),
                               '{"enabled":false}', content_type="application/json")
        self.assertEqual(response.status_code, 403)
        self.directory.refresh_from_db()
        self.assertTrue(self.directory.enabled)

    def test_deep_json_inside_an_html_form_is_rejected_without_server_exception(self):
        self.client.raise_request_exception = False
        response = self.client.post(reverse("directory-import", args=[self.directory.pk]), {
            "idempotency_key": "deep-form", "records": "["*1200+"0"+"]"*1200})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(DirectoryRun.unscoped.count(), 0)

    def test_duplicate_object_properties_inside_html_fixture_are_rejected(self):
        remote = str(self.account.pk)
        row = ('[{"entryUUID":"'+remote+'","uid":"first","uid":"second",'
               '"enabled":true,"memberOf":[]}]')
        response = self.client.post(reverse("directory-import", args=[self.directory.pk]), {
            "idempotency_key": "duplicate-form", "records": row})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(DirectoryRun.unscoped.count(), 0)

    def test_explicit_empty_array_in_html_form_is_valid(self):
        response = self.client.post(reverse("directory-import", args=[self.directory.pk]), {
            "idempotency_key": "empty-form", "records": "[]", "complete": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["provenance"], "synthetic_fixture")

    def test_read_only_reviewer_has_no_mutation_controls_in_directory_html(self):
        self.client.force_login(self.reviewer)
        response = self.client.get(reverse("directory-detail", args=[self.directory.pk]))
        self.assertEqual(response.status_code, 200)
        for name in ("directory-import", "directory-map", "directory-enabled", "directory-rotate"):
            self.assertNotContains(response, reverse(name, args=[self.directory.pk]))
        self.assertEqual(self.post("directory-import", {
            "idempotency_key": "reader-cannot-import", "records": []}).status_code, 403)

    def test_invalid_html_source_form_never_reflects_submitted_password(self):
        response = self.client.post(reverse("directory-configure"), {
            "provider": "ldap", "name": "", "endpoint": "ldap://directory.invalid:389",
            "certificate_sha256": "1"*64, "base_dn": "dc=example,dc=invalid",
            "bind_dn": "cn=reader,dc=example,dc=invalid", "password": self.secret,
            "synthetic": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.secret)
        self.assertEqual(response["Cache-Control"], "no-store")
