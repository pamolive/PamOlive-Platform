"""Synthetic Identity 360 and directory preview authorization/regression checks."""

import json
import time
from datetime import timedelta
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection
from django.test import Client, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from platform_core.models import (
    AccountSecurity,
    AuditEvent,
    ModuleActivation,
    OrganizationMembership,
)
from platform_core.security import cipher
from platform_core.tenancy import organization_context
from platform_modules.connectors.models import AccountBinding, GroupBinding, ProvisioningConnector
from platform_modules.identity.directory_simulation import normalize_fixture, preview_reconciliation
from platform_modules.identity.identity360 import build_identity360, identity_inventory
from platform_modules.identity.models import ExternalAccount, Grant, Identity

from . import test_mover
from . import test_platform as fixture


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class Identity360Tests(TestCase):
    def setUp(self):
        fixture.PlatformTests.setUp(self)

    def read(self, **kwargs):
        return build_identity360(
            self.identity.pk, actor=self.operator, organization=self.org, **kwargs
        )

    def test_read_is_bounded_unsigned_and_distinguishes_local_from_remote(self):
        before = AuditEvent.objects.count()
        for number in range(2):
            Grant.objects.create(
                organization=self.org,
                identity=self.identity,
                account=self.account,
                resource=self.resource,
                entitlement=f"Synthetic right {number}",
                justification="Fixture",
            )
        result = self.read(limit=1)
        self.assertEqual(result["schema"], "pamolive.identity360/1")
        self.assertTrue(result["read_only"])
        self.assertEqual(result["identity"]["population"], "human")
        self.assertEqual(result["identity"]["owner_assurance"], "missing")
        self.assertEqual(result["accounts"]["items"][0]["id"], str(self.account.pk))
        self.assertEqual(len(result["grants"]["items"]), 1)
        self.assertTrue(result["grants"]["truncated"])
        self.assertEqual(
            result["grants"]["items"][0]["assurance"], "local_grant_not_provider_membership"
        )
        self.assertEqual(AuditEvent.objects.count(), before)
        self.assertNotIn("encrypted", json.dumps(result))
        self.assertNotIn("signature", json.dumps(result))

    def test_orphan_inventory_reports_inactive_and_ownerless_nonhuman_accounts(self):
        machine = Identity.objects.create(
            organization=self.org, name="Synthetic service", kind="service", owner="   "
        )
        account = ExternalAccount.objects.create(
            organization=self.org, identity=machine, username="fixture-service", system="Fixture"
        )
        Identity.objects.filter(pk=self.identity.pk).update(status="departed")
        result = identity_inventory(actor=self.operator, organization=self.org)
        warnings = {row["id"]: row["reasons"] for row in result["orphaned_accounts"]["items"]}
        self.assertEqual(warnings[str(self.account.pk)], ["inactive_identity"])
        self.assertEqual(warnings[str(account.pk)], ["missing_responsible_owner"])
        profile = build_identity360(machine.pk, actor=self.operator, organization=self.org)
        self.assertEqual(profile["identity"]["population"], "non_human")
        ExternalAccount.objects.filter(pk=account.pk).update(active=False)
        self.assertEqual(
            len(
                identity_inventory(actor=self.operator, organization=self.org)["orphaned_accounts"][
                    "items"
                ]
            ),
            1,
        )

    def test_sources_and_groups_are_references_not_membership_proofs(self):
        connector = ProvisioningConnector.objects.create(
            organization=self.org,
            name="Fixture directory",
            base_url="https://fixture.invalid/scim",
            encrypted_token="synthetic-ciphertext-not-to-project",
        )
        AccountBinding.objects.create(
            organization=self.org,
            connector=connector,
            account=self.account,
            remote_id="fixture-remote",
        )
        GroupBinding.objects.create(
            organization=self.org,
            connector=connector,
            resource=self.resource,
            entitlement="Readers",
            remote_id="same-id",
        )
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=self.resource,
            account=self.account,
            entitlement="Readers",
            justification="Fixture",
        )
        result = self.read()
        self.assertEqual(result["sources"]["items"][0]["connector_id"], str(connector.pk))
        self.assertEqual(result["directory_groups"]["items"][0]["remote_group_id"], "same-id")
        self.assertNotIn(connector.encrypted_token, json.dumps(result))
        self.assertNotIn(connector.base_url, json.dumps(result))
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        with CaptureQueriesContext(connection) as queries:
            result = self.read()
        self.assertEqual(result["sources"]["availability"], "module_disabled")
        self.assertEqual(result["directory_groups"]["items"], [])
        self.assertFalse(any('"connectors_' in row["sql"] for row in queries))

    def test_disabled_access_hides_requests_without_querying_domain(self):
        fixture.PlatformTests.intent(self)
        ModuleActivation.objects.filter(organization=self.org, module_key="access").update(
            enabled=False
        )
        with CaptureQueriesContext(connection) as queries:
            result = self.read()
        self.assertEqual(result["access_requests"]["availability"], "module_disabled")
        self.assertFalse(any('"access_accessintent"' in row["sql"] for row in queries))

    def test_tenants_context_membership_and_current_account_state_are_required(self):
        with organization_context(self.other):
            other_identity = Identity.objects.create(organization=self.other, name="Private other")
        with self.assertRaises(Identity.DoesNotExist):
            build_identity360(other_identity.pk, actor=self.operator, organization=self.org)
        with organization_context(self.other), self.assertRaises(PermissionDenied):
            self.read()
        outsider = get_user_model().objects.create_user("identity360-outsider")
        with self.assertRaises(PermissionDenied):
            build_identity360(self.identity.pk, actor=outsider, organization=self.org)
        get_user_model().objects.filter(pk=self.operator.pk).update(is_active=False)
        with self.assertRaises(PermissionDenied):
            self.read()

    def test_invalid_limits_and_disabled_identity_fail_closed(self):
        for limit in (0, 101, True, "1"):
            with self.assertRaises(ValidationError):
                self.read(limit=limit)
        ModuleActivation.objects.filter(organization=self.org, module_key="identity").update(
            enabled=False
        )
        with self.assertRaises(PermissionDenied):
            self.read()

    def test_each_read_role_is_authorized_and_stale_superuser_is_not(self):
        for role in ("admin", "operator", "reviewer", "auditor"):
            actor = get_user_model().objects.create_user("identity360-" + role)
            OrganizationMembership.objects.create(organization=self.org, account=actor, role=role)
            self.assertEqual(
                build_identity360(self.identity.pk, actor=actor, organization=self.org)["identity"][
                    "id"
                ],
                str(self.identity.pk),
            )
        get_user_model().objects.filter(pk=self.admin.pk).update(is_superuser=False)
        with self.assertRaises(PermissionDenied):
            build_identity360(self.identity.pk, actor=self.admin, organization=self.org)

    def test_expired_and_future_rights_are_not_locally_effective(self):
        now = timezone.now()
        for title, start, end in (
            ("Expired", now - timedelta(days=2), now - timedelta(days=1)),
            ("Future", now + timedelta(days=1), now + timedelta(days=2)),
        ):
            Grant.objects.create(
                organization=self.org,
                identity=self.identity,
                resource=self.resource,
                entitlement=title,
                justification="Fixture",
                valid_from=start,
                expires_at=end,
            )
        self.assertFalse(any(row["locally_effective"] for row in self.read()["grants"]["items"]))

    def test_ui_api_export_are_private_read_only_and_tenant_scoped(self):
        self.client.force_login(self.operator)
        response = self.client.get(reverse("identity360-inventory"))
        self.assertContains(response, "Identités à 360°")
        response = self.client.get(reverse("identity360-detail", args=[self.identity.pk]))
        self.assertContains(response, "Identity 360°")
        for route in ("identity360-detail", "api-identity360", "identity360-export"):
            url = reverse(route, args=[self.identity.pk])
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response["Cache-Control"], "no-store")
            self.assertEqual(self.client.post(url).status_code, 405)
        self.assertIn("attachment", response["Content-Disposition"])
        other_user = get_user_model().objects.create_user("identity360-other")
        OrganizationMembership.objects.create(
            organization=self.other, account=other_user, role="auditor"
        )
        ModuleActivation.objects.create(
            organization=self.other, module_key="identity", enabled=True
        )
        self.client.force_login(other_user)
        self.assertEqual(
            self.client.get(reverse("api-identity360", args=[self.identity.pk])).status_code, 404
        )


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class Identity360RoleTests(test_mover.MoverFixture, TestCase):
    def test_current_roles_use_verified_moves_and_never_attest_remote_membership(self):
        role = self.role()
        self.apply(self.proposal({role.pk: [self.account.pk]}))
        result = build_identity360(self.identity.pk, actor=self.operator, organization=self.org)
        self.assertEqual(result["business_roles"]["items"][0]["id"], str(role.pk))
        self.assertTrue(result["business_roles"]["items"][0]["proof_verified"])
        self.assertEqual(result["grants"]["items"], [])
        self.assertEqual(result["access_requests"]["items"][0]["status"], "pending")

    def test_invalid_move_proof_is_not_reinterpreted_as_a_role_assignment(self):
        # Read-time verifier failure must hide roles even with otherwise valid data.
        from unittest.mock import patch

        role = self.role()
        self.apply(self.proposal({role.pk: [self.account.pk]}))
        with patch("platform_modules.identity.identity360.verified", return_value=False):
            result = build_identity360(self.identity.pk, actor=self.operator, organization=self.org)
        self.assertEqual(result["business_roles"]["availability"], "unverifiable")
        self.assertEqual(result["business_roles"]["items"], [])


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class DirectorySimulationTests(TestCase):
    def setUp(self):
        fixture.PlatformTests.setUp(self)
        self.remote_id = str(uuid4())

    def row(self, provider="ad", **changes):
        keys = {
            "ad": ("objectGUID", "sAMAccountName", "enabled", "memberOf"),
            "ldap": ("entryUUID", "uid", "enabled", "memberOf"),
            "entra": ("id", "userPrincipalName", "accountEnabled", "groups"),
        }[provider]
        return dict(zip(keys, (self.remote_id, self.account.username, True, []))) | changes

    def preview(self, **changes):
        values = dict(
            provider="ad",
            source_id="synthetic-source-A",
            records=[self.row()],
            mapping={self.remote_id: str(self.account.pk)},
            actor=self.operator,
            organization=self.org,
            synthetic=True,
        )
        return preview_reconciliation(**(values | changes))

    def test_three_adapters_are_synthetic_read_only_with_explicit_stable_mapping(self):
        before = (
            Identity.objects.count(),
            ExternalAccount.objects.count(),
            AuditEvent.objects.count(),
        )
        for provider in ("ad", "ldap", "entra"):
            result = self.preview(provider=provider, records=[self.row(provider)])
            self.assertEqual(result["comparisons"][0]["state"], "fixture_matches_local_record")
            self.assertTrue(result["synthetic"])
            self.assertTrue(result["read_only"])
            self.assertFalse(result["can_apply"])
            self.assertIn("not_authenticated_collector", result["provenance"])
        self.assertEqual(
            before,
            (Identity.objects.count(), ExternalAccount.objects.count(), AuditEvent.objects.count()),
        )

    def test_identical_names_never_create_a_link_and_collisions_require_human_review(self):
        second = self.row(objectGUID=str(uuid4()))
        result = self.preview(records=[self.row(), second], mapping={})
        for row in result["comparisons"]:
            self.assertIsNone(row["account_id"])
            self.assertEqual(row["state"], "unlinked_requires_human_review")
            self.assertIn("duplicate_login_requires_human_review", row["warnings"])

    def test_missing_rows_never_authorize_revoke_and_sources_have_distinct_fingerprints(self):
        result = self.preview(records=[])
        self.assertEqual(
            result["not_observed"][0]["state"], "not_observed_in_snapshot_requires_review"
        )
        self.assertTrue(ExternalAccount.objects.get(pk=self.account.pk).active)
        self.assertNotEqual(
            result["snapshot_sha256"],
            self.preview(records=[], source_id="synthetic-source-B")["snapshot_sha256"],
        )

    def test_duplicate_remote_ids_unknown_fields_and_nonsynthetic_input_are_refused(self):
        for records in (
            [self.row(), self.row()],
            [self.row(password="never-echo-fixture")],
            [self.row(objectGUID="mutable-login")],
        ):
            with self.assertRaises(ValidationError):
                self.preview(records=records)
        with self.assertRaises(ValidationError):
            self.preview(synthetic=False)
        with self.assertRaises(ValidationError):
            normalize_fixture("ad", [{}] * 1001)

    def test_foreign_mapping_disabled_module_and_stale_actor_are_refused(self):
        with organization_context(self.other):
            identity = Identity.objects.create(organization=self.other, name="Foreign")
            account = ExternalAccount.objects.create(
                organization=self.other, identity=identity, username="same", system="same"
            )
        with self.assertRaises(ValidationError):
            self.preview(mapping={self.remote_id: str(account.pk)})
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        with self.assertRaises(PermissionDenied):
            self.preview()

    def test_json_api_and_native_form_do_not_echo_unknown_payload_properties(self):
        AccountSecurity.objects.create(
            account=self.operator,
            encrypted_secret=cipher().encrypt(b"synthetic-mfa-fixture-only").decode(),
        )
        self.client.force_login(self.operator)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        url = reverse("identity-directory-simulation")
        self.assertContains(self.client.get(url), "Réconciliation sur simulateurs")
        payload = dict(
            provider="ad",
            source_id="synthetic-source",
            synthetic=True,
            records=[self.row()],
            mapping={self.remote_id: str(self.account.pk)},
        )
        result = self.client.post(url, data=json.dumps(payload), content_type="application/json")
        self.assertEqual(result.status_code, 200)
        self.assertFalse(result.json()["can_apply"])
        form = payload | {
            "records": json.dumps(payload["records"]),
            "mapping": json.dumps(payload["mapping"]),
        }
        self.assertContains(self.client.post(url, data=form), "Résultat de la simulation")
        empty_form = form | {"records": "[]", "mapping": "{}"}
        self.assertContains(self.client.post(url, data=empty_form), "Résultat de la simulation")
        payload["records"][0]["password"] = "unknown-fixture-never-echo"
        result = self.client.post(url, data=json.dumps(payload), content_type="application/json")
        self.assertEqual(result.status_code, 400)
        self.assertNotIn("unknown-fixture-never-echo", result.content.decode())

    def test_preview_requires_recent_mfa_and_csrf(self):
        self.client.force_login(self.operator)
        payload = dict(
            provider="ad",
            source_id="synthetic-source",
            synthetic=True,
            records=[self.row()],
            mapping={},
        )
        url = reverse("identity-directory-simulation")
        self.assertRedirects(
            self.client.post(url, data=json.dumps(payload), content_type="application/json"),
            reverse("account-security"),
        )
        protected = Client(enforce_csrf_checks=True)
        protected.force_login(self.operator)
        self.assertEqual(
            protected.post(
                url, data=json.dumps(payload), content_type="application/json"
            ).status_code,
            403,
        )

    def test_preview_rejects_oversized_and_malformed_json_without_echo(self):
        AccountSecurity.objects.create(
            account=self.operator,
            encrypted_secret=cipher().encrypt(b"synthetic-mfa-fixture-only").decode(),
        )
        self.client.force_login(self.operator)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        url = reverse("identity-directory-simulation")
        self.assertEqual(
            self.client.post(url, data="x" * 131073, content_type="application/json").status_code,
            413,
        )
        self.assertEqual(
            self.client.post(
                url, data='{"unexpected": true}', content_type="application/json"
            ).status_code,
            400,
        )

    def test_canonical_uuid_and_sorted_groups_make_deterministic_preview(self):
        first = self.preview(records=[self.row(memberOf=["Readers", "Operators"])])
        second = self.preview(
            records=[
                self.row(
                    objectGUID=self.remote_id.upper(), memberOf=["Operators", "Readers", "Readers"]
                )
            ]
        )
        self.assertEqual(first["snapshot_sha256"], second["snapshot_sha256"])

    def test_malformed_negative_and_noncanonical_lengths_fail_closed(self):
        self.client.force_login(self.operator)
        url = reverse("identity-directory-simulation")
        for value in ("invalid", "-1", "+1", "01", "1.0", "999999999999999999999"):
            with self.subTest(content_length=value):
                response = self.client.get(url, CONTENT_LENGTH=value)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"], "invalid_content_length")
                self.assertEqual(response["Cache-Control"], "no-store")
                response = self.client.post(
                    url, data="{}", content_type="application/json", CONTENT_LENGTH=value
                )
                self.assertEqual(response.status_code, 400)
