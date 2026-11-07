import json
import time
from datetime import timedelta
from unittest import skipUnless

import pyotp
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.models import (
    AccountSecurity,
    AuditEvent,
    ModuleActivation,
    Organization,
    OrganizationMembership,
)
from platform_core.security import cipher, verify_mfa
from platform_core.services import disable_module, install_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessEvent
from platform_modules.access.services import create_record, ingest_event, revoke_identity
from platform_modules.approvals.services import decide
from platform_modules.connectors.services import create_source
from platform_modules.identity.models import Grant, Identity, Resource
from platform_modules.pam.models import SessionLease
from platform_modules.pam.services import expire_leases, open_lease
from platform_modules.recertification.models import Review
from platform_modules.recertification.services import review_grant, start_campaign


class PlatformTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_superuser("admin", password="test-only-strong-password")
        self.operator = User.objects.create_user("operator", password="test-only-strong-password")
        self.reviewer = User.objects.create_user("reviewer", password="test-only-strong-password")
        self.org = Organization.objects.create(key="mopacy", name="Mopacy")
        self.other = Organization.objects.create(key="other", name="Other")
        OrganizationMembership.objects.create(
            organization=self.org, account=self.operator, role="operator"
        )
        OrganizationMembership.objects.create(
            organization=self.org, account=self.reviewer, role="reviewer"
        )
        for key in ["identity", "access", "approvals", "connectors", "recertification", "pam"]:
            install_module(key, actor=self.admin, organization=self.org)
        self.ctx = organization_context(self.org)
        self.ctx.__enter__()
        self.addCleanup(self.ctx.__exit__, None, None, None)
        self.identity = create_record(
            "identity",
            {"name": "Cyriel", "kind": "human"},
            actor=self.operator,
            organization=self.org,
        )
        self.resource = create_record(
            "resource",
            {"name": "ESXi-03", "kind": "server"},
            actor=self.operator,
            organization=self.org,
        )
        self.account = create_record(
            "account",
            {
                "identity": self.identity,
                "username": "cyriel-admin",
                "system": "vSphere",
                "kind": "privileged",
            },
            actor=self.operator,
            organization=self.org,
        )
        self.now = timezone.now()

    def intent(self):
        return create_record(
            "intent",
            {
                "identity": self.identity,
                "account": self.account,
                "resource": self.resource,
                "method": "SSH",
                "reason": "Maintenance VMware",
                "reference": "CHG-2026-382",
                "starts_at": self.now - timedelta(minutes=1),
                "ends_at": self.now + timedelta(minutes=15),
            },
            actor=self.operator,
            organization=self.org,
        )

    def event(self, **overrides):
        data = {
            "source": "test",
            "external_id": "evt-1",
            "identity": self.identity,
            "account": self.account,
            "resource": self.resource,
            "method": "SSH",
            "action": "session.start",
            "occurred_at": timezone.now(),
        }
        return ingest_event({**data, **overrides}, actor=self.operator, organization=self.org)[0]

    def test_observed_access_is_explained_by_approved_intent(self):
        intent = self.intent()
        decide(
            intent.pk,
            actor=self.reviewer,
            organization=self.org,
            approved=True,
            comment="Fenêtre validée",
        )
        event = self.event()
        evaluation = event.evaluations.get()
        self.assertEqual(evaluation.verdict, "expected")
        self.assertEqual(evaluation.intent_id, intent.pk)
        self.assertTrue(
            any(f["code"] == "why" and "Maintenance" in f["detail"] for f in evaluation.findings)
        )
        self.assertTrue(verify_chain(self.org))

    def test_no_justification_means_unknown_not_invented_authorization(self):
        evaluation = self.event().evaluations.get()
        self.assertEqual(evaluation.verdict, "unknown")
        self.assertIsNone(evaluation.intent_id)

    def test_outside_approved_scope_is_a_deviation(self):
        intent = self.intent()
        decide(
            intent.pk, actor=self.reviewer, organization=self.org, approved=True, comment="Validé"
        )
        resource = Resource.objects.create(organization=self.org, name="PC-991", kind="device")
        self.assertEqual(self.event(resource=resource).evaluations.get().verdict, "deviation")

    def test_self_approval_and_second_decision_are_denied(self):
        intent = self.intent()
        OrganizationMembership.objects.filter(organization=self.org, account=self.operator).update(
            role="reviewer"
        )
        with self.assertRaises(ValidationError):
            decide(
                intent.pk, actor=self.operator, organization=self.org, approved=True, comment="Moi"
            )
        decide(
            intent.pk, actor=self.reviewer, organization=self.org, approved=True, comment="Validé"
        )
        with self.assertRaises(ValidationError):
            decide(
                intent.pk,
                actor=self.reviewer,
                organization=self.org,
                approved=False,
                comment="Rejeu",
            )

    def test_cross_organization_relations_and_missing_context_are_denied(self):
        foreign = Identity.unscoped.create(organization=self.other, name="Foreign", kind="service")
        with self.assertRaises(ValidationError):
            create_record(
                "account",
                {"identity": foreign, "username": "svc", "system": "AD"},
                actor=self.operator,
                organization=self.org,
            )
        with organization_context(None), self.assertRaises(PermissionDenied):
            list(Identity.objects.all())

    def test_tenant_switch_and_object_uuid_do_not_leak_other_organizations(self):
        foreign = Identity.unscoped.create(organization=self.other, name="Foreign", kind="machine")
        self.client.force_login(self.operator)
        response = self.client.get(reverse("record-detail", args=["identity", foreign.pk]))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            self.client.post(
                reverse("organization-switch"), {"organization": self.other.pk}
            ).status_code,
            404,
        )
        self.assertNotContains(self.client.get(reverse("identity-home")), "Foreign")

    def test_departure_revokes_accounts_grants_intents_and_leases(self):
        intent = self.intent()
        decide(
            intent.pk, actor=self.reviewer, organization=self.org, approved=True, comment="Validé"
        )
        lease = open_lease(intent.pk, actor=self.operator, organization=self.org)
        grant = Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=self.resource,
            entitlement="admin",
            justification="Poste",
        )
        revoke_identity(
            self.identity.pk, actor=self.operator, organization=self.org, reason="Fin de contrat"
        )
        self.account.refresh_from_db()
        grant.refresh_from_db()
        intent.refresh_from_db()
        lease.refresh_from_db()
        self.assertFalse(self.account.active)
        self.assertEqual(
            (grant.status, intent.status, lease.status), ("revoked", "revoked", "revoked")
        )

    def test_recertification_revoke_and_expiration_are_effective(self):
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=self.resource,
            entitlement="admin",
            justification="Fonction",
        )
        start_campaign(
            actor=self.reviewer,
            organization=self.org,
            name="Q4",
            due_at=self.now + timedelta(days=5),
        )
        review = Review.objects.get()
        review_grant(
            review.pk,
            actor=self.reviewer,
            organization=self.org,
            keep=False,
            comment="Plus nécessaire",
        )
        self.assertEqual(Grant.objects.get().status, "revoked")
        intent = self.intent()
        decide(
            intent.pk, actor=self.reviewer, organization=self.org, approved=True, comment="Validé"
        )
        lease = open_lease(intent.pk, actor=self.operator, organization=self.org)
        SessionLease.objects.filter(pk=lease.pk).update(expires_at=self.now - timedelta(seconds=1))
        expire_leases(self.org)
        expire_leases(self.org)
        lease.refresh_from_db()
        self.assertEqual(lease.status, "expired")
        self.assertEqual(
            AuditEvent.objects.filter(organization=self.org, action="pam.lease.expired.v1").count(),
            1,
        )

    def test_event_replay_is_deduplicated_and_sources_are_immutable(self):
        event = self.event()
        self.assertEqual(self.event().pk, event.pk)
        self.assertEqual(AccessEvent.objects.count(), 1)
        event.action = "tamper"
        with self.assertRaises(ValidationError):
            event.save()

    def test_source_token_ingestion_scopes_ids_and_deduplicates(self):
        _, token = create_source("Badge", actor=self.admin, organization=self.org)
        data = {
            "external_id": "badge-1",
            "identity": str(self.identity.pk),
            "account": str(self.account.pk),
            "resource": str(self.resource.pk),
            "occurred_at": self.now.isoformat(),
            "method": "badge",
            "action": "badge.presented",
            "result": "success",
        }
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        response = self.client.post(
            reverse("api-events"), json.dumps(data), content_type="application/json", **headers
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(
            self.client.post(
                reverse("api-events"), json.dumps(data), content_type="application/json", **headers
            ).status_code,
            200,
        )
        foreign = Resource.unscoped.create(organization=self.other, name="Secret", kind="door")
        data["resource"], data["external_id"] = str(foreign.pk), "badge-2"
        self.assertEqual(
            self.client.post(
                reverse("api-events"), json.dumps(data), content_type="application/json", **headers
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                reverse("api-events"), "{}", content_type="application/json"
            ).status_code,
            401,
        )

    def test_module_activation_is_per_organization_and_retains_data(self):
        self.assertFalse(ModuleActivation.objects.filter(organization=self.other).exists())
        disable_module("pam", actor=self.admin, organization=self.org)
        disable_module("connectors", actor=self.admin, organization=self.org)
        disable_module("approvals", actor=self.admin, organization=self.org)
        disable_module("access", actor=self.admin, organization=self.org)
        self.assertTrue(Identity.objects.exists())
        with self.assertRaises(PermissionDenied):
            self.event()

    def test_native_pages_and_forms_render_without_technical_admin(self):
        self.client.force_login(self.admin)
        AccountSecurity.objects.create(
            account=self.admin,
            encrypted_secret=cipher().encrypt(pyotp.random_base32().encode()).decode(),
        )
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session["organization_id"] = str(self.org.pk)
        session.save()
        for name in [
            "dashboard",
            "identity-home",
            "access-home",
            "approvals-home",
            "connectors-home",
            "recertification-home",
            "pam-home",
            "module-list",
            "audit-log",
            "system-status",
        ]:
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 200, name)
            self.assertNotContains(response, "/django-admin/")
        for kind in ["identity", "resource", "account", "credential", "grant", "intent", "event"]:
            self.assertEqual(
                self.client.get(reverse("record-create", args=[kind])).status_code, 200
            )
        response = self.client.post(
            reverse("record-create", args=["identity"]),
            {"name": "Service portes", "kind": "service"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Identity.objects.filter(name="Service portes").exists())

    def test_audit_queryset_cannot_rewrite_proofs(self):
        with self.assertRaises(ValidationError):
            AuditEvent.objects.filter(organization=self.org).update(summary="falsifié")
        with self.assertRaises(ValidationError):
            AuditEvent.objects.filter(organization=self.org).delete()

    def test_totp_replay_is_denied_and_personal_duration_is_enforced(self):
        secret = pyotp.random_base32()
        AccountSecurity.objects.create(
            account=self.operator,
            encrypted_secret=cipher().encrypt(secret.encode()).decode(),
            freshness_minutes=2,
        )
        code = pyotp.TOTP(secret).now()
        self.assertTrue(verify_mfa(self.operator, code))
        self.assertFalse(verify_mfa(self.operator, code))
        self.client.force_login(self.operator)
        session = self.client.session
        session["mfa_verified_at"] = time.time() - 121
        session.save()
        response = self.client.post(
            reverse("record-create", args=["identity"]), {"name": "Pending", "kind": "human"}
        )
        self.assertRedirects(response, reverse("account-security"))
        self.assertFalse(Identity.objects.filter(name="Pending").exists())
        self.assertIn("post_mfa_action", self.client.session)

    def test_mfa_challenge_preserves_action_and_issues_recovery_codes(self):
        self.client.force_login(self.operator)
        self.client.post(
            reverse("record-create", args=["identity"]), {"name": "Saved form", "kind": "service"}
        )
        response = self.client.get(reverse("account-security"))
        self.assertEqual(response.status_code, 200)
        secret = cipher().decrypt(self.client.session["mfa_enrollment"].encode()).decode()
        response = self.client.post(
            reverse("account-security"),
            {
                "password": "test-only-strong-password",
                "code": pyotp.TOTP(secret).now(),
                "freshness_minutes": "10",
            },
        )
        self.assertContains(response, "Reprendre mon action")
        self.assertContains(response, "Saved form")
        profile = AccountSecurity.objects.get(account=self.operator)
        self.assertEqual(profile.freshness_minutes, 10)
        self.assertEqual(len(profile.recovery_hashes), 8)
        self.assertNotEqual(profile.encrypted_secret, secret)
        self.assertEqual(
            self.client.post(
                reverse("record-create", args=["identity"]),
                {"name": "Saved form", "kind": "service"},
            ).status_code,
            302,
        )
        self.assertTrue(Identity.objects.filter(name="Saved form").exists())

    def test_login_requires_enrolled_mfa_and_denies_replay(self):
        secret = pyotp.random_base32()
        AccountSecurity.objects.create(
            account=self.operator, encrypted_secret=cipher().encrypt(secret.encode()).decode()
        )
        data = {"username": "operator", "password": "test-only-strong-password"}
        self.assertEqual(self.client.post(reverse("login"), data).status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)
        data["otp"] = pyotp.TOTP(secret).now()
        self.assertEqual(self.client.post(reverse("login"), data).status_code, 302)
        self.client.logout()
        self.assertEqual(self.client.post(reverse("login"), data).status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL database boundary")
    def test_postgresql_blocks_raw_tenant_crossing_and_evidence_rewrite(self):
        foreign = Resource.unscoped.create(organization=self.other, name="Other door", kind="door")
        event = self.event()
        with self.assertRaises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(
                "UPDATE access_accessevent SET action = 'tamper' WHERE id = %s", [event.pk]
            )
        with self.assertRaises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO identity_grant (id, organization_id, identity_id, resource_id, "
                "entitlement, justification, status, created_at) VALUES "
                "(gen_random_uuid(), %s, %s, %s, 'admin', 'test', 'active', now())",
                [self.org.pk, self.identity.pk, foreign.pk],
            )
