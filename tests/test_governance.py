import time
from datetime import UTC, datetime, timedelta
from datetime import time as wall_time
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity, OrganizationMembership
from platform_core.services import disable_module, install_module
from platform_modules.access.services import create_record, revoke_identity
from platform_modules.approvals.services import decide
from platform_modules.connectors.models import ExternalChange
from platform_modules.governance import services
from platform_modules.governance.models import ContractRevision, Supplier, SupplierContract
from platform_modules.governance.policy import assess_contract, schedule_allows
from platform_modules.governance.reconcile import reconcile_contracts
from platform_modules.identity.models import Grant, Resource
from platform_modules.identity.services import revoke_grant

from . import test_platform as baseline


class GovernanceTests(TestCase):
    intent = baseline.PlatformTests.intent
    event = baseline.PlatformTests.event

    def setUp(self):
        baseline.PlatformTests.setUp(self)
        install_module("governance", actor=self.admin, organization=self.org)
        OrganizationMembership.objects.create(
            organization=self.org, account=self.admin, role="admin"
        )
        AccountSecurity.objects.create(
            account=self.admin, encrypted_secret="test-assurance-not-a-real-key"
        )
        self.publisher = recent_authentication(self.admin, self.org, time.time())
        self.publisher.__enter__()
        self.addCleanup(self.publisher.__exit__, None, None, None)
        self.supplier = services.create_supplier(
            {"name": "Gleamer", "reference": "SUP-1", "contact": "vendor@example.test"},
            actor=self.admin,
            organization=self.org,
        )
        self.contract_data = {
            "supplier": self.supplier,
            "name": "Maintenance",
            "reference": "CTR-1",
            "sponsor": self.reviewer,
            "starts_at": self.now - timedelta(days=1),
            "ends_at": self.now + timedelta(days=30),
            "timezone_name": "Europe/Brussels",
            "weekdays": list(range(7)),
            "daily_start": wall_time(0),
            "daily_end": wall_time(0),
            "allowed_methods": ["SSH", "RDP"],
            "allowed_countries": [],
            "physical_allowed": False,
            "require_reference": True,
        }
        self.scopes = [{"resource": self.resource, "privilege": "admin", "locations": []}]
        self.contract = self.publish()
        self.participant = services.add_participant(
            {"contract": self.contract, "identity": self.identity},
            actor=self.admin,
            organization=self.org,
        )

    def publish(self, **overrides):
        return services.publish_contract(
            {**self.contract_data, **overrides},
            self.scopes,
            actor=self.admin,
            organization=self.org,
            contract_id=getattr(getattr(self, "contract", None), "pk", None),
        )

    def policy(self, **overrides):
        return services.publish_policy(
            {
                "min_reviewers": 2,
                "critical_reviewers": 3,
                "require_external_contract": True,
                "supplier_sponsor_required": True,
                **overrides,
            },
            actor=self.admin,
            organization=self.org,
        )

    def contracted_intent(self, **overrides):
        now = timezone.now()
        return create_record(
            "intent",
            {
                "identity": self.identity,
                "account": self.account,
                "resource": self.resource,
                "contract": self.contract,
                "method": "SSH",
                "privilege": "admin",
                "reason": "Maintenance",
                "reference": "CHG-1",
                "starts_at": now,
                "ends_at": now + timedelta(minutes=15),
                **overrides,
            },
            actor=self.operator,
            organization=self.org,
        )

    def approve(self, intent, actor=None):
        return decide(
            intent.pk,
            actor=actor or self.reviewer,
            organization=self.org,
            approved=True,
            comment="Périmètre vérifié",
        )

    def contract_assessment(self, **overrides):
        return assess_contract(
            contract=self.contract,
            identity=self.identity,
            resource=self.resource,
            method="SSH",
            privilege="admin",
            location="",
            country_code=overrides.pop("country_code", ""),
            reference="CHG-1",
            start=overrides.pop("start", timezone.now()),
            **overrides,
        )

    def test_policy_requires_independent_votes_and_sponsor(self):
        self.policy()
        intent = self.contracted_intent()
        self.approve(intent, self.admin)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "pending")
        with self.assertRaises(ValidationError):
            self.approve(intent, self.admin)
        self.approve(intent)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "approved")
        self.assertEqual(intent.decisions.count(), 2)
        self.assertIsNotNone(intent.approved_at)

    def test_two_votes_without_sponsor_stay_pending_and_self_vote_fails(self):
        self.policy()
        third = get_user_model().objects.create_user("third", password="test-only-password")
        OrganizationMembership.objects.create(organization=self.org, account=third, role="reviewer")
        intent = self.contracted_intent()
        self.approve(intent, self.admin)
        self.approve(intent, third)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "pending")
        OrganizationMembership.objects.filter(account=self.operator).update(role="reviewer")
        with self.assertRaises(ValidationError):
            self.approve(intent, self.operator)
        self.approve(intent)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "approved")

    def test_critical_resource_requires_three_distinct_votes(self):
        self.policy()
        self.resource.critical = True
        self.resource.save()
        intent = self.contracted_intent()
        self.approve(intent, self.admin)
        self.approve(intent)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "pending")
        third = get_user_model().objects.create_superuser(
            "second-admin", password="test-only-password"
        )
        self.approve(intent, third)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "approved")

    def test_contract_required_cannot_be_bypassed_by_direct_grant_or_module_disable(self):
        self.policy()
        self.identity.kind = "external"
        self.identity.save()
        with self.assertRaises(ValidationError):
            self.intent()
        with self.assertRaises(ValidationError):
            create_record(
                "grant",
                {
                    "identity": self.identity,
                    "resource": self.resource,
                    "entitlement": "admin",
                    "justification": "Bypass",
                },
                actor=self.admin,
                organization=self.org,
            )
        disable_module("governance", actor=self.admin, organization=self.org)
        with self.assertRaises(ValidationError):
            self.intent()

    def test_method_scope_physical_and_country_controls(self):
        self.assertEqual(self.contract_assessment().status, "allow")
        self.publish(allowed_methods=["RDP"], allowed_countries=["BE"])
        assessment = self.contract_assessment()
        self.assertEqual(assessment.status, "deny")
        self.assertTrue(
            any(
                f["code"] == "contract_country" and f["state"] == "unknown"
                for f in assessment.findings
            )
        )
        self.publish(allowed_methods=["SSH"], allowed_countries=["BE"])
        self.assertEqual(self.contract_assessment(country_code="BE").status, "allow")
        self.assertEqual(self.contract_assessment().status, "unknown")
        self.resource.kind = "door"
        self.resource.save()
        self.assertEqual(self.contract_assessment(country_code="BE").status, "deny")
        with self.assertRaises(ValidationError):
            self.contracted_intent(country_code="BE")

    def test_revision_and_late_enrollment_cannot_rewrite_past_access(self):
        before_participant = self.contract.revisions.get().effective_at
        self.assertEqual(self.contract_assessment(start=before_participant).status, "deny")
        observed = timezone.now()
        self.publish(allowed_methods=["RDP"])
        old = self.contract_assessment(start=observed)
        self.assertEqual(old.status, "allow")
        self.assertEqual(self.contract_assessment().status, "deny")
        proof = [f for f in old.findings if f["code"] == "contract_revision"][0]
        self.assertIn("révision 1", proof["detail"])

    def test_observation_does_not_invent_country_from_declared_intent(self):
        self.publish(allowed_countries=["BE"])
        intent = self.contracted_intent(country_code="BE")
        self.approve(intent)
        event = self.event(privilege="admin")
        self.assertEqual(event.evaluations.get().verdict, "unknown")
        event = self.event(privilege="admin", country_code="FR", external_id="foreign-country")
        self.assertEqual(event.evaluations.get().verdict, "deviation")

    def test_retirement_withdraws_only_linked_rights_and_preserves_shared_account(self):
        intent = self.contracted_intent(fulfillment="iam_group")
        self.approve(intent)
        intent.refresh_from_db()
        grant = intent.provisioned_grant
        independent = Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            account=self.account,
            resource=self.resource,
            entitlement="read",
            justification="Autre fonction",
        )
        services.withdraw("contract", self.contract.pk, actor=self.admin, organization=self.org)
        reconcile_contracts(self.org)
        grant.refresh_from_db()
        independent.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual(grant.status, "revoked")
        self.assertIsNotNone(grant.revoked_at)
        self.assertEqual(independent.status, "active")
        self.assertTrue(self.account.active)
        self.assertEqual(
            ExternalChange.objects.filter(grant=grant, kind="remove_membership").count(), 1
        )
        self.assertFalse(
            ExternalChange.objects.filter(account=self.account, kind="disable_account").exists()
        )

    def test_dedicated_account_is_disabled_on_participant_withdrawal(self):
        dedicated = create_record(
            "account",
            {
                "identity": self.identity,
                "username": "vendor-dedicated",
                "system": "AD",
                "managed_contract": self.contract,
            },
            actor=self.admin,
            organization=self.org,
        )
        services.withdraw(
            "participant", self.participant.pk, actor=self.admin, organization=self.org
        )
        dedicated.refresh_from_db()
        self.assertFalse(dedicated.active)
        self.assertTrue(
            ExternalChange.objects.filter(account=dedicated, kind="disable_account").exists()
        )

    def test_separation_blocks_new_overlapping_right_but_not_adjacent_window(self):
        other = Resource.objects.create(organization=self.org, name="Payments", kind="application")
        now = timezone.now()
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=other,
            entitlement="pay",
            justification="Finance",
            expires_at=now + timedelta(hours=1),
        )
        services.publish_separation(
            {
                "name": "Préparer ≠ payer",
                "left_resource": self.resource,
                "left_entitlement": "admin",
                "right_resource": other,
                "right_entitlement": "pay",
            },
            actor=self.admin,
            organization=self.org,
        )
        with self.assertRaises(ValidationError):
            self.contracted_intent()
        self.contracted_intent(starts_at=now + timedelta(hours=1), ends_at=now + timedelta(hours=2))

    def test_future_approval_never_justifies_previous_event_and_departure_preserves_history(self):
        intent = self.contracted_intent()
        before = timezone.now()
        with patch(
            "platform_modules.approvals.services.timezone.now",
            return_value=before + timedelta(seconds=1),
        ):
            self.approve(intent)
        late = self.event(occurred_at=before, privilege="admin")
        self.assertEqual(late.evaluations.get().verdict, "unknown")
        observed = before + timedelta(seconds=2)
        with patch(
            "platform_modules.access.services.timezone.now",
            return_value=before + timedelta(seconds=3),
        ):
            revoke_identity(
                self.identity.pk, actor=self.admin, organization=self.org, reason="Départ"
            )
        historic = self.event(occurred_at=observed, external_id="late-valid", privilege="admin")
        self.assertEqual(
            historic.evaluations.get().verdict, "expected", historic.evaluations.get().findings
        )
        current = self.event(
            external_id="after-departure",
            privilege="admin",
            occurred_at=before + timedelta(seconds=4),
        )
        self.assertEqual(current.evaluations.get().verdict, "deviation")

    def test_revoked_grant_remains_a_historical_justification(self):
        grant = create_record(
            "grant",
            {
                "identity": self.identity,
                "resource": self.resource,
                "entitlement": "admin",
                "justification": "Fonction",
            },
            actor=self.admin,
            organization=self.org,
        )
        observed = timezone.now()
        with patch(
            "platform_modules.identity.services.timezone.now",
            return_value=observed + timedelta(seconds=1),
        ):
            revoke_grant(grant, actor=self.admin, organization=self.org, origin="manual")
        late = self.event(occurred_at=observed, privilege="admin")
        self.assertEqual(
            late.evaluations.get().verdict, "expected", late.evaluations.get().findings
        )

    def test_future_iam_grant_is_queued_no_earlier_than_window(self):
        start = timezone.now() + timedelta(hours=1)
        intent = self.contracted_intent(
            starts_at=start, ends_at=start + timedelta(minutes=30), fulfillment="iam_group"
        )
        self.approve(intent)
        change = ExternalChange.objects.get(kind="add_membership")
        self.assertEqual(change.next_attempt_at, start)
        self.assertEqual(change.grant.valid_from, start)

    def test_admin_mfa_and_tenant_boundaries_on_publications(self):
        with (
            self.assertRaises(PermissionDenied),
            recent_authentication(self.admin, self.org, time.time() - 10000),
        ):
            self.publish()
        # An already established context for org A is not evidence for org B.
        with self.assertRaises(PermissionDenied):
            services.create_supplier({"name": "Other"}, actor=self.admin, organization=self.other)
        foreign = Supplier.unscoped.create(organization=self.other, name="Other company")
        with self.assertRaises(ValidationError):
            services.publish_contract(
                {**self.contract_data, "supplier": foreign, "reference": "CTR-X"},
                self.scopes,
                actor=self.admin,
                organization=self.org,
            )
        self.assertFalse(SupplierContract.objects.filter(reference="CTR-X").exists())

    def test_native_forms_render_and_forged_tenant_choices_are_rejected(self):
        self.client.force_login(self.admin)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session["organization_id"] = str(self.org.pk)
        session.save()
        self.assertEqual(self.client.get(reverse("governance-home")).status_code, 200)
        for kind in ["supplier", "contract", "participant", "policy", "separation"]:
            response = self.client.get(reverse("governance-create", args=[kind]))
            self.assertEqual(response.status_code, 200, response.content)
            self.assertNotContains(response, "/django-admin/")
            if kind == "contract":
                # Weekdays are a group, not one horizontally aligned boolean field.
                self.assertContains(response, 'class="form-field checkbox-field"', count=2)
        self.assertEqual(
            self.client.get(reverse("governance-contract", args=[self.contract.pk])).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(
                reverse("governance-contract-revise", args=[self.contract.pk])
            ).status_code,
            200,
        )
        foreign = Supplier.unscoped.create(organization=self.other, name="Foreign")
        response = self.client.post(
            reverse("governance-create", args=["contract"]), {"supplier": foreign.pk}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sélectionnez un choix valide")
        self.assertEqual(
            self.client.get(reverse("governance-create", args=["unknown"])).status_code, 404
        )

    def test_overnight_schedule_and_dst_are_conservative(self):
        revision = self.contract.revisions.get()
        revision.weekdays, revision.daily_start, revision.daily_end = (
            [4],
            wall_time(22),
            wall_time(2),
        )
        friday = datetime(2026, 11, 6, 22, tzinfo=UTC)  # 23:00 Brussels Friday
        self.assertTrue(schedule_allows(revision, friday, friday + timedelta(hours=1)))
        self.assertTrue(schedule_allows(revision, friday, friday + timedelta(hours=3)))
        self.assertFalse(schedule_allows(revision, friday, friday + timedelta(hours=3, minutes=1)))
        revision.weekdays, revision.daily_start, revision.daily_end = (
            [6],
            wall_time(2, 30),
            wall_time(4),
        )
        # Spring DST skips 02:30, so that window is denied rather than silently enlarged.
        spring = datetime(2027, 3, 28, 1, 35, tzinfo=UTC)
        self.assertFalse(schedule_allows(revision, spring, spring + timedelta(minutes=5)))
        # Autumn opening at 02:30 uses the later occurrence (01:30 UTC).
        autumn = datetime(2026, 10, 25, 0, 45, tzinfo=UTC)
        self.assertFalse(schedule_allows(revision, autumn, autumn + timedelta(minutes=5)))
        autumn = datetime(2026, 10, 25, 1, 45, tzinfo=UTC)
        self.assertTrue(schedule_allows(revision, autumn, autumn + timedelta(minutes=5)))

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL boundary")
    def test_database_preserves_published_policy_and_blocks_cross_tenant_contract(self):
        revision = self.contract.revisions.get()
        with self.assertRaises(DatabaseError), transaction.atomic():
            ContractRevision.objects.filter(pk=revision.pk).update(allowed_methods=["*"])
        foreign = Supplier.unscoped.create(organization=self.other, name="Foreign")
        with self.assertRaises(DatabaseError), transaction.atomic():
            SupplierContract.objects.filter(pk=self.contract.pk).update(supplier=foreign)
