import time
from datetime import UTC, datetime, timedelta
from unittest import skipUnless
from unittest.mock import patch

import pyotp
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity, OrganizationMembership
from platform_core.security import cipher
from platform_core.services import install_module
from platform_modules.access.models import AccessIntent
from platform_modules.access.services import (
    create_record,
    ingest_event,
    reevaluate_event,
    revoke_identity,
)
from platform_modules.approvals.models import ApprovalDecision
from platform_modules.approvals.services import decide
from platform_modules.governance.policy import approval_requirements
from platform_modules.governance.services import publish_policy
from platform_modules.identity.bindings import create_binding, current_binding, revoke_binding
from platform_modules.identity.models import ExternalAccount, Identity, LoginIdentityBinding
from platform_modules.pam.mandates import account_snapshot, authorized_at, scope_hash
from platform_modules.pam.services import open_lease

from . import test_platform as baseline


class PersonMandateTests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        for account in (self.admin, self.operator, self.reviewer):
            AccountSecurity.objects.create(
                account=account,
                encrypted_secret=cipher().encrypt(pyotp.random_base32().encode()).decode(),
            )
        self.service = Identity.objects.create(
            organization=self.org, name="Service Oracle", kind="service"
        )
        self.shared = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.service,
            username="svc-oracle",
            system="AD",
            kind="service",
        )
        self.reviewer_person = Identity.objects.create(
            organization=self.org, name="Independent reviewer", kind="human"
        )
        with self.assurance():
            self.binding = create_binding(
                login_account=self.operator,
                identity=self.identity,
                verification_reference="HR-verified-1",
                actor=self.admin,
                organization=self.org,
            )
            self.reviewer_binding = create_binding(
                login_account=self.reviewer,
                identity=self.reviewer_person,
                verification_reference="HR-verified-2",
                actor=self.admin,
                organization=self.org,
            )

    def assurance(self):
        return recent_authentication(self.admin, self.org, time.time())

    def request(self, **changes):
        with recent_authentication(self.operator, self.org, time.time()):
            return create_record(
                "intent",
                {
                    "identity": self.identity,
                    "account": self.shared,
                    "resource": self.resource,
                    "method": "SSH",
                    "reason": "Maintenance du service",
                    "reference": "CHG-721",
                    "fulfillment": "pam",
                    "starts_at": timezone.now() - timedelta(minutes=1),
                    "ends_at": timezone.now() + timedelta(minutes=20),
                    **changes,
                },
                actor=self.operator,
                organization=self.org,
            )

    def approve(self, intent, actor=None):
        actor = actor or self.reviewer
        with recent_authentication(actor, self.org, time.time()):
            decision = decide(
                intent.pk,
                actor=actor,
                organization=self.org,
                approved=True,
                comment="Périmètre et personne vérifiés",
            )
        intent.refresh_from_db()
        return decision

    def linked_user(self, username, identity=None, role="reviewer"):
        account = get_user_model().objects.create_user(username, password="fixture-password")
        AccountSecurity.objects.create(
            account=account,
            encrypted_secret=cipher().encrypt(pyotp.random_base32().encode()).decode(),
        )
        OrganizationMembership.objects.create(organization=self.org, account=account, role=role)
        identity = identity or Identity.objects.create(
            organization=self.org, name=username, kind="human"
        )
        with self.assurance():
            binding = create_binding(
                login_account=account,
                identity=identity,
                verification_reference="HR-additional-person",
                actor=self.admin,
                organization=self.org,
            )
        return account, binding

    def policy(self, minimum):
        install_module("governance", actor=self.admin, organization=self.org)
        with self.assurance():
            publish_policy(
                {
                    "min_reviewers": minimum,
                    "critical_reviewers": minimum,
                    "require_external_contract": True,
                    "supplier_sponsor_required": False,
                },
                actor=self.admin,
                organization=self.org,
            )

    def test_shared_service_account_is_authorized_for_the_named_person_not_reassigned(self):
        intent = self.request()
        self.assertEqual(intent.requester_binding_id, self.binding.pk)
        self.assertEqual(intent.account_snapshot, account_snapshot(self.shared))
        decision = self.approve(intent)
        self.assertEqual(decision.reviewer_identity_id, self.reviewer_person.pk)
        self.assertEqual(len(decision.signature), 64)
        lease = open_lease(intent.pk, actor=self.operator, organization=self.org)
        self.assertEqual(lease.opened_by_id, self.operator.pk)
        self.shared.refresh_from_db()
        self.assertEqual(self.shared.identity_id, self.service.pk)
        self.assertTrue(verify_chain(self.org))

    def test_pam_creation_and_vote_require_service_level_recent_mfa(self):
        with self.assertRaises(PermissionDenied):
            create_record(
                "intent",
                {
                    "identity": self.identity,
                    "account": self.shared,
                    "resource": self.resource,
                    "method": "SSH",
                    "reason": "No MFA",
                    "fulfillment": "pam",
                    "starts_at": timezone.now(),
                    "ends_at": timezone.now() + timedelta(minutes=5),
                },
                actor=self.operator,
                organization=self.org,
            )
        intent = self.request()
        with self.assertRaises(PermissionDenied):
            decide(
                intent.pk,
                actor=self.reviewer,
                organization=self.org,
                approved=True,
                comment="No MFA",
            )

    def test_native_full_account_mode_does_not_pretend_to_enforce_read_only_commands(self):
        with self.assertRaisesMessage(ValidationError, "droits natifs"):
            self.request(privilege="read_only")
        intent = self.request()
        self.assertEqual(intent.privilege, "native_full_account")

    def test_person_can_use_its_own_technical_account_without_reassignment(self):
        self.account.kind = "service"
        self.account.save(update_fields=["kind"])
        intent = self.request(account=self.account)
        self.approve(intent)
        self.assertEqual(
            open_lease(intent.pk, actor=self.operator, organization=self.org).status, "active"
        )

    def test_unsigned_or_modified_person_attestation_is_not_authority(self):
        account, binding = self.linked_user("unsigned-person")
        # Create a different row with copied proof: its UUID/person tuple is not signed.
        fake = LoginIdentityBinding(
            organization=self.org,
            login_account=self.operator,
            identity=self.identity,
            verification_reference=binding.verification_reference,
            created_by=self.admin,
            created_at=binding.created_at,
            mfa_verified_at=binding.mfa_verified_at,
            mfa_window_minutes=binding.mfa_window_minutes,
            signature=binding.signature,
        )
        from platform_modules.identity.bindings import binding_valid

        self.assertFalse(binding_valid(fake))
        self.assertTrue(binding_valid(binding))
        self.assertTrue(account.is_active)

    def test_submicrosecond_mfa_rounding_cannot_sign_an_invalid_person_attestation(self):
        # Windows can report the same clock tick across several calls. A float
        # converted with nearest-microsecond rounding may then be one us ahead
        # of Django's truncated datetime, even though MFA occurred first.
        stamp = float(int(time.time()) - 5) + 0.0000006
        truncated = datetime.fromtimestamp(int(stamp), UTC)
        self.assertGreater(datetime.fromtimestamp(stamp, UTC), truncated)
        field = LoginIdentityBinding._meta.get_field("created_at")
        with (
            patch("platform_core.authorization.time.time", return_value=stamp),
            patch.object(field, "_get_default", return_value=truncated),
        ):
            _, binding = self.linked_user("precision-person")
        from platform_modules.identity.bindings import binding_valid

        self.assertLessEqual(binding.mfa_verified_at, binding.created_at)
        self.assertTrue(binding_valid(binding))

    def test_submicrosecond_mfa_rounding_does_not_invalidate_a_signed_pam_vote(self):
        intent = self.request()
        stamp = float(int(time.time()) + 5) + 0.0000006
        truncated = datetime.fromtimestamp(int(stamp), UTC)
        field = ApprovalDecision._meta.get_field("decided_at")
        with (
            patch("platform_core.authorization.time.time", return_value=stamp),
            patch("django.utils.timezone.now", return_value=truncated),
            patch.object(field, "_get_default", return_value=truncated),
        ):
            decision = self.approve(intent)
        self.assertLessEqual(decision.mfa_verified_at, decision.decided_at)
        self.assertEqual(intent.status, "approved")

    def test_link_requires_admin_mfa_and_does_not_guess_by_identical_email(self):
        person = Identity.objects.create(
            organization=self.org, name="New person", kind="human", email=self.admin.email
        )
        with self.assertRaises(PermissionDenied):
            create_binding(
                login_account=self.admin,
                identity=person,
                verification_reference="HR",
                actor=self.admin,
                organization=self.org,
            )
        self.assertFalse(LoginIdentityBinding.objects.filter(login_account=self.admin).exists())
        with self.assurance(), self.assertRaises(ValidationError):
            create_binding(
                login_account=self.admin,
                identity=person,
                verification_reference="HR",
                actor=self.admin,
                organization=self.org,
            )

    def test_person_link_cannot_be_reassigned_or_deleted(self):
        self.binding.identity = self.reviewer_person
        with self.assertRaises(ValidationError):
            self.binding.save()
        with self.assertRaises(ValidationError):
            self.binding.delete()

    def test_request_cannot_name_another_person_or_another_personal_account(self):
        with self.assertRaises(ValidationError):
            self.request(identity=self.reviewer_person)
        personal = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.reviewer_person,
            username="reviewer-admin",
            system="AD",
            kind="privileged",
        )
        with self.assertRaises(ValidationError):
            self.request(account=personal)

    def test_self_approval_through_a_second_login_is_rejected(self):
        alias, _ = self.linked_user("requester-alias", identity=self.identity)
        intent = self.request()
        with self.assertRaisesMessage(ValidationError, "un autre compte"):
            self.approve(intent, actor=alias)
        self.assertFalse(ApprovalDecision.objects.filter(intent=intent).exists())

    def test_two_logins_of_one_reviewer_never_count_as_two_people(self):
        self.policy(2)
        alias, _ = self.linked_user("reviewer-alias", identity=self.reviewer_person)
        another, _ = self.linked_user("second-real-person")
        intent = self.request()
        self.approve(intent)
        self.assertEqual(intent.status, "pending")
        with self.assertRaisesMessage(ValidationError, "Cette personne a déjà voté"):
            self.approve(intent, actor=alias)
        self.approve(intent, actor=another)
        self.assertEqual(intent.status, "approved")
        self.assertEqual(approval_requirements(intent)["approved"], 2)

    def test_reviewer_without_a_person_link_cannot_approve_pam(self):
        account = get_user_model().objects.create_user(
            "unbound-reviewer", password="fixture-password"
        )
        AccountSecurity.objects.create(
            account=account,
            encrypted_secret=cipher().encrypt(pyotp.random_base32().encode()).decode(),
        )
        OrganizationMembership.objects.create(
            organization=self.org, account=account, role="reviewer"
        )
        with self.assertRaises(ValidationError):
            self.approve(self.request(), actor=account)

    def test_scope_changes_invalidate_previous_person_votes(self):
        intent = self.request()
        self.approve(intent)
        original_hash = scope_hash(intent)
        AccessIntent.objects.filter(pk=intent.pk).update(reason="Different intervention")
        intent.refresh_from_db()
        self.assertNotEqual(scope_hash(intent), original_hash)
        self.assertFalse(approval_requirements(intent, at=intent.approved_at)["complete"])
        with self.assertRaises(ValidationError):
            open_lease(intent.pk, actor=self.operator, organization=self.org)

    def test_a_renamed_or_reowned_account_requires_a_new_request_before_approval(self):
        intent = self.request()
        ExternalAccount.objects.filter(pk=self.shared.pk).update(username="another-principal")
        with self.assertRaises(ValidationError):
            self.approve(intent)
        self.assertFalse(ApprovalDecision.objects.filter(intent=intent).exists())

    def test_changed_account_after_approval_is_not_a_valid_execution_target(self):
        intent = self.request()
        self.approve(intent)
        ExternalAccount.objects.filter(pk=self.shared.pk).update(system="Another directory")
        with self.assertRaises(ValidationError):
            open_lease(intent.pk, actor=self.operator, organization=self.org)

    def test_copying_a_vote_to_a_different_mandate_does_not_authorize_it(self):
        first, second = self.request(), self.request()
        decision = self.approve(first)
        forged = ApprovalDecision(
            organization=self.org,
            intent=second,
            reviewer=self.reviewer,
            reviewer_binding=self.reviewer_binding,
            reviewer_identity=self.reviewer_person,
            approved=True,
            comment=decision.comment,
            scope_hash=decision.scope_hash,
            signature=decision.signature,
        )
        forged.save()
        AccessIntent.objects.filter(pk=second.pk).update(
            status="approved", approved_at=timezone.now()
        )
        second.refresh_from_db()
        self.assertFalse(approval_requirements(second)["complete"])
        with self.assertRaises(ValidationError):
            open_lease(second.pk, actor=self.operator, organization=self.org)

    def test_revoking_binding_revokes_mandates_not_global_login_or_shared_account(self):
        intent = self.request()
        self.approve(intent)
        lease = open_lease(intent.pk, actor=self.operator, organization=self.org)
        with self.assurance():
            revoke_binding(
                self.binding.pk, actor=self.admin, organization=self.org, reason="Mission terminée"
            )
        for obj in (self.operator, self.account, self.shared, intent, lease):
            obj.refresh_from_db()
        self.assertTrue(self.operator.is_active)
        self.assertTrue(self.account.active)
        self.assertTrue(self.shared.active)
        self.assertEqual((intent.status, lease.status), ("revoked", "revoked"))
        with self.assertRaises(ValidationError):
            current_binding(self.operator, organization=self.org)

    def test_replacing_a_link_does_not_reuse_old_mandates_even_for_the_same_person(self):
        intent = self.request()
        self.approve(intent)
        with self.assurance():
            revoke_binding(
                self.binding.pk,
                actor=self.admin,
                organization=self.org,
                reason="Nouvelle attestation",
            )
            replacement = create_binding(
                login_account=self.operator,
                identity=self.identity,
                verification_reference="HR-new",
                actor=self.admin,
                organization=self.org,
            )
        self.assertNotEqual(replacement.pk, self.binding.pk)
        with self.assertRaises(ValidationError):
            open_lease(intent.pk, actor=self.operator, organization=self.org)

    def test_reviewer_link_revocation_does_not_rewrite_a_valid_historical_vote(self):
        intent = self.request()
        self.approve(intent)
        with self.assurance():
            revoke_binding(
                self.reviewer_binding.pk,
                actor=self.admin,
                organization=self.org,
                reason="Compte de validation remplacé",
            )
        intent.refresh_from_db()
        self.assertTrue(approval_requirements(intent, at=intent.approved_at)["complete"])
        self.assertEqual(
            open_lease(intent.pk, actor=self.operator, organization=self.org).status, "active"
        )

    def test_departing_person_does_not_disable_the_shared_service_account(self):
        intent = self.request()
        self.approve(intent)
        revoke_identity(
            self.identity.pk, actor=self.operator, organization=self.org, reason="Départ"
        )
        for obj in (self.binding, self.shared, intent):
            obj.refresh_from_db()
        self.assertIsNotNone(self.binding.revoked_at)
        self.assertTrue(self.shared.active)
        self.assertEqual(intent.status, "revoked")

    def test_departing_service_owner_disables_its_account_and_related_mandate(self):
        intent = self.request()
        self.approve(intent)
        revoke_identity(
            self.service.pk, actor=self.operator, organization=self.org, reason="Retrait service"
        )
        self.shared.refresh_from_db()
        intent.refresh_from_db()
        self.assertFalse(self.shared.active)
        self.assertEqual(intent.status, "revoked")
        self.assertIsNone(LoginIdentityBinding.objects.get(pk=self.binding.pk).revoked_at)

    def test_historical_observation_remains_explainable_after_link_revocation(self):
        intent = self.request()
        self.approve(intent)
        before = timezone.now()
        event, _ = ingest_event(
            {
                "source": "fixture",
                "external_id": "mandate-historical",
                "occurred_at": before,
                "identity": self.identity,
                "account": self.shared,
                "resource": self.resource,
                "method": "SSH",
                "privilege": "native_full_account",
                "action": "session.start",
            },
            actor=self.operator,
            organization=self.org,
        )
        self.assertEqual(event.evaluations.get().verdict, "expected")
        with self.assurance():
            revoke_binding(
                self.binding.pk, actor=self.admin, organization=self.org, reason="Fin intervention"
            )
        intent.refresh_from_db()
        self.assertTrue(authorized_at(intent, before))
        self.assertFalse(authorized_at(intent, timezone.now()))
        self.assertEqual(
            reevaluate_event(event.pk, actor=self.operator, organization=self.org).verdict,
            "expected",
        )

    def test_legacy_unbound_approval_is_preserved_but_not_executable(self):
        intent = self.request()
        AccessIntent.objects.filter(pk=intent.pk).update(
            requester_binding=None,
            account_snapshot={},
            status="approved",
            approved_at=timezone.now(),
        )
        with self.assertRaises(ValidationError):
            open_lease(intent.pk, actor=self.operator, organization=self.org)
        self.assertTrue(AccessIntent.objects.filter(pk=intent.pk).exists())

    def test_binding_form_lists_only_members_and_people_of_this_organization(self):
        outsider = get_user_model().objects.create_user(
            "foreign-person-login", password="fixture-password"
        )
        foreign = Identity.unscoped.create(
            organization=self.other, name="Foreign IAM person", kind="human"
        )
        self.client.force_login(self.admin)
        response = self.client.get(reverse("identity-login-bindings"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, outsider.username)
        self.assertNotContains(response, foreign.name)
        self.assertNotContains(response, "/django-admin/")
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        response = self.client.post(
            reverse("identity-login-bindings"),
            {
                "login_account": outsider.pk,
                "identity": foreign.pk,
                "verification_reference": "invalid",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(LoginIdentityBinding.objects.filter(login_account=outsider).exists())

    def test_foreign_person_cannot_be_bound_even_with_an_admin_mfa(self):
        foreign = Identity.unscoped.create(organization=self.other, name="Foreign", kind="human")
        account, _ = self.linked_user("org-local-login")
        with self.assurance(), self.assertRaises(ValidationError):
            create_binding(
                login_account=account,
                identity=foreign,
                verification_reference="invalid",
                actor=self.admin,
                organization=self.org,
            )

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL person binding guards")
    def test_postgresql_refuses_rebinding_or_erasing_person_attestations(self):
        with self.assertRaises(DatabaseError), transaction.atomic():
            LoginIdentityBinding.objects.filter(pk=self.binding.pk).update(
                identity=self.reviewer_person
            )
        account, binding = self.linked_user("unreferenced-attestation")
        with self.assertRaises(DatabaseError), transaction.atomic():
            LoginIdentityBinding.objects.filter(pk=binding.pk).delete()
        self.assertTrue(get_user_model().objects.get(pk=account.pk).is_active)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL principal tuple guard")
    def test_postgresql_refuses_forged_person_and_requester_tuple(self):
        with self.assertRaises(DatabaseError), transaction.atomic():
            AccessIntent.unscoped.bulk_create(
                [
                    AccessIntent(
                        organization=self.org,
                        identity=self.identity,
                        account=self.shared,
                        resource=self.resource,
                        requested_by=self.operator,
                        requester_binding=self.reviewer_binding,
                        account_snapshot=account_snapshot(self.shared),
                        method="SSH",
                        reason="Forged requester",
                        fulfillment="pam",
                        starts_at=timezone.now(),
                        ends_at=timezone.now() + timedelta(minutes=5),
                    )
                ]
            )
