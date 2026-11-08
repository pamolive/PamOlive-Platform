import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase
from django.urls import reverse

from platform_core.audit import record, verify_chain
from platform_core.authorization import recent_authentication
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.approvals.services import decide
from platform_modules.identity.models import ExternalAccount, Grant, Identity, Resource
from platform_modules.identity.mover import (
    current_move,
    decide_move,
    propose_move,
    publish_role,
    verify_mover,
)
from platform_modules.identity.mover_models import MoveAccess, MoveDecision, MoveGrant, RoleRevision
from tests import test_platform as fixture
from tests.person_fixtures import bind_person


class MoverFixture:
    def setUp(self):
        fixture.PlatformTests.setUp(self)
        for actor, role in (
            (self.operator, "operator"),
            (self.reviewer, "reviewer"),
            (self.admin, "admin"),
        ):
            bind_person(actor, organization=self.org, administrator=self.admin, role=role)

    @contextmanager
    def mfa(self, actor):
        with recent_authentication(actor, self.org, time.time()):
            yield

    def role(self, key="tech", *, revision=0, enabled=True, resource=None):
        with self.mfa(self.admin):
            return publish_role(
                key=key,
                name=f"Role {key}",
                expected_revision=revision,
                enabled=enabled,
                entries=[
                    dict(
                        resource=(resource or self.resource).pk,
                        method="SSO",
                        privilege="read",
                        days=30,
                    )
                ],
                actor=self.admin,
                organization=self.org,
            )

    def proposal(self, assignments, *, department="Technique"):
        with self.mfa(self.operator):
            return propose_move(
                identity_id=self.identity.pk,
                department=department,
                assignments=assignments,
                reason="Changement approuvé du poste",
                reference="HR-42",
                actor=self.operator,
                organization=self.org,
            )

    def apply(self, proposal, *, actor=None, approved=True):
        actor = actor or self.reviewer
        with self.mfa(actor):
            return decide_move(
                proposal.pk,
                approved=approved,
                comment="Vérifié",
                actor=actor,
                organization=self.org,
            )

    def approve_access(self, intent, actor=None):
        actor = actor or self.reviewer
        with self.mfa(actor):
            return decide(
                intent.pk, actor=actor, organization=self.org, approved=True, comment="Contrôlé"
            )


class MoverTests(MoverFixture, TestCase):
    def test_approval_creates_only_requests_and_withdraws_only_attested_grants(self):
        old = self.role()
        independent = Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            account=self.account,
            resource=self.resource,
            entitlement="read",
            justification="Independent basis",
        )
        change = self.proposal({old.pk: [self.account.pk]})
        self.assertFalse(AccessIntent.objects.exists())
        self.apply(change)
        self.assertEqual(Grant.objects.count(), 1)
        old_request = AccessIntent.objects.get()
        self.assertEqual(old_request.status, "pending")
        self.approve_access(old_request)
        origin = MoveGrant.objects.get()
        self.assertEqual(origin.grant.status, "active")
        new = self.role("operations")
        transfer = self.proposal({new.pk: [self.account.pk]}, department="Operations")
        self.apply(transfer)
        self.identity.refresh_from_db()
        independent.refresh_from_db()
        old_request.refresh_from_db()
        origin.grant.refresh_from_db()
        self.assertEqual(self.identity.department, "Operations")
        self.assertEqual(independent.status, "active")
        self.assertEqual(old_request.status, "revoked")
        self.assertEqual(origin.grant.status, "revoked")
        self.assertEqual(AccessIntent.objects.exclude(pk=old_request.pk).get().status, "pending")
        self.assertEqual(Grant.objects.count(), 2)
        self.assertTrue(verify_chain(self.org))
        with organization_context(None):
            self.assertEqual(verify_mover(), 9)

    def test_pending_access_is_withdrawn_and_retained_role_keeps_its_provenance(self):
        old, kept = self.role(), self.role("base")
        first = self.apply(self.proposal({old.pk: [self.account.pk], kept.pk: [self.account.pk]}))
        kept_request = MoveAccess.objects.get(role=kept).intent
        self.apply(self.proposal({kept.pk: []}))
        self.assertEqual(current_move(self.identity).body["roles"], {str(kept.pk): str(first.pk)})
        self.assertEqual(MoveAccess.objects.get(role=old).intent.status, "revoked")
        self.assertEqual(AccessIntent.objects.count(), 2)
        self.approve_access(kept_request)
        self.assertEqual(MoveGrant.objects.count(), 1)

    def test_competing_moves_and_late_grant_require_fresh_review(self):
        old = self.role()
        self.apply(self.proposal({old.pk: [self.account.pk]}))
        pending = self.proposal({}, department="Other")
        self.approve_access(AccessIntent.objects.get())
        with self.assertRaisesMessage(ValidationError, "accès à retirer ont changé"):
            self.apply(pending)
        first = self.proposal({}, department="One")
        second = self.proposal({}, department="Two")
        self.apply(first)
        with self.assertRaisesMessage(ValidationError, "rôles ont changé"):
            self.apply(second)
        self.assertEqual(MoveDecision.objects.count(), 2)

    def test_account_drift_and_revised_catalog_are_rejected(self):
        role = self.role()
        pending = self.proposal({role.pk: [self.account.pk]})
        ExternalAccount.objects.filter(pk=self.account.pk).update(username="Changed account")
        with self.assertRaisesMessage(ValidationError, "compte choisi a changé"):
            self.apply(pending)
        self.role(revision=1)
        with self.assertRaisesMessage(ValidationError, "dernière révision"):
            self.apply(pending)
        self.assertFalse(MoveDecision.objects.exists())

    def test_stale_scope_cannot_be_approved_even_if_intent_changes_fulfillment(self):
        role = self.role()
        self.apply(self.proposal({role.pk: [self.account.pk]}))
        intent = AccessIntent.objects.get()
        AccessIntent.objects.filter(pk=intent.pk).update(privilege="admin", fulfillment="observe")
        with self.assertRaisesMessage(ValidationError, "provenance"):
            self.approve_access(intent)
        self.assertFalse(Grant.objects.exists())

    def test_denied_move_leaves_no_effect_and_cannot_be_replayed(self):
        role = self.role()
        move = self.proposal({role.pk: [self.account.pk]})
        self.apply(move, approved=False)
        self.assertFalse(AccessIntent.objects.exists())
        self.assertIsNone(current_move(self.identity))
        with self.assertRaisesMessage(ValidationError, "déjà reçu"):
            self.apply(move)

    def test_no_mfa_no_approval_and_second_login_of_same_person_is_not_independent(self):
        role = self.role()
        proposal = self.proposal({role.pk: [self.account.pk]})
        with self.assertRaises(PermissionDenied):
            decide_move(
                proposal.pk,
                approved=True,
                comment="No MFA",
                actor=self.reviewer,
                organization=self.org,
            )
        requester_identity = self.operator.loginidentitybinding_set.get().identity
        alias = get_user_model().objects.create_user("requester-reviewer")
        bind_person(
            alias,
            organization=self.org,
            administrator=self.admin,
            identity=requester_identity,
            role="reviewer",
        )
        with self.assertRaisesMessage(ValidationError, "ne peuvent pas décider"):
            self.apply(proposal, actor=alias)
        self.apply(proposal)
        with self.assertRaisesMessage(ValidationError, "ne peuvent pas approuver"):
            self.approve_access(AccessIntent.objects.get(), actor=alias)

    def test_late_policy_error_rolls_back_department_withdrawal_and_audit(self):
        role = self.role()
        self.apply(self.proposal({role.pk: [self.account.pk]}))
        initial = AccessIntent.objects.get()
        self.approve_access(initial)
        new = self.role("new")
        change = self.proposal({new.pk: [self.account.pk]}, department="Other")
        with (
            patch(
                "platform_modules.access.services.create_record",
                side_effect=ValidationError("Policy denied"),
            ),
            self.assertRaisesMessage(ValidationError, "Policy denied"),
        ):
            self.apply(change)
        self.identity.refresh_from_db()
        initial.refresh_from_db()
        self.assertEqual(self.identity.department, "Technique")
        self.assertEqual(initial.status, "approved")
        self.assertEqual(Grant.objects.get().status, "active")
        self.assertFalse(MoveDecision.objects.filter(proposal=change).exists())
        self.assertTrue(verify_chain(self.org))

    def test_foreign_resource_role_and_other_person_account_rejected(self):
        foreign = Resource.unscoped.create(organization=self.other, name="Other", kind="server")
        with self.assertRaises(ValidationError):
            self.role(resource=foreign)
        role = self.role()
        another = Identity.objects.create(organization=self.org, name="Another", kind="human")
        other_account = ExternalAccount.objects.create(
            organization=self.org, identity=another, username="another", system="service"
        )
        with self.assertRaises(ValidationError):
            self.proposal({role.pk: [other_account.pk]})

    def test_retired_role_does_not_issue_new_grants(self):
        role = self.role()
        self.apply(self.proposal({role.pk: [self.account.pk]}))
        self.role(revision=1, enabled=False)
        with self.assertRaisesMessage(ValidationError, "n’est plus active"):
            self.approve_access(AccessIntent.objects.get())
        self.assertFalse(Grant.objects.exists())

    def login(self, actor, *, recent=True, organization=None):
        self.client.force_login(actor)
        session = self.client.session
        session["organization_id"] = str((organization or self.org).pk)
        session["mfa_verified_at"] = time.time() if recent else 0
        session.save()

    def test_native_role_publication_and_mobility_flow(self):
        self.login(self.admin)
        url = reverse("mover-role-new")
        self.assertContains(self.client.get(url), "Créer un rôle métier")
        self.assertRedirects(
            self.client.post(
                url,
                {
                    "key": "native",
                    "name": "Native role",
                    "revision": "0",
                    "enabled": "on",
                    "entries-TOTAL_FORMS": "1",
                    "entries-INITIAL_FORMS": "0",
                    "entries-0-resource": str(self.resource.pk),
                    "entries-0-method": "SSO",
                    "entries-0-privilege": "read",
                    "entries-0-days": "30",
                },
            ),
            reverse("mover-catalog"),
        )
        role = RoleRevision.objects.get()
        self.login(self.operator)
        prepare = reverse("mover-prepare", args=[self.identity.pk])
        self.assertContains(
            self.client.get(prepare, {"choose": "1", "roles": str(role.pk)}),
            "Soumettre à un approbateur",
        )
        response = self.client.post(
            prepare,
            {
                "roles": str(role.pk),
                "department": "New team",
                "reason": "Transfer",
                "reference": "HR-UI",
                f"account_{role.pk.hex}_0": str(self.account.pk),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertContains(self.client.get(response.url), "New team")
        self.assertContains(self.client.get(response.url), "30 jours")
        proposal = self.identity.moveproposal_set.get()
        url = reverse("mover-decision", args=[proposal.pk])
        self.login(self.reviewer, recent=False)
        result = self.client.post(url, {"decision": "approve", "comment": "Checked"})
        self.assertEqual(result.status_code, 302)
        self.assertFalse(MoveDecision.objects.exists())
        self.login(self.reviewer)
        self.client.post(url, {"decision": "typo", "comment": "Checked"})
        self.assertFalse(MoveDecision.objects.exists())
        self.client.post(url, {"decision": "approve", "comment": "Checked"})
        self.assertEqual(AccessIntent.objects.get().status, "pending")

    def test_mobility_proposal_url_does_not_cross_tenants(self):
        from platform_core.services import install_module

        proposal = self.proposal({}, department="Changed")
        install_module("identity", actor=self.admin, organization=self.other)
        self.login(self.admin, organization=self.other)
        self.assertEqual(
            self.client.get(reverse("mover-detail", args=[proposal.pk])).status_code, 404
        )


@skipUnless(connection.vendor == "postgresql", "PostgreSQL mobility guards")
class MoverPostgresTests(MoverFixture, TransactionTestCase):
    def test_database_protects_attestations_and_tenant_relations(self):
        role = self.role()
        with self.assertRaises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("UPDATE identity_rolerevision SET revision=2 WHERE id=%s", [role.pk])
        audit = record(action="test.foreign", summary="Foreign proof", organization=self.other)
        with self.assertRaises(DatabaseError) as error, transaction.atomic():
            RoleRevision.unscoped.bulk_create(
                [
                    RoleRevision(
                        organization=self.org,
                        audit=audit,
                        key="forged",
                        revision=1,
                        body=role.body,
                        signature=role.signature,
                    ),
                ]
            )
        self.assertEqual(error.exception.__cause__.sqlstate, "23503")

    def test_concurrent_votes_create_only_one_set_of_access_requests(self):
        role = self.role()
        move = self.proposal({role.pk: [self.account.pk]})

        def vote():
            close_old_connections()
            try:
                with organization_context(self.org):
                    self.apply(move)
                return True
            except ValidationError:
                return False
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(lambda _: vote(), range(2))), [False, True])
        self.assertEqual(MoveDecision.objects.count(), 1)
        self.assertEqual(AccessIntent.objects.count(), 1)
