import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, connections
from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse

from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.memberships import set_membership
from platform_core.models import AccountSecurity, AuditEvent, Organization, OrganizationMembership
from platform_core.security import cipher
from platform_core.tenancy import federation_context, organization_context

PASSWORD = "Disposable-Member-Password!4972"


class MembershipTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        user = get_user_model()
        cls.admin = user.objects.create_user("member-admin")
        cls.root = user.objects.create_superuser("member-root")
        cls.foreign = user.objects.create_user("foreign-user")
        cls.org = Organization.objects.create(key="members-a", name="Members A")
        cls.other = Organization.objects.create(key="members-b", name="Members B")
        cls.admin_membership = OrganizationMembership.objects.create(
            organization=cls.org, account=cls.admin, role="admin"
        )
        cls.foreign_membership = OrganizationMembership.objects.create(
            organization=cls.other, account=cls.foreign, role="admin"
        )
        for actor in (cls.admin, cls.root):
            AccountSecurity.objects.create(
                account=actor, encrypted_secret=cipher().encrypt(b"JBSWY3DPEHPK3PXP").decode()
            )

    def setUp(self):
        context = organization_context(self.org)
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)

    def change(self, *, actor=None, **values):
        actor = actor or self.admin
        fields = dict(username="new-member", role="auditor", active=True, password=PASSWORD)
        fields.update(values)
        with recent_authentication(actor, self.org, time.time()):
            return set_membership(actor=actor, organization=self.org, **fields)

    def browser(self):
        client = Client()
        client.force_login(self.admin)
        session = client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time()
        session.save()
        return client

    def test_new_account_gets_only_requested_organization_role_and_hashed_password(self):
        member = self.change()
        self.assertTrue(member.account.check_password(PASSWORD))
        self.assertFalse(member.account.is_superuser)
        self.assertFalse(member.account.is_staff)
        self.assertEqual(member.role, "auditor")
        self.assertEqual(OrganizationMembership.objects.filter(account=member.account).count(), 1)
        self.assertTrue(verify_chain(self.org))
        event = AuditEvent.objects.filter(organization=self.org).latest("pk")
        self.assertNotIn(PASSWORD, str(event.metadata))

    def test_service_requires_personal_mfa_even_without_the_web_decorator(self):
        with self.assertRaises(PermissionDenied):
            set_membership(
                actor=self.admin,
                organization=self.org,
                username="forbidden",
                role="admin",
                password=PASSWORD,
            )
        self.assertFalse(get_user_model().objects.filter(username="forbidden").exists())

    def test_org_admin_cannot_attach_existing_foreign_account(self):
        with self.assertRaises(ValidationError):
            self.change(username=self.foreign.username)
        self.assertFalse(
            OrganizationMembership.objects.filter(
                organization=self.org, account=self.foreign
            ).exists()
        )

    def test_local_platform_admin_can_attach_but_federated_superuser_cannot(self):
        with federation_context(self.root.pk, self.org.pk), self.assertRaises(ValidationError):
            self.change(actor=self.root, username=self.foreign.username)
        member = self.change(actor=self.root, username=self.foreign.username)
        self.assertEqual(member.organization_id, self.org.pk)
        self.foreign_membership.refresh_from_db()
        self.assertEqual(self.foreign_membership.role, "admin")

    def test_last_active_admin_cannot_be_demoted_or_disabled(self):
        for changes in ({"active": False}, {"role": "auditor"}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                self.change(**dict({"username": self.admin.username, "role": "admin"}, **changes))
        self.admin_membership.refresh_from_db()
        self.assertTrue(self.admin_membership.active)
        self.assertEqual(self.admin_membership.role, "admin")

    def test_membership_disable_never_disables_global_account_or_other_organization(self):
        member = self.change()
        other_member = OrganizationMembership.objects.create(
            organization=self.other, account=member.account, role="operator"
        )
        self.change(username=member.account.username, active=False, password="ignored")
        member.refresh_from_db()
        other_member.refresh_from_db()
        member.account.refresh_from_db()
        self.assertFalse(member.active)
        self.assertTrue(member.account.is_active)
        self.assertTrue(member.account.check_password(PASSWORD))
        self.assertTrue(other_member.active)
        self.assertEqual(other_member.role, "operator")

    def test_failed_audit_rolls_back_account_and_membership_creation(self):
        with patch("platform_core.memberships.record", side_effect=ValidationError("fixture")):
            with self.assertRaises(ValidationError):
                self.change()
        self.assertFalse(get_user_model().objects.filter(username="new-member").exists())

    def test_invalid_password_and_role_never_create_an_account(self):
        for values in ({"password": "weak"}, {"role": "superuser"}, {"active": "true"}):
            with self.subTest(values=values), self.assertRaises(ValidationError):
                self.change(**values)
        self.assertFalse(get_user_model().objects.filter(username="new-member").exists())

    def test_edit_view_scopes_members_and_ignores_forged_account_name(self):
        member = self.change()
        browser = self.browser()
        self.assertEqual(
            browser.get(reverse("membership-edit", args=[self.foreign_membership.pk])).status_code,
            404,
        )
        response = browser.post(
            reverse("membership-edit", args=[member.pk]),
            {
                "username": self.foreign.username,
                "role": "reviewer",
                "active": "on",
            },
        )
        self.assertEqual(response.status_code, 302)
        member.refresh_from_db()
        self.assertEqual(member.role, "reviewer")
        self.assertEqual(member.account.username, "new-member")
        self.assertFalse(
            OrganizationMembership.objects.filter(
                organization=self.org, account=self.foreign
            ).exists()
        )

    def test_new_member_form_defaults_to_auditor_not_administrator(self):
        response = self.browser().get(reverse("system-status"))
        self.assertEqual(response.context["form"]["role"].value(), "auditor")
        self.assertTrue(response.context["form"]["active"].value())

    def test_cross_context_and_auditor_cannot_use_membership_service(self):
        with recent_authentication(self.admin, self.org, time.time()):
            with self.assertRaises(PermissionDenied):
                set_membership(
                    actor=self.admin,
                    organization=self.other,
                    username="forbidden",
                    role="admin",
                    password=PASSWORD,
                )
        member = self.change()
        AccountSecurity.objects.create(
            account=member.account, encrypted_secret=cipher().encrypt(b"fixture").decode()
        )
        with recent_authentication(member.account, self.org, time.time()):
            with self.assertRaises(PermissionDenied):
                set_membership(
                    actor=member.account,
                    organization=self.org,
                    username="forbidden",
                    role="admin",
                    password=PASSWORD,
                )

    def test_post_without_csrf_is_refused_and_expired_mfa_preserves_form(self):
        browser = self.browser()
        session = browser.session
        session["mfa_verified_at"] = 0
        session.save()
        response = browser.post(
            reverse("system-status"),
            {
                "username": "after-mfa",
                "password": PASSWORD,
                "role": "auditor",
                "active": "on",
            },
        )
        self.assertRedirects(response, reverse("account-security"), fetch_redirect_response=False)
        self.assertFalse(get_user_model().objects.filter(username="after-mfa").exists())
        self.assertNotIn(PASSWORD, browser.session["post_mfa_action"])
        guarded = Client(enforce_csrf_checks=True)
        guarded.force_login(self.admin)
        self.assertEqual(guarded.post(reverse("system-status"), {}).status_code, 403)


@skipUnless(connection.vendor == "postgresql", "PostgreSQL organization lock concurrency")
class ConcurrentMembershipTests(TransactionTestCase):
    def test_two_admins_cannot_concurrently_remove_the_last_admin_role(self):
        org = Organization.objects.create(key="members-race", name="Membership race")
        actors = [
            get_user_model().objects.create_user("race-admin-" + str(index)) for index in (1, 2)
        ]
        for actor in actors:
            OrganizationMembership.objects.create(organization=org, account=actor, role="admin")
            AccountSecurity.objects.create(
                account=actor, encrypted_secret=cipher().encrypt(b"fixture").decode()
            )
        barrier = Barrier(2)

        def demote(actor_id):
            try:
                actor = get_user_model().objects.get(pk=actor_id)
                with organization_context(org), recent_authentication(actor, org, time.time()):
                    barrier.wait(timeout=10)
                    try:
                        set_membership(
                            actor=actor,
                            organization=org,
                            username=actor.username,
                            role="auditor",
                            active=True,
                        )
                        return "changed"
                    except ValidationError:
                        return "protected"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(demote, actor.pk) for actor in actors]
            results = [future.result(timeout=20) for future in futures]
        self.assertEqual(sorted(results), ["changed", "protected"])
        self.assertEqual(
            OrganizationMembership.objects.filter(
                organization=org, role="admin", active=True
            ).count(),
            1,
        )
        self.assertTrue(verify_chain(org))
