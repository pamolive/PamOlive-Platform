"""Real portal routes: GET selection hints never convey access authority."""

import time
from datetime import timedelta
from html import unescape
from urllib.parse import urlencode
from uuid import uuid4

import pyotp
from django.contrib.auth import get_user_model
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
from platform_core.security import cipher, verify_mfa
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessEvent, AccessIntent
from platform_modules.approvals.models import ApprovalDecision
from platform_modules.connectors.models import ExternalChange
from platform_modules.identity.models import ExternalAccount, Grant, Identity
from platform_modules.pam.models import SessionLease

from . import test_platform as fixture


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class IdentityJourneyPortalTests(TestCase):
    def setUp(self):
        fixture.PlatformTests.setUp(self)
        self.second = Identity.objects.create(
            organization=self.org, name="Synthetic second person", kind="human"
        )
        self.second_account = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.second,
            username="second-synthetic",
            system="Fixture",
            kind="personal",
        )
        with organization_context(self.other):
            self.foreign = Identity.objects.create(
                organization=self.other, name="Synthetic foreign person", kind="human"
            )
            self.foreign_account = ExternalAccount.objects.create(
                organization=self.other,
                identity=self.foreign,
                username="foreign-synthetic",
                system="Fixture",
                kind="personal",
            )
        self.url = reverse("record-create", args=["intent"])
        self.login(self.operator)

    def login(self, user, *, organization=None, recent=False, client=None):
        client = client or self.client
        client.force_login(user)
        session = client.session
        session["organization_id"] = str((organization or self.org).pk)
        if recent:
            secret = pyotp.random_base32()
            AccountSecurity.objects.update_or_create(
                account=user,
                defaults={"encrypted_secret": cipher().encrypt(secret.encode()).decode()},
            )
            self.assertTrue(verify_mfa(user, pyotp.TOTP(secret).now()))
            session["mfa_verified_at"] = time.time()
        session.save()

    def selected(self, identity=None, account=None):
        data = {"identity": str(identity or self.identity.pk)}
        if account is not None:
            data["account"] = str(account)
        return self.url + "?" + urlencode(data)

    def snapshot(self):
        return tuple(
            model.objects.count()
            for model in (
                AuditEvent,
                Identity,
                ExternalAccount,
                AccessIntent,
                Grant,
                ExternalChange,
                AccessEvent,
                ApprovalDecision,
                SessionLease,
            )
        )

    def post_data(self, identity=None, account=None):
        now = timezone.now()
        return {
            "identity": str(identity or self.identity.pk),
            "account": str(account or self.account.pk),
            "resource": str(self.resource.pk),
            "method": "HTTPS",
            "reason": "Synthetic portal journey",
            "fulfillment": "observe",
            "starts_at": now.isoformat(),
            "ends_at": (now + timedelta(minutes=10)).isoformat(),
        }

    def test_identity_and_account_links_select_existing_form_without_writes(self):
        before = self.snapshot()
        with CaptureQueriesContext(connection) as queries:
            profile = self.client.get(reverse("identity360-detail", args=[self.identity.pk]))
            response = self.client.get(self.selected(account=self.account.pk))
        self.assertContains(profile, "Demander un accès")
        self.assertContains(profile, self.selected())
        self.assertIn(self.selected(account=self.account.pk), unescape(profile.content.decode()))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response.context["form"].initial["identity"], self.identity.pk)
        self.assertEqual(response.context["form"].initial["account"], self.account.pk)
        self.assertFalse(response.context["form"].is_bound)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(
            any(
                q["sql"].lstrip().upper().startswith(("INSERT ", "UPDATE ", "DELETE "))
                for q in queries
            )
        )

    def test_identity_only_and_blank_form_remain_unbound(self):
        response = self.client.get(self.selected())
        self.assertEqual(response.context["form"].initial, {"identity": self.identity.pk})
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["form"].is_bound)
        self.assertEqual(response.context["form"].initial, {})

    def test_uuid_noncanonical_empty_and_duplicates_are_generic_404(self):
        values = [
            "",
            "invalid",
            self.identity.pk.hex,
            str(self.identity.pk).upper(),
            "{" + str(self.identity.pk) + "}",
            " " + str(self.identity.pk),
        ]
        before = self.snapshot()
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(self.client.get(self.url, {"identity": value}).status_code, 404)
        for pairs in (
            [("identity", str(self.identity.pk))] * 2,
            [
                ("identity", str(self.identity.pk)),
                ("account", str(self.account.pk)),
                ("account", str(self.account.pk)),
            ],
            [("account", str(self.account.pk))],
        ):
            with self.subTest(pairs=pairs):
                self.assertEqual(
                    self.client.get(self.url + "?" + urlencode(pairs)).status_code, 404
                )
        self.assertEqual(self.snapshot(), before)

    def test_foreign_and_missing_identities_and_accounts_are_generic_404(self):
        before = self.snapshot()
        for url in (
            self.selected(self.foreign.pk),
            self.selected(uuid4()),
            self.selected(account=self.foreign_account.pk),
            self.selected(account=uuid4()),
        ):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 404)
                self.assertNotIn(self.foreign.name, response.content.decode())
                self.assertNotIn(self.foreign_account.username, response.content.decode())
        self.assertEqual(self.snapshot(), before)

    def test_account_of_another_local_person_is_not_prefilled(self):
        self.assertEqual(
            self.client.get(self.selected(account=self.second_account.pk)).status_code, 404
        )

    def test_inactive_identity_or_account_refuses_prefill_and_hides_action(self):
        for state in ("suspended", "departed"):
            Identity.objects.filter(pk=self.identity.pk).update(status=state)
            with self.subTest(state=state):
                self.assertEqual(self.client.get(self.selected()).status_code, 404)
                page = self.client.get(reverse("identity360-detail", args=[self.identity.pk]))
                self.assertNotContains(page, "Demander un accès")
        Identity.objects.filter(pk=self.identity.pk).update(status="active")
        ExternalAccount.objects.filter(pk=self.account.pk).update(active=False)
        self.assertEqual(self.client.get(self.selected(account=self.account.pk)).status_code, 404)
        page = self.client.get(reverse("identity360-detail", args=[self.identity.pk]))
        self.assertContains(page, "Demander un accès")
        self.assertNotContains(page, "Demander avec ce compte")

    def test_form_choices_exclude_other_organization(self):
        response = self.client.get(self.selected())
        form = response.context["form"]
        self.assertNotIn(
            self.foreign.pk, form.fields["identity"].queryset.values_list("pk", flat=True)
        )
        self.assertNotIn(
            self.foreign_account.pk, form.fields["account"].queryset.values_list("pk", flat=True)
        )

    def test_access_disabled_hides_link_and_denies_direct_form(self):
        ModuleActivation.objects.filter(organization=self.org, module_key="access").update(
            enabled=False
        )
        self.assertNotContains(
            self.client.get(reverse("identity360-detail", args=[self.identity.pk])),
            "Demander un accès",
        )
        self.assertEqual(self.client.get(self.selected()).status_code, 403)

    def test_disabled_dependency_denies_form_and_identity_page(self):
        ModuleActivation.objects.filter(organization=self.org, module_key="identity").update(
            enabled=False
        )
        self.assertEqual(self.client.get(self.selected()).status_code, 403)
        self.assertEqual(
            self.client.get(reverse("identity360-detail", args=[self.identity.pk])).status_code, 403
        )

    def test_second_organization_with_identity_only_has_no_access_action(self):
        other_operator = get_user_model().objects.create_user("other-portal-operator")
        OrganizationMembership.objects.create(
            organization=self.other, account=other_operator, role="operator"
        )
        install_module("identity", actor=self.admin, organization=self.other)
        self.login(other_operator, organization=self.other)
        self.assertNotContains(
            self.client.get(reverse("identity360-detail", args=[self.foreign.pk])),
            "Demander un accès",
        )
        self.assertEqual(self.client.get(self.selected(self.foreign.pk)).status_code, 403)

    def test_reviewer_and_auditor_can_read_but_have_no_action(self):
        auditor = get_user_model().objects.create_user("portal-auditor")
        OrganizationMembership.objects.create(
            organization=self.org, account=auditor, role="auditor"
        )
        for user in (self.reviewer, auditor):
            self.login(user)
            with self.subTest(role=user.username):
                self.assertNotContains(
                    self.client.get(reverse("identity360-detail", args=[self.identity.pk])),
                    "Demander un accès",
                )
                self.assertEqual(self.client.get(self.selected()).status_code, 403)

    def test_ordinary_org_admin_sees_action_and_role_changes_apply_freshly(self):
        admin = get_user_model().objects.create_user("portal-org-admin")
        membership = OrganizationMembership.objects.create(
            organization=self.org, account=admin, role="admin"
        )
        self.login(admin)
        self.assertContains(
            self.client.get(reverse("identity360-detail", args=[self.identity.pk])),
            "Demander un accès",
        )
        OrganizationMembership.objects.filter(pk=membership.pk).update(role="reviewer")
        self.assertNotContains(
            self.client.get(reverse("identity360-detail", args=[self.identity.pk])),
            "Demander un accès",
        )
        self.assertEqual(self.client.get(self.selected()).status_code, 403)

    def test_post_uses_body_only_even_with_invalid_duplicate_or_foreign_get(self):
        self.login(self.operator, recent=True)
        before_grants = Grant.objects.count()
        before_changes = ExternalChange.objects.count()
        url = (
            self.url
            + "?"
            + urlencode(
                [
                    ("identity", str(self.foreign.pk)),
                    ("identity", "invalid"),
                    ("account", str(self.foreign_account.pk)),
                ]
            )
        )
        response = self.client.post(url, self.post_data(self.second.pk, self.second_account.pk))
        self.assertEqual(response.status_code, 302)
        intent = AccessIntent.objects.get()
        self.assertEqual(intent.identity_id, self.second.pk)
        self.assertEqual(intent.account_id, self.second_account.pk)
        self.assertEqual(intent.requested_by_id, self.operator.pk)
        self.assertEqual(intent.status, "pending")
        self.assertEqual(
            (Grant.objects.count(), ExternalChange.objects.count()), (before_grants, before_changes)
        )
        self.assertFalse(ApprovalDecision.objects.exists())
        self.assertFalse(SessionLease.objects.exists())

    def test_get_does_not_fill_missing_post_fields(self):
        self.login(self.operator, recent=True)
        data = self.post_data()
        del data["identity"]
        response = self.client.post(self.selected(account=self.account.pk), data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("identity", response.context["form"].errors)
        self.assertFalse(AccessIntent.objects.exists())

    def test_post_revalidates_activity_after_get(self):
        self.login(self.operator, recent=True)
        self.assertEqual(self.client.get(self.selected(account=self.account.pk)).status_code, 200)
        ExternalAccount.objects.filter(pk=self.account.pk).update(active=False)
        response = self.client.post(self.selected(account=self.account.pk), self.post_data())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["form"].errors)
        self.assertFalse(AccessIntent.objects.exists())

    def test_get_does_not_grant_recent_mfa_or_bypass_csrf(self):
        before = self.snapshot()
        self.assertEqual(self.client.get(self.selected()).status_code, 200)
        self.assertNotIn("mfa_verified_at", self.client.session)
        self.assertRedirects(
            self.client.post(self.selected(), self.post_data()), reverse("account-security")
        )
        self.assertEqual(self.snapshot(), before)
        protected = Client(enforce_csrf_checks=True)
        self.login(self.operator, recent=True, client=protected)
        before = self.snapshot()
        self.assertEqual(protected.post(self.selected(), self.post_data()).status_code, 403)
        self.assertEqual(self.snapshot(), before)

    def test_csrf_valid_post_still_uses_existing_pending_intent_service(self):
        protected = Client(enforce_csrf_checks=True)
        self.login(self.operator, recent=True, client=protected)
        response = protected.get(self.selected(account=self.account.pk))
        self.assertEqual(response.status_code, 200)
        data = self.post_data()
        data["csrfmiddlewaretoken"] = str(response.context["csrf_token"])
        self.assertEqual(protected.post(self.selected(), data).status_code, 302)
        self.assertEqual(AccessIntent.objects.get().status, "pending")
        self.assertFalse(Grant.objects.exists())
