"""The eight pre-P0-3 attack reproductions now require independent authority."""

import json
import uuid
from datetime import time as wall_time
from datetime import timedelta
from unittest.mock import AsyncMock, patch
from zoneinfo import ZoneInfo

import pyotp
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.models import AccountSecurity, ModuleActivation, OrganizationMembership
from platform_core.security import cipher
from platform_modules.access.models import AccessIntent
from platform_modules.governance import services as governance
from platform_modules.governance.policy import approval_requirements
from platform_modules.identity.models import ExternalAccount, Identity, LoginIdentityBinding
from platform_modules.pam.models import RelayConnection
from platform_modules.pam.probe import ProbeResult
from platform_modules.pam.sessions import (
    check_startup_session,
    claim_session,
    configure_endpoint,
    endpoint_credentials,
    probe_endpoint,
    set_endpoint_enabled,
)
from platform_modules.pam.target_binding import target_scope
from platform_modules.pam.trust import contract_authority

from .person_fixtures import bind_person
from .test_pam_sessions import PamSessionFixtureMixin

PASSWORD = "P0-3-synthetic-disposable-passphrase!38"
TARGET_PASSWORD = "P0-3-synthetic-remote-credential"


@override_settings(
    PAM_ALLOWED_HOSTS={"ssh.example.test:22"},
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
)
class PamQuorumReproductionTests(PamSessionFixtureMixin, TestCase):
    def setUp(self):
        super().setUp()
        users = get_user_model()
        self.tenant_admin = users.objects.create_user("synthetic-tenant-admin", password=PASSWORD)
        OrganizationMembership.objects.create(
            organization=self.org, account=self.tenant_admin, role="admin"
        )
        ModuleActivation.objects.create(
            organization=self.org, module_key="governance", version="test", enabled=True
        )
        owner = Identity.objects.create(
            organization=self.org, name="Synthetic shared service", kind="service"
        )
        self.shared = ExternalAccount.objects.create(
            organization=self.org,
            identity=owner,
            username="synthetic-root",
            system="SSH fixture",
            kind="privileged",
        )
        # The target exists before the attack. The probe is synthetic and opens no socket.
        result = ProbeResult(
            "ssh", "ssh.example.test", 22, "192.0.2.8", "SHA256:synthetic", timezone.now()
        )
        with (
            self.assurance(),
            patch("platform_modules.pam.sessions.probe_ssh", AsyncMock(return_value=result)),
        ):
            endpoint = configure_endpoint(
                actor=self.admin,
                organization=self.org,
                resource=self.resource,
                account=self.shared,
                name="Synthetic pre-existing target",
                protocol="ssh",
                hostname="ssh.example.test",
                port=22,
                auth_method="password",
                password=TARGET_PASSWORD,
                host_key=self.host_key,
            )
            self.assertTrue(probe_endpoint(endpoint.pk, actor=self.admin, organization=self.org)[0])
            self.target = set_endpoint_enabled(
                endpoint.pk, actor=self.admin, organization=self.org, enabled=True
            )
        self.attacker = self.sign_in(self.tenant_admin)
        self.enroll(self.attacker)
        self.requester = self.new_person("synthetic-requester")
        self.bind(self.tenant_admin, self.requester)
        # The adversary is legitimately allowed to request this target. Its ordinary
        # tenant powers do not confer the independently attested reviewer role.
        person = str(uuid.uuid4())
        self.trust.people[self.tenant_admin.pk] = person

        def attest_requester(body):
            body["targets"][str(self.target.pk)] = {
                "scope": target_scope(self.target), "critical": False,
                "contract_id": "", "sponsor_person": "", "min_reviewers": 1,
            }
            body["persons"][person] = {
                "active": True, "identity_ids": [str(self.requester.pk)],
                "account_ids": [str(self.tenant_admin.pk)], "roles": ["requester"],
                "endpoint_ids": [str(self.target.pk)], "authenticators": [],
            }
            body["persons"][self.trust.people[self.admin.pk]]["endpoint_ids"].append(
                str(self.target.pk)
            )

        self.trust.update(attest_requester)
        self.trust.enroll(self.tenant_admin)

    def sign_in(self, account, otp="", *, password=PASSWORD):
        browser = Client()
        response = browser.post(
            reverse("login"), {"username": account.username, "password": password, "otp": otp}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(browser.session["_auth_user_id"], str(account.pk))
        session = browser.session
        session["organization_id"] = str(self.org.pk)
        session.save()
        return browser

    def enroll(self, browser, *, password=PASSWORD):
        path = reverse("account-security")
        form = browser.get(path)
        self.assertFalse(form.context["enabled"])
        code = pyotp.TOTP(form.context["secret"]).now()
        response = browser.post(path, {"password": password, "code": code, "freshness_minutes": 5})
        self.assertTemplateUsed(response, "security/resume.html")
        self.assertIn("mfa_verified_at", browser.session)
        return response.context["codes"]

    def new_person(self, name):
        response = self.attacker.post(
            reverse("record-create", args=["identity"]), {"name": name, "kind": "human"}
        )
        self.assertEqual(response.status_code, 302)
        return Identity.objects.get(name=name)

    def bind(self, account, person):
        response = self.attacker.post(
            reverse("identity-login-bindings"),
            {
                "login_account": account.pk,
                "identity": person.pk,
                "verification_reference": "Synthetic reference declared by the tenant admin",
            },
        )
        self.assertEqual(response.status_code, 302)
        return LoginIdentityBinding.objects.get(login_account=account, revoked_at=None)

    def controlled_reviewer(self, number, *, person=None):
        username = f"synthetic-reviewer-{number}"
        response = self.attacker.post(
            reverse("system-status"),
            {"username": username, "role": "operator", "active": "on", "password": PASSWORD},
        )
        self.assertEqual(response.status_code, 302)
        member = OrganizationMembership.objects.get(
            organization=self.org, account__username=username
        )
        self.assertFalse(member.account.is_superuser)
        edit = self.attacker.post(
            reverse("membership-edit", args=[member.pk]), {"role": "reviewer", "active": "on"}
        )
        self.assertEqual(edit.status_code, 302)
        self.bind(member.account, person or self.new_person(username))
        browser = self.sign_in(member.account)
        return member.account, browser, self.enroll(browser)

    def publish(self, minimum, *, sponsor=False, require_external_contract=False):
        fields = {"min_reviewers": minimum, "critical_reviewers": minimum}
        if sponsor:
            fields["supplier_sponsor_required"] = "on"
        if require_external_contract:
            fields["require_external_contract"] = "on"
        response = self.attacker.post(reverse("governance-create", args=["policy"]), fields)
        self.assertEqual(response.status_code, 302)

    def signed_post(self, browser, path, fields):
        """Use the actual challenge page and JSON verifier, without mocking authority."""
        response = browser.post(path, fields)
        if response.status_code == 200 and any(
            template.name == "pam/trust_action.html" for template in response.templates
        ):
            ceremony = response.context["ceremony"]
            actor_id = int(browser.session["_auth_user_id"])
            response = browser.post(
                reverse("pam-trust-action"),
                json.dumps({"operation": "finish", "challenge": ceremony["challenge"],
                            "credential": self.trust.authenticators[actor_id].response(ceremony)}),
                content_type="application/json",
            )
            self.assertEqual(response.status_code, 200, response.content)
            result = response.json()
            self.assertEqual(result["resume"]["path"], path)
            response = browser.post(path, {**fields, "_pam_trust_proof": result["proof"]})
        return response

    def request_access(self, *, contract=None, denied=False, **changes):
        now = timezone.now()
        response = self.signed_post(
            self.attacker,
            reverse("record-create", args=["intent"]),
            {
                "identity": self.requester.pk,
                "account": self.shared.pk,
                "resource": self.resource.pk,
                "method": "SSH",
                "fulfillment": "pam",
                "reason": "Synthetic privileged operation",
                "reference": "P0-3",
                "starts_at": (now if contract else now - timedelta(minutes=1)).isoformat(),
                "ends_at": (now + timedelta(minutes=30)).isoformat(),
                "contract": contract.pk if contract else "",
                **changes,
            },
        )
        if denied:
            self.assertIn(response.status_code, (200, 403))
            self.assertFalse(AccessIntent.objects.filter(requested_by=self.tenant_admin).exists())
            return response
        self.assertEqual(response.status_code, 302)
        intent = AccessIntent.objects.get(requested_by=self.tenant_admin, status="pending")
        self.assertEqual(intent.pam_destination["endpoint"], str(self.target.pk))
        return intent

    def vote(self, browser, intent, *, legitimate=False, **extra):
        initial = intent.decisions.count()
        response = self.signed_post(
            browser,
            reverse("intent-decide", args=[intent.pk]),
            {"decision": "approve", "comment": "Synthetic approval", **extra},
        )
        self.assertIn(response.status_code, (302, 403))
        intent.refresh_from_db()
        if not legitimate:
            self.assertEqual(intent.decisions.count(), initial)
            self.assertEqual(intent.status, "pending")
        return response

    def assert_relay_refused(self, intent):
        with patch("platform_modules.pam.sessions.cipher") as decryptor:
            response = self.attacker.post(reverse("pam-launch", args=[intent.pk]))
            self.assertIn(response.status_code, (302, 403))
            decryptor.assert_not_called()
        self.assertFalse(RelayConnection.objects.filter(lease__intent=intent).exists())

    def assert_relay_claimed(self, intent):
        response = self.signed_post(self.attacker, reverse("pam-launch", args=[intent.pk]), {})
        self.assertTemplateUsed(response, "pam/session.html")
        relay = RelayConnection.objects.get(lease__intent=intent)
        self.assertEqual(relay.endpoint_id, self.target.pk)
        self.assertEqual(relay.opened_by_id, self.tenant_admin.pk)
        session = {"session_key": self.attacker.session.session_key, "client_ip": "127.0.0.1"}
        _, _, owner = claim_session(
            relay.pk,
            actor=self.tenant_admin,
            ticket=response.context["player"]["ticket"],
            instance_id="synthetic-p0-3",
            **session,
        )
        authorized = check_startup_session(relay.pk, self.org, owner, **session)
        self.assertEqual(endpoint_credentials(authorized, **session), {"password": TARGET_PASSWORD})

    def test_tenant_admin_controlled_accounts_cannot_form_quorum_or_claim_relay(self):
        self.publish(3)
        reviewers = [self.controlled_reviewer(number) for number in range(3)]
        intent = self.request_access()
        self.vote(self.attacker, intent)
        self.assertFalse(intent.decisions.exists())
        for index, (_, browser, _) in enumerate(reviewers, start=1):
            self.vote(browser, intent)
            self.assertEqual(intent.status, "pending", index)
        self.assertEqual(approval_requirements(intent)["approved"], 0)
        self.assertFalse(intent.decisions.exists())
        self.assert_relay_refused(intent)
        self.assertTrue(verify_chain(self.org))

    def test_portal_recovery_cannot_authorize_pam_or_be_reused_or_reset_by_membership(self):
        self.publish(1)
        reviewer, _, codes = self.controlled_reviewer(1)
        original = AccountSecurity.objects.get(account=reviewer).encrypted_secret
        member = OrganizationMembership.objects.get(organization=self.org, account=reviewer)
        edit = reverse("membership-edit", args=[member.pk])
        for active in ("", "on"):
            response = self.attacker.post(
                edit,
                {"role": "reviewer", "active": active, "password": "synthetic-forged-reset!38"},
            )
            self.assertEqual(response.status_code, 302)
        reviewer.refresh_from_db()
        self.assertTrue(reviewer.check_password(PASSWORD))
        recovered = self.sign_in(reviewer, codes[0])
        intent = self.request_access()
        self.vote(recovered, intent)
        self.assertEqual(intent.status, "pending")
        self.assert_relay_refused(intent)
        profile = AccountSecurity.objects.get(account=reviewer)
        self.assertEqual(profile.encrypted_secret, original)
        self.assertEqual(len(profile.recovery_hashes), 7)
        response = Client().post(
            reverse("login"), {"username": reviewer.username, "password": PASSWORD, "otp": codes[0]}
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", response.wsgi_request.session)
        denied = recovered.post(
            reverse("account-security"),
            {"password": PASSWORD, "code": codes[0], "freshness_minutes": 5},
        )
        self.assertTemplateUsed(denied, "security/settings.html")
        self.assertContains(denied, "Un code déjà utilisé est refusé")
        profile.refresh_from_db()
        self.assertEqual(profile.encrypted_secret, original)

    def test_local_policy_lowering_cannot_approve_unattested_accounts_or_launch_relay(self):
        _, reviewer, _ = self.controlled_reviewer(1)
        _, independent_browser = self.independent_reviewer("policy")
        self.publish(3)
        intent = self.request_access()
        self.assertEqual(approval_requirements(intent)["minimum"], 3)
        self.publish(1)
        self.vote(reviewer, intent)
        self.vote(independent_browser, intent)
        self.assertEqual(intent.status, "pending")
        self.publish(3)
        self.assertEqual(approval_requirements(intent)["minimum"], 3)
        self.assertIsNone(intent.approved_at)
        self.assert_relay_refused(intent)

    def test_controlled_alias_cannot_impersonate_contract_sponsor(self):
        sponsor_binding = LoginIdentityBinding.objects.get(login_account=self.admin)
        alias, browser, _ = self.controlled_reviewer(1)
        alias_binding = LoginIdentityBinding.objects.get(login_account=alias)
        response = self.attacker.post(
            reverse("identity-binding-revoke", args=[alias_binding.pk]),
            {"reason": "Synthetic reassignment"},
        )
        self.assertEqual(response.status_code, 302)
        self.bind(alias, sponsor_binding.identity)
        with self.assurance():
            now = timezone.now()
            supplier = governance.create_supplier(
                {"name": "Synthetic supplier", "reference": "SYN", "contact": ""},
                actor=self.admin,
                organization=self.org,
            )
            contract = governance.publish_contract(
                {
                    "supplier": supplier,
                    "name": "Synthetic contract",
                    "reference": "SYN-1",
                    "sponsor": self.admin,
                    "starts_at": now - timedelta(days=1),
                    "ends_at": now + timedelta(days=1),
                    "timezone_name": "UTC",
                    "weekdays": list(range(7)),
                    "daily_start": wall_time(0),
                    "daily_end": wall_time(0),
                    "allowed_methods": ["ssh"],
                    "allowed_countries": [],
                    "physical_allowed": False,
                    "require_reference": True,
                },
                [{"resource": self.resource, "privilege": "", "locations": []}],
                actor=self.admin,
                organization=self.org,
            )
            governance.add_participant(
                {"contract": contract, "identity": self.requester},
                actor=self.admin,
                organization=self.org,
            )
        self.publish(1, sponsor=True)
        self.attest_contract(contract)
        intent = self.request_access(contract=contract)
        self.assertFalse(approval_requirements(intent)["sponsor_satisfied"])
        self.vote(browser, intent, delegated_by=self.admin.pk, reviewer=self.admin.pk)
        self.assertFalse(intent.decisions.exists())
        self.assertFalse(approval_requirements(intent)["sponsor_satisfied"])
        self.assert_relay_refused(intent)

    def test_editable_person_kind_cannot_bypass_attested_contract_obligation(self):
        _, reviewer, _ = self.controlled_reviewer(1)
        self.publish(1, sponsor=True, require_external_contract=True)
        self.assertIsNone(self.shared.managed_contract_id)
        self.assertEqual(self.requester.kind, "human")
        # The signed obligation is independent of the editable IAM classification.
        contract = self.synthetic_contract()
        self.attest_contract(contract)
        with patch("platform_modules.pam.sessions.cipher") as decryptor:
            self.request_access(denied=True)
            decryptor.assert_not_called()

    def test_existing_genuine_approval_launches_and_foreign_or_emergency_claims_do_not(self):
        pending = self.request_access()
        denied = self.attacker.post(reverse("pam-launch", args=[pending.pk]), {"break_glass": "1"})
        self.assertRedirects(denied, reverse("pam-home"), fetch_redirect_response=False)
        self.assertFalse(RelayConnection.objects.filter(lease__intent=pending).exists())
        reviewer, browser, _ = self.controlled_reviewer(1)
        OrganizationMembership.objects.create(
            organization=self.other, account=reviewer, role="reviewer"
        )
        ModuleActivation.objects.bulk_create(
            [
                ModuleActivation(
                    organization=self.other, module_key=module, version="test", enabled=True
                )
                for module in ("identity", "access", "approvals")
            ]
        )
        session = browser.session
        session["organization_id"] = str(self.other.pk)
        session.save()
        response = browser.post(
            reverse("intent-decide", args=[pending.pk]), {"decision": "approve", "comment": "test"}
        )
        self.assertEqual(response.status_code, 404)
        self.assertFalse(pending.decisions.exists())
        separate_password = "P0-3-independent-fixture-passphrase!63"
        independent = get_user_model().objects.create_user(
            "synthetic-independent-reviewer", password=separate_password
        )
        OrganizationMembership.objects.create(
            organization=self.org, account=independent, role="reviewer"
        )
        independent_browser = self.sign_in(independent, password=separate_password)
        self.enroll(independent_browser, password=separate_password)
        bind_person(independent, organization=self.org, administrator=self.admin, role="reviewer")
        binding = LoginIdentityBinding.objects.get(login_account=independent, revoked_at=None)
        self.attest_independent(independent, binding.identity)
        # An existing request is invalidated by the registry mutation. Reapproval
        # begins with a freshly signed request, never by promoting its old votes.
        self.assert_relay_refused(pending)
        AccessIntent.objects.filter(pk=pending.pk).update(status="denied")
        pending = self.request_access()
        self.vote(independent_browser, pending, legitimate=True)
        self.assertEqual(pending.decisions.get().reviewer_id, independent.pk)
        self.assert_relay_claimed(pending)
        with self.assurance(self.operator):
            from platform_modules.pam.sessions import launch_session
            with self.assertRaises(ValidationError):
                launch_session(
                    self.intent.pk, actor=self.operator, organization=self.org,
                    session_key=self.session_key, client_ip="127.0.0.1",
                )

    def test_unattested_reassignment_and_alias_cannot_cast_any_pam_vote(self):
        self.publish(3)
        first, first_browser, _ = self.controlled_reviewer(1)
        binding = LoginIdentityBinding.objects.get(login_account=first)
        _, alias_browser, _ = self.controlled_reviewer(2, person=binding.identity)
        intent = self.request_access()
        self.vote(first_browser, intent)
        self.vote(alias_browser, intent)
        self.assertEqual(approval_requirements(intent)["approved"], 0)
        response = self.attacker.post(
            reverse("identity-binding-revoke", args=[binding.pk]), {"reason": "Test reassignment"}
        )
        self.assertEqual(response.status_code, 302)
        self.bind(first, self.new_person("synthetic-reassigned-reviewer"))
        self.vote(first_browser, intent)
        self.assertEqual(intent.decisions.count(), 0)
        self.assertEqual(intent.status, "pending")
        self.assert_relay_refused(intent)

    def test_public_password_throttling_blocks_new_login_without_granting_pam_authority(self):
        reviewer, browser, codes = self.controlled_reviewer(1)
        anonymous = Client()
        for _ in range(10):
            response = anonymous.post(
                reverse("login"), {"username": reviewer.username, "password": "wrong-synthetic"}
            )
            self.assertEqual(response.status_code, 200)
        response = anonymous.post(
            reverse("login"),
            {"username": reviewer.username, "password": PASSWORD, "otp": codes[0]},
        )
        self.assertContains(response, "Trop de tentatives")
        self.assertNotIn("_auth_user_id", anonymous.session)
        intent = self.request_access()
        self.vote(browser, intent)
        self.assertEqual(intent.status, "pending")
        self.assert_relay_refused(intent)

    def attest_independent(self, actor, identity, *, roles=("reviewer",)):
        person = str(uuid.uuid4())
        self.trust.people[actor.pk] = person
        self.trust.update(lambda body: body["persons"].update({person: {
            "active": True, "identity_ids": [str(identity.pk)], "account_ids": [str(actor.pk)],
            "endpoint_ids": [str(self.target.pk)], "roles": list(roles), "authenticators": [],
        }}))
        self.trust.enroll(actor)
        return person

    def attest_contract(self, contract):
        def attest(body):
            body["targets"][str(self.target.pk)].update(
                contract_id=str(contract.pk), contract_authority=contract_authority(contract),
                sponsor_person=self.trust.people[self.admin.pk],
            )

        self.trust.update(attest)

    def synthetic_contract(self):
        with self.assurance():
            now = timezone.now()
            supplier = governance.create_supplier(
                {"name": "Synthetic required supplier", "reference": "SYN-REQ", "contact": ""},
                actor=self.admin, organization=self.org,
            )
            contract = governance.publish_contract(
                {"supplier": supplier, "name": "Required contract", "reference": "SYN-REQ",
                 "sponsor": self.admin, "starts_at": now - timedelta(days=1),
                 "ends_at": now + timedelta(days=1), "timezone_name": "UTC",
                 "weekdays": list(range(7)), "daily_start": wall_time(0),
                 "daily_end": wall_time(0), "allowed_methods": ["ssh"],
                 "allowed_countries": [], "physical_allowed": False, "require_reference": True},
                [{"resource": self.resource, "privilege": "", "locations": []}],
                actor=self.admin, organization=self.org,
            )
            governance.add_participant(
                {"contract": contract, "identity": self.requester},
                actor=self.admin, organization=self.org,
            )
        return contract

    def independent_reviewer(self, number):
        actor = get_user_model().objects.create_user(
            f"independent-attested-{number}", password=PASSWORD
        )
        OrganizationMembership.objects.create(
            organization=self.org, account=actor, role="reviewer"
        )
        browser = self.sign_in(actor)
        codes = self.enroll(browser)
        if not hasattr(self, "independent_recovery_codes"):
            self.independent_recovery_codes = {}
        self.independent_recovery_codes[actor.pk] = codes
        binding = bind_person(
            actor, organization=self.org, administrator=self.admin, role="reviewer"
        )
        self.attest_independent(actor, binding.identity)
        return actor, browser

    def test_portal_recovery_of_attested_person_cannot_replace_personal_action_proof(self):
        actor, _ = self.independent_reviewer("recovery")
        recovered = self.sign_in(actor, self.independent_recovery_codes[actor.pk][0])
        intent = self.request_access()
        # The account and canonical person are valid, but a portal recovery code
        # carries no signature from the independently commissioned authenticator.
        with patch("platform_modules.pam.sessions.cipher") as decryptor:
            response = recovered.post(
                reverse("intent-decide", args=[intent.pk]),
                {"decision": "approve", "comment": "Recovered ordinary portal session"},
            )
            self.assertTemplateUsed(response, "pam/trust_action.html")
            decryptor.assert_not_called()
        self.assertFalse(intent.decisions.exists())
        self.assert_relay_refused(intent)

    def trusted_sponsor_browser(self):
        profile = AccountSecurity.objects.get(account=self.admin)
        otp = pyotp.TOTP(cipher().decrypt(profile.encrypted_secret.encode()).decode()).now()
        return self.sign_in(self.admin, otp, password="fixture-password")

    def test_critical_requires_two_people_despite_editable_local_resource_classification(self):
        _, first = self.independent_reviewer(1)
        _, second = self.independent_reviewer(2)
        self.trust.update(lambda body: body["targets"][str(self.target.pk)].update(critical=True))
        self.assertFalse(self.resource.critical)
        self.publish(1)
        intent = self.request_access()
        self.vote(first, intent, legitimate=True)
        self.assertEqual(intent.status, "pending")
        self.assertEqual(approval_requirements(intent)["minimum"], 2)
        self.assert_relay_refused(intent)
        self.vote(second, intent, legitimate=True)
        self.assertEqual(intent.status, "approved")
        self.assertEqual(approval_requirements(intent)["approved"], 2)
        self.assert_relay_claimed(intent)

    def test_attested_requester_alias_still_cannot_vote_for_its_canonical_person(self):
        alias, browser, _ = self.controlled_reviewer("requester-alias")
        binding = LoginIdentityBinding.objects.get(login_account=alias, revoked_at=None)
        person = self.trust.people[self.tenant_admin.pk]

        def attest_alias(body):
            actual = body["persons"][person]
            actual["account_ids"].append(str(alias.pk))
            actual["identity_ids"].append(str(binding.identity_id))
            actual["roles"].append("reviewer")

        self.trust.update(attest_alias)
        self.trust.authenticators[alias.pk] = self.trust.authenticators[self.tenant_admin.pk]
        intent = self.request_access()
        self.vote(browser, intent)
        self.assertFalse(intent.decisions.exists())
        self.assert_relay_refused(intent)

    def test_attested_reviewer_alias_cannot_add_a_second_canonical_vote(self):
        first, browser = self.independent_reviewer(1)
        alias, alias_browser, _ = self.controlled_reviewer("attested-alias")
        binding = LoginIdentityBinding.objects.get(login_account=alias, revoked_at=None)
        person = self.trust.people[first.pk]

        def attest_alias(body):
            actual = body["persons"][person]
            actual["account_ids"].append(str(alias.pk))
            actual["identity_ids"].append(str(binding.identity_id))
            body["targets"][str(self.target.pk)]["critical"] = True

        self.trust.update(attest_alias)
        self.trust.authenticators[alias.pk] = self.trust.authenticators[first.pk]
        intent = self.request_access()
        self.vote(browser, intent, legitimate=True)
        self.vote(alias_browser, intent)
        self.assertEqual(approval_requirements(intent)["approved"], 1)
        self.assertEqual(intent.decisions.count(), 1)
        self.assert_relay_refused(intent)

    def test_non_utc_request_survives_database_roundtrip_with_real_action_signatures(self):
        now = timezone.now().astimezone(ZoneInfo("Europe/Brussels"))
        intent = self.request_access(
            starts_at=(now - timedelta(minutes=1)).isoformat(),
            ends_at=(now + timedelta(minutes=30)).isoformat(),
        )
        intent.refresh_from_db()
        self.vote(self.trusted_sponsor_browser(), intent, legitimate=True)
        self.assertEqual(intent.status, "approved")
        self.assert_relay_claimed(intent)

    def test_contract_republication_invalidates_ticket_and_preserves_historical_approval(self):
        contract = self.synthetic_contract()
        self.attest_contract(contract)
        intent = self.request_access(contract=contract)
        self.vote(self.trusted_sponsor_browser(), intent, legitimate=True)
        self.assertEqual(intent.status, "approved")
        response = self.signed_post(self.attacker, reverse("pam-launch", args=[intent.pk]), {})
        self.assertTemplateUsed(response, "pam/session.html")
        relay = RelayConnection.objects.get(lease__intent=intent)
        original_scope = intent.pam_trust.copy()
        revision = contract.revisions.get()
        fields = {key: getattr(revision, key) for key in (
            "starts_at", "ends_at", "sponsor", "timezone_name", "weekdays", "daily_start",
            "daily_end", "allowed_methods", "allowed_countries", "physical_allowed",
            "require_reference",
        )}
        fields["require_reference"] = False
        with self.assurance(self.tenant_admin):
            governance.publish_contract(
                fields, [{"resource": self.resource, "privilege": "", "locations": []}],
                actor=self.tenant_admin, organization=self.org, contract_id=contract.pk,
            )
        with patch("platform_modules.pam.sessions.cipher") as decryptor:
            with self.assertRaises((PermissionDenied, ValidationError)):
                claim_session(
                    relay.pk, actor=self.tenant_admin,
                    ticket=response.context["player"]["ticket"],
                    session_key=self.attacker.session.session_key, client_ip="127.0.0.1",
                    instance_id="synthetic-after-contract-edit",
                )
            decryptor.assert_not_called()
        self.assertTrue(approval_requirements(intent, at=intent.approved_at)["complete"])
        intent.refresh_from_db()
        self.assertEqual(intent.pam_trust, original_scope)

    def test_policy_roundtrip_does_not_restore_an_already_issued_ticket(self):
        _, browser = self.independent_reviewer("policy-ticket")
        self.publish(1)
        intent = self.request_access()
        self.vote(browser, intent, legitimate=True)
        self.assertEqual(intent.status, "approved")
        response = self.signed_post(self.attacker, reverse("pam-launch", args=[intent.pk]), {})
        self.assertTemplateUsed(response, "pam/session.html")
        relay = RelayConnection.objects.get(lease__intent=intent)
        self.publish(3)
        self.publish(1)
        with patch("platform_modules.pam.sessions.cipher") as decryptor:
            with self.assertRaises((PermissionDenied, ValidationError)):
                claim_session(
                    relay.pk, actor=self.tenant_admin,
                    ticket=response.context["player"]["ticket"],
                    session_key=self.attacker.session.session_key, client_ip="127.0.0.1",
                    instance_id="synthetic-after-policy-roundtrip",
                )
            decryptor.assert_not_called()
