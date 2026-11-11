"""P1-G preparation: existing services, real loopback HTTPS, synthetic tenants only."""

import json
import time
from datetime import timedelta

import pyotp
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core.access_contract import build_access_contract
from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity, ModuleActivation, OrganizationMembership
from platform_core.security import cipher, verify_mfa
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.access.evidence import verify_evaluation
from platform_modules.access.models import AccessIntent
from platform_modules.access.provenance import verify_provenance_receipt
from platform_modules.access.services import create_record, ingest_event
from platform_modules.approvals.services import decide
from platform_modules.connectors.models import ExternalChange
from platform_modules.connectors.outbound import configure_connector, process_changes, retry_change
from platform_modules.connectors.services import create_source
from platform_modules.identity.identity360 import build_identity360
from platform_modules.identity.models import Grant
from platform_modules.identity.services import revoke_grant

from . import test_provisioning as provisioning
from .test_scim_creation import ScimCreationFixture


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class IdentityJourneyContractTests(ScimCreationFixture, TestCase):
    # Reuse only the established TLS server lifecycle, not its preapproved setup.
    configured = provisioning.ProvisioningTests.configured

    def setUp(self):
        provisioning.ProvisioningTests.setUp(self)
        self.server.RequestHandlerClass = provisioning.ScimHandler
        self.configured()

    def request_access(self):
        now = timezone.now()
        return create_record(
            "intent",
            dict(
                identity=self.identity,
                account=self.account,
                resource=self.resource,
                method="SCIM",
                privilege="reader",
                reason="Synthetic bounded mission",
                reference="JOURNEY-SYNTHETIC",
                fulfillment="iam_group",
                starts_at=now - timedelta(minutes=1),
                ends_at=now + timedelta(minutes=15),
            ),
            actor=self.operator,
            organization=self.org,
        )

    def approve(self, intent):
        with self.assurance(self.reviewer):
            return decide(
                intent.pk,
                actor=self.reviewer,
                organization=self.org,
                approved=True,
                comment="Independent synthetic reviewer decision",
            )

    def read(self, intent):
        return build_access_contract(intent.pk, actor=self.operator, organization=self.org)

    def test_https_journey_keeps_decision_execution_observation_and_withdrawal_distinct(self):
        initial = build_identity360(self.identity.pk, actor=self.operator, organization=self.org)
        self.assertEqual(initial["access_requests"]["items"], [])
        intent = self.request_access()
        pending = self.read(intent)
        self.assertEqual(pending["intention"]["status"], "pending")
        self.assertEqual(pending["confirmed_executions"]["items"], [])
        self.assertEqual(self.server.state["effects"], 0)
        decision = self.approve(intent)
        self.assertTrue(decision.approved)
        intent.refresh_from_db()
        approved = self.read(intent)
        self.assertEqual(len(approved["local_grant"]["items"]), 1)
        self.assertEqual(approved["provisioned_right"]["items"], [])
        self.assertEqual(process_changes(self.org), 1)
        addition = ExternalChange.objects.get(kind="add_membership")
        self.assertTrue(addition.proofs.get().confirmed)
        self.assertEqual(self.server.state["members"], {"user-1"})
        confirmed = self.read(intent)
        self.assertEqual(confirmed["provisioned_right"]["items"][0]["effect"], "add_membership")
        self.assertEqual(
            confirmed["provisioned_right"]["items"][0]["current_provider_state"], "not_asserted"
        )
        source, token = create_source(
            "Synthetic collector", actor=self.admin, organization=self.org
        )
        event, created = ingest_event(
            dict(
                external_id="journey-1",
                identity=self.identity,
                account=self.account,
                resource=self.resource,
                method="SCIM",
                privilege="reader",
                action="application.access",
                occurred_at=timezone.now(),
            ),
            source=source,
            source_token=token,
            organization=self.org,
        )
        self.assertTrue(created)
        self.assertTrue(verify_provenance_receipt(event.provenance_receipt))
        evaluation = event.evaluations.get()
        self.assertTrue(verify_evaluation(evaluation))
        self.assertEqual(evaluation.intent_id, intent.pk)
        observed = self.read(intent)["observations"]["items"][0]
        self.assertEqual(observed["provenance"], "collector")
        self.assertTrue(observed["provenance_verified"])
        self.assertEqual(observed["association"], "verified_evaluation_reference_not_causality")
        grant = Grant.objects.get(pk=intent.provisioned_grant_id)
        with self.assertRaises(PermissionDenied):
            revoke_grant(
                grant,
                actor=self.operator,
                organization=self.org,
                origin="journey.synthetic.withdrawal",
            )
        grant.refresh_from_db()
        self.assertEqual(grant.status, "active")
        with self.assurance(self.operator):
            revoke_grant(
                grant,
                actor=self.operator,
                organization=self.org,
                origin="journey.synthetic.withdrawal",
            )
        self.assertEqual(self.server.state["members"], {"user-1"})
        self.assertEqual(process_changes(self.org), 1)
        withdrawal = ExternalChange.objects.get(kind="remove_membership")
        self.assertTrue(withdrawal.proofs.get().confirmed)
        self.assertEqual(withdrawal.binding_id, addition.binding_id)
        self.assertEqual(self.server.state["members"], set())
        self.assertTrue(self.server.state["active"])
        final = self.read(intent)
        self.assertEqual(
            {row["effect"] for row in final["provisioned_right"]["items"]},
            {"add_membership", "remove_membership"},
        )
        self.assertEqual(len(final["observations"]["items"]), 1)
        self.assertNotIn(token, json.dumps(final))
        self.assertTrue(verify_chain(self.org))

    def test_second_tenant_cannot_read_decide_or_ingest_against_the_first(self):
        intent = self.request_access()
        for module in ("identity", "access", "approvals", "connectors"):
            install_module(module, actor=self.admin, organization=self.other)
        OrganizationMembership.objects.create(
            organization=self.other, account=self.reviewer, role="reviewer"
        )
        with organization_context(self.other):
            with self.assertRaises(AccessIntent.DoesNotExist):
                build_access_contract(intent.pk, actor=self.reviewer, organization=self.other)
            with self.assertRaises(AccessIntent.DoesNotExist):
                decide(
                    intent.pk,
                    actor=self.reviewer,
                    organization=self.other,
                    approved=True,
                    comment="Foreign",
                )
            foreign_source, foreign_token = create_source(
                "Synthetic foreign", actor=self.admin, organization=self.other
            )
        with self.assertRaises((PermissionDenied, ValidationError)):
            ingest_event(
                dict(
                    external_id="foreign-1",
                    identity=self.identity,
                    resource=self.resource,
                    method="SCIM",
                    action="access",
                    occurred_at=timezone.now(),
                ),
                organization=self.org,
                source=foreign_source,
                source_token=foreign_token,
            )
        self.assertEqual(self.server.state["effects"], 0)
        self.assertTrue(verify_chain(self.other))

    def test_revoked_connect_module_pauses_queued_effect_and_hides_execution(self):
        intent = self.request_access()
        self.approve(intent)
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        self.assertEqual(process_changes(self.org), 0)
        self.assertEqual(self.server.state["effects"], 0)
        self.assertEqual(self.read(intent)["execution_attempts"]["availability"], "module_disabled")
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=True
        )
        queued = ExternalChange.objects.get()
        self.assertEqual(queued.status, "blocked")
        self.assertEqual(queued.result_code, "connector_configuration_changed")
        self.assertEqual(process_changes(self.org), 0)
        with self.assurance(self.operator), self.assertRaises(PermissionDenied):
            retry_change(queued.pk, actor=self.operator, organization=self.org)
        with self.assurance(self.admin):
            retry_change(queued.pk, actor=self.admin, organization=self.org)
        self.assertEqual(process_changes(self.org), 1)
        self.assertEqual(self.server.state["members"], {"user-1"})

    def test_operator_cannot_self_approve_or_configure_a_connector(self):
        intent = self.request_access()
        with self.assurance(self.operator), self.assertRaises(PermissionDenied):
            decide(
                intent.pk, actor=self.operator, organization=self.org, approved=True, comment="Self"
            )
        with self.assurance(self.operator), self.assertRaises(PermissionDenied):
            configure_connector(
                name="Denied",
                base_url=self.url,
                token="synthetic-denied",
                actor=self.operator,
                organization=self.org,
            )
        OrganizationMembership.objects.filter(organization=self.org, account=self.operator).update(
            role="reviewer"
        )
        with self.assurance(self.operator), self.assertRaises(ValidationError):
            decide(
                intent.pk,
                actor=self.operator,
                organization=self.org,
                approved=True,
                comment="Self with role",
            )
        self.assertEqual(self.server.state["effects"], 0)

    def test_missing_privilege_telemetry_does_not_invent_a_matched_intent(self):
        intent = self.request_access()
        self.approve(intent)
        source, token = create_source(
            "Incomplete synthetic telemetry", actor=self.admin, organization=self.org
        )
        event, _ = ingest_event(
            dict(
                external_id="missing-scope",
                identity=self.identity,
                account=self.account,
                resource=self.resource,
                method="SCIM",
                action="application.access",
                occurred_at=timezone.now(),
            ),
            source=source,
            source_token=token,
            organization=self.org,
        )
        evaluation = event.evaluations.get()
        self.assertIsNone(evaluation.intent_id)
        self.assertEqual(evaluation.verdict, "unknown")
        self.assertTrue(verify_evaluation(evaluation))
        self.assertTrue(verify_provenance_receipt(event.provenance_receipt))
        self.assertEqual(self.read(intent)["observations"]["items"], [])

    def test_reviewer_membership_revoked_after_request_cannot_decide(self):
        intent = self.request_access()
        OrganizationMembership.objects.filter(organization=self.org, account=self.reviewer).delete()
        with self.assertRaises(PermissionDenied):
            with self.assurance(self.reviewer):
                decide(
                    intent.pk,
                    actor=self.reviewer,
                    organization=self.org,
                    approved=True,
                    comment="Stale membership",
                )
        intent.refresh_from_db()
        self.assertEqual(intent.status, "pending")
        self.assertEqual(intent.decisions.count(), 0)
        self.assertEqual(self.server.state["effects"], 0)

    def test_real_synthetic_totp_required_for_explicit_connector_assurance(self):
        seed = pyotp.random_base32()
        AccountSecurity.objects.filter(account=self.admin).update(
            encrypted_secret=cipher().encrypt(seed.encode()).decode()
        )
        kwargs = dict(
            name="Fresh synthetic config",
            base_url=self.url,
            token="synthetic-new-token",
            actor=self.admin,
            organization=self.org,
        )
        with self.assertRaises(PermissionDenied):
            configure_connector(**kwargs)
        self.assertTrue(verify_mfa(self.admin, pyotp.TOTP(seed).now()))
        with recent_authentication(self.admin, self.org, time.time()):
            configured = configure_connector(**kwargs)
        self.assertFalse(configured.enabled)
        with self.assertRaises(PermissionDenied):
            with recent_authentication(self.admin, self.org, time.time() - 86400):
                configure_connector(**kwargs)

    def test_identity_page_exposes_existing_access_story_without_claiming_remote_state(self):
        intent = self.request_access()
        self.client.force_login(self.operator)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        profile = self.client.get(reverse("identity360-detail", args=[self.identity.pk]))
        self.assertContains(profile, reverse("access-contract-detail", args=[intent.pk]))
        story = self.client.get(reverse("access-contract-detail", args=[intent.pk]))
        self.assertContains(story, reverse("access-contract-export", args=[intent.pk]))
        self.assertContains(story, "ne confirment pas")
