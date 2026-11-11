"""Opt-in: real public HTTPS sources and an isolated loopback PamOlive."""

import time
from pathlib import Path

from django.test import LiveServerTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from integrations import business_bridge as bridge
from platform_modules.access.models import AccessIntent
from platform_modules.connectors.business import create_business_source, verify_business_receipt
from platform_modules.connectors.business_models import BusinessReceipt
from platform_modules.identity.models import Grant
from platform_modules.identity.mover import propose_move

from . import test_platform as baseline
from .test_mover import MoverFixture

EXAMPLES = Path(__file__).resolve().parents[1] / "integrations"
PUBLIC_ISSUES = {"github": "42", "gitlab": "42", "jira": "138883"}


@override_settings(ALLOWED_HOSTS=["127.0.0.1", "testserver"], SECURE_SSL_REDIRECT=False)
class PublicBusinessSourceQualification(MoverFixture, LiveServerTestCase):
    host = "127.0.0.1"
    event = baseline.PlatformTests.event

    def test_three_sources_to_one_governed_access_explanation(self):
        source_client, platform_client = bridge.Client(), bridge.Client()
        receipts, publisher_tokens = {}, {}
        for key, external_id in PUBLIC_ISSUES.items():
            with self.mfa(self.admin):
                source, token = create_business_source(
                    {"key": key, "name": key}, actor=self.admin, organization=self.org
                )
            publisher_tokens[key] = token
            example = EXAMPLES / f"business-bridge.{key}.example.json"
            config = bridge.decode(example.read_bytes())
            self.assertFalse(config["source"]["headers_env"])
            config["pamolive"].update(
                url=self.live_server_url, organization_id=str(self.org.pk), source_id=str(source.pk)
            )
            result = bridge.run(
                config,
                external_id,
                write=True,
                local_http=True,
                environ={config["pamolive"]["token_env"]: token},
                source_client=source_client,
                platform_client=platform_client,
                now=timezone.now,
            )
            self.assertFalse(result["local_access_approval"])
            self.assertTrue(result["current_source_assertion"])
            self.assertEqual(result["sequence"], 1)
            receipt = BusinessReceipt.objects.get(pk=result["receipt_id"])
            self.assertEqual(receipt.record.source_id, source.pk)
            self.assertEqual(receipt.record.external_id, external_id)
            self.assertIn(receipt.payload["state"], {"open", "closed"})
            self.assertTrue(verify_business_receipt(receipt))
            self.assertTrue({"body", "description", "author", "user"}.isdisjoint(receipt.payload))
            receipts[key] = receipt

        self.assertEqual(BusinessReceipt.objects.count(), 3)
        self.assertNotEqual(receipts["github"].record_id, receipts["gitlab"].record_id)
        self.assertFalse(AccessIntent.objects.exists())
        self.assertFalse(Grant.objects.exists())
        for key in ("github", "gitlab"):
            headers = {"Authorization": f"Bearer {publisher_tokens[key]}"}
            status, reading = platform_client.request(
                f"{self.live_server_url}/api/v1/business-records/?external_id=42", headers
            )
            self.assertEqual(status, 200)
            self.assertEqual(reading["receipt_id"], str(receipts[key].pk))
            status, _ = platform_client.request(
                f"{self.live_server_url}/api/v1/business-records/?external_id=138883", headers
            )
            self.assertEqual(status, 404)

        role = self.role()
        with self.mfa(self.operator):
            proposal = propose_move(
                identity_id=self.identity.pk,
                department="Operations",
                assignments={role.pk: [self.account.pk]},
                reason="Verify the explanation of a synthetic access",
                reference="PUBLIC-SOURCE-PILOT",
                business_receipts=[item.pk for item in receipts.values()],
                actor=self.operator,
                organization=self.org,
            )
        self.assertFalse(AccessIntent.objects.exists())
        self.assertTrue(self.apply(proposal).applied)
        intent = AccessIntent.objects.get()
        self.assertEqual(intent.status, "pending")
        self.assertFalse(Grant.objects.exists())
        self.approve_access(intent)

        event = self.event(method="SSO", privilege="read")
        self.assertEqual(event.evaluations.get().intent_id, intent.pk)
        self.client.force_login(self.reviewer)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time()
        session.save()
        response = self.client.get(reverse("event-export", args=[event.pk]))
        self.assertEqual(response.status_code, 200)
        mobility = response.json()["business_context"]["mobility"]
        self.assertFalse(mobility["local_authorizations_modified"])
        rows = [row for row in mobility["rows"] if row["state"] == "verified_origin"]
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(
                {
                    ref["reviewed"]["source_key"]: ref["reviewed"]["receipt_id"]
                    for ref in row["references"]
                },
                {key: str(receipt.pk) for key, receipt in receipts.items()},
            )
        self.assertTrue(Grant.objects.filter(status="active").exists())
