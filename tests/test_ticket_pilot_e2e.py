"""Two synthetic ticket providers, the real API, local approval and observed access."""

import json
import threading
import time
from contextlib import contextmanager
from datetime import timedelta
from tempfile import TemporaryDirectory
from wsgiref.simple_server import make_server

from django.core.wsgi import get_wsgi_application
from django.test import TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from integrations import business_bridge as bridge
from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity
from platform_modules.access.models import AccessEvaluation
from platform_modules.connectors.business import create_business_source
from platform_modules.connectors.business_models import BusinessAssociation, BusinessReceipt
from platform_modules.connectors.services import create_source

from . import test_platform as baseline
from .fixtures.oidc import tls_material
from .test_oidc_tls import ThreadedWSGI, TLSHandler


@contextmanager
def endpoint(app, tls_context):
    with make_server(
        "127.0.0.1", 0, app, server_class=ThreadedWSGI, handler_class=TLSHandler
    ) as server:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"https://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            thread.join(5)


def provider(path, credential, payload, calls):
    def serve(environ, start_response):
        if environ["REQUEST_METHOD"] != "GET" or environ["PATH_INFO"] != path:
            start_response("404 Not Found", [])
            return []
        if environ.get("HTTP_AUTHORIZATION") != credential:
            start_response("401 Unauthorized", [])
            return []
        calls.append(path)
        start_response("200 OK", [("Content-Type", "application/json")])
        return [json.dumps(payload).encode()]

    return serve


@override_settings(ALLOWED_HOSTS=["127.0.0.1", "testserver"], SECURE_SSL_REDIRECT=False)
class TicketPilotTests(TransactionTestCase):
    intent = baseline.PlatformTests.intent

    def setUp(self):
        baseline.PlatformTests.setUp(self)
        for actor in (self.admin, self.operator, self.reviewer):
            AccountSecurity.objects.create(account=actor, encrypted_secret="fixture-assurance")
        with recent_authentication(self.admin, self.org, time.time()):
            self.incidents, self.incident_token = create_business_source(
                {"key": "pilot-incidents", "name": "Synthetic incidents"},
                actor=self.admin,
                organization=self.org,
            )
            self.changes, self.change_token = create_business_source(
                {"key": "pilot-changes", "name": "Synthetic changes"},
                actor=self.admin,
                organization=self.org,
            )
        _, self.observation_token = create_source(
            "Synthetic access telemetry", actor=self.admin, organization=self.org
        )

    def portal(self, actor):
        self.client.force_login(actor)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time()
        session.save()

    def publish(self, platform, source_url, source, credentials, fields, states, kind, client):
        return bridge.run(
            {
                "source": {
                    "url": source_url,
                    "headers_env": {"Authorization": "TICKET_READ"},
                    "fields": fields,
                    "states": states,
                    "kind": kind,
                },
                "pamolive": {
                    "url": platform,
                    "organization_id": str(self.org.pk),
                    "source_id": str(source.pk),
                    "token_env": "PUBLISH",
                },
            },
            "483",
            write=True,
            local_http=False,
            environ={"TICKET_READ": credentials[0], "PUBLISH": credentials[1]},
            source_client=client,
            platform_client=client,
            now=timezone.now,
        )

    def observe(self, client, platform, external_id, *, token=None):
        status, receipt = client.request(
            platform + "/api/v1/events/",
            {"Authorization": f"Bearer {token or self.observation_token}"},
            {
                "external_id": external_id,
                "occurred_at": timezone.now().isoformat(),
                "identity": str(self.identity.pk),
                "account": str(self.account.pk),
                "resource": str(self.resource.pk),
                "method": "SSH",
                "action": "session.start",
                "result": "success",
            },
        )
        if token is not None:
            self.assertEqual(status, 401)
            return None
        self.assertEqual(status, 201)
        return receipt["event_id"]

    def test_two_real_https_feeds_never_approve_and_only_selected_ticket_explains_access(self):
        modified = (timezone.now() - timedelta(minutes=2)).isoformat()
        incidents = {
            "id": 483,
            "key": "MAINT-483",
            "state": "accepted",
            "updated": modified,
            "title": "Correct ticket: maintenance of the server",
            "private_body": "Never transferred",
        }
        changes = {
            "change": {
                "id": "483",
                "reference": "MAINT-483",
                "status": 3,
                "modified": modified,
                "summary": "Different ticket with the same number and reference",
            }
        }
        calls = []
        incident_peer = provider("/incidents/483", "Bearer fixture-incident", incidents, calls)
        change_peer = provider("/changes/483", "Bearer fixture-change", changes, calls)
        with TemporaryDirectory(prefix="pamolive-tickets-tls-") as directory:
            context, ca = tls_material(directory)
            with (
                endpoint(incident_peer, context) as incident_url,
                endpoint(change_peer, context) as change_url,
                endpoint(get_wsgi_application(), context) as platform,
            ):
                client = bridge.Client(ca)
                incident = self.publish(
                    platform,
                    incident_url + "/incidents/{id}",
                    self.incidents,
                    ("Bearer fixture-incident", self.incident_token),
                    {
                        "external_id": "/id",
                        "reference": "/key",
                        "state": "/state",
                        "source_updated_at": "/updated",
                        "title": "/title",
                    },
                    {"accepted": "approved"},
                    "incident",
                    client,
                )
                change = self.publish(
                    platform,
                    change_url + "/changes/{id}",
                    self.changes,
                    ("Bearer fixture-change", self.change_token),
                    {
                        "external_id": "/change/id",
                        "reference": "/change/reference",
                        "state": "/change/status",
                        "source_updated_at": "/change/modified",
                        "title": "/change/summary",
                    },
                    {"3": "closed"},
                    "change",
                    client,
                )
                self.assertEqual(calls, ["/incidents/483", "/changes/483"])
                self.assertNotEqual(incident["receipt_id"], change["receipt_id"])
                self.assertFalse(incident["local_access_approval"])
                self.assertFalse(change["local_access_approval"])
                self.assertEqual(BusinessReceipt.objects.count(), 2)
                self.assertNotIn(
                    "private_body",
                    BusinessReceipt.objects.get(pk=incident["receipt_id"]).payload,
                )
                self.observe(client, platform, "wrong-token", token=self.incident_token)

                item = self.intent(reference="MAINT-483")
                self.portal(self.operator)
                url = reverse("intent-business-associate", args=[item.pk])
                values = dict(source=str(self.incidents.pk), external_id="483", rationale="Pilot")
                self.assertContains(
                    self.client.post(url, {**values, "command": "preview"}),
                    "Confirmer cette association",
                )
                self.assertFalse(BusinessAssociation.objects.exists())
                self.client.post(
                    url, {**values, "receipt_id": change["receipt_id"], "command": "associate"}
                )
                self.assertFalse(BusinessAssociation.objects.exists())
                self.assertEqual(
                    self.client.post(
                        url,
                        {**values, "receipt_id": incident["receipt_id"], "command": "associate"},
                    ).status_code,
                    302,
                )
                item.refresh_from_db()
                self.assertEqual(item.status, "pending")
                early = self.observe(client, platform, "before-local-decision")
                evaluation = AccessEvaluation.objects.get(event_id=early)
                self.assertIsNone(evaluation.intent_id)
                self.assertNotEqual(evaluation.verdict, "expected")

                self.portal(self.reviewer)
                self.assertEqual(
                    self.client.post(
                        reverse("intent-decide", args=[item.pk]),
                        {"decision": "approve", "comment": "Approved independently in PamOlive"},
                    ).status_code,
                    302,
                )
                item.refresh_from_db()
                self.assertEqual(item.status, "approved")
                observed = self.observe(client, platform, "after-local-decision")
                evaluation = AccessEvaluation.objects.get(event_id=observed)
                self.assertEqual(evaluation.verdict, "expected")
                self.assertEqual(evaluation.intent_id, item.pk)

                self.portal(self.operator)
                exported = self.client.get(reverse("event-export", args=[observed]))
                self.assertEqual(exported.status_code, 200)
                business = exported.json()["business_context"]
                self.assertFalse(business["included_in_historical_evaluation"])
                (intent_context,) = business["intents"]
                (association,) = intent_context["rows"]
                self.assertTrue(association["association_known_before_access"])
                self.assertEqual(association["pinned_read"]["source_key"], self.incidents.key)
                self.assertEqual(association["pinned_read"]["payload"]["title"], incidents["title"])
                self.assertNotIn(change["receipt_id"], json.dumps(business))
                self.assertEqual(AccessEvaluation.objects.filter(event_id=early).count(), 1)
                self.assertIsNone(AccessEvaluation.objects.get(event_id=early).intent_id)
                self.assertTrue(verify_chain(self.org))
