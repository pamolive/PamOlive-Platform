import json
import time
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from tempfile import TemporaryDirectory
from threading import Thread
from unittest.mock import Mock
from urllib.parse import urlsplit

from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from integrations import business_bridge as bridge
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity
from platform_modules.access.models import AccessIntent
from platform_modules.connectors.business import create_business_source
from platform_modules.connectors.business_models import BusinessReceipt
from platform_modules.identity.models import Grant

from . import test_platform as baseline
from .fixtures.oidc import tls_material


class DjangoTransport:
    def __init__(self):
        self.client = Client(enforce_csrf_checks=True)
        self.calls = []
        self.lose_next_successful_post = False
        self.publish_first = None

    def request(self, url, headers, payload=None):
        parsed = urlsplit(url)
        target = parsed.path + ("?" + parsed.query if parsed.query else "")
        self.calls.append((target, payload))
        options = {"HTTP_AUTHORIZATION": headers["Authorization"]}
        if payload is None:
            response = self.client.get(target, **options)
        else:
            if self.publish_first:
                competing, self.publish_first = self.publish_first(payload), None
                installed = self.client.post(
                    target, json.dumps(competing), content_type="application/json", **options
                )
                if installed.status_code != 201:
                    raise AssertionError("Competing request did not publish")
            response = self.client.post(
                target, json.dumps(payload), content_type="application/json", **options
            )
        if payload and response.status_code == 201 and self.lose_next_successful_post:
            self.lose_next_successful_post = False
            raise bridge.TransportError("Synthetic lost response after commit")
        return response.status_code, response.json()


class BusinessBridgeTests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        self.transport = DjangoTransport()
        self.observed = timezone.now()
        AccountSecurity.objects.create(account=self.admin, encrypted_secret="synthetic-assurance")
        with recent_authentication(self.admin, self.org, time.time()):
            self.source, self.token = self.publisher("bridge-one")
            self.second, self.second_token = self.publisher("bridge-two")

    def publisher(self, key):
        return create_business_source(
            {"key": key, "name": key}, actor=self.admin, organization=self.org
        )

    def configuration(self, source):
        return {
            "source": {
                "url": "https://tickets.example.test/api/dossier/{id}?fields=summary",
                "headers_env": {"Authorization": "SOURCE_READ_CREDENTIAL"},
                "fields": {
                    "external_id": "/id",
                    "reference": "/ref",
                    "source_updated_at": "/fields/modified",
                    "state": "/fields/status",
                    "title": "/fields/summary",
                },
                "kind": "change",
                "states": {"2": "approved", "3": "closed"},
            },
            "pamolive": {
                "url": "https://pamolive.example.test",
                "organization_id": str(self.org.pk),
                "source_id": str(source.pk),
                "token_env": "PUBLISHER_TOKEN",
            },
        }

    def provider(self, status=2, record_id=483):
        obj = Mock()
        obj.request.return_value = (
            200,
            {
                "id": record_id,
                "ref": "CHG-483",
                "fields": {
                    "modified": (self.observed - timedelta(minutes=2)).isoformat(),
                    "status": status,
                    "summary": "Synthetic confidential title",
                    "description": "Synthetic body never exported",
                },
            },
        )
        return obj

    def run_bridge(self, provider=None, source=None, token=None, *, write=True, config=None):
        return bridge.run(
            config or self.configuration(source or self.source),
            "483",
            write=write,
            local_http=False,
            environ={
                "SOURCE_READ_CREDENTIAL": "Bearer synthetic",
                "PUBLISHER_TOKEN": token or self.token,
            },
            source_client=provider or self.provider(),
            platform_client=self.transport,
            now=lambda: self.observed,
        )

    def test_preview_never_contacts_pamolive_and_a_wrong_scope_never_contacts_source(self):
        provider = self.provider()
        preview = self.run_bridge(provider, write=False)
        self.assertEqual(
            preview, dict(mode="preview", kind="change", state="approved", written=False)
        )
        self.assertEqual(self.transport.calls, [])
        provider.reset_mock()
        with self.assertRaisesMessage(bridge.BridgeError, "ne correspond pas à l’organisation"):
            self.run_bridge(provider, source=self.second)
        provider.request.assert_not_called()
        self.assertFalse(BusinessReceipt.objects.exists())

    def test_source_endpoint_only_returns_authenticated_scope_without_caching(self):
        url = "/api/v1/business-source/"
        self.assertEqual(self.transport.client.get(url).status_code, 401)
        response = self.transport.client.get(url, HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(
            response.json(),
            {
                "schema": "pamolive.business-source/1",
                "organization_id": str(self.org.pk),
                "source_id": str(self.source.pk),
                "source_key": self.source.key,
                "source_revision": self.source.revision,
            },
        )
        self.assertNotIn(self.token, response.content.decode())
        self.assertEqual(
            self.transport.client.get(
                url, {"source_id": str(self.second.pk)}, HTTP_AUTHORIZATION=f"Bearer {self.token}"
            ).status_code,
            400,
        )

    def test_two_tool_accounts_can_publish_same_id_without_sharing_scope_or_granting_access(self):
        first = self.run_bridge()
        second = self.run_bridge(self.provider(3), self.second, self.second_token)
        self.assertEqual([first["sequence"], second["sequence"]], [1, 1])
        self.assertNotEqual(first["receipt_id"], second["receipt_id"])
        self.assertFalse(first["local_access_approval"])
        self.assertFalse(AccessIntent.objects.exists())
        self.assertFalse(Grant.objects.exists())
        for receipt in BusinessReceipt.objects.all():
            self.assertNotIn("description", receipt.payload)
            self.assertNotIn("Synthetic body", str(receipt.payload))
        self.assertNotIn("Synthetic confidential title", str(first))

    def test_lost_post_response_replays_the_exact_body_and_does_not_duplicate_receipts(self):
        self.transport.lose_next_successful_post = True
        original = self.run_bridge()
        posts = [payload for _, payload in self.transport.calls if payload is not None]
        self.assertEqual(len(posts), 2)
        self.assertEqual(posts[0], posts[1])
        self.assertEqual(self.run_bridge()["receipt_id"], original["receipt_id"])
        self.assertEqual(BusinessReceipt.objects.count(), 1)
        self.observed += timedelta(seconds=1)
        refreshed = self.run_bridge()
        self.assertEqual(refreshed["sequence"], 2)
        self.assertEqual(BusinessReceipt.objects.count(), 2)

    def test_mismatched_provider_id_and_equal_time_conflicting_state_never_write(self):
        with self.assertRaisesMessage(bridge.BridgeError, "identifiant immuable"):
            self.run_bridge(self.provider(record_id=484))
        self.assertFalse(BusinessReceipt.objects.exists())
        self.run_bridge()
        with self.assertRaisesMessage(bridge.BridgeError, "lecture concurrente"):
            self.run_bridge(self.provider(3))
        self.assertEqual(BusinessReceipt.objects.count(), 1)

    def test_competing_sequence_is_reloaded_without_altering_source_timestamps(self):
        self.transport.publish_first = lambda payload: dict(
            payload,
            observed_at=(self.observed - timedelta(seconds=1)).isoformat(timespec="microseconds"),
            state="open",
        )
        published = self.run_bridge()
        self.assertEqual(published["sequence"], 2)
        rows = list(BusinessReceipt.objects.order_by("sequence"))
        self.assertEqual([row.payload["state"] for row in rows], ["open", "approved"])
        self.assertEqual(
            rows[1].payload["observed_at"], self.observed.isoformat(timespec="microseconds")
        )


class BridgeTransportTests(SimpleTestCase):
    def test_local_http_is_explicit_and_accepts_only_private_or_loopback_ip(self):
        self.assertEqual(
            bridge._url("http://192.168.0.25:8010", local_http=True).hostname, "192.168.0.25"
        )
        for url in (
            "http://192.168.0.25.example.test:8010",
            "http://100.64.0.1:8010",
            "http://169.254.169.254",
            "http://user@192.168.0.25",
            "http://192.168.0.25:8010#fragment",
            "http://[::ffff:192.168.0.25]",
        ):
            with self.subTest(url=url), self.assertRaises(bridge.BridgeError):
                bridge._url(url, local_http=True)
        with self.assertRaises(bridge.BridgeError):
            bridge._url("http://127.0.0.1")

    def test_real_tls_requires_trust_and_a_redirect_never_forwards_the_credential(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization")))
                if self.path == "/initial":
                    self.send_response(302)
                    self.send_header("Location", "/would-leak")
                    self.end_headers()
                else:
                    body = b'{"id":483}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        with TemporaryDirectory() as directory:
            context, ca = tls_material(directory)
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            base = f"https://127.0.0.1:{server.server_port}"
            headers = {"Authorization": "Bearer test"}
            try:
                with self.assertRaises(bridge.TransportError):
                    bridge.Client().request(base + "/initial", headers)
                self.assertEqual(seen, [])
                client = bridge.Client(ca)
                self.assertEqual(client.request(base + "/initial", headers), (302, None))
                self.assertEqual(client.request(base + "/ticket", headers), (200, {"id": 483}))
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)
        self.assertEqual(seen, [("/initial", "Bearer test"), ("/ticket", "Bearer test")])

    def test_duplicate_json_and_malformed_pointer_are_rejected(self):
        with self.assertRaises(bridge.BridgeError):
            bridge.decode(b'{"id":1,"id":2}')
        with self.assertRaises(bridge.BridgeError):
            bridge._pointer({"x": 1}, "/x~3")
        self.assertEqual(bridge._pointer({"x/y": [{"~z": 4}]}, "/x~1y/0/~0z"), 4)
