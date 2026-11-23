"""Exercise the real ASGI application on an owned local TLS socket."""

import asyncio
import http.client
import socket
import ssl
import tempfile
import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TransactionTestCase, override_settings
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

from platform_modules.pam.models import RelayConnection

from .fixtures.asgi import TLSASGIServer
from .fixtures.oidc import write_loopback_tls_files


@override_settings(ALLOWED_HOSTS=["127.0.0.1"], PAM_TRUSTED_PROXY_NETWORKS=())
class TLSASGIFixtureTests(TransactionTestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory(prefix="pamolive-tls-asgi-"))
        certificate, key = write_loopback_tls_files(directory)
        self.server = self.enterContext(TLSASGIServer(certificate, key))
        self.tls = ssl.create_default_context(cafile=str(certificate))

    def test_https_serves_shipped_static_asset_only_under_trusted_tls(self):
        with socket.create_connection((self.server.host, self.server.port), timeout=5) as tcp:
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.tls.wrap_socket(tcp, server_hostname="different-fixture.invalid")
        untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        for context, trusted in ((untrusted, False), (self.tls, True)):
            connection = http.client.HTTPSConnection(
                self.server.host, self.server.port, timeout=5, context=context,
            )
            try:
                if trusted:
                    connection.request("GET", "/static/platform_core/pam.js")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertIn(b"pagehide", response.read(65536))
                else:
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        connection.request("GET", "/static/platform_core/pam.js")
            finally:
                connection.close()

    def test_authenticated_relay_upgrade_requires_exact_origin_and_route(self):
        actor = get_user_model().objects.create_user(username="p1g-asgi-synthetic")
        self.client.force_login(actor)
        cookie = f"{settings.SESSION_COOKIE_NAME}={self.client.session.session_key}"
        path = f"/ws/pam/{uuid.uuid4()}/"

        def open_relay(path, origin, headers=None):
            return connect(
                self.server.websocket_origin + path,
                ssl=self.tls, proxy=None, origin=origin, subprotocols=["guacamole"],
                additional_headers=headers, open_timeout=5, close_timeout=2,
            )

        async def observe():
            for route, origin, headers in (
                (path, self.server.origin, None),
                (path, "https://other-origin.invalid", {"Cookie": cookie}),
                ("/ws/pam/not-a-uuid/", self.server.origin, {"Cookie": cookie}),
            ):
                with self.assertRaises(InvalidStatus) as caught:
                    async with open_relay(route, origin, headers):
                        self.fail("Unexpected WebSocket admission")
                self.assertEqual(caught.exception.response.status_code, 403)
            async with open_relay(path, self.server.origin, {"Cookie": cookie}) as socket:
                self.assertEqual(socket.subprotocol, "guacamole")

        with override_settings(PAM_PUBLIC_ORIGIN=self.server.origin):
            asyncio.run(observe())
        self.assertFalse(RelayConnection.unscoped.exists())
