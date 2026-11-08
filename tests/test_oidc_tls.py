"""Real HTTPS/cookie/CSRF/PKCE flow, no mocked OIDC discovery or token transport."""

import json
import ssl
import tempfile
import threading
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from socketserver import ThreadingMixIn
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, HTTPSHandler, ProxyHandler, Request, build_opener
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from django.contrib.auth import SESSION_KEY, get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.sessions.models import Session
from django.core.wsgi import get_wsgi_application
from django.db import connections
from django.test import TransactionTestCase, override_settings
from django.urls import reverse

from platform_core.audit import verify_chain
from platform_core.models import AccountSecurity, Organization, OrganizationMembership
from platform_core.oidc.client import OIDCFailure, request_json
from platform_core.oidc.models import OIDCAttempt, OIDCDraft, OIDCLink, OIDCProvider
from platform_core.security import cipher
from tests.fixtures.oidc import OIDCPeer, tls_material


class TLSHandler(WSGIRequestHandler):
    def get_environ(self):
        environ = super().get_environ()
        environ["HTTPS"] = "on"
        return environ

    def log_message(self, *args):
        pass

    def finish(self):
        try:
            super().finish()
        finally:
            connections.close_all()


class ThreadedWSGI(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    block_on_close = True


class Fields(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.values = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name"):
            self.values[attrs["name"]] = attrs.get("value", "")


@override_settings(
    ALLOWED_HOSTS=["127.0.0.1"],
    SESSION_COOKIE_SECURE=True,
    CSRF_COOKIE_SECURE=True,
    SECURE_SSL_REDIRECT=False,
)
class OIDCHTTPSRoundTripTests(TransactionTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pamolive-oidc-tls-")
        self.addCleanup(self.temp.cleanup)
        context, ca_file = tls_material(self.temp.name)
        self.peer = OIDCPeer(context)
        self.addCleanup(self.peer.close)
        self.server = make_server(
            "127.0.0.1",
            0,
            get_wsgi_application(),
            server_class=ThreadedWSGI,
            handler_class=TLSHandler,
        )
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.origin = f"https://127.0.0.1:{self.server.server_port}"
        settings = override_settings(
            OIDC_PUBLIC_ORIGIN=self.origin,
            OIDC_ALLOWED_HOSTS={f"localhost:{self.peer.server.server_port}"},
            OIDC_ALLOWED_NETWORKS=("127.0.0.1/32", "::1/128"),
            OIDC_CA_BUNDLE=ca_file,
            CSRF_TRUSTED_ORIGINS=[self.origin],
        )
        settings.enable()
        self.addCleanup(settings.disable)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_application)
        self.jar = CookieJar()
        self.browser = build_opener(
            ProxyHandler({}),
            HTTPCookieProcessor(self.jar),
            HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)),
        )
        self.actor = get_user_model().objects.create_superuser(
            "https-oidc-owner", password="disposable-local-password"
        )
        self.org = Organization.objects.create(key="oidc-tls", name="HTTPS fixture")
        OrganizationMembership.objects.create(
            account=self.actor, organization=self.org, role="admin"
        )
        AccountSecurity.objects.create(
            account=self.actor,
            encrypted_secret=cipher().encrypt(b"JBSWY3DPEHPK3PXP").decode(),
            recovery_hashes=[make_password(value) for value in ("fixture-local", "fixture-sso")],
        )
        self.peer.redirect_uri = self.origin + reverse(
            "oidc-callback", args=[self.org.pk, "test-idp"]
        )

    def stop_application(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def page(self, path, fields=None):
        url = self.origin + path
        data, headers = None, {}
        if fields is not None:
            fields = dict(fields)
            csrf = next((cookie.value for cookie in self.jar if "csrftoken" in cookie.name), "")
            fields["csrfmiddlewaretoken"] = csrf
            data = urlencode(fields).encode()
            headers.update(Referer=url, Origin=self.origin)
        response = self.browser.open(Request(url, data=data, headers=headers), timeout=10)
        return response.geturl(), response.read().decode(), response.headers

    def session_data(self):
        key = next(
            cookie.value for cookie in self.jar if cookie.name == "pamolive_platform_session"
        )
        return Session.objects.get(session_key=key).get_decoded()

    def test_full_https_test_self_association_and_sso_with_local_mfa_and_replay_refusal(self):
        self.page(reverse("login"))
        self.page(
            reverse("login"),
            dict(
                username=self.actor.username,
                password="disposable-local-password",
                otp="fixture-local",
            ),
        )
        local = self.session_data()
        self.assertEqual(local[SESSION_KEY], str(self.actor.pk))
        values = dict(
            slug="test-idp",
            name="Disposable HTTPS IdP",
            issuer=self.peer.issuer,
            client_id=self.peer.client_id,
            client_secret=self.peer.client_secret,
            algorithm="RS256",
            auth_method="client_secret_basic",
            action="probe",
        )
        _, html, _ = self.page(reverse("oidc-provider-new"), values)
        self.assertIn("Tester la connexion complète", html)
        self.assertFalse(OIDCProvider.unscoped.exists())
        draft = OIDCDraft.unscoped.get()
        _, html, headers = self.page(reverse("oidc-test-start", args=[draft.pk]))
        self.assertIn("Test complet réussi", html)
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(self.session_data()[SESSION_KEY], local[SESSION_KEY])
        self.assertFalse(OIDCLink.unscoped.exists())
        draft.refresh_from_db()
        self.assertIsNotNone(draft.verified_at)
        self.assertEqual(
            json.loads(cipher().decrypt(draft.encrypted_result.encode()))["subject"],
            self.peer.subject,
        )
        self.page(reverse("oidc-provider-new"), dict(values, draft_id=str(draft.pk), action="save"))
        provider = OIDCProvider.unscoped.get()
        self.assertFalse(provider.enabled)
        self.page(reverse("oidc-provider-activation", args=[provider.pk]), {"action": "enable"})
        self.page(reverse("oidc-link-start", args=[provider.pk]))
        self.assertEqual(OIDCLink.unscoped.get().account_id, self.actor.pk)
        self.page(reverse("logout"), {})
        url, html, _ = self.page(reverse("oidc-login-start", args=[provider.pk]))
        self.assertTrue(url.endswith(reverse("oidc-mfa")))
        self.assertIn("Code MFA", html)
        self.assertNotIn(SESSION_KEY, self.session_data())
        self.page(reverse("oidc-mfa"), {"code": "fixture-sso"})
        session = self.session_data()
        self.assertEqual(session[SESSION_KEY], str(self.actor.pk))
        self.assertEqual(session["oidc"]["organization_id"], str(self.org.pk))
        self.assertIn("mfa_verified_at", session)
        self.assertEqual(self.peer.exchanges, 3)
        self.assertEqual(self.peer.last_redirect, self.peer.redirect_uri)
        self.assertEqual(get_user_model().objects.count(), 1)
        self.assertFalse(OIDCAttempt.unscoped.exclude(encrypted_flow="").exists())
        self.assertTrue(verify_chain(self.org))
        with self.assertRaises(HTTPError) as error:
            self.page(reverse("oidc-mfa"), {"code": "fixture-sso"})
        self.assertEqual(error.exception.code, 400)

    def test_real_tls_refuses_untrusted_certificate_and_still_allows_local_login(self):
        with override_settings(OIDC_CA_BUNDLE=""), self.assertRaises(OIDCFailure):
            request_json(self.peer.issuer + "/.well-known/openid-configuration")
        url, html, _ = self.page(reverse("login"))
        self.assertTrue(url.endswith(reverse("login")))
        self.assertIn('name="password"', html)
        self.assertFalse(OIDCProvider.unscoped.exists())
