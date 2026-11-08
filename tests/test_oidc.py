import copy
import logging
import time
import uuid
from unittest import skipUnless
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
import pyotp
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import SESSION_KEY, get_user_model
from django.contrib.auth.hashers import make_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity, Organization, OrganizationMembership
from platform_core.oidc import services
from platform_core.oidc.client import (
    OIDCFailure,
    address,
    discover,
    endpoint,
    request_json,
    validate_token,
)
from platform_core.oidc.logging import OIDCQueryRedactor
from platform_core.oidc.models import OIDCAttempt, OIDCDraft, OIDCLink, OIDCProvider
from platform_core.oidc.restoration import verify_evidence
from platform_core.security import cipher
from platform_core.tenancy import federation_context, organization_context
from platform_modules.pam.sessions import session_actor

SECRET = "JBSWY3DPEHPK3PXP"
ISSUER = "https://idp.example.test"
METADATA = dict(
    issuer=ISSUER,
    authorization_endpoint=ISSUER + "/authorize",
    token_endpoint=ISSUER + "/token",
    jwks_uri=ISSUER + "/jwks",
)
VALUES = dict(
    slug="infomaniak",
    name="First SSO",
    issuer=ISSUER,
    client_id="fixture-client",
    client_secret="fixture-private-client-secret",
    algorithm="RS256",
    auth_method="client_secret_basic",
)


@override_settings(
    OIDC_PUBLIC_ORIGIN="https://testserver.invalid",
    OIDC_ALLOWED_HOSTS={"idp.example.test:443"},
    ALLOWED_HOSTS=["testserver"],
)
class OIDCTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = dict(
            jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key(), as_dict=True),
            kid="fixture-key",
            use="sig",
            alg="RS256",
        )
        User = get_user_model()
        cls.admin = User.objects.create_superuser("oidc-admin", password="local-fixture-password")
        cls.owner = User.objects.create_user(
            "oidc-owner", password="local-fixture-password", email="owner@example.test"
        )
        cls.org = Organization.objects.create(key="sso-a", name="A")
        cls.other = Organization.objects.create(key="sso-b", name="B")
        for actor in (cls.admin, cls.owner):
            OrganizationMembership.objects.create(
                organization=cls.org,
                account=actor,
                role="admin" if actor.is_superuser else "operator",
            )
            AccountSecurity.objects.create(
                account=actor,
                encrypted_secret=cipher().encrypt(SECRET.encode()).decode(),
                recovery_hashes=[make_password("fixture-recovery-code")],
            )
        OrganizationMembership.objects.create(
            organization=cls.other, account=cls.owner, role="admin"
        )

    def setUp(self):
        self.context = organization_context(self.org)
        self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.client.force_login(self.admin)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session["organization_id"] = str(self.org.pk)
        session.save()

    def token(self, expected_nonce, **changes):
        claims = dict(
            iss=ISSUER,
            aud=VALUES["client_id"],
            sub="subject-fixture",
            iat=int(time.time()),
            exp=int(time.time()) + 300,
            nonce=expected_nonce,
        )
        claims.update(changes)
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "fixture-key"})

    def callback_for(self, browser, response, *, subject="subject-fixture"):
        params = parse_qs(urlsplit(response.url).query)

        def remote(url, **kwargs):
            if url.endswith("/token"):
                self.assertEqual(
                    kwargs["fields"]["redirect_uri"],
                    services.callback_uri(self.org, VALUES["slug"]),
                )
                self.assertIn("code_verifier", kwargs["fields"])
                return {"id_token": self.token(params["nonce"][0], sub=subject)}
            self.assertEqual(url, METADATA["jwks_uri"])
            return {"keys": [self.jwk]}

        path = reverse(
            "oidc-callback", kwargs={"organization_id": self.org.pk, "slug": VALUES["slug"]}
        )
        with patch("platform_core.oidc.client.request_json", side_effect=remote):
            return browser.get(
                path + "?" + urlencode(dict(state=params["state"][0], code="once-code")),
                secure=True,
            )

    def draft(self):
        with (
            patch("platform_core.oidc.services.discover", return_value=METADATA),
            recent_authentication(self.admin, self.org, time.time()),
        ):
            return services.probe(
                VALUES, actor=self.admin, organization=self.org, session=self.client.session
            )

    def provider(self):
        draft = self.draft()
        result = self.client.get(reverse("oidc-test-start", args=[draft.pk]), secure=True)
        self.assertEqual(result.status_code, 302)
        result = self.callback_for(self.client, result)
        self.assertEqual(result.status_code, 302)
        with recent_authentication(self.admin, self.org, time.time()):
            provider = services.save_provider(
                draft.pk, actor=self.admin, organization=self.org, session=self.client.session
            )
            services.set_enabled(provider, True, actor=self.admin, organization=self.org)
        provider.refresh_from_db()
        return provider

    def owner_client(self):
        browser = Client()
        browser.force_login(self.owner)
        session = browser.session
        session["mfa_verified_at"] = time.time()
        session["organization_id"] = str(self.org.pk)
        session.save()
        return browser

    def linked(self):
        provider = self.provider()
        browser = self.owner_client()
        response = browser.get(reverse("oidc-link-start", args=[provider.pk]), secure=True)
        self.assertEqual(self.callback_for(browser, response).status_code, 302)
        return provider, OIDCLink.objects.get(), browser

    def test_discovery_before_save_does_not_install_or_enable_a_provider(self):
        draft = self.draft()
        self.assertFalse(OIDCProvider.objects.exists())
        self.assertNotIn(VALUES["client_secret"], draft.encrypted_config)
        with (
            recent_authentication(self.admin, self.org, time.time()),
            self.assertRaises(OIDCFailure),
        ):
            services.save_provider(
                draft.pk, actor=self.admin, organization=self.org, session=self.client.session
            )

    def test_complete_unsaved_test_keeps_local_session_and_creates_no_link(self):
        draft = self.draft()
        original_user = self.client.session[SESSION_KEY]
        response = self.client.get(reverse("oidc-test-start", args=[draft.pk]), secure=True)
        self.assertEqual(self.callback_for(self.client, response).status_code, 302)
        draft.refresh_from_db()
        self.assertTrue(draft.verification_proof)
        self.assertEqual(self.client.session[SESSION_KEY], original_user)
        self.assertFalse(OIDCProvider.objects.exists())
        self.assertFalse(OIDCLink.objects.exists())
        self.assertEqual(OIDCAttempt.objects.get().encrypted_flow, "")

    def test_login_requires_explicit_self_association_not_email_or_idp_roles(self):
        provider = self.provider()
        browser = Client()
        response = browser.get(reverse("oidc-login-start", args=[provider.pk]), secure=True)
        self.assertEqual(self.callback_for(browser, response).status_code, 400)
        self.assertNotIn(SESSION_KEY, browser.session)
        self.assertEqual(get_user_model().objects.count(), 2)

    def test_local_login_stays_on_the_page_and_works_with_federation_enabled(self):
        self.provider()
        browser = Client()
        response = browser.get(reverse("login"), secure=True)
        self.assertContains(response, "First SSO")
        self.assertContains(response, 'name="password"')
        result = browser.post(
            reverse("login"),
            {
                "username": self.owner.username,
                "password": "local-fixture-password",
                "otp": pyotp.TOTP(SECRET).now(),
            },
            secure=True,
        )
        self.assertEqual(result.status_code, 302)
        self.assertNotIn("oidc", browser.session)

    def test_signed_sso_keeps_local_mfa_and_locks_session_to_organization(self):
        provider, link, _ = self.linked()
        browser = Client()
        response = browser.get(reverse("oidc-login-start", args=[provider.pk]), secure=True)
        result = self.callback_for(browser, response)
        self.assertEqual(result.url, reverse("oidc-mfa"))
        self.assertNotIn(SESSION_KEY, browser.session)
        result = browser.post(reverse("oidc-mfa"), {"code": pyotp.TOTP(SECRET).now()}, secure=True)
        self.assertEqual(result.url, reverse("dashboard"))
        self.assertEqual(browser.session["oidc"]["link_id"], str(link.pk))
        self.assertEqual(
            session_actor(browser.session.session_key, organization=self.org).pk, self.owner.pk
        )
        with self.assertRaises(PermissionDenied):
            session_actor(browser.session.session_key, organization=self.other)
        self.assertEqual(
            browser.post(
                reverse("organization-switch"), {"organization": str(self.other.pk)}, secure=True
            ).status_code,
            404,
        )
        with federation_context(self.admin.pk, self.org.pk), self.assertRaises(PermissionDenied):
            from platform_core.services import authorize

            authorize(self.admin, self.other)

    def test_disabled_provider_and_revoked_link_reject_native_session_authority(self):
        provider, link, _ = self.linked()
        browser = Client()
        result = browser.get(reverse("oidc-login-start", args=[provider.pk]), secure=True)
        self.callback_for(browser, result)
        browser.post(reverse("oidc-mfa"), {"code": "fixture-recovery-code"}, secure=True)
        with recent_authentication(self.admin, self.org, time.time()):
            services.set_enabled(provider, False, actor=self.admin, organization=self.org)
        with self.assertRaises(PermissionDenied):
            session_actor(browser.session.session_key, organization=self.org)
        self.assertEqual(browser.get(reverse("dashboard"), secure=True).status_code, 302)
        self.assertNotIn(SESSION_KEY, browser.session)

    def test_state_is_browser_bound_single_use_and_pkce_is_s256(self):
        draft = self.draft()
        response = self.client.get(reverse("oidc-test-start", args=[draft.pk]), secure=True)
        params = parse_qs(urlsplit(response.url).query)
        self.assertEqual(params["code_challenge_method"], ["S256"])
        state = params["state"][0]
        with self.assertRaises(OIDCFailure):
            services.claim(
                state,
                organization_id=self.org.pk,
                slug=VALUES["slug"],
                session=Client().session,
                actor=self.admin,
            )
        attempt, _ = services.claim(
            state,
            organization_id=self.org.pk,
            slug=VALUES["slug"],
            session=self.client.session,
            actor=self.admin,
        )
        self.assertIsNotNone(attempt.used_at)
        with self.assertRaises(OIDCFailure):
            services.claim(
                state,
                organization_id=self.org.pk,
                slug=VALUES["slug"],
                session=self.client.session,
                actor=self.admin,
            )

    def test_jwt_refuses_issuer_nonce_audience_expiry_and_privilege_claim_substitution(self):
        for changes in (
            {"iss": ISSUER + "/other"},
            {"aud": "other-client"},
            {"nonce": "wrong"},
            {"exp": int(time.time()) - 1},
            {"iat": True},
            {"aud": [VALUES["client_id"], "other"]},
        ):
            with self.subTest(changes=changes), self.assertRaises(OIDCFailure):
                validate_token(
                    self.token("nonce", **changes), {"keys": [self.jwk]}, VALUES, "nonce"
                )
        self.assertEqual(
            validate_token(
                self.token("nonce", email="different@example.test", roles=["admin"], amr=["mfa"]),
                {"keys": [self.jwk]},
                VALUES,
                "nonce",
            ),
            "subject-fixture",
        )

    def test_jwt_does_not_fetch_header_keys_or_trust_another_algorithm(self):
        token = jwt.encode(
            dict(sub="subject"),
            "attacker-key-not-a-real-shared-secret",
            algorithm="HS256",
            headers={"kid": "fixture-key"},
        )
        with self.assertRaises(OIDCFailure):
            validate_token(token, {"keys": [self.jwk]}, VALUES, "nonce")
        duplicate = dict(keys=[self.jwk, copy.deepcopy(self.jwk)])
        with self.assertRaises(OIDCFailure):
            validate_token(self.token("nonce"), duplicate, VALUES, "nonce")

    def test_draft_cannot_be_saved_after_expiry_or_from_another_browser(self):
        draft = self.draft()
        with (
            patch("platform_core.oidc.services.timezone.now", return_value=draft.expires_at),
            self.assertRaises(OIDCFailure),
        ):
            services.read_draft(
                draft.pk, actor=self.admin, organization=self.org, session=self.client.session
            )

    def test_audit_remains_valid_and_query_logging_redacts_code_and_state(self):
        self.provider()
        self.assertTrue(verify_chain(self.org))
        record = logging.LogRecord(
            "uvicorn.access",
            20,
            "",
            0,
            "%s %s %s %s %s",
            (
                "127.0.0.1",
                "GET",
                "/accounts/oidc/a/x/callback/?code=PRIVATE&state=SECRET",
                "1.1",
                302,
            ),
            None,
        )
        OIDCQueryRedactor().filter(record)
        self.assertNotIn("PRIVATE", record.getMessage())
        self.assertNotIn("SECRET", record.getMessage())

    def test_untested_forged_configuration_and_foreign_drafts_cannot_be_saved(self):
        draft = self.draft()
        with self.assertRaises(OIDCFailure):
            services.read_draft(
                draft.pk, actor=self.owner, organization=self.org, session=self.client.session
            )
        OIDCDraft.objects.filter(pk=draft.pk).update(
            verified_at=draft.created_at, verification_proof="0" * 64
        )
        with (
            recent_authentication(self.admin, self.org, time.time()),
            self.assertRaises(OIDCFailure),
        ):
            services.save_provider(
                draft.pk, actor=self.admin, organization=self.org, session=self.client.session
            )
        self.assertFalse(OIDCProvider.objects.exists())

    def test_modification_of_verification_proof_invalidates_provider(self):
        provider = self.provider()
        OIDCProvider.objects.filter(pk=provider.pk).update(verification_proof="0" * 64)
        provider.refresh_from_db()
        self.assertFalse(services.ready(provider))
        with (
            recent_authentication(self.admin, self.org, time.time()),
            self.assertRaises(OIDCFailure),
        ):
            services.set_enabled(provider, True, actor=self.admin, organization=self.org)
        self.assertNotContains(Client().get(reverse("login"), secure=True), "First SSO")

    def test_association_needs_current_mfa_and_cannot_link_another_account(self):
        provider = self.provider()
        with self.assertRaises(PermissionDenied):
            services.associate(provider, "subject", actor=self.owner, organization=self.org)
        browser = self.owner_client()
        response = browser.get(reverse("oidc-link-start", args=[provider.pk]), secure=True)
        session = browser.session
        session["mfa_verified_at"] = 0
        session.save()
        self.assertEqual(self.callback_for(browser, response).status_code, 400)
        self.assertFalse(OIDCLink.objects.exists())

    def test_revoke_association_rejects_the_existing_federated_session(self):
        provider, link, _ = self.linked()
        browser = Client()
        self.callback_for(
            browser, browser.get(reverse("oidc-login-start", args=[provider.pk]), secure=True)
        )
        browser.post(reverse("oidc-mfa"), {"code": "fixture-recovery-code"}, secure=True)
        with recent_authentication(self.admin, self.org, time.time()):
            services.revoke_link(link, actor=self.admin, organization=self.org)
        with self.assertRaises(PermissionDenied):
            session_actor(browser.session.session_key, organization=self.org)
        self.assertEqual(browser.get(reverse("dashboard"), secure=True).status_code, 302)
        self.assertNotIn(SESSION_KEY, browser.session)

    def test_duplicate_callback_parameters_and_wrong_callback_are_refused(self):
        draft = self.draft()
        response = self.client.get(reverse("oidc-test-start", args=[draft.pk]), secure=True)
        state = parse_qs(urlsplit(response.url).query)["state"][0]
        callback = reverse("oidc-callback", args=[self.org.pk, VALUES["slug"]])
        self.assertEqual(
            self.client.get(
                callback + "?" + urlencode([("state", state), ("state", state), ("code", "once")]),
                secure=True,
            ).status_code,
            400,
        )
        with self.assertRaises(OIDCFailure):
            services.claim(
                state,
                organization_id=self.org.pk,
                slug="other",
                session=self.client.session,
                actor=self.admin,
            )
        self.assertIsNone(OIDCAttempt.objects.get().used_at)

    def test_discovery_refuses_malformed_contracts_without_type_errors(self):
        good = dict(
            METADATA,
            response_types_supported=["code"],
            id_token_signing_alg_values_supported=["RS256"],
            token_endpoint_auth_methods_supported=["client_secret_basic"],
        )
        for field in (
            "response_types_supported",
            "id_token_signing_alg_values_supported",
            "token_endpoint_auth_methods_supported",
            "code_challenge_methods_supported",
        ):
            for value in (None, 3, {"S256": True}, "code", [None]):
                with (
                    self.subTest(field=field, value=value),
                    patch(
                        "platform_core.oidc.client.request_json",
                        return_value=dict(good, **{field: value}),
                    ),
                    self.assertRaises(OIDCFailure),
                ):
                    discover(VALUES)

    def test_ssrf_dns_rebinding_metadata_addresses_and_redirects_are_refused(self):
        for url in (
            "http://idp.example.test",
            "https://idp.example.test:444",
            "https://unapproved.example.test",
            "https://user:pass@idp.example.test",
            "https://idp.example.test/a/../token",
            "https://idp.example.test?redirect=x",
        ):
            with self.subTest(url=url), self.assertRaises(OIDCFailure):
                endpoint(url)
        for ips in (("8.8.8.8", "127.0.0.1"), ("169.254.169.254",), ("100.100.100.200",)):
            resolved = [(2, 1, 6, "", (item, 443)) for item in ips]
            with (
                patch("platform_core.oidc.client.socket.getaddrinfo", return_value=resolved),
                self.assertRaises(OIDCFailure),
            ):
                address("idp.example.test", 443)
        with (
            patch("platform_core.oidc.client.address", return_value="8.8.8.8"),
            patch("platform_core.oidc.client.PinnedHTTPS") as transport,
        ):
            transport.return_value.getresponse.return_value.status = 302
            with self.assertRaises(OIDCFailure):
                request_json(ISSUER + "/token")
            transport.return_value.request.assert_called_once()
            transport.return_value.close.assert_called_once()

    def test_orm_does_not_allow_retargeting_links_or_replacing_capsules(self):
        _, link, _ = self.linked()
        with self.assertRaises(ValidationError):
            OIDCLink.objects.filter(pk=link.pk).update(account=self.admin)
        link.subject = "attacker"
        with self.assertRaises(ValidationError):
            link.save()
        draft = OIDCDraft.objects.get()
        with self.assertRaises(ValidationError):
            OIDCDraft.objects.filter(pk=draft.pk).update(encrypted_config="replacement")

    def test_offline_restore_checks_secrets_links_and_proofs_even_when_disabled(self):
        provider, _, _ = self.linked()
        encrypted, signed = verify_evidence()
        self.assertGreaterEqual(encrypted, 3)
        self.assertGreaterEqual(signed, 3)
        with override_settings(OIDC_ALLOWED_HOSTS=(), OIDC_PUBLIC_ORIGIN=""):
            self.assertEqual(verify_evidence(), (encrypted, signed))
        with override_settings(PAMOLIVE_ENCRYPTION_KEY="wrong-fixture-restoration-key"):
            from cryptography.fernet import InvalidToken

            with self.assertRaises(InvalidToken):
                verify_evidence()
        OIDCProvider.objects.filter(pk=provider.pk).update(
            verification_proof="0" * 64, enabled=False
        )
        with self.assertRaisesRegex(RuntimeError, "provider evidence"):
            verify_evidence()

    def test_synthetic_restore_corpus_covers_all_oidc_encrypted_and_signed_records(self):
        from deploy.prepare_restore_fixture import oidc_corpus

        oidc_corpus(self.owner, self.org)
        encrypted, signed = verify_evidence()
        self.assertEqual(encrypted, 4)
        self.assertEqual(signed, 6)
        self.assertEqual(OIDCAttempt.objects.count(), 2)

    @skipUnless(connection.vendor == "postgresql", "Authoritative PostgreSQL guards")
    def test_postgres_guards_reject_sql_retargeting_replay_and_cross_tenant_inserts(self):
        provider, link, _ = self.linked()
        used = OIDCAttempt.objects.filter(used_at__isnull=False).first()
        attempts = (
            (
                "UPDATE platform_core_oidclink SET account_id=%s WHERE id=%s",
                [self.admin.pk, link.pk],
            ),
            (
                "UPDATE platform_core_oidcprovider SET issuer=%s WHERE id=%s",
                [ISSUER + "/evil", provider.pk],
            ),
            ("UPDATE platform_core_oidcattempt SET used_at=NULL WHERE id=%s", [used.pk]),
            ("UPDATE platform_core_oidcattempt SET purpose='login' WHERE id=%s", [used.pk]),
        )
        for statement, params in attempts:
            with self.subTest(statement=statement), self.assertRaises(DatabaseError):
                with transaction.atomic(), connection.cursor() as cursor:
                    cursor.execute(statement, params)
        clone = copy.copy(link)
        clone.pk, clone.organization, clone.subject = uuid.uuid4(), self.other, "foreign"
        with self.assertRaises(DatabaseError), transaction.atomic():
            OIDCLink.unscoped.bulk_create([clone])
