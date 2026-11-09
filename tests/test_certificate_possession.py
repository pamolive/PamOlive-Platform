import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest import skipUnless
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID
from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.models import AuditEvent, ModuleActivation, Organization
from platform_core.tenancy import organization_context
from platform_modules.access import certificate_possession as proof
from platform_modules.access.services import ingest_event
from platform_modules.connectors.services import create_source
from platform_modules.identity.models import Credential, Identity


def certificate(key, *, expired=False):
    now = timezone.now()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.example.test")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 1))
        .sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256())
    )


class CertificatePossessionTests(TransactionTestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser("certificate-admin")
        self.org = Organization.objects.create(key="certificate-a", name="Certificate A")
        self.other = Organization.objects.create(key="certificate-b", name="Certificate B")
        for org in (self.org, self.other):
            for module in ("access", "identity", "connectors"):
                ModuleActivation.objects.create(
                    organization=org, module_key=module, version="0.2.0", enabled=True
                )
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.cert = certificate(self.key)
        with organization_context(self.org):
            self.source, self.token = create_source(
                "TLS observations", actor=self.admin, organization=self.org
            )
            self.identity = Identity.objects.create(
                organization=self.org, name="Machine", kind="machine"
            )
            self.credential = Credential.objects.create(
                organization=self.org,
                name="TLS fixture",
                identity=self.identity,
                kind="certificate",
                fingerprint=self.cert.fingerprint(hashes.SHA256()).hex(),
            )
        with organization_context(self.other):
            _, self.foreign_token = create_source(
                "Other source", actor=self.admin, organization=self.other
            )
        self.event = self.create_event("session-1")

    def create_event(self, external_id, *, manual=False):
        data = {
            "source": str(self.source.pk),
            "external_id": external_id,
            "occurred_at": timezone.now() - timedelta(minutes=10),
            "domain": "certificate",
            "credential": self.credential,
            "method": "TLS",
            "action": "connect",
            "credential_observation": "possession_asserted",
        }
        event, _ = ingest_event(
            data,
            organization=self.org,
            actor=self.admin if manual else None,
            source=None if manual else self.source,
        )
        return event

    def post(self, endpoint, data, *, event=None, token=None, secure=True):
        return self.client.post(
            reverse(endpoint, args=[(event or self.event).pk]),
            data,
            content_type="application/json",
            secure=secure,
            HTTP_AUTHORIZATION="Bearer " + (self.token if token is None else token),
        )

    def challenge(self, *, event=None):
        result = self.post("certificate-challenge", {}, event=event)
        self.assertEqual(result.status_code, 200, result.content)
        self.assertEqual(result["Cache-Control"], "no-store")
        return result.json()

    def answer(self, challenge, *, key=None, cert=None):
        key = key or self.key
        cert = cert or self.cert
        message = base64.b64decode(challenge["message_b64"], validate=True)
        if isinstance(key, rsa.RSAPrivateKey):
            signature = key.sign(
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
        else:
            signature = key.sign(message)
        return {
            "challenge": challenge["challenge"],
            "certificate": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),
            "signature": base64.b64encode(signature).decode(),
        }

    def test_real_signed_proof_reaches_ui_and_export_without_changing_history(self):
        with organization_context(self.org):
            original_eval = self.event.evaluations.get()
        body = self.answer(self.challenge())
        response = self.post("certificate-proof", body)
        self.assertEqual(response.status_code, 201, response.content)
        public = response.json()
        self.assertEqual(public["algorithm"], "Ed25519")
        self.assertFalse(public["historical_access_verified"])
        self.assertFalse(public["authorization_inferred"])
        self.assertEqual(self.post("certificate-proof", body).status_code, 409)
        self.assertEqual(AuditEvent.objects.filter(action=proof.ACTION).count(), 1)
        self.assertTrue(verify_chain(self.org))
        self.event.refresh_from_db()
        self.assertEqual(self.event.credential_observation, "possession_asserted")
        with organization_context(self.org):
            self.assertEqual(self.event.evaluations.get().signature, original_eval.signature)
        self.client.force_login(self.admin)
        export = self.client.get(reverse("event-export", args=[self.event.pk]))
        self.assertEqual(export.status_code, 200, export.content)
        self.assertEqual(export.json()["certificate_possession"], public)
        self.assertNotIn("certificate_der_b64", export.json()["certificate_possession"])
        detail = self.client.get(reverse("record-detail", args=["event", self.event.pk]))
        self.assertContains(detail, "Vérifiée au moment du défi")
        self.event.action = "altered source"
        self.assertEqual(proof.summary(self.event), {"status": "invalid"})

    def test_scope_enforces_https_source_receipt_and_tenant(self):
        self.assertEqual(self.post("certificate-challenge", {}, secure=False).status_code, 403)
        spoofed = self.client.post(
            reverse("certificate-challenge", args=[self.event.pk]),
            {},
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer " + self.token,
            HTTP_X_FORWARDED_PROTO="https",
            REMOTE_ADDR="203.0.113.15",
        )
        self.assertEqual(spoofed.status_code, 403)
        self.assertEqual(self.post("certificate-challenge", {}, token="").status_code, 401)
        self.assertEqual(
            self.post("certificate-challenge", {}, token=self.foreign_token).status_code, 404
        )
        manual = self.create_event("manual", manual=True)
        self.assertEqual(self.post("certificate-challenge", {}, event=manual).status_code, 404)
        body = self.answer(self.challenge())
        event2 = self.create_event("session-2")
        self.assertEqual(self.post("certificate-proof", body, event=event2).status_code, 400)
        self.assertEqual(
            self.post("certificate-proof", body, token=self.foreign_token).status_code, 404
        )
        self.assertFalse(AuditEvent.objects.filter(action=proof.ACTION).exists())

    def test_wrong_certificate_signature_tampered_challenge_and_expiration(self):
        challenge = self.challenge()
        body = self.answer(challenge)
        same_key_other_certificate = certificate(self.key)
        self.assertEqual(
            self.post(
                "certificate-proof", self.answer(challenge, cert=same_key_other_certificate)
            ).status_code,
            400,
        )
        self.assertEqual(
            self.post(
                "certificate-proof",
                self.answer(challenge, key=ed25519.Ed25519PrivateKey.generate()),
            ).status_code,
            400,
        )
        self.assertEqual(
            self.post(
                "certificate-proof", {**body, "challenge": "bad:" + body["challenge"]}
            ).status_code,
            400,
        )
        with patch.object(proof, "_now", return_value=timezone.now() + timedelta(seconds=121)):
            self.assertEqual(self.post("certificate-proof", body).status_code, 400)
        self.assertFalse(AuditEvent.objects.filter(action=proof.ACTION).exists())

    def test_rsa_pss_and_p256_real_signatures_and_expired_certificate(self):
        cases = (
            (
                rsa.generate_private_key(public_exponent=65537, key_size=2048),
                "RSA-PSS-SHA256",
                False,
            ),
            (ec.generate_private_key(ec.SECP256R1()), "ECDSA-P256-SHA256", False),
            (ed25519.Ed25519PrivateKey.generate(), None, True),
        )
        for number, (key, algorithm, expired) in enumerate(cases):
            cert = certificate(key, expired=expired)
            self.credential.fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            self.credential.save(update_fields=["fingerprint"])
            event = self.create_event(f"algorithm-{number}")
            response = self.post(
                "certificate-proof",
                self.answer(self.challenge(event=event), key=key, cert=cert),
                event=event,
            )
            self.assertEqual(response.status_code, 400 if expired else 201, response.content)
            if algorithm:
                self.assertEqual(response.json()["algorithm"], algorithm)

    def test_budget_applies_to_invalid_requests_and_disable_invalidates_challenge(self):
        with (
            patch.object(proof, "CALLS_PER_MINUTE", 2),
            patch.object(proof, "_now", return_value=timezone.now()),
        ):
            challenge = self.challenge()
            self.assertEqual(self.post("certificate-proof", {"extra": True}).status_code, 400)
            throttled = self.post("certificate-challenge", {})
            self.assertEqual(throttled.status_code, 429)
            self.assertEqual(throttled["Retry-After"], "60")
        self.source.active = False
        self.source.save(update_fields=["active"])
        self.assertEqual(self.post("certificate-proof", self.answer(challenge)).status_code, 401)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL organization lock")
    def test_concurrent_signed_challenges_preserve_one_proof(self):
        answers = [self.answer(self.challenge()) for _ in range(2)]

        def submit(data):
            close_old_connections()
            try:
                with organization_context(self.org):
                    proof.submit(
                        self.source,
                        self.event.pk,
                        data["challenge"],
                        data["certificate"],
                        data["signature"],
                    )
                return "saved"
            except proof.Conflict:
                return "conflict"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(submit, answers)), ["saved", "conflict"])
        self.assertEqual(AuditEvent.objects.filter(action=proof.ACTION).count(), 1)
