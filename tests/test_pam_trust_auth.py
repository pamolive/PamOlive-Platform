"""Real synthetic WebAuthn signatures with no authenticator or target service."""

import hashlib
import json
import secrets
import uuid
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core.models import Organization, OrganizationMembership
from platform_modules.pam import trust_auth
from platform_modules.pam.trust_auth_models import (
    PAMTrustAuthorization,
    PAMTrustChallenge,
    PAMTrustEnrollment,
)
from platform_modules.pam.trust_models import PAMAuthenticatorState

RP_ID = "pam.example.test"
ORIGIN = "https://pam.example.test"


def virtual_credential():
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    cose_key = cbor2.dumps(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )
    return private_key, {
        "id": trust_auth.b64encode(secrets.token_bytes(32)),
        "public_key": trust_auth.b64encode(cose_key),
        "rp_id": RP_ID,
        "origin": ORIGIN,
        "active": True,
        "enrollment_id": str(uuid.uuid4()),
    }


def authenticator_response(
    private_key,
    credential,
    options,
    *,
    counter=0,
    flags=5,
    origin=ORIGIN,
    rp_id=RP_ID,
    cross_origin=False,
):
    client = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": options["publicKey"]["challenge"],
            "origin": origin,
            "crossOrigin": cross_origin,
        },
        separators=(",", ":"),
    ).encode()
    data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big")
    signature = private_key.sign(data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "id": credential["id"],
        "rawId": credential["id"],
        "type": "public-key",
        "response": {
            "clientDataJSON": trust_auth.b64encode(client),
            "authenticatorData": trust_auth.b64encode(data),
            "signature": trust_auth.b64encode(signature),
            "userHandle": None,
        },
    }


def registration_response(credential, options, *, flags=0x45, origin=ORIGIN):
    client = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": options["publicKey"]["challenge"],
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    identifier = trust_auth.b64decode(credential["id"])
    data = (
        hashlib.sha256(RP_ID.encode()).digest()
        + bytes([flags])
        + b"\0" * 4
        + b"\0" * 16
        + len(identifier).to_bytes(2, "big")
        + identifier
        + trust_auth.b64decode(credential["public_key"])
    )
    attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": data})
    return {
        "id": credential["id"],
        "rawId": credential["id"],
        "type": "public-key",
        "response": {
            "clientDataJSON": trust_auth.b64encode(client),
            "attestationObject": trust_auth.b64encode(attestation),
        },
    }


@override_settings(PAM_TRUST_RP_ID=RP_ID, PAM_TRUST_ORIGIN=ORIGIN)
class PAMTrustAuthenticationTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(key="trust-auth", name="Trust auth")
        self.actor = get_user_model().objects.create_user("trust-person", password="fixture-only")
        OrganizationMembership.objects.create(
            organization=self.organization,
            account=self.actor,
            role="operator",
        )
        self.person_id = str(uuid.uuid4())
        self.private_key, self.credential = virtual_credential()
        self.registry = SimpleNamespace(
            organization_id=self.organization.pk,
            generation=uuid.uuid4(),
            revision=1,
            revision_hash="a" * 64,
            body={
                "policy": {"standard_min": 1, "critical_min": 2},
                "custodians": {},
                "persons": {
                    self.person_id: {
                        "active": True,
                        "account_ids": [str(self.actor.pk)],
                        "identity_ids": [],
                        "endpoint_ids": [],
                        "roles": ["requester", "reviewer", "sponsor"],
                        "authenticators": [self.credential],
                    }
                },
            },
        )
        self.registry_patch = patch(
            "platform_modules.pam.trust_auth.recognized_registry",
            return_value=self.registry,
        )
        self.registry_patch.start()
        self.addCleanup(self.registry_patch.stop)
        # This suite isolates WebAuthn validation; full chain validation has its
        # own signed integration suite. Keep its mocked head referentially real.
        from platform_modules.pam.trust_models import PAMTrustRevision

        PAMTrustRevision.unscoped.create(
            organization=self.organization,
            generation=self.registry.generation,
            revision=1,
            previous_hash="",
            body=self.registry.body,
            signatures={},
            commissioning_signatures={},
            revision_hash=self.registry.revision_hash,
        )
        self.request = self.browser()
        self.payload = {"target": {"hostname": "synthetic.invalid", "epoch": 1}, "intent": "abc"}

    def browser(self):
        request = RequestFactory().post("/pam/fixture/", {})
        SessionMiddleware(lambda request: None).process_request(request)
        request.session.save()
        request.user, request.organization = self.actor, self.organization
        return request

    def proof(self, *, action="request", payload=None, counter=0):
        options = trust_auth.begin_action(self.request, action, payload or self.payload)
        response = authenticator_response(
            self.private_key,
            self.credential,
            options,
            counter=counter,
        )
        return trust_auth.finish_action(self.request, options["challenge"], response)

    def consume(self, value, *, action="request", payload=None, request=None):
        request = request or self.request
        request.POST = request.POST.copy()
        request.POST["_pam_trust_proof"] = value["proof"]
        with trust_auth.action_authentication(request):
            return trust_auth.require_action(
                self.actor,
                self.organization,
                action,
                payload or self.payload,
            )

    def test_real_signature_is_consumed_once_for_exact_action_and_payload(self):
        value = self.proof()
        for action, payload in (("launch", self.payload), ("request", {"target": "other"})):
            with self.assertRaises(PermissionDenied):
                self.consume(value, action=action, payload=payload)
        proof = self.consume(value)
        self.assertEqual(str(proof.challenge.person_id), self.person_id)
        with self.assertRaises(PermissionDenied):
            self.consume(value)
        self.assertEqual(
            PAMTrustAuthorization.unscoped.filter(consumed_at__isnull=False).count(),
            1,
        )

    def test_challenge_and_proof_cannot_cross_browser_sessions(self):
        options = trust_auth.begin_action(self.request, "request", self.payload)
        response = authenticator_response(self.private_key, self.credential, options)
        with self.assertRaises(PermissionDenied):
            trust_auth.finish_action(self.browser(), options["challenge"], response)
        value = trust_auth.finish_action(self.request, options["challenge"], response)
        with self.assertRaises(PermissionDenied):
            self.consume(value, request=self.browser())

    def test_signature_rp_origin_presence_uv_and_cross_origin_are_verified(self):
        for changes in (
            {"origin": "https://evil.example.test"},
            {"rp_id": "evil.example.test"},
            {"flags": 1},
            {"flags": 4},
            {"cross_origin": True},
        ):
            options = trust_auth.begin_action(self.request, "request", self.payload)
            response = authenticator_response(self.private_key, self.credential, options, **changes)
            with self.assertRaises((PermissionDenied, ValidationError)):
                trust_auth.finish_action(self.request, options["challenge"], response)
            # Cancel this isolated negative ceremony, without altering its signed binding.
            PAMTrustChallenge.unscoped.filter(pk=options["challenge"]).update(
                used_at=timezone.now()
            )
        options = trust_auth.begin_action(self.request, "request", self.payload)
        other_key, _ = virtual_credential()
        with self.assertRaises(PermissionDenied):
            trust_auth.finish_action(
                self.request,
                options["challenge"],
                authenticator_response(other_key, self.credential, options),
            )

    def test_counter_never_regresses_and_zero_counter_passkeys_use_unique_challenges(self):
        first = self.proof(counter=4)
        self.consume(first)
        with self.assertRaises(PermissionDenied):
            self.proof(counter=3)
        self.assertEqual(PAMAuthenticatorState.unscoped.get().sign_count, 4)
        self.private_key, self.credential = virtual_credential()
        self.registry.body["persons"][self.person_id]["authenticators"] = [self.credential]
        self.consume(self.proof(counter=0))
        self.consume(self.proof(counter=0))
        self.assertEqual(
            PAMAuthenticatorState.unscoped.get(credential_id=self.credential["id"]).sign_count,
            0,
        )

    def test_registry_change_and_expiration_invalidate_pending_proofs(self):
        value = self.proof()
        self.registry.revision_hash = "b" * 64
        with self.assertRaises(PermissionDenied):
            self.consume(value)
        self.registry.revision_hash = "a" * 64
        with (
            patch(
                "platform_modules.pam.trust_auth.timezone.now",
                return_value=timezone.now() + timedelta(seconds=121),
            ),
            self.assertRaises(PermissionDenied),
        ):
            self.consume(value)

    def test_portal_session_or_recovery_alone_cannot_enroll_an_uncommissioned_person(self):
        self.request.session["mfa_verified_at"] = timezone.now().timestamp()
        self.registry.body["persons"] = {}
        with self.assertRaises(PermissionDenied):
            trust_auth.begin_enrollment(self.request)
        self.assertFalse(PAMTrustChallenge.unscoped.exists())

    def test_registration_needs_a_second_assertion_and_independent_publication(self):
        private_key, candidate = virtual_credential()
        options = trust_auth.begin_enrollment(self.request)
        pending = trust_auth.finish_registration(
            self.request,
            options["challenge"],
            registration_response(candidate, options),
        )
        authenticator = {**candidate, "enrollment_id": pending["enrollment"]}
        with self.assertRaises(ValidationError):
            trust_auth.consume_enrollment(self.organization, self.person_id, authenticator)
        self.assertIsNone(PAMTrustEnrollment.unscoped.get().verified_at)
        receipt = trust_auth.finish_enrollment(
            self.request,
            pending["enrollment"],
            authenticator_response(private_key, candidate, pending, counter=1),
        )
        self.assertNotIn(
            candidate["id"],
            [
                item["id"]
                for item in self.registry.body["persons"][self.person_id]["authenticators"]
            ],
        )
        saved = trust_auth.consume_enrollment(self.organization, self.person_id, receipt)
        self.assertEqual(saved.sign_count, 1)
        with self.assertRaises(ValidationError):
            trust_auth.consume_enrollment(self.organization, self.person_id, receipt)

    def test_public_key_fingerprint_ignores_cose_encoding_order(self):
        key = cbor2.loads(trust_auth.b64decode(self.credential["public_key"]))
        reordered = trust_auth.b64encode(cbor2.dumps(dict(reversed(list(key.items())))))
        self.assertEqual(
            trust_auth.public_key_fingerprint(self.credential["public_key"]),
            trust_auth.public_key_fingerprint(reordered),
        )

    def test_historical_evidence_keeps_signature_after_current_credential_revocation(self):
        proof = self.consume(self.proof())
        evidence = trust_auth.authorization_evidence(proof)
        with patch(
            "platform_modules.pam.trust_registry.historical_registry",
            return_value=self.registry,
        ):
            self.assertTrue(trust_auth.verify_authorization_evidence(evidence))
            self.assertFalse(
                trust_auth.verify_authorization_evidence({**evidence, "action": "launch"}),
            )
        self.assertEqual(evidence["payload_hash"], trust_auth.payload_hash(self.payload))

    def test_missing_request_context_and_plain_portal_session_are_refused(self):
        with self.assertRaises(PermissionDenied):
            trust_auth.require_action(self.actor, self.organization, "request", self.payload)

    def test_http_endpoints_require_csrf_and_verify_an_assertion(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.actor)
        session = client.session
        session["organization_id"] = str(self.organization.pk)
        session.save()
        enrollment_page = client.get(reverse("pam-trust-enrollment"))
        self.assertEqual(enrollment_page.status_code, 200)
        path = reverse("pam-trust-action")
        data = {"operation": "begin", "action": "request", "payload": self.payload}
        self.assertEqual(client.post(path, data, content_type="application/json").status_code, 403)
        csrf = client.cookies["pamolive_platform_csrftoken"].value
        response = client.post(
            path,
            data,
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf,
        )
        self.assertEqual(response.status_code, 200)
        options = response.json()
        response = client.post(
            path,
            {
                "operation": "finish",
                "challenge": options["challenge"],
                "credential": authenticator_response(self.private_key, self.credential, options),
            },
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertIn("proof", response.json())

    def test_form_resume_is_encrypted_and_survives_post_body_parsing(self):
        from platform_modules.pam.trust_views import challenge_response

        self.request.POST = self.request.POST.copy()
        self.request.POST["comment"] = "Reviewed exact target"
        self.request.POST["password"] = "synthetic-sensitive-form-value"
        required = trust_auth.PAMActionRequired("request", self.payload)
        response = challenge_response(self.request, required)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"synthetic-sensitive-form-value", response.content)
        challenge = PAMTrustChallenge.unscoped.get()
        self.assertNotIn("synthetic-sensitive-form-value", challenge.encrypted_form)
        options = trust_auth._authentication_options(challenge)
        verified = trust_auth.finish_action(
            self.request,
            challenge.pk,
            authenticator_response(self.private_key, self.credential, options),
        )
        self.assertIn(["password", "synthetic-sensitive-form-value"], verified["resume"]["fields"])
        with (
            trust_auth.action_authentication(self.request),
            self.assertRaises(
                trust_auth.PAMActionRequired,
            ),
        ):
            trust_auth.require_action(self.actor, self.organization, "request", self.payload)
