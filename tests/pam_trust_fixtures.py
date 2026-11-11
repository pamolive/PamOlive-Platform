"""Synthetic independent commissioning and virtual authenticators; real signatures."""

import hashlib
import json
import secrets
import tempfile
import uuid
from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, override_settings
from django.utils import timezone

from platform_core.models import OrganizationMembership
from platform_modules.pam import trust_auth as auth
from platform_modules.pam import trust_registry as registry
from platform_modules.pam.target_binding import target_scope


class VirtualAuthenticator:
    def __init__(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        public = self.private.public_key().public_numbers()
        self.cose = cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")}
        )
        self.raw_id = secrets.token_bytes(32)
        self.id = auth.b64encode(self.raw_id)

    def response(self, options, *, registration=False, origin="https://pam.example.test", flags=5):
        client = json.dumps(
            {
                "type": "webauthn.create" if registration else "webauthn.get",
                "challenge": options["publicKey"]["challenge"],
                "origin": origin,
                "crossOrigin": False,
            }
        ).encode()
        data = (
            hashlib.sha256(b"pam.example.test").digest()
            + bytes([flags | (64 if registration else 0)])
            + bytes(4)
        )
        response = {"clientDataJSON": auth.b64encode(client)}
        if registration:
            data += bytes(16) + len(self.raw_id).to_bytes(2, "big") + self.raw_id + self.cose
            response["attestationObject"] = auth.b64encode(
                cbor2.dumps(
                    {
                        "fmt": "none",
                        "attStmt": {},
                        "authData": data,
                    }
                )
            )
            response["transports"] = ["internal"]
        else:
            response.update(
                authenticatorData=auth.b64encode(data),
                userHandle=None,
                signature=auth.b64encode(
                    self.private.sign(
                        data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
                    )
                ),
            )
        return {"id": self.id, "rawId": self.id, "type": "public-key", "response": response}


def public(key):
    return auth.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


class TrustFixture:
    def __init__(self, case, organization, endpoints, people):
        self.case, self.org = case, organization
        self.directory = tempfile.TemporaryDirectory(prefix="pamolive-trust-synthetic-")
        case.addCleanup(self.directory.cleanup)
        self.commissioner = ed25519.Ed25519PrivateKey.generate()
        self.witness = ed25519.Ed25519PrivateKey.generate()
        self.custodians = {
            str(uuid.uuid4()): ed25519.Ed25519PrivateKey.generate() for _ in range(3)
        }
        self.authenticators, self.requests = {}, {}
        self.settings = override_settings(
            PAM_TRUST_INSTALLATION_ID="synthetic-isolated-installation",
            PAM_TRUST_RP_ID="pam.example.test",
            PAM_TRUST_ORIGIN="https://pam.example.test",
            PAM_TRUST_CHECKPOINT_DIRECTORY=self.directory.name,
            PAM_TRUST_COMMISSIONING_KEYS={
                str(organization.pk): {"commissioner": public(self.commissioner)}
            },
            PAM_TRUST_CHECKPOINT_KEYS={str(organization.pk): {"witness": public(self.witness)}},
        )
        self.settings.enable()
        case.addCleanup(self.settings.disable)
        now = timezone.now()
        self.body = {
            "format": registry.REGISTRY_FORMAT,
            "installation": "synthetic-isolated-installation",
            "organization": str(organization.pk),
            "generation": str(uuid.uuid4()),
            "revision": 1,
            "previous_hash": "",
            "operation": "bootstrap",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=23)).isoformat(),
            "persons": {
                person: {
                    "active": True,
                    "identity_ids": [],
                    "account_ids": [],
                    "endpoint_ids": [],
                    "roles": [],
                    "authenticators": [],
                }
                for person in self.custodians
            },
            "custodians": {
                person: {"public_key": public(key), "active": True}
                for person, key in self.custodians.items()
            },
            "targets": {
                str(endpoint.pk): {
                    "scope": target_scope(endpoint),
                    "critical": False,
                    "contract_id": "",
                    "sponsor_person": "",
                    "min_reviewers": 1,
                }
                for endpoint in endpoints
            },
            "policy": {"standard_min": 1, "critical_min": 2},
        }
        self.people = {}
        for actor, identity, roles in people:
            OrganizationMembership.objects.get_or_create(
                organization=organization, account=actor, defaults={"role": "admin", "active": True}
            )
            person = str(uuid.uuid4())
            self.people[actor.pk] = person
            self.body["persons"][person] = {
                "active": True,
                "identity_ids": [str(identity.pk)],
                "account_ids": [str(actor.pk)],
                "endpoint_ids": list(self.body["targets"]),
                "roles": list(roles),
                "authenticators": [],
            }
        self.row = self.publish(self.body, bootstrap=True)
        self.checkpoint()
        for actor, _, _ in people:
            self.enroll(actor)

    def envelope(self, body, *, signers=None, commissioning=False):
        signers = signers or list(self.custodians)[:2]
        message = registry.signature_message(body)
        return {
            "body": deepcopy(body),
            "signatures": {
                person: auth.b64encode(self.custodians[person].sign(message)) for person in signers
            },
            "commissioning_signatures": {
                "commissioner": auth.b64encode(self.commissioner.sign(message))
            }
            if commissioning
            else {},
        }

    def publish(self, body, *, bootstrap=False):
        row = registry.publish_registry(
            self.envelope(body, commissioning=bootstrap), bootstrap=bootstrap
        )
        self.body, self.row = deepcopy(body), row
        return row

    def checkpoint(self, row=None):
        row = row or self.row
        now = timezone.now()
        body = {
            "format": registry.CHECKPOINT_FORMAT,
            "installation": "synthetic-isolated-installation",
            "organization": str(self.org.pk),
            "generation": str(row.generation),
            "revision": row.revision,
            "registry_hash": row.revision_hash,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=60)).isoformat(),
        }
        document = {
            "body": body,
            "key_id": "witness",
            "signature": auth.b64encode(self.witness.sign(registry.checkpoint_message(body))),
        }
        (Path(self.directory.name) / (str(self.org.pk) + ".json")).write_text(json.dumps(document))
        return document

    def next_body(self):
        body = deepcopy(self.body)
        body.update(
            revision=self.row.revision + 1,
            previous_hash=self.row.revision_hash,
            operation="update",
            issued_at=timezone.now().isoformat(),
        )
        return body

    def update(self, mutate):
        body = self.next_body()
        mutate(body)
        self.publish(body)
        self.checkpoint()
        return self.row

    def request(self, actor):
        if actor.pk not in self.requests:
            request = RequestFactory().post("/synthetic-test/")
            request.user, request.organization = actor, self.org
            SessionMiddleware(lambda r: None).process_request(request)
            request.session.save()
            self.requests[actor.pk] = request
        return self.requests[actor.pk]

    def enroll(self, actor):
        device = VirtualAuthenticator()
        request = self.request(actor)
        start = auth.begin_enrollment(request)
        possession = auth.finish_registration(
            request, start["challenge"], device.response(start, registration=True)
        )
        receipt = auth.finish_enrollment(
            request, possession["enrollment"], device.response(possession)
        )
        person = self.people[actor.pk]
        self.update(lambda body: body["persons"][person]["authenticators"].append(receipt))
        self.authenticators[actor.pk] = device
        return device

    def proof(self, actor, action, payload, request=None):
        request = request or self.request(actor)
        options = auth.begin_action(request, action, payload)
        result = auth.finish_action(
            request, options["challenge"], self.authenticators[actor.pk].response(options)
        )
        return result["proof"]

    @contextmanager
    def personal_action(self, actor, request=None):
        request = request or self.request(actor)
        original = auth.require_action

        def signed_action(actual_actor, organization, action, payload):
            token = self.proof(actual_actor, action, payload, request)
            request.POST = request.POST.copy()
            request.POST["_pam_trust_proof"] = token
            return original(actual_actor, organization, action, payload)

        with (
            auth.action_authentication(request),
            patch.object(auth, "require_action", signed_action),
        ):
            yield
