"""Synthetic HA commissioning; real signatures, never a production trust service.

The host retains all signing/authenticator private keys; application containers
mount only public checkpoints read-only. Software keys do not model real people.
"""

import base64
import hashlib
import importlib
import json
import os
import re
import secrets
import sys
import tempfile
import time
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

INSTALLATION = "synthetic-ha-qualification"
RP = "ha.pamolive.test"
ORIGIN = "https://" + RP
CHECKPOINT_TARGET = "/tmp/pamolive-ha-public-checkpoints"


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decoded(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def public(key):
    from cryptography.hazmat.primitives import serialization

    return encoded(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ))


def canonical(body):
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class QualificationAuthority:
    """Ephemeral host-side commissioners/custodians and monotonic witness."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        # Fail before any container start, without silently installing tools.
        importlib.import_module("cbor2")
        self.temporary = tempfile.TemporaryDirectory(prefix="pamolive-ha-public-trust-")
        self.directory = Path(self.temporary.name) / "checkpoints"
        self.directory.mkdir(mode=0o755)
        self.keys, self.heads, self.authenticators = {}, {}, {}
        for _ in range(2):
            self.keys[str(uuid.uuid4())] = {
                "generation": str(uuid.uuid4()),
                "commissioner": Ed25519PrivateKey.generate(),
                "witness": Ed25519PrivateKey.generate(),
                "custodians": {str(uuid.uuid4()): Ed25519PrivateKey.generate() for _ in range(3)},
            }

    def settings(self):
        return {
            "PAM_TRUST_INSTALLATION_ID": INSTALLATION,
            "PAM_TRUST_RP_ID": RP,
            "PAM_TRUST_ORIGIN": ORIGIN,
            "PAM_TRUST_CHECKPOINT_DIRECTORY": CHECKPOINT_TARGET,
            "PAM_TRUST_COMMISSIONING_KEYS": json.dumps({
                org: {"commissioner": public(keys["commissioner"])}
                for org, keys in self.keys.items()
            }),
            "PAM_TRUST_CHECKPOINT_KEYS": json.dumps({
                org: {"witness": public(keys["witness"])} for org, keys in self.keys.items()
            }),
        }

    def commissioning(self, organization):
        keys = self.keys[organization]
        return {
            "generation": keys["generation"],
            "custodians": {person: public(key) for person, key in keys["custodians"].items()},
        }

    def sign_registry(self, organization, body):
        keys = self.keys[organization]
        if (body["organization"] != organization or body["generation"] != keys["generation"]
                or body["installation"] != INSTALLATION):
            raise RuntimeError("Refusing another synthetic commissioning scope.")
        message = b"pamolive.pam.trust-registry.v1\0" + canonical(body)
        return {
            "body": body,
            "signatures": {person: encoded(key.sign(message))
                           for person, key in list(keys["custodians"].items())[:2]},
            "commissioning_signatures": {
                "commissioner": encoded(keys["commissioner"].sign(message))
            } if body["operation"] == "bootstrap" else {},
        }

    def authenticate(self, organization, report):
        if organization not in self.keys:
            raise RuntimeError("Unknown synthetic authenticator organization.")
        key = (organization, str(report["account"]))
        if key not in self.authenticators:
            self.authenticators[key] = SoftwareAuthenticator()
        return self.authenticators[key].response(
            report["options"], registration=report.get("registration") is True,
        )

    def checkpoint(self, head):
        if (set(head) != {"organization", "generation", "revision", "registry_hash"}
                or type(head["revision"]) is not int or head["revision"] < 1
                or not re.fullmatch(r"[a-f0-9]{64}", head.get("registry_hash", ""))):
            raise RuntimeError("Invalid synthetic registry checkpoint head.")
        org = head["organization"]
        if org not in self.keys or head["generation"] != self.keys[org]["generation"]:
            raise RuntimeError("Unexpected synthetic trust generation.")
        previous = self.heads.get(org)
        if previous and (
            head["revision"] < previous["revision"]
            or (head["revision"] == previous["revision"]
                and head["registry_hash"] != previous["registry_hash"])
        ):
            raise RuntimeError("Synthetic witness refuses registry rollback.")
        self.heads[org] = dict(head)
        now = datetime.now(timezone.utc)  # noqa: UP017 - qualification host supports Python 3.8
        body = {
            "format": "pamolive.pam.trust-checkpoint/1", "installation": INSTALLATION,
            **head, "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=60)).isoformat(),
        }
        document = {
            "body": body, "key_id": "witness",
            "signature": encoded(self.keys[org]["witness"].sign(
                b"pamolive.pam.trust-checkpoint.v1\0" + canonical(body)
            )),
        }
        temporary = self.directory / (org + ".next")
        temporary.write_text(json.dumps(document), encoding="utf-8")
        temporary.chmod(0o644)
        temporary.replace(self.directory / (org + ".json"))
        return document

    def close(self):
        self.temporary.cleanup()


class SoftwareAuthenticator:
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        self.private = ec.generate_private_key(ec.SECP256R1())
        self.raw_id = secrets.token_bytes(32)
        self.id = encoded(self.raw_id)

    def response(self, options, *, registration=False):
        import cbor2
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        client = json.dumps({
            "type": "webauthn.create" if registration else "webauthn.get",
            "challenge": options["publicKey"]["challenge"], "origin": ORIGIN,
            "crossOrigin": False,
        }).encode()
        data = hashlib.sha256(RP.encode()).digest() + bytes([69 if registration else 5]) + bytes(4)
        response = {"clientDataJSON": encoded(client)}
        if registration:
            point = self.private.public_key().public_numbers()
            cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: point.x.to_bytes(32, "big"),
                                -3: point.y.to_bytes(32, "big")})
            data += bytes(16) + len(self.raw_id).to_bytes(2, "big") + self.raw_id + cose
            response["attestationObject"] = encoded(cbor2.dumps(
                {"fmt": "none", "attStmt": {}, "authData": data}
            ))
            response["transports"] = ["internal"]
        else:
            response.update(authenticatorData=encoded(data), userHandle=None,
                            signature=encoded(self.private.sign(
                                data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
                            )))
        return {"id": self.id, "rawId": self.id, "type": "public-key", "response": response}


class RemoteAuthenticator:
    """Private orchestration RPC: no authenticator private key enters a server."""

    def __init__(self, document):
        self.account = str(document["account"])

    def document(self):
        return {"account": self.account}

    def response(self, options, *, registration=False):
        print(json.dumps({"stage": "trust-authenticate", "account": self.account,
                          "options": options, "registration": registration}), flush=True)
        return json.loads(sys.stdin.readline(1024 * 1024))


class CommissionedFixture:
    def __init__(self, organization, endpoint, people, authority, *, browser_session):
        from django.contrib.sessions.backends.db import SessionStore
        from django.utils import timezone

        from platform_modules.pam import trust_auth as auth
        from platform_modules.pam import trust_registry as registry
        from platform_modules.pam.target_binding import target_scope

        from .active_active_fixture import require_test_database

        require_test_database()
        self.org = organization
        self.custodians = authority["custodians"]
        self.requests, self.devices = {}, {}
        now = timezone.now()
        body = {
            "format": registry.REGISTRY_FORMAT, "installation": INSTALLATION,
            "organization": str(organization.pk), "generation": authority["generation"],
            "revision": 1, "previous_hash": "", "operation": "bootstrap",
            "issued_at": now.isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
            "persons": {person: {"active": True, "identity_ids": [], "account_ids": [],
                                  "endpoint_ids": [], "roles": [], "authenticators": []}
                        for person in self.custodians},
            "custodians": {person: {"public_key": key, "active": True}
                           for person, key in self.custodians.items()},
            "targets": {str(endpoint.pk): {"scope": target_scope(endpoint), "critical": False,
                        "contract_id": "", "sponsor_person": "", "min_reviewers": 1}},
            "policy": {"standard_min": 1, "critical_min": 2},
        }
        persons = {}
        for index, (actor, identity, roles) in enumerate(people):
            person = str(uuid.uuid4())
            persons[actor.pk] = person
            body["persons"][person] = {
                "active": True, "identity_ids": [str(identity.pk)],
                "account_ids": [str(actor.pk)], "endpoint_ids": [str(endpoint.pk)],
                "roles": roles, "authenticators": [],
            }
            session = SessionStore(session_key=browser_session) if index == 0 else SessionStore()
            if not session.session_key:
                session.create()
            self.requests[actor.pk] = SimpleNamespace(
                user=actor, organization=organization, session=session, POST={}, headers={},
            )
        self.publish(body, bootstrap=True)
        for actor, _, _ in people:
            request, device = self.requests[actor.pk], RemoteAuthenticator({"account": actor.pk})
            started = auth.begin_enrollment(request)
            possession = auth.finish_registration(
                request, started["challenge"], device.response(started, registration=True)
            )
            receipt = auth.finish_enrollment(
                request, possession["enrollment"], device.response(possession)
            )
            body = deepcopy(self.row.body)
            body.update(revision=self.row.revision + 1, previous_hash=self.row.revision_hash,
                        operation="update", issued_at=timezone.now().isoformat())
            body["persons"][persons[actor.pk]]["authenticators"].append(receipt)
            self.publish(body)
            self.devices[actor.pk] = device

    def publish(self, body, *, bootstrap=False):
        from platform_modules.pam import trust_registry as registry

        # A private orchestration pipe, never a Web endpoint. Signing keys stay
        # outside both application containers; only the public envelope returns.
        print(json.dumps({"stage": "trust-sign", "body": body}), flush=True)
        envelope = json.loads(sys.stdin.readline(2 * 1024 * 1024))
        if envelope.get("body") != body:
            raise RuntimeError("The host signed another synthetic registry body.")
        self.row = registry.publish_registry(envelope, bootstrap=bootstrap)
        # The host witness observes committed DB heads and publishes a signed
        # checkpoint through the read-only directory. No verifier is overridden.
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                if registry.recognized_registry(self.org).pk == self.row.pk:
                    return
            except registry.TrustError:
                pass
            time.sleep(0.1)
        raise RuntimeError("The external synthetic witness did not acknowledge the trust head.")

    def perform(self, actor, operation):
        from platform_modules.pam import trust_auth as auth

        request = self.requests[actor.pk]
        request.POST = {}
        with auth.action_authentication(request):
            try:
                return operation()
            except auth.PAMActionRequired as required:
                action, payload = required.action, required.payload
        options = auth.begin_action(request, action, payload)
        proof = auth.finish_action(request, options["challenge"], self.devices[actor.pk].response(
            options
        ))
        request.POST = {"_pam_trust_proof": proof["proof"]}
        with auth.action_authentication(request):
            return operation()


def snapshots(organizations):
    from platform_modules.pam.trust_models import PAMTrustRevision

    from .active_active_fixture import require_test_database

    require_test_database()
    result = []
    for organization in organizations:
        if str(uuid.UUID(organization)) != organization:
            raise ValueError("Invalid synthetic organization.")
        row = PAMTrustRevision.unscoped.filter(organization_id=organization).order_by(
            "-revision"
        ).first()
        if row:
            result.append({"organization": organization, "generation": str(row.generation),
                           "revision": row.revision, "registry_hash": row.revision_hash})
    return result


def main():
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    django.setup()
    value = json.loads(sys.stdin.readline(4096))
    print(json.dumps(snapshots(value["organizations"])))


if __name__ == "__main__":
    main()
