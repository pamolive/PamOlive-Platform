"""Fresh real synthetic signatures/registration only. No human/hardware claims.

Keys are generated in test RAM, never runtime defaults or persisted repository keys.
The P0 registration/possession evidence is independently verified here; this does
not execute Django's publish/consume enrollment SQL lifecycle.
"""

import copy
import hashlib
import ipaddress
import json
import secrets
from datetime import UTC, datetime
from uuid import UUID

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pamolive_usage_anchor.authority import Authority
from pamolive_usage_anchor.codec import b64, encode, materials_frame, sha
from pamolive_usage_anchor.slot import parse_slot
from pamolive_vault_contracts import OperationDraft, confirmation_challenge, p0_canonical
from webauthn import verify_authentication_response, verify_registration_response

RP = "confirm.pamolive.invalid"
ORIGIN = "https://" + RP


def uid(n):
    return str(UUID(int=n))


def utc(n):
    return datetime.fromtimestamp(n, UTC).isoformat(timespec="microseconds")


def raw_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def assertion(key, auth, challenge, *, count=0, spaced=False, client_raw=None):
    client = {"type": "webauthn.get", "challenge": b64(challenge), "origin": ORIGIN}
    if client_raw is None:
        client_raw = json.dumps(client, indent=2).encode() if spaced else raw_json(client)
    data = hashlib.sha256(RP.encode()).digest() + bytes([5]) + count.to_bytes(4, "big")
    signature = key.sign(data + hashlib.sha256(client_raw).digest())
    return {
        "id": auth["id"],
        "rawId": auth["id"],
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(client_raw),
            "authenticatorData": b64(data),
            "signature": b64(signature),
            "userHandle": None,
        },
    }


def enrolled(person, now, registry_hash):
    key = Ed25519PrivateKey.generate()
    credential = secrets.token_bytes(32)
    cose = cbor2.dumps({1: 1, 3: -8, -1: 6, -2: key.public_key().public_bytes_raw()})
    challenge = secrets.token_bytes(32)
    client = raw_json({"type": "webauthn.create", "challenge": b64(challenge), "origin": ORIGIN})
    data = (
        hashlib.sha256(RP.encode()).digest()
        + bytes([0x45])
        + bytes(4)
        + bytes(16)
        + len(credential).to_bytes(2, "big")
        + credential
        + cose
    )
    response = {
        "id": b64(credential),
        "rawId": b64(credential),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(client),
            "attestationObject": b64(cbor2.dumps({"fmt": "none", "authData": data, "attStmt": {}})),
        },
    }
    registration = verify_registration_response(
        credential=response,
        expected_challenge=challenge,
        expected_rp_id=RP,
        expected_origin=ORIGIN,
        require_user_presence=True,
        require_user_verification=True,
    )
    auth = {
        "id": b64(registration.credential_id),
        "public_key": b64(registration.credential_public_key),
        "rp_id": RP,
        "origin": ORIGIN,
        "active": True,
        "enrollment_id": uid(1000 + person),
    }
    # Exact P0 action-challenge/1 fields/canonical encoding, independent of Django.
    binding = {
        "schema": "pamolive.pam.action-challenge/1",
        "id": uid(2000 + person),
        "organization": uid(2),
        "account": uid(3000 + person),
        "person": uid(person),
        "action": "enrollment-possession",
        "payload_hash": sha(
            p0_canonical({"enrollment": auth["enrollment_id"], "public_key": auth["public_key"]})
        ),
        "session_hash": "f" * 64,
        "registry_hash": registry_hash,
        "registry_generation": uid(3),
        "registry_revision": 1,
        "policy_hash": sha(p0_canonical({"standard_min": 1, "critical_min": 2})),
        "credential_id": auth["id"],
        "public_key": auth["public_key"],
        "rp_id": RP,
        "origin": ORIGIN,
        "nonce": b64(secrets.token_bytes(32)),
        "expires_at": utc(now + 120),
    }
    possession_challenge = bytes.fromhex(sha(p0_canonical(binding)))
    possession = assertion(key, auth, possession_challenge)
    verify_authentication_response(
        credential=possession,
        expected_challenge=possession_challenge,
        expected_rp_id=RP,
        expected_origin=ORIGIN,
        credential_public_key=registration.credential_public_key,
        credential_current_sign_count=registration.sign_count,
        require_user_verification=True,
    )
    return key, auth, {"registration": response, "possession": possession, "binding": binding}


def certificate_authority(now):
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SYNTHETIC W1 CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.fromtimestamp(now - 100, UTC))
        .not_valid_after(datetime.fromtimestamp(now + 7200, UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, None)
    )
    return key, cert


def certificate(now, san, *, server=False, ca=None):
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SYNTHETIC W1")])
    names = (
        [
            x509.DNSName("witness.synthetic.invalid"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("10.253.249.3")),
        ]
        if server
        else [x509.UniformResourceIdentifier(san)]
    )
    issuer_key, issuer_cert = ca if ca is not None else (key, None)
    # Leaf SKI/AKI/KeyUsage support future strict OpenSSL qualification.
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.fromtimestamp(now - 100, UTC))
        .not_valid_after(datetime.fromtimestamp(now + 3600, UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), True
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
        .add_extension(x509.SubjectAlternativeName(names), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False
        )
        .sign(issuer_key, None)
    )
    return key, cert


class MemoryReader:
    """Test-only RO substitute; not POSIX/host isolation evidence."""

    def __init__(self, value):
        self.value = value

    def check(self):
        return self.value


class Fixture:
    def __init__(self, now=1800000000):
        self.now = now
        self.custodians = {uid(n): Ed25519PrivateKey.generate() for n in (10, 11, 12)}
        self.commissioner, self.cp_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        people = {
            p: {
                "active": True,
                "identity_ids": [],
                "account_ids": [],
                "endpoint_ids": [],
                "roles": [],
                "authenticators": [],
            }
            for p in self.custodians
        }
        # People/accounts are independently commissioned BEFORE enrollment. P0's
        # consume_enrollment resolves the person against this previous revision.
        for n in (20, 21, 22):
            people[uid(n)] = {
                "active": True,
                "identity_ids": [uid(4000 + n)],
                "account_ids": [uid(3000 + n)],
                "endpoint_ids": [uid(7)],
                "roles": ["requester"] if n == 20 else ["reviewer", "sponsor"],
                "authenticators": [],
            }
        body = {
            "format": "pamolive.pam.trust-registry/1",
            "installation": "opaque-P0",
            "organization": uid(2),
            "generation": uid(3),
            "revision": 1,
            "operation": "bootstrap",
            "previous_hash": "",
            "issued_at": utc(now - 10),
            "expires_at": utc(now + 3600),
            "persons": people,
            "custodians": {
                p: {"active": True, "public_key": b64(k.public_key().public_bytes_raw())}
                for p, k in self.custodians.items()
            },
            "targets": {},
            "policy": {"standard_min": 1, "critical_min": 2},
        }
        bootstrap = self.sign(body, commissioning=True)
        first_hash = self.registry_hash(bootstrap)
        self.keys, self.auths, self.enrollment_evidence = {}, {}, {}
        updated = copy.deepcopy(body)
        for n in (20, 21, 22):
            key, auth, evidence = enrolled(n, now, first_hash)
            self.keys[uid(n)], self.auths[uid(n)], self.enrollment_evidence[uid(n)] = (
                key,
                auth,
                evidence,
            )
            updated["persons"][uid(n)] = {
                "active": True,
                "identity_ids": [uid(4000 + n)],
                "account_ids": [uid(3000 + n)],
                "endpoint_ids": [uid(7)],
                "roles": ["requester"] if n == 20 else ["reviewer", "sponsor"],
                "authenticators": [auth],
            }
        self.scope = {
            "organization": uid(2),
            "endpoint": uid(7),
            "epoch": 1,
            "resource": uid(8),
            "account": uid(9),
            "username": "synthetic",
            "protocol": "ssh",
            "hostname": "target.synthetic.invalid",
            "port": 22,
            "domain": "",
            "auth_method": "password",
            "fingerprint": "SHA256:SYNTHETIC-PIN",
        }
        self.intent = {
            "schema": "pamolive.vault.synthetic-intent/1",
            "intent_id": uid(6),
            "organization_id": uid(2),
            "requester_person_id": uid(20),
            "target_id": uid(7),
            "destination_scope_hash": sha(p0_canonical(self.scope)),
            "purpose": "synthetic-no-release-validation",
            "not_before": now,
            "expires_at": now + 300,
        }
        updated.update(
            revision=2, operation="update", previous_hash=first_hash, issued_at=utc(now - 9)
        )
        updated["targets"] = {
            uid(7): {
                "scope": self.scope,
                "critical": True,
                "min_reviewers": 1,
                "sponsor_person": uid(21),
                "contract_id": "",
            }
        }
        head = self.sign(updated)
        self.head = head
        registry_hash = self.registry_hash(head)
        cpbody = {
            "format": "pamolive.pam.trust-checkpoint/1",
            "installation": "opaque-P0",
            "organization": uid(2),
            "generation": uid(3),
            "revision": 2,
            "registry_hash": registry_hash,
            "issued_at": utc(now),
            "expires_at": utc(now + 40),
        }
        cp = {
            "body": cpbody,
            "key_id": "cp",
            "signature": b64(
                self.cp_key.sign(b"pamolive.pam.trust-checkpoint.v1\0" + p0_canonical(cpbody))
            ),
        }
        self.materials = materials_frame((raw_json(bootstrap), raw_json(head)), raw_json(cp))
        self.ca_key, self.ca_cert = certificate_authority(now)
        ca = (self.ca_key, self.ca_cert)
        self.vault_key, self.vault_cert = certificate(now, "urn:pamolive:vault:w1", ca=ca)
        self.activation_key, self.activation_cert = certificate(
            now, "urn:pamolive:activation:w1", ca=ca
        )
        self.broker_key, self.broker_cert = certificate(now, "urn:pamolive:broker:w1", ca=ca)
        self.server_key, self.server_cert = certificate(now, "", server=True, ca=ca)
        self.vault_der = self.vault_cert.public_bytes(serialization.Encoding.DER)
        self.activation_der = self.activation_cert.public_bytes(serialization.Encoding.DER)
        broker_der = self.broker_cert.public_bytes(serialization.Encoding.DER)
        self.draft = OperationDraft(
            installation_id=uid(1),
            organization_id=uid(2),
            trust_generation=uid(3),
            ledger_incarnation=uid(4),
            request_id=uid(60),
            idempotency_key=uid(61),
            session_id=uid(62),
            broker_instance_id=uid(63),
            requester_person_id=uid(20),
            approver_person_ids=(uid(21), uid(22)),
            sponsor_person_id=uid(21),
            requested_caller_service_id="broker-w1",
            broker_service_id="broker-w1",
            vault_service_id="vault-w1",
            broker_certificate_sha256=sha(broker_der),
            intent_id=uid(6),
            intent_scope_hash=sha(encode(self.intent, 4096)),
            policy_revision=uid(5),
            policy_hash=sha(p0_canonical(body["policy"])),
            registry_revision=2,
            registry_hash=registry_hash,
            checkpoint_hash=sha(raw_json(cp)),
            authority_materials_sha256=sha(self.materials),
            target_id=uid(7),
            destination_epoch=1,
            destination_scope_hash=sha(p0_canonical(self.scope)),
            credential_secret_id=uid(80),
            credential_version=1,
            wrapping_revision=1,
        )
        from pamolive_vault_runtime.slot import EXPECTED_FIELDS

        expected = {k: getattr(self.draft, k) for k in EXPECTED_FIELDS}

        def external(key_id, key):
            return {
                "key_id": key_id,
                "public_key_hex": key.public_key().public_bytes_raw().hex(),
                "active": True,
                "not_before": utc(now - 100),
                "not_after": utc(now + 3600),
                "revoked_at": "",
            }

        def principal(service, instance, der, san, audience):
            return {
                "service_id": service,
                "instance_id": uid(instance),
                "certificate_sha256": [sha(der)],
                "san_uri": san,
                "audience": audience,
            }

        self.slot_value = {
            "schema": "pamolive.usage-anchor.slot/1",
            "context_id": uid(90),
            "witness_incarnation": uid(91),
            "installation_p0": "opaque-P0",
            "intent_requester_person_id": self.intent["requester_person_id"],
            "expectations": expected,
            "commissioning_keys": [external("commissioner", self.commissioner)],
            "checkpoint_keys": [external("cp", self.cp_key)],
            "principals": [
                principal(
                    "vault-w1", 50, self.vault_der, "urn:pamolive:vault:w1", "usage-anchor.vault/1"
                ),
                principal(
                    "activation-w1",
                    51,
                    self.activation_der,
                    "urn:pamolive:activation:w1",
                    "usage-anchor.activation/1",
                ),
            ],
            "credentials": {p: a["id"] for p, a in self.auths.items()},
            "lease_epoch": 1,
            "minimum_reviewers": 1,
            "allow_zero": True,
            "not_before": now - 10,
            "not_after": now + 3600,
            "quota": 64,
            "quota_bytes": 64 * 1024 * 1024,
            "broker": {
                "service_id": "broker-w1",
                "instance_id": uid(63),
                "certificate_sha256": sha(broker_der),
            },
        }
        self.slot_raw = encode(self.slot_value, 65536, special=True)
        self.slot = parse_slot(self.slot_raw, sha(self.slot_raw))
        self.guard = MemoryReader(self.slot)
        self.authority = Authority(self.guard, MemoryReader(self.materials))

    def sign(self, body, commissioning=False):
        message = b"pamolive.pam.trust-registry.v1\0" + p0_canonical(body)
        return {
            "body": body,
            "signatures": {
                p: b64(self.custodians[p].sign(message)) for p in sorted(self.custodians)[:2]
            },
            "commissioning_signatures": {"commissioner": b64(self.commissioner.sign(message))}
            if commissioning
            else {},
        }

    @staticmethod
    def registry_hash(envelope):
        return sha(b"pamolive.pam.trust-registry.v1\0" + p0_canonical(envelope))

    def final_bundle(self, transcript, operation_id, *, negative=False, count=0, spaced=False):
        roles = (
            [(uid(21), "reviewer", "refuse")]
            if negative
            else [
                (uid(20), "requester", "launch"),
                (uid(21), "reviewer", "approve"),
                (uid(21), "sponsor", "sponsor"),
                (uid(22), "reviewer", "approve"),
            ]
        )
        entries = []
        increments = {}
        for person, role, decision in roles:
            n = count + increments.get(person, 0) if count else 0
            increments[person] = increments.get(person, 0) + 1
            challenge = confirmation_challenge(
                transcript, person_id=person, role=role, decision=decision
            )
            raw = encode(
                assertion(self.keys[person], self.auths[person], challenge, count=n, spaced=spaced),
                65536,
                depth=4,
                nodes=64,
                string=12000,
                special=True,
            )
            entries.append(
                {
                    "person_id": person,
                    "role": role,
                    "decision": decision,
                    "credential_id": self.auths[person]["id"],
                    "assertion_b64": b64(raw),
                }
            )
        return encode(
            {
                "schema": "pamolive.vault.final-proof-bundle/1",
                "operation_id": operation_id,
                "body_hash": __import__("pamolive_vault_contracts").body_hash(transcript),
                "assertions": entries,
            },
            2097152,
            string=90000,
        )
