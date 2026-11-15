"""PUBLIC deterministic test keys ONLY. No fixture is a commissioned authority.

Private key objects exist only in pure test memory; these public reproducible
seeds MUST NEVER be used outside synthetic tests. No TLS handshake is mocked
into a claim of authentication: tests exercise only DER metadata and the bridge.
"""

import base64
import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pamolive_vault_contracts import OperationDraft, p0_canonical
from pamolive_vault_runtime.admission import utc_text
from pamolive_vault_runtime.bounded import sha
from pamolive_vault_runtime.slot import parse_slot

NOW = 1800000000


def uid(number):
    return str(UUID(int=number))


def key(label):
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(("PUBLIC TEST ONLY " + label).encode()).digest()
    )


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def certificate(
    *,
    serial=1,
    before=NOW - 100,
    after=NOW + 100,
    san="urn:pamolive:broker:lab",
    eku=ExtendedKeyUsageOID.CLIENT_AUTH,
    ca=False,
):
    private = key("broker certificate")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PUBLIC SYNTHETIC TEST")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.fromtimestamp(before, UTC))
        .not_valid_after(datetime.fromtimestamp(after, UTC))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]), critical=False
        )
        .sign(private, algorithm=None)
        .public_bytes(serialization.Encoding.DER)
    )


class Guard:
    """Pure substitute for the POSIX RO guard; never a real filesystem/TLS/SQL proof."""

    def __init__(self, slot):
        self.slot, self.checks = slot, 0

    def check(self):
        self.checks += 1
        return self.slot


class Fixture:
    def __init__(self, *, now=NOW, der=None):
        # Explicit synthetic lab preparation only. Runtime never imports these seeds.
        self.der = der if der is not None else certificate(before=now - 100, after=now + 100)
        people = [uid(i) for i in (10, 11, 12)]
        custody = {person: key(person) for person in people}
        commissioner, checkpoint = key("commissioner"), key("checkpoint")
        body = {
            "format": "pamolive.pam.trust-registry/1",
            "installation": "opaque-É-P0",
            "organization": uid(2),
            "generation": uid(3),
            "revision": 1,
            "operation": "bootstrap",
            "previous_hash": "",
            "issued_at": utc_text(now - 60),
            "expires_at": utc_text(now + 3600),
            "persons": {
                person: {
                    "active": True,
                    "identity_ids": [],
                    "account_ids": [],
                    "endpoint_ids": [],
                    "roles": [],
                    "authenticators": [],
                }
                for person in people
            },
            "custodians": {
                person: {"active": True, "public_key": b64(private.public_key().public_bytes_raw())}
                for person, private in custody.items()
            },
            "targets": {},
            "policy": {"standard_min": 2, "critical_min": 3},
        }
        message = b"pamolive.pam.trust-registry.v1\0" + p0_canonical(body)
        self.envelope = {
            "body": body,
            "signatures": {person: b64(custody[person].sign(message)) for person in people[:2]},
            "commissioning_signatures": {"commissioner": b64(commissioner.sign(message))},
        }
        registry_hash = sha(b"pamolive.pam.trust-registry.v1\0" + p0_canonical(self.envelope))
        cp = {
            "format": "pamolive.pam.trust-checkpoint/1",
            "installation": body["installation"],
            "organization": uid(2),
            "generation": uid(3),
            "revision": 1,
            "registry_hash": registry_hash,
            "issued_at": utc_text(now - 1),
            "expires_at": utc_text(now + 40),
        }
        self.checkpoint = {
            "body": cp,
            "key_id": "checkpoint",
            "signature": b64(
                checkpoint.sign(b"pamolive.pam.trust-checkpoint.v1\0" + p0_canonical(cp))
            ),
        }
        self.expected = {
            "installation_id": uid(1),
            "organization_id": uid(2),
            "trust_generation": uid(3),
            "ledger_incarnation": uid(4),
            "vault_service_id": "vault-lab",
            "policy_revision": uid(5),
            "policy_hash": "1" * 64,
            "registry_revision": 1,
            "registry_hash": registry_hash,
            "checkpoint_hash": sha(encode(self.checkpoint)),
            "authority_materials_sha256": "5" * 64,  # OPAQUE administrative test reference only.
            "intent_id": uid(6),
            "intent_scope_hash": "6" * 64,
            "target_id": uid(7),
            "destination_epoch": 1,
            "destination_scope_hash": "7" * 64,
            "credential_secret_id": uid(8),
            "credential_version": 1,
            "wrapping_revision": 1,
        }
        self.draft = OperationDraft(
            **self.expected,
            request_id=uid(100),
            idempotency_key=uid(101),
            session_id=uid(102),
            broker_instance_id=uid(103),
            requester_person_id=uid(10),
            approver_person_ids=(uid(11),),
            sponsor_person_id="",
            requested_caller_service_id="broker-lab",
            broker_service_id="broker-lab",
            broker_certificate_sha256=sha(self.der),
        )

        def public_row(name, private):
            return {
                "key_id": name,
                "public_key_hex": private.public_key().public_bytes_raw().hex(),
                "active": True,
                "not_before": utc_text(now - 1000),
                "not_after": utc_text(now + 10000),
                "revoked_at": "",
            }

        self.config = {
            "schema": "pamolive.vault.local-reservation-slot/1",
            "slot_id": uid(200),
            "serving_state": "open",
            "installation_p0": body["installation"],
            "expectations": self.expected,
            "commissioning_keys": [public_row("commissioner", commissioner)],
            "checkpoint_keys": [public_row("checkpoint", checkpoint)],
            "principals": [
                {
                    "service_id": "broker-lab",
                    "broker_instance_id": uid(103),
                    "certificate_sha256": [sha(self.der)],
                    "san_uri": "urn:pamolive:broker:lab",
                }
            ],
            "not_before": now - 10,
            "not_after": now + 1000,
            "quota": 2,
            "registry_max_seconds": 86400,
            "checkpoint_max_seconds": 60,
        }
        self.refresh()

    def refresh(self):
        self.config_raw = encode(self.config)
        self.slot = parse_slot(self.config_raw, sha(self.config_raw))
        self.guard = Guard(self.slot)

    def request(self, draft=None):
        from pamolive_vault_contracts import serialize_draft

        return encode(
            {
                "draft": json.loads(serialize_draft(draft or self.draft)),
                "registry_chain": [b64(encode(self.envelope))],
                "checkpoint": b64(encode(self.checkpoint)),
            }
        )
