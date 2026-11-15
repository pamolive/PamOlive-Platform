"""Server-owned context and real V1 verification, followed by pending-only reservation."""

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from pamolive_pam_trust_verifier import InvalidMaterials, verify_current_registry_materials
from pamolive_vault_contracts.canonical import ContractError, canonical_v2
from pamolive_vault_contracts.contracts import draft_hash, parse_draft, serialize_draft

from .bounded import Refusal, b64decode, closed, json_object, need, sha

MAX_REQUEST = 3 * 1024**2
MAX_MATERIALS = 2 * 1024**2


def utc_text(now):
    need(type(now) is int and 1 <= now <= 253402300799, "unavailable", 503)
    return datetime.fromtimestamp(now, UTC).isoformat(timespec="microseconds")


def epoch(value):
    parsed = datetime.fromisoformat(value)
    need(parsed.tzinfo is not None, "context_refused", 403)
    return int(parsed.timestamp())  # Round expiry DOWN, never extend it.


@dataclass(frozen=True, slots=True)
class Peer:
    service_id: str
    broker_instance_id: str
    certificate_sha256: str
    expires_at: int


def authenticate(der, slot, now):
    """DER is supplied only by the per-connection TLS adapter; never by JSON/header."""
    need(type(der) is bytes and 0 < len(der) <= 16384, "caller_refused", 403)
    fingerprint = sha(der)
    matches = [p for p in slot.principals if fingerprint in p.certificate_sha256]
    need(len(matches) == 1, "caller_refused", 403)
    principal = matches[0]
    cert = x509.load_der_x509_certificate(der)
    need(
        cert.not_valid_before_utc.timestamp() <= now < cert.not_valid_after_utc.timestamp(),
        "caller_refused",
        403,
    )
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    need(
        not constraints.ca and list(usages) == [ExtendedKeyUsageOID.CLIENT_AUTH],
        "caller_refused",
        403,
    )
    need(
        len(names) == 1
        and names.get_values_for_type(x509.UniformResourceIdentifier) == [principal.san_uri],
        "caller_refused",
        403,
    )
    return Peer(
        principal.service_id,
        principal.broker_instance_id,
        fingerprint,
        int(cert.not_valid_after_utc.timestamp()),
    )


class Reservations:
    """Host-owned assembly. No public JSON boolean can substitute for its dependencies."""

    def __init__(self, slot_guard, ledger, clock=None):
        self.slot_guard, self.ledger = slot_guard, ledger
        self.clock = clock or (lambda: int(time.time()))

    def prepare(self, raw, peer_der):
        try:
            return self._prepare(raw, peer_der)
        except Refusal as error:
            code, status = error.code, error.status
        except InvalidMaterials:
            code, status = "context_refused", 403
        except (ContractError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            code, status = "invalid_request", 400
        except Exception:
            code, status = "unavailable", 503
        # Outside the handler: a public exception must not retain private parser/SQL context.
        raise Refusal(code, status)

    def _prepare(self, raw, peer_der):
        # Take immutable request buffers once; no caller mapping is reused after checks.
        need(type(raw) is bytes and type(peer_der) is bytes)
        value = json_object(raw, MAX_REQUEST)
        closed(value, {"draft", "registry_chain", "checkpoint"})
        draft = parse_draft(canonical_v2(value["draft"], 16384))
        rows = value["registry_chain"]
        need(type(rows) is list and 1 <= len(rows) <= 16)
        encoded = (*rows, value["checkpoint"])
        need(all(type(item) is str for item in encoded))
        need(sum((len(item) * 3) // 4 for item in encoded) <= MAX_MATERIALS)
        chain = tuple(b64decode(item, MAX_MATERIALS) for item in rows)
        checkpoint = b64decode(value["checkpoint"], 65536)
        need(sum(map(len, chain)) + len(checkpoint) <= MAX_MATERIALS)
        original_slot = self.slot_guard.check()

        def recheck():
            slot = self.slot_guard.check()
            need(slot == original_slot, "context_refused", 403)
            now = self.clock()
            utc = utc_text(now)
            need(slot.not_before <= now < slot.not_after, "context_refused", 403)
            peer = authenticate(peer_der, slot, now)  # Revalidated for every request AND precommit.
            for name, expected in slot.expectations:
                need(getattr(draft, name) == expected, "context_refused", 403)
            need(
                draft.broker_service_id == draft.requested_caller_service_id == peer.service_id
                and draft.broker_instance_id == peer.broker_instance_id
                and draft.broker_certificate_sha256 == peer.certificate_sha256,
                "caller_refused",
                403,
            )
            current = verify_current_registry_materials(chain, checkpoint, slot.context(utc))
            need(current.checkpoint_sha256 == draft.checkpoint_hash, "context_refused", 403)
            # These are VERIFIED V1 bytes, not a new materials-assembly hash or permission.
            head = json.loads(current.canonical_head_envelope)["body"]
            cp_envelope = json.loads(current.canonical_checkpoint)
            cp = cp_envelope["body"]
            keys = [key for key in slot.checkpoint_keys if key.key_id == cp_envelope["key_id"]]
            need(len(keys) == 1, "context_refused", 403)
            key = keys[0]
            need(
                key.active
                and epoch(key.not_before) <= now < epoch(key.not_after)
                and (not key.revoked_at or now < epoch(key.revoked_at)),
                "context_refused",
                403,
            )
            end = min(
                slot.not_after,
                peer.expires_at,
                epoch(head["expires_at"]),
                epoch(cp["expires_at"]),
                epoch(key.not_after),
            )
            need(now < end, "context_refused", 403)
            return now, end, peer, slot

        now, end, peer, slot = recheck()
        # No hash for undefined materials assembly: only independent opaque equality above.
        return self.ledger.reserve(
            slot=slot,
            peer=peer,
            draft=draft,
            canonical_draft=serialize_draft(draft),
            draft_sha256=draft_hash(draft),
            now=now,
            end=min(now + 30, end),
            recheck=recheck,
        )
