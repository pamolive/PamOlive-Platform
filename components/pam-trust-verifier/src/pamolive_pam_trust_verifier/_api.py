"""Whole-history V1 material inspections. No storage or business authority."""

import hashlib
from dataclasses import dataclass, fields
from datetime import timedelta

from ._codec import CHECKPOINT_BYTES, canonical, chain_input, fail, parse, public_call
from ._context import CurrentContext, HistoricalContext, external_key, timestamp, validate_context
from ._crypto import decode, verify
from ._v1_rules import _affected_people, _preserve_people, _remember_owners, _validate_body

REGISTRY_DOMAIN = b"pamolive.pam.trust-registry.v1\0"
CHECKPOINT_DOMAIN = b"pamolive.pam.trust-checkpoint.v1\0"
PROFILE = "pamolive.public-pam-v1-bounded/1"


def _digest_document(envelope):
    return {
        "body": envelope["body"],
        "signatures": envelope.get("signatures", {}),
        "commissioning_signatures": envelope.get("commissioning_signatures", {}),
    }


def digest(envelope):
    return hashlib.sha256(REGISTRY_DOMAIN + canonical(_digest_document(envelope))).hexdigest()


def _transition(envelope, previous, context):
    if type(envelope) is not dict or set(envelope) - {
        "body",
        "signatures",
        "commissioning_signatures",
    }:
        fail()
    body = envelope.get("body")
    issued, expires = _validate_body(body, context)
    signatures, commissioning = (
        envelope.get("signatures", {}),
        envelope.get("commissioning_signatures", {}),
    )
    if type(signatures) is not dict or type(commissioning) is not dict:
        fail()
    operation = body["operation"]
    if previous is None:
        if operation != "bootstrap" or body["revision"] != 1 or body.get("previous_hash") != "":
            fail()
    elif (
        body["revision"] != previous["body"]["revision"] + 1
        or body.get("previous_hash") != digest(previous)
        or issued < timestamp(previous["body"]["issued_at"])
    ):
        fail()
    message = REGISTRY_DOMAIN + canonical(body)
    if operation == "update":
        if (
            previous is None
            or body["generation"] != previous["body"]["generation"]
            or commissioning
        ):
            fail()
        _preserve_people(previous["body"], body)
        eligible = {
            person
            for person, value in previous["body"]["custodians"].items()
            if value["active"] and previous["body"]["persons"][person]["active"]
        }
        eligible -= _affected_people(previous["body"], body)
        custody = previous["body"]["custodians"]
    else:
        if previous and (
            operation != "recommission" or body["generation"] == previous["body"]["generation"]
        ):
            fail()
        if (
            any(person.get("authenticators") for person in body["persons"].values())
            or not commissioning
        ):
            fail()
        for key_id, signature in commissioning.items():
            verify(
                external_key(context.commissioning_keys, key_id, issued, historical=True),
                signature,
                message,
            )
        custody = body["custodians"]
        eligible = {person for person, value in custody.items() if value["active"]}
    if len(signatures) < 2 or not set(signatures) <= eligible:
        fail()
    for person, signature in signatures.items():
        verify(decode(custody[person]["public_key"], length=32), signature, message)
    return issued, expires


def _context_hash(context):
    values = {
        name: getattr(context, name)
        for name in ("installation", "organization", "generation", "revision", "registry_hash")
    }
    for authority in ("commissioning_keys", "checkpoint_keys"):
        if hasattr(context, authority):
            values[authority] = [
                {
                    "key_id": key.key_id,
                    "public_key_hex": key.public_key.hex(),
                    "active": key.active,
                    "not_before": key.not_before,
                    "not_after": key.not_after,
                    "revoked_at": key.revoked_at,
                }
                for key in getattr(context, authority)
            ]
    if type(context) is CurrentContext:
        values.update(
            now_utc=context.now_utc,
            registry_max_seconds=context.registry_max_seconds,
            checkpoint_max_seconds=context.checkpoint_max_seconds,
        )
    return hashlib.sha256(
        b"pamolive.public-pam-context-fingerprint.v1\0" + canonical(values)
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class HistoricalRegistry:
    profile: str
    installation: str
    organization: str
    generation: str
    revision: int
    registry_hash: str
    context_fingerprint: str
    input_sha256: tuple[str, ...]
    envelope_commitments: tuple[str, ...]
    canonical_head_envelope: bytes
    owner_counts: tuple[tuple[str, int], ...]

    def __post_init__(self):
        public_call(_result_shape, self)


@dataclass(frozen=True, slots=True)
class CurrentRegistry:
    profile: str
    installation: str
    organization: str
    generation: str
    revision: int
    registry_hash: str
    context_fingerprint: str
    input_sha256: tuple[str, ...]
    envelope_commitments: tuple[str, ...]
    canonical_head_envelope: bytes
    owner_counts: tuple[tuple[str, int], ...]
    checkpoint_sha256: str
    canonical_checkpoint: bytes
    checked_at_utc: str

    def __post_init__(self):
        public_call(_result_shape, self)


def _result_shape(result):
    pending = [(getattr(result, field.name), 1) for field in fields(result)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > 8192 or depth > 16:
            fail()
        if type(value) is tuple:
            if len(value) > 256 or nodes + len(pending) + len(value) > 8192:
                fail()
            pending.extend((child, depth + 1) for child in value)
        elif type(value) is bytes:
            if len(value) > 2 * 1024 * 1024:
                fail()
        elif type(value) is str:
            if len(value) > 65536:
                fail()
        elif type(value) is int:
            if value < 0 or value > (1 << 63) - 1:
                fail()
        else:
            fail()


def _history(raw, context):
    chain_input(raw)
    previous = None
    owners = ({}, {}, {}, {}, {})
    commitments = []
    for encoded in raw:
        envelope = parse(encoded)
        _transition(envelope, previous, context)
        _remember_owners(envelope["body"], *owners)
        commitments.append(digest(envelope))
        previous = envelope
    body = previous["body"]
    if (
        body["generation"] != context.generation
        or body["revision"] != context.revision
        or commitments[-1] != context.registry_hash
    ):
        fail()
    values = (
        PROFILE,
        context.installation,
        context.organization,
        body["generation"],
        body["revision"],
        commitments[-1],
        _context_hash(context),
        tuple(hashlib.sha256(item).hexdigest() for item in raw),
        tuple(commitments),
        canonical(_digest_document(previous)),
        tuple(
            (kind, len(mapping))
            for kind, mapping in zip(
                ("identity", "account", "credential", "spki", "custody-key"), owners, strict=True
            )
        ),
    )
    return previous, values


def _archive(raw, context):
    validate_context(context, False)
    _, values = _history(raw, context)
    return HistoricalRegistry(*values)


def _current(raw, raw_checkpoint, context):
    validate_context(context, True)
    # Validate both complete raw input budgets before any document is parsed.
    chain_input(raw)
    if type(raw_checkpoint) is not bytes or not 0 < len(raw_checkpoint) <= CHECKPOINT_BYTES:
        fail()
    envelope, values = _history(raw, context)
    now = timestamp(context.now_utc)
    body = envelope["body"]
    issued, expires = timestamp(body["issued_at"]), timestamp(body["expires_at"])
    if not issued <= now < expires or not issued < expires <= issued + timedelta(
        seconds=context.registry_max_seconds
    ):
        fail()
    checkpoint = parse(raw_checkpoint, CHECKPOINT_BYTES)
    if type(checkpoint) is not dict or set(checkpoint) != {"body", "key_id", "signature"}:
        fail()
    cp = checkpoint["body"]
    # Preserve V1 equality, including signed float/bool revision compatibility.
    if type(cp) is not dict or (
        cp.get("format") != "pamolive.pam.trust-checkpoint/1"
        or cp.get("installation") != context.installation
        or cp.get("organization") != context.organization
        or cp.get("generation") != body["generation"]
        or cp.get("revision") != body["revision"]
        or cp.get("registry_hash") != values[5]
    ):
        fail()
    cp_issued, cp_expires = timestamp(cp.get("issued_at")), timestamp(cp.get("expires_at"))
    if not cp_issued < cp_expires <= cp_issued + timedelta(seconds=context.checkpoint_max_seconds):
        fail()
    key_id = checkpoint["key_id"]
    if type(key_id) is not str:
        fail()
    public = external_key(context.checkpoint_keys, key_id, cp_issued, historical=False)
    verify(public, checkpoint["signature"], CHECKPOINT_DOMAIN + canonical(cp, CHECKPOINT_BYTES))
    if not cp_issued <= now < cp_expires:
        fail()
    return CurrentRegistry(
        *values,
        hashlib.sha256(raw_checkpoint).hexdigest(),
        canonical(checkpoint, CHECKPOINT_BYTES),
        context.now_utc,
    )


def verify_archived_registry_chain(
    raw_envelopes: tuple[bytes, ...], context: HistoricalContext
) -> HistoricalRegistry:
    """Inspect a complete V1 history; no current freshness or action is implied."""
    return public_call(_archive, raw_envelopes, context)


def verify_current_registry_materials(
    raw_envelopes: tuple[bytes, ...], raw_checkpoint: bytes, context: CurrentContext
) -> CurrentRegistry:
    """Inspect current materials only, against caller-supplied independent expectations."""
    return public_call(_current, raw_envelopes, raw_checkpoint, context)
