"""Authenticate a historical audit checkpoint using independently pinned inputs."""

from collections.abc import Callable
from dataclasses import asdict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import codec
from .audit_archive import Checkpoint

SCHEMA = "pamolive.vault.usage-audit-anchor/1"
DOMAIN = b"pamolive.vault.usage-audit-anchor.v1\0"
MAX_ANCHOR_BYTES = 1024
PROFILE = {"depth": 4, "nodes": 40, "string": 86}
CHECKPOINT_FIELDS = {
    "context_id",
    "slot_sha256",
    "organization_id",
    "installation_id",
    "last_seq",
    "head_sha256",
}


def _pinned_key(public_key: bytes) -> Ed25519PublicKey:
    codec.need(type(public_key) is bytes and len(public_key) == 32, "anchor_refused", 403)
    try:
        return Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError:
        raise codec.Error("anchor_refused", 403) from None


def _verify_signature(key: Ed25519PublicKey, signature: bytes, message: bytes) -> None:
    codec.need(type(signature) is bytes and len(signature) == 64, "anchor_refused", 403)
    try:
        key.verify(signature, message)
    except InvalidSignature:
        raise codec.Error("anchor_refused", 403) from None


def sign_checkpoint(
    checkpoint: Checkpoint, *, public_key: bytes, sign: Callable[[bytes], bytes]
) -> bytes:
    """Use the caller's external signer and check its result against the pinned key."""
    codec.need(type(checkpoint) is Checkpoint and callable(sign))
    key = _pinned_key(public_key)
    fields = asdict(checkpoint)
    codec.closed(fields, CHECKPOINT_FIELDS)
    body = {"schema": SCHEMA, "key_sha256": codec.sha(public_key), "checkpoint": fields}
    message = DOMAIN + codec.encode(body, MAX_ANCHOR_BYTES, **PROFILE)
    signature = sign(message)
    _verify_signature(key, signature, message)
    return codec.encode(
        {"body": body, "signature": codec.b64(signature)}, MAX_ANCHOR_BYTES, **PROFILE
    )


def verify_checkpoint(raw: bytes, *, public_key: bytes, expected_sha256: str) -> Checkpoint:
    """Verify the checkpoint against the digest and key retained by the archive custodian."""
    codec.need(type(raw) is bytes and 0 < len(raw) <= MAX_ANCHOR_BYTES)
    codec.need(
        type(expected_sha256) is str and codec.sha(raw) == expected_sha256,
        "anchor_refused",
        403,
    )
    key = _pinned_key(public_key)
    envelope = codec.parse(raw, MAX_ANCHOR_BYTES, **PROFILE)
    codec.closed(envelope, {"body", "signature"})
    body = envelope["body"]
    codec.closed(body, {"schema", "key_sha256", "checkpoint"})
    codec.need(body["schema"] == SCHEMA)
    codec.need(body["key_sha256"] == codec.sha(public_key), "anchor_refused", 403)
    codec.closed(body["checkpoint"], CHECKPOINT_FIELDS)
    try:
        signature = codec.unb64(envelope["signature"], 64)
    except codec.Error:
        raise codec.Error("anchor_refused", 403) from None
    _verify_signature(key, signature, DOMAIN + codec.encode(body, MAX_ANCHOR_BYTES, **PROFILE))
    return Checkpoint(**body["checkpoint"])
