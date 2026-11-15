"""V1 encodings and maintained cryptography/WebAuthn primitives only."""

import base64
import hashlib
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from webauthn.helpers import decode_credential_public_key, decoded_public_key_to_cryptography
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from ._codec import fail


def decode(value, *, length=None, maximum=8192):
    if type(value) is not str or len(value) > maximum * 2:
        fail()
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value):
        fail()
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if len(raw) > maximum or length is not None and len(raw) != length:
        fail()
    return raw


def verify(public, signature, message):
    Ed25519PublicKey.from_public_bytes(public).verify(decode(signature, length=64), message)


def public_key_fingerprint(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,16384}", value):
        fail()
    raw = decode(value)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        fail()
    key = decode_credential_public_key(raw)
    if key.alg not in (
        COSEAlgorithmIdentifier.ECDSA_SHA_256,
        COSEAlgorithmIdentifier.EDDSA,
        COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
    ):
        fail()
    maintained = decoded_public_key_to_cryptography(key)
    return hashlib.sha256(
        maintained.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()
