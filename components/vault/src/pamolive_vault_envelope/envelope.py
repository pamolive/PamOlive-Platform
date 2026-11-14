"""ADR-020 primitives. Registry selection and access decisions belong to the caller.

No settings, process-global key/provider, key lookup, persistence, HTTP or legacy
fallback exists here. Providers are trusted injected implementations; this code
checks their contract, not their network or tenant IAM policy.
"""

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import dataclass, field, replace
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA = "pamolive.vault-envelope/1"
WRAP_SCHEMA = "pamolive.kms-context-wrap/1"
ALGORITHM = "AES-256-GCM"
DOMAIN = "technical-credentials"
MAX_JSON = 128 * 1024
MAX_PLAINTEXT = 65536
MAX_WRAPPED = 16 * 1024
MAX_AAD = 4096
MAX_VERSION = 2**63 - 1
SHA = re.compile(r"[0-9a-f]{64}\Z")
B64 = re.compile(r"[A-Za-z0-9_-]+\Z")


class EnvelopeError(ValueError):
    """Constant integrity/format failure; no partial plaintext or input repr."""

    def __init__(self):
        super().__init__("invalid_envelope")


class ProviderError(ValueError):
    """Constant missing/incompatible/unavailable provider failure."""

    def __init__(self):
        super().__init__("provider_failure")


def _require(condition):
    if not condition:
        raise EnvelopeError


def _uuid(value):
    _require(type(value) is str and len(value) == 36)
    try:
        valid = str(UUID(value)) == value
    except ValueError:
        valid = False
    _require(valid)


def _ref(value, maximum):
    # Local opaque registry IDs, not URLs, paths, aliases or user names.
    _require(type(value) is str and 1 <= len(value) <= maximum)
    _require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", value, flags=re.ASCII) is not None)


def _version(value):
    _require(type(value) is int and 1 <= value <= MAX_VERSION)


def _scope(installation_id, organization_id, domain):
    _uuid(installation_id)
    _uuid(organization_id)
    _require(type(domain) is str and domain == DOMAIN)


@dataclass(frozen=True, slots=True)
class Binding:
    installation_id: str
    organization_id: str
    domain: str
    secret_id: str
    secret_version: int
    purpose: str
    destination_scope_hash: str

    def __post_init__(self):
        _scope(self.installation_id, self.organization_id, self.domain)
        _uuid(self.secret_id)
        _version(self.secret_version)
        _ref(self.purpose, 64)
        _require(
            type(self.destination_scope_hash) is str
            and SHA.fullmatch(self.destination_scope_hash) is not None
        )


@dataclass(frozen=True, slots=True)
class KeyRef:
    installation_id: str
    organization_id: str
    domain: str
    provider_id: str
    kek_id: str
    kek_version: int

    def __post_init__(self):
        _scope(self.installation_id, self.organization_id, self.domain)
        _ref(self.provider_id, 64)
        _ref(self.kek_id, 128)
        _version(self.kek_version)


@dataclass(frozen=True, slots=True)
class WrappedKey:
    key_ref: KeyRef
    blob: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class UnwrappedKey:
    key_ref: KeyRef
    dek: bytes = field(repr=False)


class KeyProvider(Protocol):
    """Authenticate the COMPLETE context, and restrict keys outside this package.

    A network adapter must independently impose deadlines, quotas, identity and
    tenant/domain IAM. Raw adapter exceptions never leave the primitive.
    """

    provider_id: str

    def wrap_key(self, dek: bytes, key_ref: KeyRef, context: bytes) -> WrappedKey: ...

    def unwrap_key(self, blob: bytes, key_ref: KeyRef, context: bytes) -> UnwrappedKey: ...


@dataclass(frozen=True, slots=True)
class Wrapping:
    key_ref: KeyRef
    wrapped_dek: bytes = field(repr=False)
    context_hash: str
    schema: str = WRAP_SCHEMA

    def __post_init__(self):
        _require(type(self.key_ref) is KeyRef)
        self.key_ref.__post_init__()
        _require(type(self.wrapped_dek) is bytes and 1 <= len(self.wrapped_dek) <= MAX_WRAPPED)
        _require(type(self.context_hash) is str and SHA.fullmatch(self.context_hash) is not None)
        _require(type(self.schema) is str and self.schema == WRAP_SCHEMA)


@dataclass(frozen=True, slots=True)
class Envelope:
    binding: Binding
    dek_id: str
    payload_nonce: bytes = field(repr=False)
    payload_ciphertext: bytes = field(repr=False)
    wrapping: Wrapping
    schema: str = SCHEMA
    payload_algorithm: str = ALGORITHM

    def __post_init__(self):
        _require(type(self.binding) is Binding and type(self.wrapping) is Wrapping)
        self.binding.__post_init__()
        self.wrapping.__post_init__()
        _matching_scope(self.binding, self.wrapping.key_ref)
        _uuid(self.dek_id)
        _require(type(self.payload_nonce) is bytes and len(self.payload_nonce) == 12)
        _require(
            type(self.payload_ciphertext) is bytes
            and 17 <= len(self.payload_ciphertext) <= MAX_PLAINTEXT + 16
        )
        _require(type(self.schema) is str and self.schema == SCHEMA)
        _require(type(self.payload_algorithm) is str and self.payload_algorithm == ALGORITHM)


def _matching_scope(binding, key_ref):
    _require(type(binding) is Binding and type(key_ref) is KeyRef)
    binding.__post_init__()
    key_ref.__post_init__()
    _require(
        (binding.installation_id, binding.organization_id, binding.domain)
        == (key_ref.installation_id, key_ref.organization_id, key_ref.domain)
    )


def _binding_object(binding):
    return {name: getattr(binding, name) for name in Binding.__dataclass_fields__}


def _canonical(value, maximum):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    _require(len(raw) <= maximum)
    return raw


def _payload_aad(binding, dek_id):
    return _canonical(
        {
            "schema": "pamolive.vault-payload-aad/1",
            "envelope_schema": SCHEMA,
            "payload_algorithm": ALGORITHM,
            "binding": _binding_object(binding),
            "dek_id": dek_id,
        },
        MAX_AAD,
    )


def _wrap_context(binding, dek_id, key_ref):
    return _canonical(
        {
            "schema": "pamolive.vault-wrap-aad/1",
            "installation_id": binding.installation_id,
            "organization_id": binding.organization_id,
            "domain": binding.domain,
            "secret_id": binding.secret_id,
            "secret_version": binding.secret_version,
            "dek_id": dek_id,
            "payload_aad_sha256": hashlib.sha256(_payload_aad(binding, dek_id)).hexdigest(),
            "provider_id": key_ref.provider_id,
            "kek_id": key_ref.kek_id,
            "kek_version": key_ref.kek_version,
        },
        MAX_AAD,
    )


def _provider(provider, key_ref):
    try:
        valid = (
            type(provider.provider_id) is str
            and provider.provider_id == key_ref.provider_id
            and callable(provider.wrap_key)
            and callable(provider.unwrap_key)
        )
    except Exception:
        valid = False
    if not valid:
        raise ProviderError


def _invoke(provider, operation, *args):
    try:
        return getattr(provider, operation)(*args)
    except Exception:
        pass
    # Outside the except block: no raw provider exception in __context__.
    raise ProviderError


def _wrap(provider, dek, key_ref, context):
    result = _invoke(provider, "wrap_key", dek, key_ref, context)
    if not (
        type(result) is WrappedKey
        and type(result.key_ref) is KeyRef
        and result.key_ref == key_ref
        and type(result.blob) is bytes
        and 1 <= len(result.blob) <= MAX_WRAPPED
    ):
        raise ProviderError
    return Wrapping(key_ref, result.blob, hashlib.sha256(context).hexdigest())


def _unwrap(provider, envelope, expected_binding, expected_kek):
    _require(type(envelope) is Envelope)
    envelope.__post_init__()
    _matching_scope(expected_binding, expected_kek)
    _require(envelope.binding == expected_binding and envelope.wrapping.key_ref == expected_kek)
    context = _wrap_context(expected_binding, envelope.dek_id, expected_kek)
    _require(envelope.wrapping.context_hash == hashlib.sha256(context).hexdigest())
    _provider(provider, expected_kek)
    result = _invoke(provider, "unwrap_key", envelope.wrapping.wrapped_dek, expected_kek, context)
    if not (
        type(result) is UnwrappedKey
        and type(result.key_ref) is KeyRef
        and result.key_ref == expected_kek
        and type(result.dek) is bytes
        and len(result.dek) == 32
    ):
        raise ProviderError
    return result.dek


def _decrypt(envelope, binding, dek):
    plaintext = None
    try:
        plaintext = AESGCM(dek).decrypt(
            envelope.payload_nonce,
            envelope.payload_ciphertext,
            _payload_aad(binding, envelope.dek_id),
        )
    except InvalidTag:
        pass
    _require(type(plaintext) is bytes and 1 <= len(plaintext) <= MAX_PLAINTEXT)
    return plaintext


def seal_new_version(plaintext_bytes, expected_binding, approved_kek, explicit_provider):
    """Create once for a NEW stored version; caller owns durable uniqueness/retries."""
    _require(type(plaintext_bytes) is bytes and 1 <= len(plaintext_bytes) <= MAX_PLAINTEXT)
    _matching_scope(expected_binding, approved_kek)
    _provider(explicit_provider, approved_kek)
    dek_id = str(uuid4())
    aad = _payload_aad(expected_binding, dek_id)
    context = _wrap_context(expected_binding, dek_id, approved_kek)
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    wrapping = _wrap(explicit_provider, dek, approved_kek, context)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext_bytes, aad)
    return Envelope(expected_binding, dek_id, nonce, ciphertext, wrapping)


def open_authorized_version(envelope, expected_binding, expected_kek, explicit_provider):
    """Crypto only: the name presumes, but does NOT perform, caller authorization."""
    dek = _unwrap(explicit_provider, envelope, expected_binding, expected_kek)
    return _decrypt(envelope, expected_binding, dek)


def rewrap(
    envelope, expected_binding, expected_source_kek, approved_destination_kek, explicit_provider
):
    """Authenticate before rewrapping the SAME DEK; never reencrypt the payload."""
    _matching_scope(expected_binding, expected_source_kek)
    _matching_scope(expected_binding, approved_destination_kek)
    _require(expected_source_kek.provider_id == approved_destination_kek.provider_id)
    _provider(explicit_provider, approved_destination_kek)
    dek = _unwrap(explicit_provider, envelope, expected_binding, expected_source_kek)
    _decrypt(envelope, expected_binding, dek)
    context = _wrap_context(expected_binding, envelope.dek_id, approved_destination_kek)
    wrapping = _wrap(explicit_provider, dek, approved_destination_kek, context)
    return replace(envelope, wrapping=wrapping)


def _encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value, minimum, maximum):
    _require(
        type(value) is str
        and 1 <= len(value) <= (maximum * 4 + 2) // 3
        and B64.fullmatch(value) is not None
    )
    decoded = None
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        pass
    _require(
        type(decoded) is bytes and minimum <= len(decoded) <= maximum and _encode(decoded) == value
    )
    return decoded


def serialize_envelope(envelope):
    _require(type(envelope) is Envelope)
    envelope.__post_init__()
    wrapping = envelope.wrapping
    return _canonical(
        {
            "schema": envelope.schema,
            "payload_algorithm": envelope.payload_algorithm,
            "binding": _binding_object(envelope.binding),
            "dek_id": envelope.dek_id,
            "payload_nonce": _encode(envelope.payload_nonce),
            "payload_ciphertext": _encode(envelope.payload_ciphertext),
            "wrapping": {
                "schema": wrapping.schema,
                "provider_id": wrapping.key_ref.provider_id,
                "kek_id": wrapping.key_ref.kek_id,
                "kek_version": wrapping.key_ref.kek_version,
                "wrapped_dek": _encode(wrapping.wrapped_dek),
                "context_hash": wrapping.context_hash,
            },
        },
        MAX_JSON,
    )


def _pairs(items):
    value = {}
    for key, item in items:
        _require(key not in value)
        value[key] = item
    return value


def _integer(value):
    _require(len(value) <= 19)
    return int(value)


def _no_float(_value):
    raise EnvelopeError


def _structure(value, depth=0, count=None):
    count = [0] if count is None else count
    count[0] += 1
    _require(depth <= 8 and count[0] <= 128)
    if type(value) is dict:
        for item in value.values():
            _structure(item, depth + 1, count)
    elif type(value) is list:
        for item in value:
            _structure(item, depth + 1, count)


def _closed(value, fields):
    _require(type(value) is dict and set(value) == set(fields))


def parse_envelope(raw):
    """Bound bytes before parsing; reject duplicate keys and noncanonical base64url."""
    _require(type(raw) is bytes and 1 <= len(raw) <= MAX_JSON)
    value = None
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_no_float,
            parse_constant=_no_float,
        )
    except (ValueError, UnicodeError, RecursionError):
        pass
    _require(type(value) is dict)
    _structure(value)
    _closed(
        value,
        (
            "schema",
            "payload_algorithm",
            "binding",
            "dek_id",
            "payload_nonce",
            "payload_ciphertext",
            "wrapping",
        ),
    )
    _closed(value["binding"], Binding.__dataclass_fields__)
    binding = Binding(**value["binding"])
    wrap = value["wrapping"]
    _closed(wrap, ("schema", "provider_id", "kek_id", "kek_version", "wrapped_dek", "context_hash"))
    key_ref = KeyRef(
        binding.installation_id,
        binding.organization_id,
        binding.domain,
        wrap["provider_id"],
        wrap["kek_id"],
        wrap["kek_version"],
    )
    return Envelope(
        binding,
        value["dek_id"],
        _decode(value["payload_nonce"], 12, 12),
        _decode(value["payload_ciphertext"], 17, MAX_PLAINTEXT + 16),
        Wrapping(
            key_ref,
            _decode(wrap["wrapped_dek"], 1, MAX_WRAPPED),
            wrap["context_hash"],
            wrap["schema"],
        ),
        value["schema"],
        value["payload_algorithm"],
    )
