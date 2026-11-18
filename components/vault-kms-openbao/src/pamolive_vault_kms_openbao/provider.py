"""Map one commissioned key family to OpenBao's documented Transit AEAD profile."""

import base64
import json
import re
from dataclasses import dataclass, field
from threading import BoundedSemaphore

from pamolive_vault_envelope import KeyRef, ProviderError, UnwrappedKey, WrappedKey

from .transport import TransitTransport

REMOTE_KEY = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
SERVICE_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,1024}")
MAX_RESPONSE = 8192
MAX_CONTEXT = 4096
DEK_BYTES = 32
WRAPPED_BYTES = 12 + DEK_BYTES + 16  # Transit AES-256-GCM nonce, ciphertext and tag.
RESPONSE_FIELDS = {
    "request_id",
    "lease_id",
    "lease_duration",
    "renewable",
    "data",
    "wrap_info",
    "warnings",
    "auth",
    "mount_type",
}


def require(condition):
    if not condition:
        raise ProviderError()


def unique_object(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs))
    return result


def refuse_number(_value):
    raise ProviderError()


def encoded(raw):
    return base64.b64encode(raw).decode("ascii")


def decode(value, length):
    require(type(value) is str and len(value) == (length + 2) // 3 * 4)
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raw = b""
    require(len(raw) == length and encoded(raw) == value)
    return raw


def ciphertext(value, version):
    prefix = f"vault:v{version}:"
    require(type(value) is str and value.startswith(prefix))
    decode(value[len(prefix) :], WRAPPED_BYTES)
    return value


@dataclass(frozen=True, slots=True, repr=False)
class TransitProvider:
    """Bind immutable Vault policy to one operator-provisioned Transit key.

    The scoped service token must have only update on the two exact paths. The
    provider does not administer keys or authorize Vault business operations.
    """

    active: KeyRef
    remote_key: str
    readable_versions: frozenset[int]
    transport: TransitTransport = field(repr=False)
    token: str = field(repr=False)
    _capacity: BoundedSemaphore = field(init=False, default_factory=lambda: BoundedSemaphore(4))

    def __post_init__(self):
        require(type(self.active) is KeyRef)
        require(type(self.remote_key) is str and REMOTE_KEY.fullmatch(self.remote_key))
        require(type(self.token) is str and SERVICE_TOKEN.fullmatch(self.token))
        require(
            type(self.readable_versions) is frozenset and 1 <= len(self.readable_versions) <= 64
        )
        require(
            all(type(v) is int and 0 < v <= self.active.kek_version for v in self.readable_versions)
        )
        require(self.active.kek_version in self.readable_versions)

    @property
    def provider_id(self):
        return self.active.provider_id

    def _check(self, key_ref, context):
        active = self.active
        require(type(key_ref) is KeyRef)
        require(
            key_ref.installation_id == active.installation_id
            and key_ref.organization_id == active.organization_id
            and key_ref.domain == active.domain
            and key_ref.provider_id == active.provider_id
            and key_ref.kek_id == active.kek_id
        )
        require(type(context) is bytes and 0 < len(context) <= MAX_CONTEXT)

    def _call(self, operation, payload):
        require(self._capacity.acquire(blocking=False))
        try:
            body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("ascii")
            raw = self.transport.post(
                f"/v1/transit/{operation}/{self.remote_key}", self.token, body
            )
            require(type(raw) is bytes and 0 < len(raw) <= MAX_RESPONSE)
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=refuse_number,
                parse_float=refuse_number,
            )
            require(type(value) is dict and value.keys() <= RESPONSE_FIELDS)
            require(value.get("warnings") in (None, []) and value.get("wrap_info") is None)
            require(value.get("auth") is None and type(value.get("data")) is dict)
            return value["data"]
        except Exception:
            pass
        finally:
            self._capacity.release()
        raise ProviderError()

    def wrap_key(self, dek, key_ref, context):
        self._check(key_ref, context)
        require(key_ref == self.active and type(dek) is bytes and len(dek) == DEK_BYTES)
        response = self._call(
            "encrypt",
            {
                "plaintext": encoded(dek),
                "key_version": key_ref.kek_version,
                "associated_data": encoded(context),
            },
        )
        require(response.keys() == {"ciphertext", "key_version"})
        require(
            type(response["key_version"]) is int and response["key_version"] == key_ref.kek_version
        )
        value = ciphertext(response["ciphertext"], key_ref.kek_version).encode("ascii")
        return WrappedKey(key_ref, value)

    def unwrap_key(self, blob, key_ref, context):
        self._check(key_ref, context)
        require(key_ref.kek_version in self.readable_versions)
        require(type(blob) is bytes and 0 < len(blob) <= 128)
        require(blob.isascii())
        value = ciphertext(blob.decode("ascii"), key_ref.kek_version)
        response = self._call("decrypt", {"ciphertext": value, "associated_data": encoded(context)})
        require(response.keys() == {"plaintext"})
        return UnwrappedKey(key_ref, decode(response["plaintext"], DEK_BYTES))
