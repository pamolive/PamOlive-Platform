"""Bounded encodings, not signature/proof verification or release capabilities."""

import hashlib
import json
import math
from datetime import UTC, datetime
from uuid import UUID

P0_REGISTRY_DOMAIN = b"pamolive.pam.trust-registry.v1\0"
P0_CHECKPOINT_DOMAIN = b"pamolive.pam.trust-checkpoint.v1\0"
DRAFT_DOMAIN = b"pamolive.vault.operation-draft.v1\0"
BODY_DOMAIN = b"pamolive.vault.operation-body.v2\0"
CONFIRMATION_DOMAIN = b"pamolive.vault.confirmation-challenge.v2\0"
ASSERTIONS_DOMAIN = b"pamolive.vault.final-assertions.v1\0"
MAX_P0_BYTES = 2 * 1024**2
MAX_ASSERTIONS_BYTES = 2 * 1024**2


class ContractError(ValueError):
    """Constant format failure; never an authorization decision."""

    def __init__(self):
        super().__init__("invalid_operation_contract")


def require(condition):
    if not condition:
        raise ContractError


def _walk(value, *, ascii_only, depth=0, count=None):
    count = [0] if count is None else count
    count[0] += 1
    require(depth <= (8 if ascii_only else 16) and count[0] <= (512 if ascii_only else 8192))
    if type(value) is dict:
        for key, item in value.items():
            require(type(key) is str)
            _walk(key, ascii_only=ascii_only, depth=depth + 1, count=count)
            _walk(item, ascii_only=ascii_only, depth=depth + 1, count=count)
    elif type(value) in (list, tuple):
        for item in value:
            _walk(item, ascii_only=ascii_only, depth=depth + 1, count=count)
    elif type(value) is str:
        require(len(value) <= (4096 if ascii_only else 65536) and "\0" not in value)
        require(not ascii_only or value.isascii())
    elif type(value) is int:
        require(-(2**63) <= value <= 2**63 - 1)
    elif not ascii_only and type(value) is float:
        require(math.isfinite(value))
    elif not ascii_only and type(value) in (bool, type(None), UUID, datetime):
        pass
    else:
        raise ContractError


def _bounded_encode(value, encoder, maximum):
    """Bound UTF-8 output before retaining each iterencode chunk.

    _walk bounds every individual string first. Repeated references still count
    toward the output budget on EVERY occurrence, without expanding the graph
    into an unbounded JSON string first. Joining retains at most maximum bytes.
    """
    require(type(maximum) is int and 1 <= maximum <= MAX_P0_BYTES)
    parts, total, failed = [], 0, False
    try:
        for chunk in encoder.iterencode(value):
            raw = chunk.encode("utf8")
            total += len(raw)
            require(total <= maximum)
            parts.append(raw)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        failed = True
    if failed:
        # No raw encoder exception is retained as the public exception context.
        raise ContractError
    return b"".join(parts)


def canonical_v2(value, maximum):
    _walk(value, ascii_only=True)
    encoder = json.JSONEncoder(
        sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    return _bounded_encode(value, encoder, maximum)


def p0_canonical(value):
    """Exact P0 encoding for bounded values; DOES NOT validate P0 authority.

    P0 allows Unicode and finite floats in its generic encoder. Preserve its
    datetime/UUID encoding and domains; V2 deliberately uses a separate profile.
    No legacy caller is changed by this compatibility encoder.
    """
    _walk(value, ascii_only=False)

    def encode(item):
        if isinstance(item, datetime):
            require(item.tzinfo is not None and item.utcoffset() is not None)
            return item.astimezone(UTC).isoformat(timespec="microseconds")
        if isinstance(item, UUID):
            return str(item)
        raise ContractError

    encoder = json.JSONEncoder(
        default=encode,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return _bounded_encode(value, encoder, MAX_P0_BYTES)


def p0_registry_message(body):
    return P0_REGISTRY_DOMAIN + p0_canonical(body)


def p0_checkpoint_message(body):
    return P0_CHECKPOINT_DOMAIN + p0_canonical(body)


def final_assertions_digest(raw):
    """Hash bounded opaque final bytes, without parsing or accepting any proof.

    This digest is stored separately from the transcript those assertions sign.
    A digest is neither a verified attestation nor an AuthorizedRelease.
    """
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_ASSERTIONS_BYTES)
    return hashlib.sha256(ASSERTIONS_DOMAIN + raw).hexdigest()


def _pairs(items):
    value = {}
    for key, item in items:
        require(key not in value)
        value[key] = item
    return value


def _integer(value):
    require(len(value) <= 19)
    result = int(value)
    require(0 <= result <= 2**63 - 1)
    return result


def _invalid(_value):
    raise ContractError


def parse_object(raw, maximum):
    require(type(raw) is bytes and 1 <= len(raw) <= maximum)
    try:
        value = json.loads(
            raw.decode("utf8"),
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_invalid,
            parse_constant=_invalid,
        )
        _walk(value, ascii_only=True)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ContractError from None
    require(type(value) is dict)
    return value
