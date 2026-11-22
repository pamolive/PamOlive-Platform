"""ADR026 closed byte codecs. SHA commitments are not permissions."""

import base64
import hashlib
import json
import re
from uuid import UUID

MATERIALS = b"pamolive.vault.public-materials.v1\0"
BASELINE = b"pamolive.vault.counter-baseline.v1\0"
EFFECTIVE = b"pamolive.vault.effective-policy.v1\0"
MAX_MATERIALS = len(MATERIALS) + 4 + 4 * 256 + 33554432 + 4 + 65536


class Error(Exception):
    def __init__(self, code="invalid_request", status=400):
        allowed = {
            "invalid_request": 400,
            "proof_refused": 403,
            "context_refused": 403,
            "caller_refused": 403,
            "idempotency_conflict": 409,
            "baseline_stale": 409,
            "expired": 410,
            "quota_exceeded": 429,
            "unavailable": 503,
        }
        if allowed.get(code) != status:
            code, status = "unavailable", 503
        self.code, self.status = code, status
        super().__init__(code)


def need(condition, code="invalid_request", status=400):
    if not condition:
        raise Error(code, status)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def uuid(value):
    need(type(value) is str and len(value) == 36)
    try:
        need(str(UUID(value)) == value)
    except ValueError:
        raise Error from None
    return value


def integer(value, minimum=1, maximum=2**63 - 1):
    need(type(value) is int and minimum <= value <= maximum)
    return value


def digest(value):
    need(type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None)
    return value


def closed(value, keys):
    need(type(value) is dict and set(value) == set(keys))


def terminal_receipt(raw, *, reservation_id, operation_id, body_hash, final_digest):
    """Validate the existing terminal format while retaining its original bytes."""
    value = parse(raw, 4096, special=True)
    closed(
        value,
        {
            "schema",
            "operation_id",
            "reservation_id",
            "state",
            "body_hash",
            "final_assertions_digest",
            "issued_at",
            "expires_at",
            "terminal_at",
            "authorized",
        },
    )
    need(
        value["authorized"] is False
        and value["schema"] == "pamolive.vault.usage-terminal/1"
        and value["state"] in ("consumed_no_release", "refused_no_release")
        and value["operation_id"] == operation_id
        and value["body_hash"] == body_hash
        and value["reservation_id"] == reservation_id
        and value["final_assertions_digest"] == final_digest,
        "context_refused",
        403,
    )
    return value


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64(value, maximum):
    need(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3)
    need(re.fullmatch("[A-Za-z0-9_-]+", value) is not None)
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        raise Error from None
    need(0 < len(raw) <= maximum and b64(raw) == value)
    return raw


def _pairs(items):
    value = {}
    for key, child in items:
        need(key not in value)
        value[key] = child
    return value


def _invalid(_):
    raise Error


def _int(value):
    need(len(value) <= 19)
    return integer(int(value), 0)


def shape(value, *, depth=8, nodes=2048, string=4096, special=False, ascii_only=True):
    pending, count = [(value, 1)], 0
    while pending:
        item, level = pending.pop()
        count += 1
        need(count <= nodes and level <= depth)
        if type(item) is dict:
            need(count + len(pending) + 2 * len(item) <= nodes)
            pending.extend((part, level + 1) for pair in item.items() for part in pair)
        elif type(item) is list:
            need(count + len(pending) + len(item) <= nodes)
            pending.extend((part, level + 1) for part in item)
        elif type(item) is str:
            need((not ascii_only or item.isascii()) and "\0" not in item and len(item) <= string)
        elif type(item) is int:
            integer(item, 0)
        elif not (special and (item is None or type(item) is bool)):
            raise Error


def encode(value, maximum, **profile):
    shape(value, **profile)
    parts, size = [], 0
    for part in json.JSONEncoder(
        ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).iterencode(value):
        raw = part.encode("ascii")
        size += len(raw)
        need(size <= maximum)
        parts.append(raw)
    return b"".join(parts)


def parse(raw, maximum, *, canonical=True, **profile):
    need(type(raw) is bytes and 0 < len(raw) <= maximum)
    # Preallocation scan bounds containers/tokens before json.loads, including keys.
    nesting = tokens = 0
    quoted = escaped = scalar = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            tokens += 1
            quoted, scalar = True, False
        elif byte in (91, 123):
            nesting += 1
            tokens += 1
            scalar = False
        elif byte in (93, 125):
            nesting -= 1
            scalar = False
        elif byte in (9, 10, 13, 32, 44, 58):
            scalar = False
        elif not scalar:
            tokens += 1
            scalar = True
        need(0 <= nesting <= profile.get("depth", 8) and tokens <= profile.get("nodes", 2048))
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_pairs,
            parse_int=_int,
            parse_float=_invalid,
            parse_constant=_invalid,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise Error from None
    shape(value, **profile)
    need(type(value) is dict)
    if canonical:
        need(encode(value, maximum, **profile) == raw)
    return value


def length(raw):
    need(type(raw) is bytes and 0 < len(raw) < 2**32)
    return len(raw).to_bytes(4, "big") + raw


def commitment(domain, raw):
    return sha(domain + length(raw))


def materials_frame(chain, checkpoint):
    need(type(chain) is tuple and 1 <= len(chain) <= 256)
    need(all(type(doc) is bytes and 0 < len(doc) <= 2097152 for doc in chain))
    need(sum(map(len, chain)) <= 33554432)
    need(type(checkpoint) is bytes and 0 < len(checkpoint) <= 65536)
    return (
        MATERIALS
        + len(chain).to_bytes(4, "big")
        + b"".join(map(length, chain))
        + length(checkpoint)
    )


def parse_materials(raw):
    need(type(raw) is bytes and len(raw) <= MAX_MATERIALS and raw.startswith(MATERIALS))
    at = len(MATERIALS)

    def number():
        nonlocal at
        need(at + 4 <= len(raw))
        n = int.from_bytes(raw[at : at + 4], "big")
        at += 4
        return n

    count = number()
    need(1 <= count <= 256)
    slices, total = [], 0
    for index in range(count + 1):
        n = number()
        need(0 < n <= (65536 if index == count else 2097152) and at + n <= len(raw))
        if index < count:
            total += n
            need(total <= 33554432)
        slices.append((at, n))
        at += n
    need(at == len(raw))
    docs = tuple(raw[a : a + n] for a, n in slices)
    need(materials_frame(docs[:-1], docs[-1]) == raw)
    return docs[:-1], docs[-1]


BASE_FIELDS = {
    "schema",
    "installation_id",
    "organization_id",
    "trust_generation",
    "registry_revision",
    "registry_hash",
    "policy_binding_id",
    "policy_hash",
    "effective_policy_sha256",
    "witness_incarnation",
    "witness_slot_sha256",
    "activations",
}
ACT_FIELDS = {
    "person_id",
    "role",
    "credential_id",
    "spki_sha256",
    "enrollment_id",
    "rp_id",
    "origin",
    "activation_version",
    "state_version",
    "sign_count",
}


def baseline(raw):
    value = parse(raw, 65536)
    closed(value, BASE_FIELDS)
    need(value["schema"] == "pamolive.vault.counter-baseline/1")
    for key in (
        "installation_id",
        "organization_id",
        "trust_generation",
        "policy_binding_id",
        "witness_incarnation",
    ):
        uuid(value[key])
    for key in ("registry_hash", "policy_hash", "effective_policy_sha256", "witness_slot_sha256"):
        digest(value[key])
    integer(value["registry_revision"])
    rows = value["activations"]
    need(type(rows) is list and 1 <= len(rows) <= 18)
    keys = []
    for row in rows:
        closed(row, ACT_FIELDS)
        uuid(row["person_id"])
        uuid(row["enrollment_id"])
        digest(row["spki_sha256"])
        unb64(row["credential_id"], 1024)
        need(row["role"] in ("requester", "reviewer", "sponsor"))
        need(type(row["rp_id"]) is str and 1 <= len(row["rp_id"]) <= 253)
        need(
            type(row["origin"]) is str
            and row["origin"].startswith("https://")
            and len(row["origin"]) <= 512
        )
        for key in ("activation_version", "state_version"):
            integer(row[key])
        integer(row["sign_count"], 0, 2**32 - 1)
        keys.append((row["person_id"], row["role"], row["credential_id"]))
    need(keys == sorted(keys) and len({k[:2] for k in keys}) == len(keys))
    return value


def bundle(raw):
    value = parse(raw, 2097152, string=90000)
    closed(value, {"schema", "operation_id", "body_hash", "assertions"})
    need(value["schema"] == "pamolive.vault.final-proof-bundle/1")
    uuid(value["operation_id"])
    digest(value["body_hash"])
    rows = value["assertions"]
    need(type(rows) is list and 1 <= len(rows) <= 18)
    keys = []
    allowed = {
        "requester": {"launch"},
        "reviewer": {"approve", "refuse"},
        "sponsor": {"sponsor", "refuse"},
    }
    for row in rows:
        closed(row, {"person_id", "role", "decision", "credential_id", "assertion_b64"})
        uuid(row["person_id"])
        unb64(row["credential_id"], 1024)
        need(type(row["role"]) is str and type(row["decision"]) is str)
        need(row["decision"] in allowed.get(row["role"], set()))
        unb64(row["assertion_b64"], 65536)
        keys.append((row["person_id"], row["role"], row["credential_id"]))
    need(keys == sorted(keys) and len({k[:2] for k in keys}) == len(keys))
    return value
