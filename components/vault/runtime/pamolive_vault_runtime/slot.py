"""A fixed, externally pinned POSIX RO slot; no request-controlled lookup or reload."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from pamolive_pam_trust_verifier import CurrentContext, ExternalKey

from .bounded import Refusal, closed, digest, integer, json_object, need, service, sha, uuid

MAX_SLOT = 65536
UUID_FIELDS = {
    "installation_id",
    "organization_id",
    "trust_generation",
    "ledger_incarnation",
    "policy_revision",
    "intent_id",
    "target_id",
    "credential_secret_id",
}
HASH_FIELDS = {
    "policy_hash",
    "registry_hash",
    "checkpoint_hash",
    "authority_materials_sha256",
    "intent_scope_hash",
    "destination_scope_hash",
}
NUMBER_FIELDS = {
    "registry_revision",
    "destination_epoch",
    "credential_version",
    "wrapping_revision",
}
EXPECTED_FIELDS = UUID_FIELDS | HASH_FIELDS | NUMBER_FIELDS | {"vault_service_id"}


@dataclass(frozen=True, slots=True)
class Principal:
    service_id: str
    broker_instance_id: str
    certificate_sha256: tuple[str, ...]
    san_uri: str


@dataclass(frozen=True, slots=True)
class Slot:
    slot_id: str
    source_sha256: str
    installation_p0: str
    expectations: tuple[tuple[str, object], ...]
    commissioning_keys: tuple[ExternalKey, ...]
    checkpoint_keys: tuple[ExternalKey, ...]
    principals: tuple[Principal, ...]
    not_before: int
    not_after: int
    quota: int
    registry_max_seconds: int
    checkpoint_max_seconds: int

    def expected(self):
        return dict(self.expectations)

    def context(self, now_utc):
        values = self.expected()
        return CurrentContext(
            self.installation_p0,
            values["organization_id"],
            values["trust_generation"],
            values["registry_revision"],
            values["registry_hash"],
            self.commissioning_keys,
            self.checkpoint_keys,
            now_utc,
            self.registry_max_seconds,
            self.checkpoint_max_seconds,
        )


def _keys(rows):
    need(type(rows) is list and 1 <= len(rows) <= 16)
    result = []
    for row in rows:
        closed(row, {"key_id", "public_key_hex", "active", "not_before", "not_after", "revoked_at"})
        service(row["key_id"])
        digest(row["public_key_hex"])
        need(type(row["active"]) is bool)
        # Explicit periods are administrative inputs, not inferred from materials.
        need(
            all(type(row[k]) is str and 0 < len(row[k]) <= 64 for k in ("not_before", "not_after"))
        )
        need(type(row["revoked_at"]) is str and len(row["revoked_at"]) <= 64)
        result.append(
            ExternalKey(
                row["key_id"],
                bytes.fromhex(row["public_key_hex"]),
                row["active"],
                row["not_before"],
                row["not_after"],
                row["revoked_at"],
            )
        )
    need(len({key.key_id for key in result}) == len(result))
    return tuple(result)


def parse_slot(raw, expected_sha256):
    """Pure administrative loader. Constructing a Slot does not authenticate a request."""
    digest(expected_sha256)
    need(type(raw) is bytes and len(raw) <= MAX_SLOT and sha(raw) == expected_sha256)
    value = json_object(raw, MAX_SLOT)
    closed(
        value,
        {
            "schema",
            "slot_id",
            "serving_state",
            "installation_p0",
            "expectations",
            "commissioning_keys",
            "checkpoint_keys",
            "principals",
            "not_before",
            "not_after",
            "quota",
            "registry_max_seconds",
            "checkpoint_max_seconds",
        },
    )
    need(
        value["schema"] == "pamolive.vault.local-reservation-slot/1"
        and value["serving_state"] == "open"
    )
    uuid(value["slot_id"])
    opaque = value["installation_p0"]
    need(type(opaque) is str and 0 < len(opaque) <= 128 and bool(opaque.strip()))
    opaque.encode("utf-8")  # Deliberately no NFC, UUID conversion or implicit hash mapping.
    expected = value["expectations"]
    closed(expected, EXPECTED_FIELDS)
    for key in UUID_FIELDS:
        uuid(expected[key])
    for key in HASH_FIELDS:
        digest(expected[key])
    for key in NUMBER_FIELDS:
        integer(expected[key])
    service(expected["vault_service_id"])
    rows = value["principals"]
    need(type(rows) is list and 1 <= len(rows) <= 16)
    principals = []
    certificates = set()
    for row in rows:
        closed(row, {"service_id", "broker_instance_id", "certificate_sha256", "san_uri"})
        service(row["service_id"])
        uuid(row["broker_instance_id"])
        hashes = row["certificate_sha256"]
        need(type(hashes) is list and 1 <= len(hashes) <= 4)
        for item in hashes:
            digest(item)
            need(item not in certificates)
            certificates.add(item)
        uri = row["san_uri"]
        need(type(uri) is str and uri.startswith("urn:pamolive:broker:") and len(uri) <= 160)
        need(uri.isascii() and not any(ord(c) < 33 for c in uri))
        principals.append(
            Principal(row["service_id"], row["broker_instance_id"], tuple(hashes), uri)
        )
    need(len({p.service_id for p in principals}) == len(principals))
    before, after = integer(value["not_before"]), integer(value["not_after"])
    need(before < after)
    return Slot(
        value["slot_id"],
        sha(raw),
        opaque,
        tuple(sorted(expected.items())),
        _keys(value["commissioning_keys"]),
        _keys(value["checkpoint_keys"]),
        tuple(principals),
        before,
        after,
        integer(value["quota"], maximum=64),
        integer(value["registry_max_seconds"], maximum=86400),
        integer(value["checkpoint_max_seconds"], maximum=60),
    )


def _identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_ro(path, owner_uid):
    need(os.name == "posix" and isinstance(path, Path) and path.is_absolute())
    need(type(owner_uid) is int and owner_uid >= 0)
    need(".." not in path.parts and not str(path).startswith("//"))
    parents = []
    for parent in reversed(path.parents):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == owner_uid and not info.st_mode & 0o022)
        parents.append((parent, _identity(info)))
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == owner_uid)
    need(not before.st_mode & 0o222 and 0 < before.st_size <= MAX_SLOT)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(_identity(os.fstat(descriptor)) == _identity(before))
        pieces, remaining = [], MAX_SLOT + 1
        while remaining:
            chunk = os.read(descriptor, min(8192, remaining))
            if not chunk:
                break
            pieces.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(pieces)
        need(len(raw) == before.st_size and len(raw) <= MAX_SLOT)
        need(_identity(os.fstat(descriptor)) == _identity(before) == _identity(path.lstat()))
        need(all(_identity(parent.lstat()) == identity for parent, identity in parents))
    finally:
        os.close(descriptor)
    return raw, (_identity(before), tuple(parents))


def _checked_read(path, owner_uid):
    try:
        return _read_ro(path, owner_uid)
    except Exception:
        pass
    raise Refusal("context_refused", 403)


class SlotFile:
    """Administrative constructor only. Recheck bytes AND identity before each SQL mutation."""

    def __init__(self, path, expected_sha256, owner_uid=0):
        self.path, self.pin, self.owner_uid = path, expected_sha256, owner_uid
        raw, self.identity = _checked_read(path, owner_uid)
        self.slot = parse_slot(raw, expected_sha256)

    def check(self):
        raw, identity = _checked_read(self.path, self.owner_uid)
        need(identity == self.identity and sha(raw) == self.pin, "context_refused", 403)
        return self.slot
