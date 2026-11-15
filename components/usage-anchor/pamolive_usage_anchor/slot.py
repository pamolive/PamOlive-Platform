"""Administrative RO context. No request-controlled path, key or incarnation."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from pamolive_pam_trust_verifier import CurrentContext
from pamolive_vault_runtime.admission import authenticate, utc_text
from pamolive_vault_runtime.slot import EXPECTED_FIELDS, Principal
from pamolive_vault_runtime.slot import parse_slot as parse_vault_slot

from .codec import closed, digest, encode, integer, need, parse, sha, unb64, uuid


def _identity(info):
    return tuple(
        getattr(info, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


class ReadOnly:
    def __init__(self, path, pin, maximum, owner_uid=0):
        need(type(owner_uid) is int and owner_uid >= 0, "context_refused", 403)
        self.path, self.pin, self.maximum, self.owner_uid = (
            Path(path),
            digest(pin),
            maximum,
            owner_uid,
        )
        _, self.identity = self._read()

    def _read(self):
        need(
            os.name == "posix"
            and self.path.is_absolute()
            and ".." not in self.path.parts
            and not str(self.path).startswith("//"),
            "context_refused",
            403,
        )
        parents = []
        for parent in reversed(self.path.parents):
            info = parent.lstat()
            need(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == self.owner_uid
                and not info.st_mode & 0o022,
                "context_refused",
                403,
            )
            parents.append((parent, _identity(info)))
        before = self.path.lstat()
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_uid == self.owner_uid
            and not before.st_mode & 0o222
            and 0 < before.st_size <= self.maximum,
            "context_refused",
            403,
        )
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(_identity(os.fstat(fd)) == _identity(before), "context_refused", 403)
            parts, total = [], 0
            while total <= self.maximum:
                part = os.read(fd, min(8192, self.maximum + 1 - total))
                if not part:
                    break
                parts.append(part)
                total += len(part)
            raw = b"".join(parts)
            need(
                total == before.st_size and total <= self.maximum and sha(raw) == self.pin,
                "context_refused",
                403,
            )
            need(
                _identity(os.fstat(fd)) == _identity(before) == _identity(self.path.lstat())
                and all(_identity(p.lstat()) == i for p, i in parents),
                "context_refused",
                403,
            )
        finally:
            os.close(fd)
        return raw, (_identity(before), tuple(parents))

    def check(self):
        raw, identity = self._read()
        need(identity == self.identity, "context_refused", 403)
        return raw


@dataclass(frozen=True)
class Slot:
    source_sha256: str
    context_id: str
    witness_incarnation: str
    installation_p0: str
    intent_requester_person_id: str
    expectations: tuple
    commissioning_keys: tuple
    checkpoint_keys: tuple
    principals: tuple
    purposes: tuple
    credentials: tuple
    broker: tuple
    lease_epoch: int
    minimum_reviewers: int
    allow_zero: bool
    not_before: int
    not_after: int
    quota: int
    quota_bytes: int

    def expected(self):
        return dict(self.expectations)

    def context(self, now):
        e = self.expected()
        return CurrentContext(
            self.installation_p0,
            e["organization_id"],
            e["trust_generation"],
            e["registry_revision"],
            e["registry_hash"],
            self.commissioning_keys,
            self.checkpoint_keys,
            utc_text(now),
            86400,
            40,
        )

    def peer(self, der, now, purpose):
        try:
            peer = authenticate(der, self, now)
        except Exception:
            peer = None
        need(peer is not None, "caller_refused", 403)
        need(dict(self.purposes).get(peer.service_id) == purpose, "caller_refused", 403)
        need(self.not_before <= now < self.not_after, "context_refused", 403)
        return peer


def parse_slot(raw, pin):
    need(sha(raw) == digest(pin), "context_refused", 403)
    v = parse(raw, 65536, special=True, ascii_only=False)
    closed(
        v,
        {
            "schema",
            "context_id",
            "witness_incarnation",
            "installation_p0",
            "intent_requester_person_id",
            "expectations",
            "commissioning_keys",
            "checkpoint_keys",
            "principals",
            "credentials",
            "lease_epoch",
            "minimum_reviewers",
            "allow_zero",
            "not_before",
            "not_after",
            "quota",
            "quota_bytes",
            "broker",
        },
    )
    need(v["schema"] == "pamolive.usage-anchor.slot/1")
    uuid(v["context_id"])
    uuid(v["witness_incarnation"])
    uuid(v["intent_requester_person_id"])
    closed(v["expectations"], EXPECTED_FIELDS)
    # Reuse independent V context/keys/types without changing its parser or runtime.
    dummy = {
        "schema": "pamolive.vault.local-reservation-slot/1",
        "slot_id": v["context_id"],
        "serving_state": "open",
        "installation_p0": v["installation_p0"],
        "expectations": v["expectations"],
        "commissioning_keys": v["commissioning_keys"],
        "checkpoint_keys": v["checkpoint_keys"],
        "principals": [
            {
                "service_id": "validation-only",
                "broker_instance_id": v["context_id"],
                "certificate_sha256": ["0" * 64],
                "san_uri": "urn:pamolive:broker:validation-only",
            }
        ],
        "not_before": v["not_before"],
        "not_after": v["not_after"],
        "quota": v["quota"],
        "registry_max_seconds": 86400,
        "checkpoint_max_seconds": 40,
    }
    raw_dummy = encode(dummy, 65536, special=True, ascii_only=False)
    checked = parse_vault_slot(raw_dummy, sha(raw_dummy))
    principals, purposes, pins = [], [], set()
    need(type(v["principals"]) is list and 2 <= len(v["principals"]) <= 16)
    for p in v["principals"]:
        closed(p, {"service_id", "instance_id", "san_uri", "certificate_sha256", "audience"})
        need(p["audience"] in ("usage-anchor.vault/1", "usage-anchor.activation/1"))
        need(
            type(p["service_id"]) is str
            and p["service_id"].isascii()
            and 1 <= len(p["service_id"]) <= 64
        )
        uuid(p["instance_id"])
        need(
            type(p["san_uri"]) is str
            and p["san_uri"].isascii()
            and p["san_uri"].startswith("urn:pamolive:")
            and len(p["san_uri"]) <= 160
        )
        need(type(p["certificate_sha256"]) is list and 1 <= len(p["certificate_sha256"]) <= 4)
        for cert in p["certificate_sha256"]:
            digest(cert)
            need(cert not in pins)
            pins.add(cert)
        principals.append(
            Principal(
                p["service_id"], p["instance_id"], tuple(p["certificate_sha256"]), p["san_uri"]
            )
        )
        purposes.append((p["service_id"], p["audience"]))
    need(len(dict(purposes)) == len(purposes))
    need(sum(p[1] == "usage-anchor.vault/1" for p in purposes) == 1)
    need(type(v["credentials"]) is dict and 1 <= len(v["credentials"]) <= 18)
    for person, cred in v["credentials"].items():
        uuid(person)
        unb64(cred, 1024)
    need(len(set(v["credentials"].values())) == len(v["credentials"]))
    need(type(v["allow_zero"]) is bool)
    closed(v["broker"], {"service_id", "instance_id", "certificate_sha256"})
    need(
        type(v["broker"]["service_id"]) is str
        and v["broker"]["service_id"].isascii()
        and 1 <= len(v["broker"]["service_id"]) <= 64
    )
    uuid(v["broker"]["instance_id"])
    digest(v["broker"]["certificate_sha256"])
    return Slot(
        pin,
        v["context_id"],
        v["witness_incarnation"],
        checked.installation_p0,
        v["intent_requester_person_id"],
        checked.expectations,
        checked.commissioning_keys,
        checked.checkpoint_keys,
        tuple(principals),
        tuple(purposes),
        tuple(sorted(v["credentials"].items())),
        tuple(sorted(v["broker"].items())),
        integer(v["lease_epoch"]),
        integer(v["minimum_reviewers"], maximum=16),
        v["allow_zero"],
        checked.not_before,
        checked.not_after,
        checked.quota,
        integer(v["quota_bytes"], maximum=64 * 1024 * 1024),
    )


class SlotFile:
    def __init__(self, path, pin, owner_uid=0):
        self.reader = ReadOnly(path, pin, 65536, owner_uid)
        self.slot = parse_slot(self.reader.check(), pin)

    def check(self):
        self.reader.check()
        return self.slot
