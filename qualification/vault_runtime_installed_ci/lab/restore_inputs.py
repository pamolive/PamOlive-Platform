"""Bind the new restore context outside both lab databases before taking a dump."""

import hashlib
import json
import re
from uuid import UUID, uuid4

RESTORE_CLIENT = frozenset(
    {"restored-slot.json", "restore-plan.json"}
    | {"restored-" + role + "-db.json" for role in ("runtime", "owner", "web", "worker")}
)


def need(value):
    if not value:
        raise ValueError("vault_restore_fixture_refused")


def restored_database(original):
    need(type(original) is str and re.fullmatch(r"vault_n0_lab_[a-z0-9_]{1,40}", original))
    return original + "_restored"


def create(client, original, expires_at, *, new_uuid=uuid4):
    """Extend the client view without modifying the original server or slot."""
    target = restored_database(original)
    need(type(expires_at) is int and expires_at > 0)
    view = dict(client)
    need(not {"lab/" + name for name in RESTORE_CLIENT}.intersection(view))
    old_raw, mode, uid, gid = view["lab/slot.json"]
    need((mode, uid, gid) == (0o444, 0, 0))
    slot = json.loads(old_raw)
    need(slot["schema"] == "pamolive.vault.local-reservation-slot/1")
    old_incarnation = slot["expectations"]["ledger_incarnation"]
    new_incarnation = str(new_uuid())
    need(str(UUID(old_incarnation)) == old_incarnation)
    need(str(UUID(new_incarnation)) == new_incarnation and old_incarnation != new_incarnation)
    slot["expectations"]["ledger_incarnation"] = new_incarnation
    new_raw = json.dumps(slot, separators=(",", ":"), sort_keys=True).encode()
    additions = {"restored-slot.json": new_raw}
    for role in ("runtime", "owner", "web", "worker"):
        old = json.loads(view[f"lab/{role}-db.json"][0])
        need(old["dbname"] == original)
        old["dbname"] = target
        additions[f"restored-{role}-db.json"] = json.dumps(old, separators=(",", ":")).encode()
    plan = {
        "schema": "pamolive.vault.synthetic-restore-plan/1",
        "original_database": original,
        "restored_database": target,
        "slot_id": slot["slot_id"],
        "old_incarnation": old_incarnation,
        "new_incarnation": new_incarnation,
        "old_slot_sha256": hashlib.sha256(old_raw).hexdigest(),
        "new_slot_sha256": hashlib.sha256(new_raw).hexdigest(),
        "new_slot_path": "/lab/restored-slot.json",
    }
    additions["restore-plan.json"] = json.dumps(plan, separators=(",", ":")).encode()
    need(set(additions) == RESTORE_CLIENT)
    view.update({"lab/" + name: (raw, 0o444, 0, 0) for name, raw in additions.items()})
    return view, {"plan": plan, "expires_at": expires_at}
