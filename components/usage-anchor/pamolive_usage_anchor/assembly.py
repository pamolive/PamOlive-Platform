"""Trusted startup only; construction performs no migrations and starts no listener."""

from .authority import Authority
from .codec import MAX_MATERIALS
from .http import Application
from .ledger import PostgresLedger
from .service import Service
from .slot import ReadOnly, SlotFile


def application(*, slot_path, slot_sha256, materials_path, connect, owner_uid=0):
    guard = SlotFile(slot_path, slot_sha256, owner_uid)
    materials = ReadOnly(
        materials_path,
        guard.check().expected()["authority_materials_sha256"],
        MAX_MATERIALS,
        owner_uid,
    )
    ledger = PostgresLedger(connect)
    ledger.startup(guard.check())
    return Application(Service(Authority(guard, materials), ledger))
