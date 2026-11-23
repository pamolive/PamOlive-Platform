"""Trusted startup only; construction performs no migrations and starts no listener."""

from .audit_archive import MAX_PAGE_EVENTS
from .authority import Authority
from .codec import MAX_MATERIALS
from .http import Application, HistoryApplication
from .ledger import PostgresHistory, PostgresLedger
from .service import HistoryService, Service
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


def history_application(*, slot_path, slot_sha256, connect, owner_uid=0):
    """Start an observer for an already closed and fenced witness."""
    guard = SlotFile(slot_path, slot_sha256, owner_uid)
    ledger = PostgresHistory(connect)
    ledger.startup(guard.check())
    return HistoryApplication(HistoryService(guard, ledger))


def audit_archive_page(
    *,
    slot_path,
    slot_sha256,
    connect,
    checkpoint,
    after_seq=0,
    limit=MAX_PAGE_EVENTS,
    owner_uid=0,
):
    """Export one observer page through the trusted, pinned slot path."""
    guard = SlotFile(slot_path, slot_sha256, owner_uid)
    page = PostgresHistory(connect).archive_page(guard.check(), checkpoint, after_seq, limit=limit)
    guard.check()
    return page
