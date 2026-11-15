"""Trusted startup composition only; imports neither Django nor AEAD/provider code."""

from .admission import Reservations
from .asgi import Application
from .ledger import PostgresLedger
from .slot import SlotFile


def application(*, slot_path, slot_sha256, connect, owner_uid=0):
    guard = SlotFile(slot_path, slot_sha256, owner_uid)
    ledger = PostgresLedger(connect)
    ledger.startup(guard.check())
    return Application(Reservations(guard, ledger))
