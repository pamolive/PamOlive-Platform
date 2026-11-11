"""Fail-closed origin status for observation consumers.

An event's typed column is a routing claim. Consumers that attribute collector
coverage or display an authenticated origin must also verify its V8 receipt.
Historical rows retain an explicitly unknown origin.
"""

from .provenance import verify_provenance_receipt


def verified_origin_status(event):
    receipt = getattr(event, "provenance_receipt", None)
    if event.provenance_channel == "legacy_unknown":
        return "legacy_unknown" if receipt is None else "invalid_provenance"
    if event.provenance_channel not in {"manual", "collector", "internal"}:
        return "invalid_provenance"
    if receipt is None or not verify_provenance_receipt(receipt):
        return "invalid_provenance"
    return event.provenance_channel


def verified_origin(event):
    """Short public name for exports and other read paths."""
    return verified_origin_status(event)
