"""Offline archive integrity and scope tests using synthetic W events."""

import hashlib
import unittest
from dataclasses import FrozenInstanceError, asdict, replace
from types import SimpleNamespace
from uuid import UUID

from pamolive_usage_anchor import audit_archive as archive
from pamolive_usage_anchor import codec


def uid(number):
    return str(UUID(int=number))


CONTEXT = uid(1)
ORGANIZATION = uid(2)
INSTALLATION = uid(3)
SLOT = "ac" * 32
GENESIS = "0" * 64


def event(kind, subject, value=""):
    return {"event": kind, "operation_id": subject, "at": 1782200000, "digest": value}


def audit_rows(events):
    previous = GENESIS
    rows = []
    for seq, value in enumerate(events, 1):
        raw = value if type(value) is bytes else codec.encode(value, 4096)
        current = hashlib.sha256(
            b"pamolive.vault.usage-audit.v1\0" + bytes.fromhex(previous) + raw
        ).hexdigest()
        rows.append(
            {
                "seq": seq,
                "event_bytes": raw,
                "previous_sha256": previous,
                "event_sha256": current,
            }
        )
        previous = current
    return rows


def checkpoint(rows):
    head = rows[-1]["event_sha256"] if rows else GENESIS
    return archive.Checkpoint(CONTEXT, SLOT, ORGANIZATION, INSTALLATION, len(rows), head)


def page(expected, rows, after=0, limit=1):
    previous = rows[after - 1]["event_sha256"] if after else GENESIS
    return archive.encode_archive_page(
        expected, after, previous, rows[after : after + limit], limit=limit
    )


def update(raw, change):
    value = codec.parse(raw, archive.MAX_PAGE_BYTES, **archive.PAGE_PROFILE)
    change(value)
    return codec.encode(value, archive.MAX_PAGE_BYTES, **archive.PAGE_PROFILE)


class AuditArchiveTests(unittest.TestCase):
    def setUp(self):
        self.rows = audit_rows(
            [
                event("activation_challenge", uid(10)),
                event("activated", uid(10), "a" * 64),
                event("bound", uid(11), "b" * 64),
                event("consumed_no_release", uid(11), "c" * 64),
                event("refused_no_release", uid(12), "d" * 64),
                event("activation_revoked", "e" * 64),
                event("closed_and_fenced", CONTEXT),
            ]
        )
        self.checkpoint = checkpoint(self.rows)

    def test_canonical_pages_preserve_every_existing_audit_event(self):
        verifier = archive.ArchiveVerifier(self.checkpoint)
        for after in (0, 3, 6):
            raw = page(self.checkpoint, self.rows, after, limit=3)
            parsed = codec.parse(raw, archive.MAX_PAGE_BYTES, **archive.PAGE_PROFILE)
            self.assertEqual(parsed["checkpoint"], asdict(self.checkpoint))
            actual = [codec.unb64(entry["event_b64"], 4096) for entry in parsed["entries"]]
            self.assertEqual(actual, [row["event_bytes"] for row in self.rows[after : after + 3]])
            verifier.accept(raw)
            self.assertEqual(verifier.after_seq, min(after + 3, len(self.rows)))
        self.assertIs(verifier.finish(), self.checkpoint)

    def test_independent_anchor_rejects_foreign_scope_and_terminal_head(self):
        raw = page(self.checkpoint, self.rows)
        for changes in (
            {"context_id": uid(20)},
            {"organization_id": uid(21)},
            {"installation_id": uid(22)},
            {"slot_sha256": "f" * 64},
            {"head_sha256": "a" * 64},
            {"last_seq": self.checkpoint.last_seq + 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(codec.Error):
                archive.ArchiveVerifier(replace(self.checkpoint, **changes)).accept(raw)

    def test_checkpoint_is_frozen_and_validates_slot_identity(self):
        slot = SimpleNamespace(
            context_id=CONTEXT,
            source_sha256=SLOT,
            expected=lambda: {"organization_id": ORGANIZATION, "installation_id": INSTALLATION},
        )
        self.checkpoint.require_slot(slot)
        for changes in (
            {"context_id": uid(20)},
            {"organization_id": uid(21)},
            {"installation_id": uid(22)},
            {"slot_sha256": "f" * 64},
        ):
            with self.subTest(changes=changes), self.assertRaises(codec.Error) as failure:
                replace(self.checkpoint, **changes).require_slot(slot)
            self.assertEqual(
                (failure.exception.code, failure.exception.status), ("context_refused", 403)
            )
        with self.assertRaises(FrozenInstanceError):
            self.checkpoint.last_seq = 0

    def test_checkpoint_refuses_bad_identifiers_digests_and_genesis(self):
        for changes in (
            {"context_id": "1"},
            {"organization_id": None},
            {"installation_id": uid(10).upper()},
            {"slot_sha256": SLOT.upper()},
            {"last_seq": True},
            {"last_seq": -1},
            {"last_seq": 2**63},
            {"last_seq": 0},
            {"head_sha256": GENESIS},
        ):
            with self.subTest(changes=changes), self.assertRaises(codec.Error):
                replace(self.checkpoint, **changes)

    def test_reorder_replay_and_incomplete_chain_fail_without_advancing(self):
        verifier = archive.ArchiveVerifier(self.checkpoint)
        with self.assertRaises(codec.Error):
            verifier.accept(page(self.checkpoint, self.rows, 2, limit=2))
        first = page(self.checkpoint, self.rows, limit=2)
        verifier.accept(first)
        for action in (lambda: verifier.accept(first), verifier.finish):
            with self.assertRaises(codec.Error):
                action()
        self.assertEqual(
            (verifier.after_seq, verifier.head_sha256), (2, self.rows[1]["event_sha256"])
        )
        verifier.accept(page(self.checkpoint, self.rows, 2, limit=5))
        self.assertEqual(verifier.finish(), self.checkpoint)
        with self.assertRaises(codec.Error):
            verifier.accept(first)

    def test_late_tamper_leaves_a_previously_verified_cursor_intact(self):
        verifier = archive.ArchiveVerifier(self.checkpoint)
        verifier.accept(page(self.checkpoint, self.rows, limit=2))
        old = verifier.after_seq, verifier.head_sha256
        raw = page(self.checkpoint, self.rows, 2, limit=5)
        corrupted = update(raw, lambda doc: doc["entries"][-1].update(event_sha256="f" * 64))
        with self.assertRaises(codec.Error):
            verifier.accept(corrupted)
        self.assertEqual((verifier.after_seq, verifier.head_sha256), old)
        verifier.accept(raw)
        self.assertEqual(verifier.finish(), self.checkpoint)

    def test_external_head_is_required_even_for_a_valid_rewritten_chain(self):
        altered = audit_rows([event("activation_challenge", uid(99))])
        rewritten = checkpoint(altered)
        verifier = archive.ArchiveVerifier(self.checkpoint)
        with self.assertRaises(codec.Error):
            verifier.accept(page(rewritten, altered))
        with self.assertRaises(codec.Error):
            archive.encode_archive_page(
                self.checkpoint, self.checkpoint.last_seq - 1, GENESIS, altered, limit=1
            )
        with self.assertRaises(codec.Error):
            archive.encode_archive_page(
                replace(rewritten, head_sha256="f" * 64), 0, GENESIS, altered, limit=1
            )

    def test_noncanonical_or_unrecognized_page_and_event_fields_fail(self):
        raw = page(self.checkpoint, self.rows)
        for malformed in (
            raw + b"\n",
            update(raw, lambda doc: doc.update(extra="synthetic")),
            update(raw, lambda doc: doc["entries"][0].update(extra="synthetic")),
            update(raw, lambda doc: doc["entries"][0].update(event_b64="====")),
            update(raw, lambda doc: doc["checkpoint"].update(extra="synthetic")),
        ):
            with self.subTest(malformed=malformed[:80]), self.assertRaises(codec.Error):
                archive.ArchiveVerifier(self.checkpoint).accept(malformed)
        cases = (
            event("future_event", uid(10)),
            event("closed_and_fenced", uid(99)),
            event("activation_revoked", uid(10)),
            event("bound", uid(11)),
            event("activation_challenge", uid(10), "d" * 64),
            {**event("activation_challenge", uid(10)), "extra": "synthetic"},
            codec.encode(event("activation_challenge", uid(10)), 4096) + b"\n",
        )
        for item in cases:
            rows = audit_rows([item])
            with self.subTest(item=item), self.assertRaises(codec.Error):
                page(checkpoint(rows), rows)

    def test_count_cursor_and_digest_limits_are_checked_before_export(self):
        first, second = self.rows[:2]
        for after, prev, rows, limit in (
            (-1, GENESIS, [first], 1),
            (0, "a" * 64, [first], 1),
            (0, GENESIS, [first], 0),
            (0, GENESIS, [first], archive.MAX_PAGE_EVENTS + 1),
            (0, GENESIS, [], 1),
            (0, GENESIS, [first, second], 1),
            (0, GENESIS, [second], 1),
            (0, GENESIS, [{**first, "previous_sha256": "x" * 64}], 1),
            (0, GENESIS, [{**first, "event_sha256": "x" * 64}], 1),
            (0, GENESIS, [{**first, "extra": "synthetic"}], 1),
            (0, GENESIS, iter((first,)), 1),
        ):
            with self.subTest(after=after, limit=limit), self.assertRaises(codec.Error):
                archive.encode_archive_page(self.checkpoint, after, prev, rows, limit=limit)

    def test_bounded_pages_cover_a_chain_longer_than_one_page(self):
        count = archive.MAX_PAGE_EVENTS + 1
        rows = audit_rows([event("activation_challenge", uid(i)) for i in range(100, 100 + count)])
        expected = checkpoint(rows)
        verifier = archive.ArchiveVerifier(expected)
        with self.assertRaises(codec.Error):
            verifier.accept(b"x" * (archive.MAX_PAGE_BYTES + 1))
        verifier.accept(page(expected, rows, limit=archive.MAX_PAGE_EVENTS))
        self.assertEqual(verifier.after_seq, archive.MAX_PAGE_EVENTS)
        verifier.accept(page(expected, rows, archive.MAX_PAGE_EVENTS))
        self.assertEqual(verifier.finish(), expected)

    def test_empty_checkpoint_is_exact_and_rejects_repeated_empty_pages(self):
        expected = checkpoint([])
        verifier = archive.ArchiveVerifier(expected)
        self.assertEqual(verifier.finish(), expected)
        raw = page(expected, [])
        verifier.accept(raw)
        self.assertEqual(verifier.finish(), expected)
        with self.assertRaises(codec.Error):
            verifier.accept(raw)


if __name__ == "__main__":
    unittest.main()
