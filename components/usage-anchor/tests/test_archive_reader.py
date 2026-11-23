"""Offline tests for the bounded PostgreSQL observer export."""

import traceback
import unittest
from dataclasses import replace
from unittest.mock import Mock, patch

from fixtures import Fixture, uid
from pamolive_usage_anchor import assembly, codec, ledger
from pamolive_usage_anchor.audit_archive import (
    AUDIT_DOMAIN,
    GENESIS_SHA256,
    MAX_PAGE_EVENTS,
    ArchiveVerifier,
    Checkpoint,
)
from psycopg import OperationalError
from test_cold_history import connector, observer_rows


class ArchiveReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slot = Fixture().slot
        cls.events = []
        previous = GENESIS_SHA256
        for seq, event, subject in (
            (1, "activation_challenge", uid(901)),
            (2, "closed_and_fenced", cls.slot.context_id),
        ):
            raw = codec.encode(
                {"event": event, "operation_id": subject, "at": seq, "digest": ""}, 4096
            )
            current = codec.sha(AUDIT_DOMAIN + bytes.fromhex(previous) + raw)
            cls.events.append(
                {
                    "seq": seq,
                    "event_bytes": raw,
                    "previous_sha256": previous,
                    "event_sha256": current,
                }
            )
            previous = current
        expected = cls.slot.expected()
        cls.checkpoint = Checkpoint(
            cls.slot.context_id,
            cls.slot.source_sha256,
            expected["organization_id"],
            expected["installation_id"],
            2,
            previous,
        )

    def head(self):
        return {"seq": self.checkpoint.last_seq, "head_sha256": self.checkpoint.head_sha256}

    def test_paged_reader_checks_role_fence_head_and_cursor_in_one_snapshot(self):
        verifier = ArchiveVerifier(self.checkpoint)
        for event in self.events:
            after_seq = verifier.after_seq
            rows = [*observer_rows(), self.head()]
            if after_seq:
                rows.append({"event_sha256": verifier.head_sha256})
            connect, cursor = connector(rows)
            cursor.fetchall.return_value = [event]
            connection = connect.return_value

            def encode_page(*args, **kwargs):
                connection.__exit__.assert_called_once()
                connection.transaction.return_value.__exit__.assert_called_once()
                connection.cursor.return_value.__exit__.assert_called_once()
                return encoder(*args, **kwargs)

            encoder = ledger.encode_archive_page
            with patch.object(ledger, "encode_archive_page", side_effect=encode_page):
                page = ledger.PostgresHistory(connect).archive_page(
                    self.slot, self.checkpoint, after_seq, limit=1
                )
            connect.assert_called_once_with()
            connection.transaction.assert_called_once_with()
            queries = [call.args for call in cursor.execute.call_args_list]
            self.assertEqual(
                queries[0], ("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",)
            )
            self.assertEqual(queries[4][1], ("usage_anchor_observer",))
            self.assertIn("c.tenant_id=%s", queries[7][0])
            self.assertIn("c.serving_state='closed'", queries[7][0])
            self.assertIn("FROM pam_usage_anchor.audit_heads", queries[8][0])
            self.assertEqual(queries[8][1], (self.slot.context_id,))
            if after_seq:
                self.assertIn("WHERE context_id=%s AND seq=%s", queries[9][0])
                self.assertEqual(queries[9][1], (self.slot.context_id, after_seq))
            self.assertEqual(len(queries), 10 + after_seq)
            self.assertIn(
                "WHERE context_id=%s AND seq>%s AND seq<=%s ORDER BY seq LIMIT %s", queries[-1][0]
            )
            self.assertEqual(queries[-1][1], (self.slot.context_id, after_seq, 2, 1))
            verifier.accept(page)
        self.assertEqual(verifier.finish(), self.checkpoint)

    def test_refuses_mismatched_slot_identity_without_database_access(self):
        for key, value in (
            ("context_id", uid(901)),
            ("installation_id", uid(902)),
            ("organization_id", uid(903)),
            ("slot_sha256", "f" * 64),
        ):
            with self.subTest(key=key):
                connect = Mock()
                checkpoint = replace(self.checkpoint, **{key: value})
                with self.assertRaisesRegex(codec.Error, "^context_refused$"):
                    ledger.PostgresHistory(connect).archive_page(self.slot, checkpoint, 0)
                connect.assert_not_called()

    def test_refuses_unbounded_or_completed_requests_without_database_access(self):
        connect = Mock()
        for after_seq, limit in (
            (-1, 1),
            (2, 1),
            (3, 1),
            (False, 1),
            (0, 0),
            (0, True),
            (0, MAX_PAGE_EVENTS + 1),
        ):
            with self.subTest(after_seq=after_seq, limit=limit):
                with self.assertRaisesRegex(codec.Error, "^invalid_request$"):
                    ledger.PostgresHistory(connect).archive_page(
                        self.slot, self.checkpoint, after_seq, limit=limit
                    )
        connect.assert_not_called()

    def test_refuses_unfenced_slot_before_loading_checkpoint_or_events(self):
        connect, cursor = connector(observer_rows(fenced=False))
        with self.assertRaisesRegex(codec.Error, "^context_refused$"):
            ledger.PostgresHistory(connect).archive_page(self.slot, self.checkpoint, 0)
        self.assertFalse(
            any("pam_usage_anchor.audit_" in call.args[0] for call in cursor.execute.call_args_list)
        )
        cursor.fetchall.assert_not_called()

    def test_refuses_missing_or_mismatched_live_head_before_loading_events(self):
        for head in (None, dict(self.head(), seq=1), dict(self.head(), head_sha256="f" * 64)):
            with self.subTest(head=head):
                connect, cursor = connector([*observer_rows(), head])
                with self.assertRaisesRegex(codec.Error, "^context_refused$"):
                    ledger.PostgresHistory(connect).archive_page(self.slot, self.checkpoint, 1)
                self.assertIn("pam_usage_anchor.audit_heads", cursor.execute.call_args.args[0])
                cursor.fetchall.assert_not_called()

    def test_refuses_missing_cursor_row_or_incomplete_page(self):
        connect, cursor = connector([*observer_rows(), self.head(), None])
        with self.assertRaisesRegex(codec.Error, "^context_refused$"):
            ledger.PostgresHistory(connect).archive_page(self.slot, self.checkpoint, 1)
        cursor.fetchall.assert_not_called()

        connect, cursor = connector([*observer_rows(), self.head()])
        cursor.fetchall.return_value = [self.events[0]]
        with self.assertRaisesRegex(codec.Error, "^invalid_request$"):
            ledger.PostgresHistory(connect).archive_page(self.slot, self.checkpoint, 0)
        connect.return_value.__exit__.assert_called_once()

    def test_database_diagnostics_do_not_escape(self):
        connect, cursor = connector([*observer_rows(), self.head()])
        cursor.fetchall.side_effect = OperationalError("sensitive synthetic database diagnostic")
        try:
            ledger.PostgresHistory(connect).archive_page(self.slot, self.checkpoint, 0)
        except codec.Error as error:
            self.assertEqual((error.status, error.code), (503, "unavailable"))
            self.assertNotIn("sensitive synthetic database diagnostic", traceback.format_exc())
        else:
            self.fail("The database failure did not fail the export")
        connect.return_value.__exit__.assert_called_once()

    def test_trusted_assembly_rechecks_slot_after_observer_returns(self):
        guard = Mock()
        guard.check.side_effect = [self.slot, codec.Error("context_refused", 403)]
        connect = Mock()
        with (
            patch.object(assembly, "SlotFile", return_value=guard) as slot_file,
            patch.object(assembly, "PostgresHistory") as history,
            self.assertRaisesRegex(codec.Error, "^context_refused$"),
        ):
            assembly.audit_archive_page(
                slot_path="synthetic-slot",
                slot_sha256=self.slot.source_sha256,
                connect=connect,
                checkpoint=self.checkpoint,
                owner_uid=123,
            )
        slot_file.assert_called_once_with("synthetic-slot", self.slot.source_sha256, 123)
        history.assert_called_once_with(connect)
        history.return_value.archive_page.assert_called_once_with(
            self.slot, self.checkpoint, 0, limit=MAX_PAGE_EVENTS
        )
        self.assertEqual(guard.check.call_count, 2)
