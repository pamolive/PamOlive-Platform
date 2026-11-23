"""Offline tests for reading the source checkpoint of a closed witness."""

import traceback
import unittest
from unittest.mock import Mock, patch

from fixtures import Fixture
from pamolive_usage_anchor import assembly, codec, ledger
from pamolive_usage_anchor.audit_archive import GENESIS_SHA256, Checkpoint
from psycopg import OperationalError
from test_cold_history import connector, observer_rows


class CheckpointCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slot = Fixture().slot
        expected = cls.slot.expected()
        cls.checkpoint = Checkpoint(
            context_id=cls.slot.context_id,
            slot_sha256=cls.slot.source_sha256,
            organization_id=expected["organization_id"],
            installation_id=expected["installation_id"],
            last_seq=9,
            head_sha256="f" * 64,
        )

    def source(self):
        return {"seq": self.checkpoint.last_seq, "head_sha256": self.checkpoint.head_sha256}

    def test_capture_reads_observer_fence_and_head_in_one_read_only_snapshot(self):
        connect, cursor = connector([*observer_rows(), self.source()])
        result = ledger.PostgresHistory(connect).capture_checkpoint(self.slot)
        self.assertEqual(result, self.checkpoint)
        connect.assert_called_once_with()
        connection = connect.return_value
        connection.transaction.assert_called_once_with()
        connection.transaction.return_value.__exit__.assert_called_once_with(None, None, None)
        connection.__exit__.assert_called_once_with(None, None, None)
        queries = [call.args for call in cursor.execute.call_args_list]
        self.assertEqual(len(queries), 9)
        self.assertEqual(queries[0], ("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",))
        self.assertEqual(queries[4][1], ("usage_anchor_observer",))
        fence_sql, fence_args = queries[7]
        self.assertIn("c.serving_state='closed'", fence_sql)
        self.assertIn("l.serving_state='closed' AND l.epoch>%s", fence_sql)
        self.assertEqual(
            fence_args[:5],
            (
                self.checkpoint.context_id,
                self.checkpoint.installation_id,
                self.checkpoint.organization_id,
                self.slot.witness_incarnation,
                self.checkpoint.slot_sha256,
            ),
        )
        self.assertEqual(
            queries[8],
            (
                "SELECT seq,head_sha256 FROM pam_usage_anchor.audit_heads WHERE context_id=%s",
                (self.checkpoint.context_id,),
            ),
        )
        cursor.fetchall.assert_not_called()

    def test_role_or_fence_refusal_precedes_head_access(self):
        wrong_role = observer_rows()
        wrong_role[0]["correct"] = False
        writable_role = observer_rows()
        writable_role[2]["relation_write"] = True
        for rows, expected in (
            (wrong_role, ("unavailable", 503)),
            (writable_role, ("unavailable", 503)),
            (observer_rows(fenced=False), ("context_refused", 403)),
        ):
            with self.subTest(expected=expected):
                connect, cursor = connector(rows)
                with self.assertRaises(codec.Error) as caught:
                    ledger.PostgresHistory(connect).capture_checkpoint(self.slot)
                self.assertEqual((caught.exception.code, caught.exception.status), expected)
                self.assertFalse(
                    any("audit_heads" in call.args[0] for call in cursor.execute.call_args_list)
                )

    def test_missing_or_malformed_head_refuses_checkpoint(self):
        for head in (
            None,
            {},
            {"seq": self.checkpoint.last_seq},
            {**self.source(), "seq": True},
            {**self.source(), "seq": -1},
            {**self.source(), "seq": 2**63},
            {**self.source(), "seq": 0},
            {**self.source(), "head_sha256": GENESIS_SHA256},
            {**self.source(), "head_sha256": "G" * 64},
        ):
            with self.subTest(head=head):
                connect, _ = connector([*observer_rows(), head])
                with self.assertRaises(codec.Error) as caught:
                    ledger.PostgresHistory(connect).capture_checkpoint(self.slot)
                self.assertEqual(
                    (caught.exception.code, caught.exception.status), ("context_refused", 403)
                )

    def test_database_failure_even_at_transaction_exit_refuses_checkpoint(self):
        for failure_phase in ("read", "exit"):
            with self.subTest(phase=failure_phase):
                connect, cursor = connector([*observer_rows(), self.source()])
                connection = connect.return_value
                diagnostic = OperationalError("synthetic private database diagnostic")
                if failure_phase == "read":
                    cursor.fetchone.side_effect = [*observer_rows(), diagnostic]
                else:
                    connection.transaction.return_value.__exit__.side_effect = diagnostic
                with self.assertRaises(codec.Error) as caught:
                    try:
                        ledger.PostgresHistory(connect).capture_checkpoint(self.slot)
                    except codec.Error:
                        self.assertNotIn(
                            "synthetic private database diagnostic", traceback.format_exc()
                        )
                        raise
                self.assertEqual(
                    (caught.exception.code, caught.exception.status), ("unavailable", 503)
                )
                connection.__exit__.assert_called_once()

    def capture_from_slot_file(self, guard, connect):
        with patch.object(assembly, "SlotFile", return_value=guard) as slot_file:
            try:
                return assembly.capture_audit_checkpoint(
                    slot_path="synthetic-slot",
                    slot_sha256=self.slot.source_sha256,
                    connect=connect,
                    owner_uid=123,
                )
            finally:
                slot_file.assert_called_once_with("synthetic-slot", self.slot.source_sha256, 123)

    def test_assembly_checks_pinned_slot_before_and_after_database_capture(self):
        guard = Mock()
        connect, _ = connector([*observer_rows(), self.source()])
        connection = connect.return_value

        def recheck():
            if guard.check.call_count == 1:
                connect.assert_not_called()
            else:
                connection.__exit__.assert_called_once()
            return self.slot

        guard.check.side_effect = recheck
        self.assertEqual(self.capture_from_slot_file(guard, connect), self.checkpoint)
        self.assertEqual(guard.check.call_count, 2)

    def test_bad_initial_pin_does_not_enter_the_database(self):
        guard = Mock()
        guard.check.side_effect = codec.Error("context_refused", 403)
        connect = Mock()
        with self.assertRaisesRegex(codec.Error, "^context_refused$"):
            self.capture_from_slot_file(guard, connect)
        connect.assert_not_called()

    def test_pin_changed_after_capture_discards_the_checkpoint(self):
        guard = Mock()
        guard.check.side_effect = [self.slot, codec.Error("context_refused", 403)]
        connect, _ = connector([*observer_rows(), self.source()])
        with self.assertRaisesRegex(codec.Error, "^context_refused$"):
            self.capture_from_slot_file(guard, connect)
        self.assertEqual(guard.check.call_count, 2)
        connect.assert_called_once_with()
