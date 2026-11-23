"""Offline checks for retrieving a committed receipt through the history route."""

import unittest
from unittest.mock import MagicMock, Mock

from fixtures import Fixture, uid
from pamolive_usage_anchor import codec
from pamolive_usage_anchor.client import VaultMirror
from pamolive_usage_anchor.service import Service
from pamolive_vault_contracts import FullTranscript, body_hash, final_assertions_digest

ROUTE = "/v1/operations/observe-terminal"


class TerminalHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = Fixture()
        cls.operation_id, cls.reservation_id = uid(901), uid(902)
        now = cls.fixture.now
        transcript = FullTranscript(
            cls.fixture.draft, codec.b64(bytes(range(32))), "a" * 64, now, now, now + 30
        )
        cls.bundle_raw = cls.fixture.final_bundle(transcript, cls.operation_id, negative=True)
        cls.other_bundle = cls.fixture.final_bundle(
            transcript, cls.operation_id, negative=True, spaced=True
        )
        cls.body_hash = body_hash(transcript)
        cls.final_digest = final_assertions_digest(cls.bundle_raw)
        cls.terminal = {
            "schema": "pamolive.vault.usage-terminal/1",
            "operation_id": cls.operation_id,
            "reservation_id": cls.reservation_id,
            "state": "refused_no_release",
            "body_hash": cls.body_hash,
            "final_assertions_digest": cls.final_digest,
            "issued_at": now,
            "expires_at": now + 30,
            "terminal_at": now + 1,
            "authorized": False,
        }
        cls.terminal_raw = codec.encode(cls.terminal, 4096, special=True)

    def setUp(self):
        # The operation has expired, while the authenticated peer and slot remain current.
        self.now = self.fixture.now + 60
        self.row = {
            "reservation_id": self.reservation_id,
            "state": "refused_no_release",
            "body_hash": self.body_hash,
            "final_bundle": self.bundle_raw,
            "final_digest": self.final_digest,
            "terminal_response": self.terminal_raw,
        }
        self.ledger = Mock(spec_set=["read_terminal", "transaction"])
        self.ledger.read_terminal.return_value = self.row
        self.ledger.transaction.side_effect = AssertionError("history attempted mutation")
        self.service = Service(self.fixture.authority, self.ledger, lambda: self.now)
        self.addCleanup(self.ledger.transaction.assert_not_called)

    def assert_refused(self, status, code, *, raw=None, der=None):
        with self.assertRaises(codec.Error) as caught:
            self.service.dispatch(
                ROUTE,
                self.bundle_raw if raw is None else raw,
                self.fixture.vault_der if der is None else der,
            )
        self.assertEqual((caught.exception.status, caught.exception.code), (status, code))

    def test_exact_terminal_dispatch_after_operation_expiry(self):
        peer = self.fixture.slot.peer(self.fixture.vault_der, self.now, "usage-anchor.vault/1")
        self.assertEqual(
            self.service.dispatch(ROUTE, self.bundle_raw, self.fixture.vault_der),
            (200, self.terminal_raw),
        )
        self.ledger.read_terminal.assert_called_once_with(
            self.fixture.slot, peer, self.operation_id
        )

    def test_ineligible_operation_refused_without_mutation(self):
        # The ledger projects missing, pending and out-of-scope operations as no row.
        self.ledger.read_terminal.return_value = None
        self.assert_refused(403, "context_refused")
        self.ledger.read_terminal.assert_called_once()

    def test_wrong_peer_purpose_refused_before_lookup(self):
        self.assert_refused(403, "caller_refused", der=self.fixture.activation_der)
        self.ledger.read_terminal.assert_not_called()

    def test_exact_bytes_and_digest_required(self):
        self.assertNotEqual(self.bundle_raw, self.other_bundle)
        self.assert_refused(409, "idempotency_conflict", raw=self.other_bundle)
        self.row["final_digest"] = "b" * 64
        self.assert_refused(409, "idempotency_conflict")

    def test_corrupted_stored_receipt_is_never_returned(self):
        for change in (
            {"authorized": True},
            {"reservation_id": uid(903)},
            {"state": "consumed_no_release"},
        ):
            with self.subTest(change=change):
                self.row["terminal_response"] = codec.encode(
                    self.terminal | change, 4096, special=True
                )
                self.assert_refused(403, "context_refused")

    def test_current_peer_is_rechecked_after_lookup(self):
        def expire_during_read(*_):
            self.now = self.fixture.slot.not_after + 1
            return self.row

        self.ledger.read_terminal.side_effect = expire_during_read
        with self.assertRaises(codec.Error) as caught:
            self.service.dispatch(ROUTE, self.bundle_raw, self.fixture.vault_der)
        self.assertEqual(caught.exception.status, 403)
        self.ledger.read_terminal.assert_called_once()

    def mirror_client(self, row):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        scope = connection.transaction.return_value
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = row
        witness = Mock(spec_set=["request"])

        def request(route, raw):
            scope.__exit__.assert_called_once_with(None, None, None)
            connection.__exit__.assert_called_once_with(None, None, None)
            self.assertEqual((route, raw), (ROUTE, self.bundle_raw))
            return 200, self.terminal_raw

        witness.request.side_effect = request
        return VaultMirror(lambda: connection, witness), cursor, witness

    def test_vault_reads_original_binding_before_request_without_persisting_receipt(self):
        mirror, cursor, witness = self.mirror_client(
            {
                "operation_id": self.operation_id,
                "body_hash": self.body_hash,
                "state": "bound",
                "terminal_response": None,
            }
        )
        self.assertEqual(
            mirror.observe_terminal(self.reservation_id, self.bundle_raw), self.terminal_raw
        )
        witness.request.assert_called_once_with(ROUTE, self.bundle_raw)
        self.assertEqual(len(cursor.execute.call_args_list), 3)
        transaction, timeout, lookup = (call.args for call in cursor.execute.call_args_list)
        self.assertEqual(transaction, ("SET TRANSACTION READ ONLY",))
        self.assertEqual(timeout, ("SET LOCAL statement_timeout='3000ms'",))
        self.assertTrue(lookup[0].startswith("SELECT "))
        self.assertNotIn("FOR UPDATE", lookup[0])
        self.assertEqual(lookup[1], (self.reservation_id,))

    def test_vault_missing_binding_refused_before_network(self):
        mirror, _, witness = self.mirror_client(None)
        with self.assertRaises(codec.Error) as caught:
            mirror.observe_terminal(self.reservation_id, self.bundle_raw)
        self.assertEqual((caught.exception.status, caught.exception.code), (403, "context_refused"))
        witness.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
