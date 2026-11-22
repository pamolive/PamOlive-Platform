"""Offline startup, role separation, and route checks for the cold witness."""

import unittest
from unittest.mock import MagicMock, Mock, patch

from fixtures import Fixture, uid
from pamolive_usage_anchor import assembly, codec
from pamolive_usage_anchor.ledger import PostgresHistory, PostgresLedger
from pamolive_usage_anchor.service import OBSERVE_TERMINAL
from pamolive_vault_contracts import FullTranscript, body_hash, final_assertions_digest


def connector(rows):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = rows
    return Mock(return_value=connection), cursor


def observer_rows(fenced=True):
    return [
        {"correct": True, "rolsuper": False, "memberships": False},
        {"fsync": "on"},
        {
            "no_login": False,
            "database_owner": False,
            "temporary_create": False,
            "schema_ddl": False,
            "relation_write": False,
            "sequence_write": False,
            "elevated_execute": False,
        },
        {"fenced": fenced},
    ]


class ColdHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = Fixture()
        cls.slot = cls.fixture.slot

    def application(self, connect):
        with patch.object(assembly, "SlotFile", return_value=self.fixture.guard) as guard:
            app = assembly.history_application(
                slot_path="public-synthetic-slot",
                slot_sha256=self.slot.source_sha256,
                connect=connect,
            )
            guard.assert_called_once_with("public-synthetic-slot", self.slot.source_sha256, 0)
        self.addCleanup(app.close)
        return app

    def test_startup_binds_slot_and_fenced_lease_using_read_only_observer(self):
        connect, cursor = connector(observer_rows())
        app = self.application(connect)
        self.assertFalse(hasattr(app.service, "consume"))
        self.assertFalse(hasattr(app.service.ledger, "transaction"))
        self.assertEqual(app.routes, {OBSERVE_TERMINAL})
        calls = [entry.args for entry in cursor.execute.call_args_list]
        self.assertEqual(calls[0], ("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",))
        self.assertEqual(calls[1], ("SET LOCAL statement_timeout='3000ms'",))
        self.assertEqual(calls[2], ("SET LOCAL lock_timeout='2000ms'",))
        self.assertEqual(calls[4][1], ("usage_anchor_observer",))
        self.assertIn("has_any_column_privilege", calls[6][0])
        self.assertIn("has_table_privilege", calls[6][0])
        query, values = calls[7]
        self.assertIn("c.serving_state='closed'", query)
        self.assertIn("l.serving_state='closed' AND l.epoch>%s", query)
        self.assertNotIn("FOR UPDATE", query)
        expected = self.slot.expected()
        self.assertEqual(
            values,
            (
                self.slot.context_id,
                expected["installation_id"],
                expected["organization_id"],
                self.slot.witness_incarnation,
                self.slot.source_sha256,
                "vault-w1",
                expected["ledger_incarnation"],
                [codec.sha(self.fixture.vault_der)],
                self.slot.lease_epoch,
            ),
        )

    def test_startup_refuses_unfenced_context(self):
        connect, _ = connector(observer_rows(fenced=False))
        with self.assertRaises(codec.Error) as caught:
            self.application(connect)
        self.assertEqual((caught.exception.status, caught.exception.code), (403, "context_refused"))

    def test_role_and_effective_writes_fail_closed(self):
        wrong_role = [{"correct": False, "memberships": False}]
        cases = [wrong_role]
        for privilege in observer_rows()[2]:
            rows = observer_rows()
            rows[2][privilege] = True
            cases.append(rows)
        for rows in cases:
            with self.subTest(rows=rows):
                connect, cursor = connector(rows)
                with self.assertRaises(codec.Error) as caught:
                    self.application(connect)
                self.assertEqual(
                    (caught.exception.status, caught.exception.code), (503, "unavailable")
                )
                queries = (call.args[0] for call in cursor.execute.call_args_list)
                self.assertFalse(any("AS fenced" in query for query in queries))

    def test_regular_startup_still_refuses_closed_context(self):
        state = {
            "slot_sha256": self.slot.source_sha256,
            "witness_incarnation": self.slot.witness_incarnation,
            "serving_state": "closed",
        }
        connect, cursor = connector([{"correct": True}, {"fsync": "on"}, state])
        with self.assertRaises(codec.Error) as caught:
            PostgresLedger(connect).startup(self.slot)
        self.assertEqual((caught.exception.status, caught.exception.code), (403, "context_refused"))
        self.assertEqual(cursor.execute.call_args_list[1].args[1], ("usage_anchor_runtime",))

    def test_fence_rechecked_in_read_snapshot(self):
        connect, cursor = connector([*observer_rows(), *observer_rows(fenced=False)])
        ledger = PostgresHistory(connect)
        ledger.startup(self.slot)
        peer = self.slot.peer(self.fixture.vault_der, self.fixture.now, "usage-anchor.vault/1")
        with self.assertRaises(codec.Error) as caught:
            ledger.read_terminal(self.slot, peer, uid(901))
        self.assertEqual((caught.exception.status, caught.exception.code), (403, "context_refused"))
        queries = [call.args[0] for call in cursor.execute.call_args_list]
        self.assertEqual(sum("AS fenced" in query for query in queries), 2)
        self.assertFalse(any("o.final_bundle" in query for query in queries))

    def test_http_refuses_mutating_routes_before_body_read(self):
        connect, _ = connector(observer_rows())
        app = self.application(connect)
        handler = app.for_tls_peer(self.fixture.vault_der)

        async def receive():
            self.fail("cold endpoint tried to read an ineligible request body")

        for route in (
            "/v1/operations/bind",
            "/v1/operations/consume",
            "/v1/activations/begin",
            "/v1/activations/finish",
            "/v1/operations/unknown",
        ):
            with self.subTest(route=route):
                sent = []

                async def send(event):
                    sent.append(event)

                scope = {
                    "type": "http",
                    "method": "POST",
                    "scheme": "https",
                    "http_version": "1.1",
                    "path": route,
                    "raw_path": route.encode(),
                    "query_string": b"",
                    "headers": [],
                }
                request = handler(scope, receive, send)
                with self.assertRaises(StopIteration):
                    request.send(None)
                status, error = (
                    (400, "invalid_request")
                    if route.endswith("unknown")
                    else (403, "context_refused")
                )
                self.assertEqual(sent[0]["status"], status)
                self.assertEqual(
                    codec.parse(sent[1]["body"], 4096, special=True),
                    {"authorized": False, "error": error},
                )
        connect.assert_called_once_with()

    def test_exact_committed_receipt_runs_through_cold_dispatch(self):
        operation_id, reservation_id = uid(901), uid(902)
        now = self.fixture.now
        transcript = FullTranscript(
            self.fixture.draft, codec.b64(bytes(range(32))), "a" * 64, now, now, now + 30
        )
        bundle = self.fixture.final_bundle(transcript, operation_id, negative=True)
        final_digest = final_assertions_digest(bundle)
        terminal = codec.encode(
            {
                "schema": "pamolive.vault.usage-terminal/1",
                "operation_id": operation_id,
                "reservation_id": reservation_id,
                "state": "refused_no_release",
                "body_hash": body_hash(transcript),
                "final_assertions_digest": final_digest,
                "issued_at": now,
                "expires_at": now + 30,
                "terminal_at": now + 1,
                "authorized": False,
            },
            4096,
            special=True,
        )
        row = {
            "reservation_id": reservation_id,
            "state": "refused_no_release",
            "body_hash": body_hash(transcript),
            "final_bundle": bundle,
            "final_digest": final_digest,
            "terminal_response": terminal,
        }
        connect, cursor = connector([*observer_rows(), *observer_rows(), row])
        app = self.application(connect)
        app.service.clock = lambda: now + 60
        self.assertEqual(
            app.service.dispatch(OBSERVE_TERMINAL, bundle, self.fixture.vault_der), (200, terminal)
        )
        query, values = cursor.execute.call_args.args
        self.assertNotIn("FOR UPDATE", query)
        self.assertEqual(values[0], operation_id)
        self.assertEqual(values[-1], codec.sha(self.fixture.vault_der))
