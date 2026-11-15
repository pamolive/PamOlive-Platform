"""PREPARED ONLY: explicit new-lab TLS/PostgreSQL reception. Never imported by pure discovery.

Root must separately authorize/provision a new DB and TLS listener. No defaults,
existing DSN, historical database, automatic fixture generation or network fallback.
"""

import argparse
import concurrent.futures
import http.client
import json
import ssl
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psycopg
from pamolive_vault_contracts import parse_draft, serialize_draft
from pamolive_vault_runtime.admission import Reservations
from pamolive_vault_runtime.bounded import Refusal, need
from pamolive_vault_runtime.ledger import PostgresLedger
from pamolive_vault_runtime.slot import SlotFile
from serve_lab import connector, lab_inputs, local_bytes

VALUES = None


def request_copy(*, rotate=False, fresh=True):
    value = json.loads(local_bytes(VALUES["request_file"], 65536))
    draft = parse_draft(json.dumps(value["draft"]).encode())
    if fresh:
        draft = replace(draft, idempotency_key=str(uuid4()), request_id=str(uuid4()))
    if rotate:
        import hashlib

        der = local_bytes(VALUES["client_b_der"], 16384)
        draft = replace(draft, broker_certificate_sha256=hashlib.sha256(der).hexdigest())
    value["draft"] = json.loads(serialize_draft(draft))
    return value


def wire(value):
    return json.dumps(value, separators=(",", ":")).encode()


def client(*, identity="a", bad=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode, context.check_hostname = ssl.CERT_REQUIRED, True
    context.load_verify_locations(cafile=VALUES["server_ca"])
    context.keylog_filename = None
    if bad is not None:
        context.load_cert_chain(bad["certificate"], bad["private_key"])
    elif identity is not None:
        context.load_cert_chain(
            VALUES[f"client_{identity}_certificate"], VALUES[f"client_{identity}_key"]
        )
    return http.client.HTTPSConnection(
        VALUES["server_host"], VALUES["port"], context=context, timeout=5
    )


def post(connection, value, headers=None):
    body = wire(value)
    connection.putrequest("POST", "/v1/reservations", skip_accept_encoding=True)
    for name, header in {
        "content-type": "application/json",
        "content-length": str(len(body)),
        **(headers or {}),
    }.items():
        connection.putheader(name, header)
    connection.endheaders(body)
    response = connection.getresponse()
    raw = response.read(1025)
    need(len(raw) <= 1024)
    return response.status, json.loads(raw)


class PostgreSQLReception(unittest.TestCase):
    def setUp(self):
        need(VALUES is not None)
        self.runtime = connector(VALUES["runtime_database_file"], role="vault_n0_runtime")
        self.owner = connector(VALUES["owner_database_file"], role="vault_n0_owner_lab_login")
        self.guard = SlotFile(Path(VALUES["slot_path"]), VALUES["slot_sha256"])
        with self.owner() as connection:
            need(connection.info.dbname.startswith("vault_n0_lab_"))
            # TEST OWNER ONLY, disposable lab. Never a runtime grant or production cleanup.
            connection.execute("TRUNCATE vault_reservation.audit, vault_reservation.reservations")
        self.service = Reservations(self.guard, PostgresLedger(self.runtime))
        self.der = local_bytes(VALUES["client_a_der"], 16384)

    def test_real_concurrent_writers_same_key_same_durable_row_and_nonce(self):
        raw = wire(request_copy())
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            answers = list(pool.map(lambda _: self.service.prepare(raw, self.der), range(4)))
        self.assertEqual(len({answer.reservation_id for answer in answers}), 1)
        with self.owner() as connection:
            count, nonce_size = connection.execute(
                "SELECT count(*), min(octet_length(nonce)) FROM vault_reservation.reservations"
            ).fetchone()
            self.assertEqual((count, nonce_size), (1, 32))
            self.assertEqual(
                connection.execute("SELECT count(*) FROM vault_reservation.audit").fetchone(), (1,)
            )
        restarted = Reservations(
            SlotFile(Path(VALUES["slot_path"]), VALUES["slot_sha256"]), PostgresLedger(self.runtime)
        )
        self.assertEqual(restarted.prepare(raw, self.der), answers[0])

    def test_actual_runtime_cannot_ddl_change_context_delete_or_update_reservation(self):
        forbidden = [
            "CREATE TABLE vault_reservation.forbidden_probe (x int)",
            "UPDATE vault_reservation.commissioned_state SET serving_state='closed'",
            "DELETE FROM vault_reservation.reservations",
            "UPDATE vault_reservation.reservations SET expires_at=expires_at+30",
            "SET ROLE vault_n0_owner",
        ]
        for statement in forbidden:
            with (
                self.subTest(statement=statement),
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                with self.runtime() as connection:
                    connection.execute(statement)
        for role, name in (
            ("web_n0_lab", "web_database_file"),
            ("worker_n0_lab", "worker_database_file"),
        ):
            with self.subTest(role=role), self.assertRaises(psycopg.Error):
                with connector(VALUES[name], role=role)() as connection:
                    connection.execute("SELECT * FROM vault_reservation.reservations")

    def test_actual_cert_rotation_same_key_conflicts(self):
        value = request_copy()
        first = self.service.prepare(wire(value), self.der)
        import hashlib

        other_der = local_bytes(VALUES["client_b_der"], 16384)
        value["draft"]["broker_certificate_sha256"] = hashlib.sha256(other_der).hexdigest()
        with self.assertRaises(Refusal) as caught:
            self.service.prepare(wire(value), other_der)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(
            self.service.prepare(
                wire(
                    {
                        **value,
                        "draft": {
                            **value["draft"],
                            "broker_certificate_sha256": hashlib.sha256(self.der).hexdigest(),
                        },
                    }
                ),
                self.der,
            ),
            first,
        )

    def test_real_quota_and_owner_seeded_expired_retry_never_renew(self):
        need(self.guard.slot.quota == 2)
        first_raw = wire(request_copy())
        first = self.service.prepare(first_raw, self.der)
        self.service.prepare(wire(request_copy()), self.der)
        with self.assertRaises(Refusal) as caught:
            self.service.prepare(wire(request_copy()), self.der)
        self.assertEqual(caught.exception.status, 429)
        # Deliberate TEST OWNER data seeding, not a simulated claim that real time elapsed.
        with self.owner() as connection:
            before = connection.execute(
                "SELECT nonce FROM vault_reservation.reservations WHERE reservation_id=%s",
                (first.reservation_id,),
            ).fetchone()[0]
            connection.execute(
                "UPDATE vault_reservation.reservations "
                "SET issued_at=issued_at-31, expires_at=issued_at-1"
            )
        with self.assertRaises(Refusal) as caught:
            self.service.prepare(first_raw, self.der)
        self.assertEqual(caught.exception.status, 410)
        with self.assertRaises(Refusal) as caught:
            self.service.prepare(wire(request_copy()), self.der)
        self.assertEqual(
            caught.exception.status, 429
        )  # Expiration does not delete idempotency or free retained quota.
        with self.owner() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT nonce FROM vault_reservation.reservations WHERE reservation_id=%s",
                    (first.reservation_id,),
                ).fetchone()[0],
                before,
            )

    def test_real_commit_followed_by_simulated_lost_response_retries_same_row(self):
        raw = wire(request_copy())
        real_connect = self.runtime

        class LostResponse:
            def __init__(self):
                self.connection = real_connect()

            def __enter__(self):
                self.connection.__enter__()
                return self.connection

            def __exit__(self, *args):
                self.connection.__exit__(*args)  # Real commit first.
                raise RuntimeError("synthetic lost response after commit")

        faulted = Reservations(self.guard, PostgresLedger(LostResponse))
        with self.assertRaises(Refusal) as caught:
            faulted.prepare(raw, self.der)
        self.assertEqual(caught.exception.status, 503)
        with self.owner() as connection:
            original = connection.execute(
                "SELECT reservation_id::text, nonce, issued_at, expires_at "
                "FROM vault_reservation.reservations"
            ).fetchone()
        result = self.service.prepare(raw, self.der)
        self.assertEqual(
            (result.reservation_id, result.issued_at, result.expires_at),
            (original[0], original[2], original[3]),
        )
        with self.owner() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT reservation_id::text, nonce, issued_at, expires_at "
                    "FROM vault_reservation.reservations"
                ).fetchone(),
                original,
            )

    def test_actual_declared_closed_or_changed_incarnation_refuses_before_insert(self):
        slot = self.guard.slot
        for incarnation, state in (
            (slot.expected()["ledger_incarnation"], "closed"),
            (str(uuid4()), "open"),
        ):
            try:
                with self.owner() as connection:
                    connection.execute(
                        "UPDATE vault_reservation.commissioned_state "
                        "SET incarnation=%s, serving_state=%s WHERE slot_id=%s",
                        (incarnation, state, slot.slot_id),
                    )
                with self.assertRaises(Refusal):
                    self.service.prepare(wire(request_copy()), self.der)
                with self.owner() as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT count(*) FROM vault_reservation.reservations"
                        ).fetchone(),
                        (0,),
                    )
            finally:
                # TEST OWNER restores only this disposable lab state. No runtime repair exists.
                with self.owner() as connection:
                    connection.execute(
                        "UPDATE vault_reservation.commissioned_state "
                        "SET incarnation=%s, serving_state='open' WHERE slot_id=%s",
                        (slot.expected()["ledger_incarnation"], slot.slot_id),
                    )


class TLSReception(unittest.TestCase):
    def setUp(self):
        need(VALUES is not None)
        with connector(
            VALUES["owner_database_file"], role="vault_n0_owner_lab_login"
        )() as connection:
            need(connection.info.dbname.startswith("vault_n0_lab_"))
            connection.execute("TRUNCATE vault_reservation.audit, vault_reservation.reservations")

    def test_real_tls_no_client_certificate_refused(self):
        connection = client(identity=None)
        try:
            with self.assertRaises((ssl.SSLError, ConnectionError, http.client.HTTPException)):
                post(connection, request_copy())
        finally:
            connection.close()

    def test_real_tls_unknown_ca_expired_future_client_refused(self):
        good = client()
        try:
            self.assertEqual(post(good, request_copy())[0], 200)
        finally:
            good.close()
        for row in VALUES["bad_tls_clients"]:
            connection = client(bad=row)
            try:
                with (
                    self.subTest(case=row["case"]),
                    self.assertRaises((ssl.SSLError, ConnectionError, http.client.HTTPException)),
                ):
                    post(connection, request_copy())
            finally:
                connection.close()

    def test_real_two_connections_der_never_crosses_and_keepalive_revalidates_mapping(self):
        first_value, second_value = request_copy(), request_copy(rotate=True)
        first, second = client(), client(identity="b")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [
                    pool.submit(post, first, first_value),
                    pool.submit(post, second, second_value),
                ]
                self.assertEqual([future.result()[0] for future in futures], [200, 200])
            # Each request's claimed fingerprint must match its OWN connection's DER.
            self.assertEqual(post(first, second_value)[0], 403)
            self.assertEqual(post(second, first_value)[0], 403)
        finally:
            first.close()
            second.close()

    def test_real_keepalive_original_retry_and_header_does_not_supply_identity(self):
        connection = client()
        value = request_copy()
        try:
            status, first = post(connection, value)
            self.assertEqual(
                (status, first["state"], first["authorized"]), (200, "pending_proofs", False)
            )
            status, second = post(connection, value)
            self.assertEqual((status, second), (200, first))
            status, refused = post(connection, value, {"x-client-cert": "approved"})
            self.assertEqual((status, refused["authorized"]), (400, False))
            self.assertNotIn("nonce", first)
        finally:
            connection.close()


def main():
    global VALUES
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-new-synthetic-lab", action="store_true", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    VALUES = lab_inputs(args.manifest)
    suite = unittest.TestSuite(
        [
            unittest.defaultTestLoader.loadTestsFromTestCase(PostgreSQLReception),
            unittest.defaultTestLoader.loadTestsFromTestCase(TLSReception),
        ]
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)


if __name__ == "__main__":
    main()
