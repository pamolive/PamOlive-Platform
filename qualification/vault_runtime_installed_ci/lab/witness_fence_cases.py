"""Exercise Vault commission boundaries in the installed two-cluster W01 lab."""

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from threading import Barrier


def require(condition):
    if not condition:
        raise AssertionError("witness_fence_case_refused")


@dataclass(frozen=True)
class Commission:
    slot_id: str
    incarnation: str
    slot_sha256: str
    serving_state: str


def change_commission(connect, old, new):
    """Commit a single compare-and-set through the synthetic owner login."""
    with connect() as conn, conn.transaction(), conn.cursor() as cursor:
        require(re.fullmatch(r"w01_[a-f0-9]{16}_vpg", conn.info.dbname) is not None)
        require(conn.info.user == "vault_n0_admin" and old.slot_id == new.slot_id)
        cursor.execute("SET LOCAL ROLE vault_n0_owner")
        cursor.execute(
            """UPDATE vault_reservation.commissioned_state
               SET incarnation=%s, slot_sha256=%s, serving_state=%s
               WHERE slot_id=%s AND incarnation=%s AND slot_sha256=%s AND serving_state=%s""",
            (
                new.incarnation,
                new.slot_sha256,
                new.serving_state,
                old.slot_id,
                old.incarnation,
                old.slot_sha256,
                old.serving_state,
            ),
        )
        require(cursor.rowcount == 1)


def vault_evidence(connect):
    """Compare full committed rows without exporting reservation or proof bytes."""
    statements = (
        "SELECT to_jsonb(r)::text FROM vault_reservation.reservations AS r ORDER BY reservation_id",
        "SELECT to_jsonb(a)::text FROM vault_reservation.audit AS a ORDER BY reservation_id",
        "SELECT to_jsonb(m)::text FROM vault_reservation.usage_mirrors AS m"
        " ORDER BY reservation_id",
    )
    with connect() as conn, conn.transaction(), conn.cursor() as cursor:
        cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        rows = []
        for statement in statements:
            cursor.execute(statement)
            rows.append(cursor.fetchall())
        return tuple(rows)


def witness_evidence(connect, context_id, bind_id, consume_id):
    with connect() as conn, conn.transaction(), conn.cursor() as cursor:
        cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        cursor.execute(
            """SELECT reservation_id, operation_id, state, bound_response, final_bundle,
                      terminal_response
               FROM pam_usage_anchor.operations
               WHERE context_id=%s AND reservation_id IN (%s,%s)""",
            (context_id, bind_id, consume_id),
        )
        rows = {str(row[0]): row[1:] for row in cursor.fetchall()}
        require(set(rows) == {bind_id, consume_id})
        cursor.execute(
            """SELECT operation_id, count(*)
               FROM pam_usage_anchor.proof_uses
               WHERE context_id=%s AND operation_id IN (%s,%s)
               GROUP BY operation_id""",
            (context_id, rows[bind_id][0], rows[consume_id][0]),
        )
        return rows, dict(cursor.fetchall())


class NoWitness:
    def __init__(self):
        self.calls = 0

    def request(self, _route, _raw):
        self.calls += 1
        raise AssertionError("fenced_vault_attempted_witness_request")


class RespondThenFence:
    def __init__(self, client, route, status, barrier, *, lose_response=False):
        self.client = client
        self.route = route
        self.status = status
        self.barrier = barrier
        self.lose_response = lose_response
        self.calls = 0
        self.response = None

    def request(self, route, raw):
        self.calls += 1
        require(self.calls == 1 and route == self.route)
        status, response = self.client.request(route, raw)
        require(status == self.status)
        self.response = response
        self.barrier.wait()
        if self.lose_response:
            from pamolive_usage_anchor.codec import Error

            raise Error("unavailable", 503)
        return status, response


def expect_error(code, status, operation, *args):
    from pamolive_usage_anchor.codec import Error

    try:
        operation(*args)
    except Error as error:
        require((error.code, error.status) == (code, status))
    else:
        raise AssertionError("fenced_vault_returned_live_response")


def expect_no_witness(connect, bind_id, consume_id, proofs):
    from pamolive_usage_anchor.client import VaultMirror

    client = NoWitness()
    mirror = VaultMirror(connect, client)
    expect_error("context_refused", 403, mirror.prepare_reserved, bind_id)
    expect_error("context_refused", 403, mirror.consume, consume_id, proofs)
    require(client.calls == 0)


def reserve_pair(fixture, connect, slot):
    from cryptography.hazmat.primitives import serialization
    from fixtures import MemoryReader, uid
    from pamolive_usage_anchor.codec import b64, parse_materials
    from pamolive_vault_contracts import serialize_draft
    from pamolive_vault_runtime.admission import Reservations
    from pamolive_vault_runtime.ledger import PostgresLedger

    reservations = Reservations(MemoryReader(slot), PostgresLedger(connect))
    broker_der = fixture.broker_cert.public_bytes(serialization.Encoding.DER)
    chain, checkpoint = parse_materials(fixture.materials)
    ids = []
    for sequence in (820, 830):
        draft = replace(fixture.draft, request_id=uid(sequence), idempotency_key=uid(sequence + 1))
        request = json.dumps(
            {
                "draft": json.loads(serialize_draft(draft)),
                "registry_chain": [b64(item) for item in chain],
                "checkpoint": b64(checkpoint),
            },
            separators=(",", ":"),
        ).encode()
        ids.append(reservations.prepare(request, broker_der).reservation_id)
    return tuple(ids)


def run_fence_cases(
    *,
    fixture,
    witness_client,
    vault_runtime_connect,
    vault_admin_connect,
    witness_observer_connect,
    advance,
):
    from fixtures import uid
    from pamolive_usage_anchor.client import MTLSClient, VaultMirror
    from pamolive_usage_anchor.codec import parse, unb64
    from pamolive_vault_contracts import parse_transcript
    from scenario import vault_slot

    advance("fence_preparation")
    require(type(witness_client) is MTLSClient)
    require((witness_client.host, witness_client.port) == ("witness.synthetic.invalid", 9443))
    slot = vault_slot(fixture)
    active = Commission(
        slot.slot_id, fixture.slot.expected()["ledger_incarnation"], slot.source_sha256, "open"
    )
    bind_id, consume_id = reserve_pair(fixture, vault_runtime_connect, slot)
    prepared = VaultMirror(vault_runtime_connect, witness_client).prepare_reserved(consume_id)
    bound = parse(prepared, 196608, string=90000, special=True)
    transcript = parse_transcript(unb64(bound["transcript_b64"], 32768))
    proofs = fixture.final_bundle(transcript, bound["operation_id"], negative=True, spaced=True)
    vault_before = vault_evidence(vault_runtime_connect)

    for phase, mismatching in (
        ("fence_slot_mismatch", replace(active, slot_sha256="f" * 64)),
        ("fence_incarnation_mismatch", replace(active, incarnation=uid(840))),
    ):
        advance(phase)
        require(mismatching != active)
        change_commission(vault_admin_connect, active, mismatching)
        try:
            expect_no_witness(vault_runtime_connect, bind_id, consume_id, proofs)
        finally:
            # Restore the open synthetic fixture before the single irreversible close.
            change_commission(vault_admin_connect, mismatching, active)

    advance("fence_concurrent_close")
    closed = replace(active, serving_state="closed")

    def close_after_witness_responses():
        change_commission(vault_admin_connect, active, closed)

    # W has committed the bind and terminal before the separate Vault owner closes V.
    # Both consume requests return the same terminal to the adapters. One adapter
    # then injects a lost response before the application can persist that terminal.
    # Keeping a V commission lock across HTTP breaks this barrier.
    require(time.time() < fixture.now + 30)
    barrier = Barrier(3, action=close_after_witness_responses, timeout=3)
    bind_client = RespondThenFence(witness_client, "/v1/operations/bind", 201, barrier)
    consume_client = RespondThenFence(witness_client, "/v1/operations/consume", 200, barrier)
    lost_client = RespondThenFence(
        witness_client, "/v1/operations/consume", 200, barrier, lose_response=True
    )
    binding = VaultMirror(vault_runtime_connect, bind_client)
    consuming = VaultMirror(vault_runtime_connect, consume_client)
    losing = VaultMirror(vault_runtime_connect, lost_client)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = (
            pool.submit(expect_error, "context_refused", 403, binding.prepare_reserved, bind_id),
            pool.submit(
                expect_error, "context_refused", 403, consuming.consume, consume_id, proofs
            ),
            pool.submit(expect_error, "unavailable", 503, losing.consume, consume_id, proofs),
        )
        for future in futures:
            future.result()
    require(bind_client.calls == consume_client.calls == lost_client.calls == 1)
    require(consume_client.response == lost_client.response)

    advance("fence_closed_refusal")
    expect_no_witness(vault_runtime_connect, bind_id, consume_id, proofs)

    advance("fence_durable_evidence")
    require(vault_evidence(vault_runtime_connect) == vault_before)
    rows, counts = witness_evidence(
        witness_observer_connect, fixture.slot.context_id, bind_id, consume_id
    )
    bind_op, bind_state, bind_response, bind_proofs, bind_terminal = rows[bind_id]
    consume_op, consume_state, consume_bound, consume_proofs, consume_terminal = rows[consume_id]
    terminal = parse(consume_client.response, 4096, special=True)
    require(
        bind_state == "pending_proofs"
        and bytes(bind_response) == bind_client.response
        and bind_proofs is bind_terminal is None
        and bind_op not in counts
    )
    require(
        consume_state == terminal.get("state") == "refused_no_release"
        and terminal.get("authorized") is False
        and str(consume_op) == terminal.get("operation_id")
        and consume_id == terminal.get("reservation_id")
        and bytes(consume_bound) == prepared
        and bytes(consume_proofs) == proofs
        and bytes(consume_terminal) == consume_client.response
        and counts == {consume_op: 1}
    )
    return {
        "bind_close_refused_before_mirror": True,
        "consume_close_refused_after_witness_commit": True,
        "closed_v_refuses_before_witness": True,
        "slot_mismatch_refuses_before_witness": True,
        "incarnation_mismatch_refuses_before_witness": True,
        "vault_historical_rows_preserved": True,
        "reservation_rows_append_only": True,
        "unknown_witness_response_fenced": True,
    }
