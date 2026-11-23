"""Client-only assembly/SQL assertions, never a new TLS daemon or restore endpoint."""

import hashlib
import json
import os
import re
from dataclasses import replace
from pathlib import Path
from uuid import uuid4


def need(value):
    if not value:
        raise ValueError("restore_probe_refused")


STAGES = frozenset(
    {
        "inputs",
        "before_dump",
        "after_restore",
        "commissioned_startup",
        "old_request",
        "rebound_request",
        "fresh_request",
        "snapshot",
        "runtime_posture",
        "runtime_mutations",
        "web_connect",
        "worker_connect",
        "complete",
    }
)


def failure_packet(error, stage):
    """Closed codes only; never stringify a database exception or request."""
    name = type(error).__name__
    return {
        "error": "restore_probe_refused",
        "authority": False,
        "stage": stage if type(stage) is str and stage in STAGES else "unknown",
        "exception": name if name in {"ValueError", "OperationalError", "Refusal"} else "Other",
    }


def connect_denied(error, database, role):
    """Pinned lab/libpq C-locale grammar, not a general OperationalError allowance."""
    import psycopg

    need(
        type(database) is str
        and len(database) <= 63
        and re.fullmatch(r"vault_n0_lab_[a-z0-9_]{1,40}_restored", database)
        and type(role) is str
        and role in {"web_n0_lab", "worker_n0_lab"}
    )
    need(type(error) is psycopg.OperationalError and error.sqlstate is None)
    pgconn = error.pgconn
    need(type(pgconn) is psycopg.errors.FinishedPGconn and error.pgresult is None)
    for name, expected in (
        ("db", database.encode("ascii")),
        ("user", role.encode("ascii")),
        ("host", b"vault-n0-db.test"),
        ("hostaddr", b"10.253.249.2"),
        ("port", b"5432"),
    ):
        actual = getattr(pgconn, name)
        need(type(actual) is bytes and actual == expected)
    message = pgconn.error_message
    need(type(message) is bytes and 0 < len(message) <= 4096)
    expected = (
        b'connection to server at "10.253.249.2", port 5432 failed: '
        b'FATAL:  permission denied for database "'
        + database.encode("ascii")
        + b'"\nDETAIL:  User does not have CONNECT privilege.\n'
    )
    need(message == expected)
    return True


RUNTIME_SQL = (
    ("ddl", "CREATE TABLE vault_reservation.restore_denial_probe (x integer)"),
    ("delete", "DELETE FROM vault_reservation.reservations WHERE false"),
    (
        "reservation_update",
        "UPDATE vault_reservation.reservations SET expires_at=expires_at WHERE false",
    ),
    (
        "context_update",
        "UPDATE vault_reservation.commissioned_state SET incarnation=incarnation WHERE false",
    ),
)


def runtime_attempts(connect, expected_database, evidence):
    """Fixed lab SQL only. No commit path, including an unexpected successful statement."""
    import psycopg

    need(
        type(expected_database) is str
        and re.fullmatch(r"vault_n0_lab_[a-z0-9_]{1,40}_restored", expected_database)
    )
    need(
        evidence
        == {
            "attempts": [],
            "target_matches": False,
            "outer_rollback_status": None,
            "connection_closed": False,
        }
    )
    connection = connect()
    try:
        evidence["target_matches"] = (
            connection.info.dbname == expected_database
            and connection.info.user == "vault_n0_runtime"
        )
        need(evidence["target_matches"] and connection.autocommit is False)
        for name, statement in RUNTIME_SQL:
            item = {
                "attempt": name,
                "sqlstate": None,
                "savepoint": None,
                "rollback": None,
                "release": None,
            }
            evidence["attempts"].append(item)
            item["savepoint"] = connection.execute("SAVEPOINT vault_restore_denial").statusmessage
            try:
                connection.execute(statement)
            except psycopg.Error as error:
                item["sqlstate"] = error.sqlstate  # Never str(error), query or DB context.
            finally:
                try:
                    item["rollback"] = connection.execute(
                        "ROLLBACK TO SAVEPOINT vault_restore_denial"
                    ).statusmessage
                finally:
                    item["release"] = connection.execute(
                        "RELEASE SAVEPOINT vault_restore_denial"
                    ).statusmessage
            need(
                item["savepoint"] == "SAVEPOINT"
                and item["rollback"] == "ROLLBACK"
                and item["release"] == "RELEASE"
                and item["sqlstate"] == "42501"
            )
    finally:
        try:
            connection.rollback()
            evidence["outer_rollback_status"] = int(connection.info.transaction_status)
        finally:
            connection.close()
            evidence["connection_closed"] = connection.closed
    need(evidence["outer_rollback_status"] == 0 and evidence["connection_closed"] is True)
    return evidence


def snapshot(owner):
    result = {}
    with owner() as connection:
        for table in ("reservations", "audit"):
            values = connection.execute(
                "SELECT row_to_json(t)::text FROM vault_reservation."
                + table
                + " t ORDER BY reservation_id LIMIT 3"
            ).fetchall()
            need(len(values) <= 2)
            rows = []
            for value in values:
                need(type(value[0]) is str and len(value[0]) <= 40000)
                row = json.loads(value[0])
                if table == "reservations":
                    nonce, draft = row.pop("nonce"), row.pop("canonical_draft")
                    need(type(nonce) is str and nonce.startswith("\\x") and len(nonce) == 66)
                    need(type(draft) is str and draft.startswith("\\x") and len(draft) <= 32770)
                    row["nonce_sha256"] = hashlib.sha256(bytes.fromhex(nonce[2:])).hexdigest()
                    row["canonical_draft_sha256"] = hashlib.sha256(
                        bytes.fromhex(draft[2:])
                    ).hexdigest()
                rows.append(row)
            result[table] = rows
    return result


def commissioned(owner):
    with owner() as connection:
        rows = connection.execute(
            "SELECT slot_id::text, incarnation::text, slot_sha256, serving_state "
            "FROM vault_reservation.commissioned_state"
        ).fetchall()
    need(len(rows) == 1)
    return list(rows[0])


def metadata(owner):
    with owner() as connection:
        rows = connection.execute(
            "SELECT c.relname, r.rolname FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_catalog.pg_roles r ON r.oid=c.relowner "
            "WHERE n.nspname='vault_reservation' AND c.relkind='r' ORDER BY c.relname"
        ).fetchall()
        need(
            rows
            == [
                (name, "vault_n0_owner") for name in ("audit", "commissioned_state", "reservations")
            ]
        )
        need(
            connection.execute(
                "SELECT r.rolname FROM pg_catalog.pg_namespace n "
                "JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner "
                "WHERE n.nspname='vault_reservation'"
            ).fetchone()
            == ("vault_n0_owner",)
        )
        need(
            connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n "
                "ON n.oid=p.pronamespace WHERE n.nspname='vault_reservation'"
            ).fetchone()
            == (0,)
        )
        need(
            connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_trigger t "
                "JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='vault_reservation' AND NOT t.tgisinternal"
            ).fetchone()
            == (0,)
        )
    return True


def refusal(function, code, status):
    from pamolive_vault_runtime.bounded import Refusal

    try:
        value = function()
    except Refusal as error:
        need(error.code == code and error.status == status)
        return {"code": error.code, "status": error.status}
    else:
        if hasattr(value, "close"):
            value.close()
        raise ValueError("restore_expected_refusal_missing")


def execute(phase, reception, private):
    stage = "inputs"
    try:
        from pamolive_vault_contracts import parse_draft
        from pamolive_vault_runtime.assembly import application
        from pamolive_vault_runtime.ledger import role_guard
        from serve_lab import connector, lab_inputs, local_bytes

        need(phase in ("before-dump", "after-restore", "after-commission"))
        reception.VALUES = lab_inputs(Path("/lab/manifest.json"))
        values = reception.VALUES
        plan = json.loads(local_bytes("/lab/restore-plan.json", 16384))
        old_owner = connector(values["owner_database_file"], role="vault_n0_owner_lab_login")
        new_owner = connector("/lab/restored-owner-db.json", role="vault_n0_owner_lab_login")
        new_runtime = connector("/lab/restored-runtime-db.json", role="vault_n0_runtime")
        expected_old = [plan["slot_id"], plan["old_incarnation"], plan["old_slot_sha256"], "open"]

        def startup():
            return application(
                slot_path=Path(plan["new_slot_path"]),
                slot_sha256=plan["new_slot_sha256"],
                connect=new_runtime,
            )

        if phase == "before-dump":
            stage = "before_dump"
            os.mkdir(private.PRIVATE, 0o700)
            need(snapshot(old_owner) == {"reservations": [], "audit": []})
            need(commissioned(old_owner) == expected_old)
            owner_exact = metadata(old_owner)
            # Root-owned source must already exist before any reservation or dump.
            from pamolive_vault_runtime.slot import SlotFile

            barrier = SlotFile(Path(plan["new_slot_path"]), plan["new_slot_sha256"])
            need(barrier.slot.expected()["ledger_incarnation"] == plan["new_incarnation"])
            request = reception.request_copy()
            answer = private.tls(reception, request)
            snap = snapshot(old_owner)
            need(len(snap["reservations"]) == len(snap["audit"]) == 1)
            private.private_file(
                "restore.json", {"request": request, "answer": answer, "snapshot": snap}
            )
            observation = {
                "row_count": len(snap["reservations"]),
                "audit_count": len(snap["audit"]),
                "owner_exact": owner_exact,
            }
        else:
            stage = "after_restore"
            state = private.private_file("restore.json")
            original_closed = commissioned(old_owner) == [*expected_old[:3], "closed"]
            need(original_closed)
            need(snapshot(old_owner) == state["snapshot"])
            if phase == "after-restore":
                need(commissioned(new_owner) == expected_old)
                current = snapshot(new_owner)
                equal = current == state["snapshot"]
                need(equal)
                owner_exact = metadata(new_owner)
                with new_runtime() as connection, connection.cursor() as cursor:
                    role_guard(cursor)
                denied = refusal(startup, "context_refused", 403)
                connection = reception.client()
                try:
                    status, body = reception.post(connection, state["request"])
                    need(status == 403 and body["authorized"] is False)
                finally:
                    connection.close()
                observation = {
                    "row_count": len(current["reservations"]),
                    "audit_count": len(current["audit"]),
                    "snapshots_equal": equal,
                    "owner_exact": owner_exact,
                    "original_closed": original_closed,
                    "startup_code": denied["code"],
                    "startup_status": denied["status"],
                }
            else:
                stage = "commissioned_startup"
                need(
                    commissioned(new_owner)
                    == [plan["slot_id"], plan["new_incarnation"], plan["new_slot_sha256"], "open"]
                )
                app = startup()
                der = local_bytes(values["client_a_der"], 16384)
                try:
                    stage = "old_request"
                    refusal(
                        lambda: app.reservations.prepare(reception.wire(state["request"]), der),
                        "context_refused",
                        403,
                    )
                    draft = parse_draft(reception.wire(state["request"]["draft"]))
                    from pamolive_vault_contracts import serialize_draft

                    rebound = {
                        **state["request"],
                        "draft": json.loads(
                            serialize_draft(
                                replace(draft, ledger_incarnation=plan["new_incarnation"])
                            )
                        ),
                    }
                    stage = "rebound_request"
                    denied = refusal(
                        lambda: app.reservations.prepare(reception.wire(rebound), der),
                        "idempotency_conflict",
                        409,
                    )
                    fresh = {
                        **rebound,
                        "draft": json.loads(
                            serialize_draft(
                                replace(
                                    parse_draft(reception.wire(rebound["draft"])),
                                    idempotency_key=str(uuid4()),
                                    request_id=str(uuid4()),
                                )
                            )
                        ),
                    }
                    stage = "fresh_request"
                    answer = app.reservations.prepare(reception.wire(fresh), der).public()
                    need(
                        answer["authorized"] is False
                        and answer["state"] == "pending_proofs"
                        and "nonce" not in answer
                    )
                finally:
                    app.close()
                stage = "snapshot"
                current = snapshot(new_owner)
                need(len(current["reservations"]) == len(current["audit"]) == 2)
                fresh_rows = [
                    row
                    for row in current["reservations"]
                    if row["reservation_id"] == answer["reservation_id"]
                ]
                need(
                    len(fresh_rows) == 1
                    and answer["reservation_id"] != state["answer"]["reservation_id"]
                )
                private.same_pending(answer, fresh_rows[0])
                need(
                    fresh_rows[0]["nonce_sha256"]
                    != state["snapshot"]["reservations"][0]["nonce_sha256"]
                )
                preserved = all(
                    row in current[table]
                    for table in state["snapshot"]
                    for row in state["snapshot"][table]
                )
                need(preserved)
                stage = "runtime_posture"
                with new_runtime() as connection:
                    permission = connection.execute(
                        "SELECT has_schema_privilege(current_user,'vault_reservation','CREATE'), "
                        "has_table_privilege(current_user,'vault_reservation.reservations',"
                        "'DELETE'), has_table_privilege(current_user,"
                        "'vault_reservation.reservations',"
                        "'UPDATE'), has_column_privilege(current_user,"
                        "'vault_reservation.commissioned_state','incarnation','UPDATE')"
                    ).fetchone()
                need(permission == (False, False, False, False))
                before_mutations = snapshot(new_owner)
                attempt_packet = {
                    "attempts": [],
                    "target_matches": False,
                    "outer_rollback_status": None,
                    "connection_closed": False,
                }
                try:
                    stage = "runtime_mutations"
                    runtime_attempts(new_runtime, plan["restored_database"], attempt_packet)
                finally:
                    after_mutations = snapshot(new_owner)
                    private.private_file(
                        "restore-runtime-denials.json",
                        {
                            "before": before_mutations,
                            "after": after_mutations,
                            "attempts": attempt_packet,
                        },
                    )
                    need(before_mutations == after_mutations and metadata(new_owner))
                failures = {}
                import psycopg

                for role, filename in (("web_n0_lab", "web"), ("worker_n0_lab", "worker")):
                    stage = "web_connect" if filename == "web" else "worker_connect"
                    try:
                        with connector("/lab/restored-" + filename + "-db.json", role=role)():
                            pass
                    except psycopg.Error as error:
                        failures[filename] = connect_denied(error, plan["restored_database"], role)
                    else:
                        raise ValueError("restore_unauthorized_connect_succeeded")
                observation = {
                    "row_count": len(current["reservations"]),
                    "audit_count": len(current["audit"]),
                    "snapshots_equal": preserved,
                    "original_closed": original_closed,
                    "old_idem_code": denied["code"],
                    "old_idem_status": denied["status"],
                    "new_authorized": answer["authorized"],
                    "runtime_posture": list(permission),
                    "runtime_attempts": attempt_packet,
                    "web_denied": failures["web"],
                    "worker_denied": failures["worker"],
                }
        stage = "complete"
        print(
            json.dumps(
                {
                    "schema": "pamolive.vault.restore-step/1",
                    "phase": phase,
                    "observations": observation,
                    "authority": False,
                }
            ),
            flush=True,
        )
        return 0
    except Exception as error:
        print(json.dumps(failure_packet(error, stage)), flush=True)
        return 1
