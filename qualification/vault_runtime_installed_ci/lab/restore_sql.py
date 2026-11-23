"""Bounded restore coordinator over parent-owned callbacks, never opens a connection.

The only supported archive is the private dump just obtained from the same newly
owned cluster. R5 data/role/close guarantees remain separate from service probes.
No Docker, filesystem spool, DSN, SDK or runtime import is implemented here.
"""

import hashlib
import json
import math
import re
import time
from types import SimpleNamespace
from uuid import UUID

MAX_DUMP = 8 * 1024**2
MAX_STDERR = 16384
MAX_PUBLIC = 16384
OWNER = "vault_n0_owner_lab_login"
ADMIN = "vault_n0_admin"
PLAN_KEYS = {
    "schema",
    "original_database",
    "restored_database",
    "slot_id",
    "old_incarnation",
    "new_incarnation",
    "old_slot_sha256",
    "new_slot_sha256",
    "new_slot_path",
}


class RestoreRefused(ValueError):
    def __init__(self, phase):
        super().__init__("vault_installed_restore_refused")
        self.phase = phase


def need(value, _reason=None):
    if not value:
        raise ValueError("restore_sql_refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


# Static primitives extracted from the pinned R5 public source during development.
p = SimpleNamespace(need=need)


def database_pair(original, restored):
    p.need(
        type(original) is str
        and re.fullmatch("vault_n0_lab_[a-z0-9_]{1,40}", original)
        and (type(restored) is str)
        and (restored == original + "_restored")
        and (len(restored) <= 63)
        and (restored != original),
        "restore_database_pair",
    )


def grants(schema):
    p.need(type(schema) is bytes and len(schema) <= 65536, "restore_grants_source")
    lines = [
        line
        for line in schema.decode("ascii").splitlines()
        if line.startswith(("GRANT ", "REVOKE ", "ALTER DEFAULT PRIVILEGES "))
    ]
    p.need(
        len(lines) == 7
        and all(line.endswith(";") for line in lines)
        and (not any("CREATE" in line or "DROP" in line or "DATABASE" in line for line in lines)),
        "restore_grants_source",
    )
    return (
        "SET ROLE vault_n0_owner;\n" + "\n".join(lines) + "\nSELECT 'RESTORE_GRANTS_APPLIED';\n"
    ).encode()


def validate_observations(phase, value):
    expected = {
        "before-dump": {"row_count", "audit_count", "owner_exact"},
        "after-restore": {
            "row_count",
            "audit_count",
            "snapshots_equal",
            "owner_exact",
            "original_closed",
            "startup_code",
            "startup_status",
        },
        "after-commission": {
            "row_count",
            "audit_count",
            "snapshots_equal",
            "original_closed",
            "old_idem_code",
            "old_idem_status",
            "new_authorized",
            "runtime_posture",
            "runtime_attempts",
            "web_denied",
            "worker_denied",
        },
    }
    p.need(
        phase in expected and type(value) is dict and (set(value) == expected[phase]),
        "restore_probe_packet",
    )
    count = 2 if phase == "after-commission" else 1
    p.need(
        all(
            type(value[key]) is int and value[key] == count for key in ("row_count", "audit_count")
        ),
        "restore_probe_packet",
    )
    for key in ("owner_exact", "snapshots_equal", "original_closed", "web_denied", "worker_denied"):
        if key in value:
            p.need(value[key] is True, "restore_probe_packet")
    if phase == "after-restore":
        p.need(
            value["startup_code"] == "context_refused"
            and type(value["startup_status"]) is int
            and (value["startup_status"] == 403),
            "restore_probe_packet",
        )
    if phase == "after-commission":
        p.need(
            value["old_idem_code"] == "idempotency_conflict"
            and type(value["old_idem_status"]) is int
            and (value["old_idem_status"] == 409)
            and (value["new_authorized"] is False)
            and (type(value["runtime_posture"]) is list)
            and (len(value["runtime_posture"]) == 4)
            and all(item is False for item in value["runtime_posture"]),
            "restore_probe_packet",
        )
        packet = value["runtime_attempts"]
        p.need(
            type(packet) is dict
            and set(packet)
            == {"attempts", "target_matches", "outer_rollback_status", "connection_closed"}
            and (packet["target_matches"] is True)
            and (packet["connection_closed"] is True)
            and (type(packet["outer_rollback_status"]) is int)
            and (packet["outer_rollback_status"] == 0)
            and (type(packet["attempts"]) is list)
            and (len(packet["attempts"]) == 4),
            "restore_probe_packet",
        )
        for item, name in zip(
            packet["attempts"], ("ddl", "delete", "reservation_update", "context_update")
        ):
            p.need(
                type(item) is dict
                and set(item) == {"attempt", "sqlstate", "savepoint", "rollback", "release"}
                and (type(item["attempt"]) is str)
                and (item["attempt"] == name)
                and all(
                    (
                        type(item[key]) is str and item[key] == expected
                        for key, expected in (
                            ("sqlstate", "42501"),
                            ("savepoint", "SAVEPOINT"),
                            ("rollback", "ROLLBACK"),
                            ("release", "RELEASE"),
                        )
                    )
                ),
                "restore_probe_packet",
            )
    return value


def close_sql(plan):
    close = (
        "SET ROLE vault_n0_owner;\n"
        "UPDATE vault_reservation.commissioned_state SET serving_state='closed' WHERE slot_id='"
        + plan["slot_id"]
        + "' AND incarnation='"
        + plan["old_incarnation"]
        + "' AND slot_sha256='"
        + plan["old_slot_sha256"]
        + "' AND serving_state='open' RETURNING 'ORIGINAL_CLOSED';\n"
    ).encode()
    return close


def create_sql(plan):
    restored = plan["restored_database"]
    create = (
        f"CREATE DATABASE {restored} OWNER vault_n0_owner;\n"
        f"REVOKE ALL ON DATABASE {restored} FROM PUBLIC;\n"
        f"GRANT CONNECT ON DATABASE {restored} TO vault_n0_runtime, {OWNER};\n"
        f"\\connect {restored}\n"
        "REVOKE ALL ON SCHEMA public FROM PUBLIC;\n"
        "SELECT 'RESTORE_DATABASE_CREATED';\n"
    ).encode()
    return create


def commission_sql(plan):
    commission = (
        "SET ROLE vault_n0_owner;\nUPDATE vault_reservation.commissioned_state SET incarnation='"
        + plan["new_incarnation"]
        + "', slot_sha256='"
        + plan["new_slot_sha256"]
        + "', serving_state='open' WHERE slot_id='"
        + plan["slot_id"]
        + "' AND incarnation='"
        + plan["old_incarnation"]
        + "' AND slot_sha256='"
        + plan["old_slot_sha256"]
        + "' AND serving_state='open' RETURNING 'RESTORE_COMMISSIONED';\n"
    ).encode()
    return commission


def dump_argv(plan):
    original = plan["original_database"]
    return [
        "pg_dump",
        "-U",
        OWNER,
        "-d",
        original,
        "--format=custom",
        "--schema=vault_reservation",
        "--strict-names",
        "--no-owner",
        "--no-acl",
        "--no-comments",
        "--no-security-labels",
        "--no-tablespaces",
        "--no-publications",
        "--no-subscriptions",
    ]


def restore_argv(plan):
    restored = plan["restored_database"]
    return [
        "pg_restore",
        "-U",
        OWNER,
        "--dbname=" + restored,
        "--role=vault_n0_owner",
        "--exit-on-error",
        "--no-owner",
        "--no-acl",
        "--no-comments",
        "--no-security-labels",
    ]


def primitives():
    """Static R5 selection; no legacy source or compilation needed at runtime."""
    return SimpleNamespace(
        **{
            name: globals()[name]
            for name in (
                "database_pair",
                "grants",
                "validate_observations",
                "close_sql",
                "create_sql",
                "commission_sql",
                "dump_argv",
                "restore_argv",
            )
        }
    )


def validate_plan(plan, primitives):
    need(type(plan) is dict and set(plan) == PLAN_KEYS)
    need(plan["schema"] == "pamolive.vault.synthetic-restore-plan/1")
    primitives.database_pair(plan["original_database"], plan["restored_database"])
    for name in ("slot_id", "old_incarnation", "new_incarnation"):
        need(type(plan[name]) is str and str(UUID(plan[name])) == plan[name])
    for name in ("old_slot_sha256", "new_slot_sha256"):
        need(type(plan[name]) is str and re.fullmatch(r"[0-9a-f]{64}", plan[name]))
    need(plan["old_incarnation"] != plan["new_incarnation"])
    need(plan["old_slot_sha256"] != plan["new_slot_sha256"])
    need(plan["new_slot_path"] == "/lab/restored-slot.json")


def sql_argv(role, database):
    need(role in (ADMIN, OWNER))
    need(database == "postgres" or re.fullmatch(r"vault_n0_lab_[a-z0-9_]{1,49}", database))
    return (
        "psql",
        "-X",
        "-w",
        "-qAt",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        "/var/run/postgresql",
        "-p",
        "5432",
        "-U",
        role,
        "-d",
        database,
        "-f",
        "-",
    )


def guarded_sql(body, role, database):
    """Confirm the local session/version, then execute the unchanged R5 SQL body."""
    sql_argv(role, database)
    need(type(body) is bytes and 0 < len(body) <= 65536)
    prefix = (
        "\\set ON_ERROR_STOP on\nSET statement_timeout='3s';\nSET lock_timeout='2s';\n"
        "SELECT (current_database()='"
        + database
        + "' AND session_user='"
        + role
        + "' AND current_user='"
        + role
        + "' AND inet_server_addr() IS NULL "
        "AND current_setting('server_version_num')='170012') IS TRUE "
        "AS vault_restore_context \\gset\n"
        "\\if :vault_restore_context\n"
    ).encode()
    return prefix + body + b"\\else\n\\echo RESTORE_CONTEXT_REFUSED\n\\endif\n"


def local_argv(argv):
    need(type(argv) is list and argv[0] in ("pg_dump", "pg_restore"))
    return (argv[0], "-h", "/var/run/postgresql", "-p", "5432", "-w", *argv[1:])


def check_result(result, cap):
    need(result.ok is True and type(result.returncode) is int and result.returncode == 0)
    need(type(result.stdout) is bytes and len(result.stdout) <= cap)
    # Notices are not failures by themselves. They remain private and bounded.
    need(type(result.stderr) is bytes and len(result.stderr) <= MAX_STDERR)
    facts = result.facts()
    required = {
        "spawn_attempted",
        "pid",
        "returncode",
        "reason",
        "exception_type",
        "killed_owned_child",
        "owned_child_reaped",
        "drains_complete",
        "cleanup_exception_type",
        "stdout_bytes",
        "stderr_bytes",
    }
    need(type(facts) is dict and required <= set(facts))
    need(
        facts["spawn_attempted"] is True
        and facts["owned_child_reaped"] is True
        and facts["drains_complete"] is True
        and facts["killed_owned_child"] is False
    )
    need(type(facts["pid"]) is int and facts["pid"] > 0)
    need(type(facts["returncode"]) is int and facts["returncode"] == 0)
    need(all(facts[key] is None for key in ("reason", "exception_type", "cleanup_exception_type")))
    need(type(facts["stdout_bytes"]) is int and facts["stdout_bytes"] == len(result.stdout))
    need(type(facts["stderr_bytes"]) is int and facts["stderr_bytes"] == len(result.stderr))
    need(result.stdout_bytes == facts["stdout_bytes"])
    return {
        "returncode": 0,
        "stdout_bytes": facts["stdout_bytes"],
        "stderr_bytes": facts["stderr_bytes"],
        "IO_released": True,
    }


def run_restore(plan, schema, descriptor, *, primitives, pg, probe, expires, clock=time.time):
    """Parent pg callback owns SAME verified CID/UID999, env, memfd and capped IO.

    pg(argv, *, data=None, stdout_cap=...) returns the existing H1 Result. Its
    timeout must be <= min(8s, remaining window), stderr cap16KiB, env cleared.
    probe(phase) returns the exact R5 observations (not the enclosing packet).
    The private envelope {plan, expires_at} and external new slot are pre-staged
    by the parent BEFORE any dump; this coordinator never writes/refreshes them.
    """
    phase = "inputs"
    archive = None
    try:
        validate_plan(plan, primitives)
        need(type(schema) is bytes and 0 < len(schema) <= 65536)
        need(
            type(descriptor) is dict
            and descriptor.get("schema") == "pamolive.vault-runtime-installed-input/2"
        )
        need(sha(schema) == descriptor.get("sql_sha256"))
        need(type(expires) is int and expires > 0)
        grants = primitives.grants(schema)
        commands, phases = [], []

        def remaining(minimum):
            now = clock()
            need(type(now) in (int, float) and math.isfinite(now) and now < expires - minimum)

        def command(operation, argv, *, data=None, cap=65536):
            remaining(0)
            need(data is None or (type(data) is bytes and 0 < len(data) <= MAX_DUMP))
            result = pg(argv, data=data, stdout_cap=cap)
            facts = check_result(result, cap)
            remaining(0)
            commands.append({"operation": operation, **facts})
            return result.stdout

        def sql(operation, role, database, body, marker):
            value = command(
                operation, sql_argv(role, database), data=guarded_sql(body, role, database)
            )
            need(value == (marker + "\n").encode("ascii"))

        def receive(name, minimum):
            remaining(minimum)
            observations = probe(name)
            primitives.validate_observations(name, observations)
            remaining(0)
            phases.append({"phase": name, "observations": observations})

        phase = "before-dump"
        receive(phase, 26)
        phase = "dump"
        archive = command(phase, local_argv(primitives.dump_argv(plan)), cap=MAX_DUMP)
        need(archive.startswith(b"PGDMP") and len(archive) >= 5)
        archive_sha = sha(archive)
        phase = "dump-list"
        command(phase, ("pg_restore", "--list"), data=archive)
        phase = "close-source"
        sql(phase, OWNER, plan["original_database"], primitives.close_sql(plan), "ORIGINAL_CLOSED")
        remaining(18)
        phase = "create-target"
        sql(phase, ADMIN, "postgres", primitives.create_sql(plan), "RESTORE_DATABASE_CREATED")
        need(sha(archive) == archive_sha)
        phase = "restore-target"
        command(phase, local_argv(primitives.restore_argv(plan)), data=archive)
        phase = "grants-target"
        sql(phase, OWNER, plan["restored_database"], grants, "RESTORE_GRANTS_APPLIED")
        phase = "after-restore"
        receive(phase, 10)
        phase = "commission-target"
        sql(
            phase,
            OWNER,
            plan["restored_database"],
            primitives.commission_sql(plan),
            "RESTORE_COMMISSIONED",
        )
        phase = "after-commission"
        receive(phase, 4)
        remaining(0)
        result = {
            "schema": "pamolive.vault-installed-restore-sql/1",
            "ok": True,
            "authority": False,
            "restore_into_original": False,
            "source_mutations": "trusted_close_only",
            "commands": commands,
            "phases": phases,
        }
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        need(len(encoded) <= MAX_PUBLIC)
        return result
    except Exception:
        raise RestoreRefused(phase) from None
    finally:
        # Drops this reference; no zeroization claim for Python immutable bytes.
        archive = None
