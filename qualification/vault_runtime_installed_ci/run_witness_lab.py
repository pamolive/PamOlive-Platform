"""Run the installed W01 witness on new, isolated PostgreSQL clusters in CI."""

import argparse
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from lab import postgres_stage, witness_postgres  # noqa: E402
from lab_docker import (  # noqa: E402
    POSTGRES_IMAGE,
    WITNESS_ENDPOINTS,
    WITNESS_PREPARER_MOUNTS,
    Container,
    Volume,
    WitnessLab,
)
from run_installed_lab import CLIENT_TMPFS, WORK_TMPFS  # noqa: E402
from support import load, need, read_regular, sha  # noqa: E402

PYTHON = ("/opt/vault/bin/python", "-I", "-B", "-c")
PG_ROLES = {"wpg": "w-postgres", "vpg": "v-postgres"}
READY_PG = (
    'test "$(cat /proc/1/comm)" = postgres && '
    "pg_isready -q -h /var/run/postgresql -p 5432 -U postgres -d postgres"
)
W_FRAME_CAP = 256 * 1024
PUBLIC_CAP = 8192
DRIVER_PHASES = frozenset(
    (
        b"boundary\n",
        b"installed_wheels\n",
        b"database_configuration\n",
        b"database_roles\n",
        b"database_connection\n",
        b"database_ca\n",
        b"database_peer\n",
        b"database_channel_binding\n",
        b"database_tls\n",
        b"database_authentication\n",
        b"database_hba\n",
        b"database_startup\n",
        b"database_transport\n",
        b"database_other_connection\n",
        b"database_client\n",
        b"database_connection_binding\n",
        b"database_role_query\n",
        b"database_role_mismatch\n",
        b"initialized_publish\n",
        b"prepare_wait\n",
        b"fixture\n",
        b"execute_wait\n",
        b"native_cases\n",
        b"witness_tls_ready\n",
        b"witness_activation\n",
        b"vertical_round_trip\n",
        b"vertical_vault_reservation\n",
        b"vertical_witness_binding\n",
        b"vertical_witness_consume\n",
        b"vertical_exact_retry\n",
        b"vertical_committed_evidence\n",
        b"pending_binding\n",
        b"database_snapshot\n",
        b"forwarded_header\n",
        b"tls_refusals\n",
        b"principal_audiences\n",
        b"witness_sql_permissions\n",
        b"vault_sql_permissions\n",
        b"snapshot_comparison\n",
        b"acknowledge\n",
    )
)
NATIVE_CASES = (
    "vertical_positive",
    "vertical_negative",
    "runtime_sql_and_triggers",
    "terminal_null_shape",
    "mtls_no_client",
    "mtls_unknown_ca",
    "mtls_server_hostname",
    "mtls_principal_audiences",
    "identity_header_refused",
)


def role_command(role, *args):
    need(role in {"prepare", "server", "driver"})
    # All three modules are byte-pinned in the pre-build runner inventory.
    command = (
        "import runpy,sys; sys.path[:0]=['/witness','/inputs','/inputs/controller']; "
        f"runpy.run_module('lab.witness_{role}',run_name='__main__')"
    )
    return (*PYTHON, command, *args)


def create(lab, consumer, postgres, run_id, source_sha):
    pg_environment = {
        "PGDATA": "/var/lib/postgresql/data",
        "POSTGRES_USER": "postgres",
        "POSTGRES_DB": "postgres",
        "POSTGRES_PASSWORD_FILE": "/lab/initial-password",
        "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256 --auth-local=peer",
    }
    pg_env = tuple(f"{name}={value}" for name, value in pg_environment.items())
    pg_cmd = ("postgres", "-c", "config_file=/lab/postgresql.conf")
    pg_tmpfs = tuple(postgres_stage.profile()["tmpfs"].items())
    common = ("--run", run_id, "--source-sha", source_sha)
    specs = [
        Container(
            consumer,
            "preparer",
            "0:0",
            ("/bin/sleep", "300"),
            WITNESS_PREPARER_MOUNTS,
            WORK_TMPFS,
            chown=True,
        )
    ]
    for role, command in (
        ("w-postgres", pg_cmd),
        ("v-postgres", pg_cmd),
        ("witness", role_command("server", *common)),
        ("driver", role_command("driver", *common)),
    ):
        user, address, alias = WITNESS_ENDPOINTS[role]
        sql = role in PG_ROLES.values()
        specs.append(
            Container(
                postgres if sql else consumer,
                role,
                user,
                command,
                (Volume(role, "/lab"),),
                pg_tmpfs if sql else CLIENT_TMPFS if role == "driver" else (),
                pg_env if sql else (),
                address=address,
                alias=alias,
            )
        )
    return {spec.role: (lab.create_container(spec), spec) for spec in specs}


def run_pg(lab, item, spec, sql):
    state = lab.container_profile(item, spec)["State"]
    need(state["Running"] is True and state["OOMKilled"] is False)
    return lab.engine.run(
        *witness_postgres.exec_args(item["identity"]), data=sql, timeout=20, stdout_cap=4096
    )


def checked(result, expected=None):
    need(result.returncode == 0 and not result.stderr and result.stdout)
    if expected is not None:
        need(result.stdout == expected)
    return result.stdout


def read_role(lab, role, name, cap):
    return checked(lab.exec(*role, "/bin/cat", name, stdout_cap=cap))


def wait(lab, role, command, seconds):
    end = min(time.monotonic() + seconds, lab.engine.deadline)
    while time.monotonic() < end:
        result = lab.exec(*role, *command, timeout=4, stdout_cap=1024)
        if not result.returncode and not result.stdout and not result.stderr:
            return
        time.sleep(0.15)
    need(False)


def stage(lab, prepare, run_id, phase, marker, **options):
    return checked(
        lab.exec(*prepare, *role_command("prepare", phase, "--run", run_id), **options),
        marker,
    )


def bootstrap(lab, roles, run_id, report):
    prepare = roles["preparer"]
    report["phase"] = "postgres_staging"
    stage(lab, prepare, run_id, "base", b"W01_BASE_READY\n", timeout=25)
    report["phase"] = "postgres_startup"
    for name in PG_ROLES.values():
        lab.start(*roles[name])
    for name in PG_ROLES.values():
        wait(lab, roles[name], ("/bin/sh", "-ec", READY_PG), 55)

    report["phase"] = "postgres_read_only_preflight"
    receipts = []
    for role, name in PG_ROLES.items():
        sql = read_role(lab, prepare, f"/work/{role}-preflight.sql", 8192)
        receipts.append(
            checked(run_pg(lab, *roles[name], sql), f"W01_{run_id}_{role}_EMPTY\n".encode("ascii"))
        )
    report["empty_clusters_verified"] = 2
    report["phase"] = "postgres_provisioning"
    stage(lab, prepare, run_id, "provision", b"W01_PROVISION_READY\n", data=b"".join(receipts))
    for role, name in PG_ROLES.items():
        sql = read_role(lab, prepare, f"/work/{role}-provision.sql", 128 * 1024)
        receipt = checked(
            run_pg(lab, *roles[name], sql), f"W01_{run_id}_{role}_PROVISIONED\n".encode("ascii")
        )
        report["clusters_provisioned"] += 1
        if role == "wpg":
            stage(
                lab,
                prepare,
                run_id,
                "provision-vault",
                b"W01_VAULT_PROVISION_READY\n",
                data=receipt,
            )


def mark(lab, driver, name):
    need(name in {"prepare", "execute", "acknowledge"})
    result = lab.exec(*driver, "/bin/sh", "-ec", f"umask 077; set -C; : > /work/{name}")
    need(result.returncode == 0 and not result.stdout and not result.stderr)


def wait_driver(lab, driver, file, seconds, report):
    need(file in {"initialized", "w-stage.json", "public.json"})
    probe = f"if test -f /work/failed; then exit 42; else test -f /work/{file}; fi"
    end = min(time.monotonic() + seconds, lab.engine.deadline)
    while time.monotonic() < end:
        result = lab.exec(*driver, "/bin/sh", "-ec", probe, timeout=4, stdout_cap=64)
        need(not result.stderr and not result.stdout)
        if result.returncode == 0:
            return
        if result.returncode == 42:
            phase = read_role(lab, driver, "/work/failed", 64)
            need(phase in DRIVER_PHASES)
            report["driver_failure"] = phase[:-1].decode("ascii")
            mark(lab, driver, "acknowledge")
            need(
                lab.engine.checked("container", "wait", driver[0]["identity"], timeout=5) == b"42\n"
            )
            need(False)
        need(result.returncode == 1)
        time.sleep(0.15)
    need(False)


def collect_pure(lab, prepare, source_sha, descriptor_sha):
    raw = read_role(lab, prepare, "/witness/public.json", PUBLIC_CAP)
    result = json.loads(raw)
    expected = {
        "schema": "pamolive.witness-installed-pure/1",
        "phase": "complete",
        "tests": 62,
        "failures": 0,
        "errors": 0,
        "skips": 0,
        "external_attempts": 0,
        "source_index_sha256": source_sha,
        "vault_input_sha256": descriptor_sha,
        "installed_files_verified": True,
        "authority": False,
        "ok": True,
    }
    digests = {"wheel_sha256", "installed_record_sha256"}
    need(type(result) is dict and set(result) == expected.keys() | digests)
    need(all(type(result[k]) is type(v) and result[k] == v for k, v in expected.items()))
    need(all(type(result[k]) is str and re.fullmatch(r"[a-f0-9]{64}", result[k]) for k in digests))
    return result


def collect_native(raw, source_sha):
    # Consume only a closed receipt. No child payload, request, or private
    # material may cross into an uploaded qualification artifact.
    expected = {
        "schema": "W01-results/2",
        "source_sha256": source_sha,
        "cases": dict.fromkeys(NATIVE_CASES, True),
        "postgres": {
            "clusters": 2,
            "version": 170012,
            "verify_full": True,
            "channel_binding_required": True,
            "assigned_roles_verified": True,
            "vault_forbidden_roles": 2,
            "vault_reservation_lock_denied": True,
            "witness_forbidden_roles": 2,
        },
        "terminal_states": ["consumed_no_release", "refused_no_release"],
        "stored_exact_retries": True,
        "operations": 3,
        "proof_uses": 5,
        "negative_probes_no_side_effect": True,
        "vault_listener_exercised": False,
        "W04_W08_executed": False,
        "secret_release": False,
        "authority": False,
    }
    canonical = json.dumps(expected, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    need(raw == canonical.encode("ascii") + b"\n")
    return expected


def run(lab, report):
    work = lab.work
    stage_root = work / "verified-consumer-context"
    descriptor_sha = sha(read_regular(stage_root / "descriptor.json", 65536))
    source_sha = sha(read_regular(ROOT / "witness-source.sha256", 16384))
    report["phase"] = "image_binding"
    consumer = lab.image(read_regular(work / "witness-consumer.iid", 128).decode("ascii").strip())
    postgres = lab.image(POSTGRES_IMAGE, pull=True)
    report["phase"] = "role_reservation"
    run_id = lab.reservation.removeprefix("pv-")[:16]
    lab.create_network()
    for role in WITNESS_ENDPOINTS:
        lab.create_volume(role)
    roles = create(lab, consumer, postgres, run_id, source_sha)
    prepare, driver, witness = (roles[name] for name in ("preparer", "driver", "witness"))
    lab.start(*prepare)
    report["installed"] = collect_pure(lab, prepare, source_sha, descriptor_sha)
    bootstrap(lab, roles, run_id, report)
    report["phase"] = "driver_startup"
    lab.start(*driver)
    # Nine checked connections each have a three-second bound. The signed
    # witness fixture and its lease are created only after initialization.
    wait_driver(lab, driver, "initialized", 35, report)
    need(read_role(lab, driver, "/work/initialized", 64) == b"W01_INITIALIZED\n")
    report["phase"] = "witness_staging"
    mark(lab, driver, "prepare")
    wait_driver(lab, driver, "w-stage.json", 9, report)
    frame = read_role(lab, driver, "/work/w-stage.json", W_FRAME_CAP)
    stage(lab, prepare, run_id, "stage-witness", b"W01_WITNESS_READY\n", data=frame, timeout=5)
    need(lab.container_profile(*prepare)["State"]["Running"] is True)
    lab.engine.checked("container", "stop", "--time", "1", prepare[0]["identity"], timeout=4)
    need(lab.container_profile(*prepare)["State"]["Status"] == "exited")
    report["phase"] = "witness_round_trip"
    lab.start(*witness)
    mark(lab, driver, "execute")
    wait_driver(lab, driver, "public.json", 32, report)
    report["native"] = collect_native(
        read_role(lab, driver, "/work/public.json", PUBLIC_CAP), source_sha
    )
    mark(lab, driver, "acknowledge")
    need(lab.engine.checked("container", "wait", driver[0]["identity"], timeout=5) == b"0\n")
    state = lab.container_profile(*driver)["State"]
    need(state["Status"] == "exited" and state["ExitCode"] == 0 and state["OOMKilled"] is False)
    report["phase"] = "complete"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    options = parser.parse_args()
    report = {
        "schema": "pamolive.witness-installed-dual-cluster/2",
        "phase": "reservation",
        "installed": None,
        "empty_clusters_verified": 0,
        "clusters_provisioned": 0,
        "native": None,
        "driver_failure": None,
        "cleaned_up": False,
        "ok": False,
        "authority": False,
    }
    lab = None
    try:
        lab = WitnessLab(options.work)
        run(lab, report)
    except Exception:
        pass
    finally:
        if lab is not None:
            report["cleaned_up"] = lab.cleanup()
    report["ok"] = report["phase"] == "complete" and report["cleaned_up"]
    if lab is not None:
        load("controller.py").atomic(options.work / "witness-lab-public.json", report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 42


if __name__ == "__main__":
    raise SystemExit(main())
