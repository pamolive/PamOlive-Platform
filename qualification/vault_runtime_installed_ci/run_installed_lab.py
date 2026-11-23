"""Run the ten installed tests in the reserved Vault and PostgreSQL laboratory."""

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from consumer_inputs import TEST_SHA  # noqa: E402
from lab import pg_bootstrap, postgres_stage, restore_probe  # noqa: E402
from lab_docker import POSTGRES_IMAGE, Container, Lab, Volume  # noqa: E402
from support import load, need, read_regular, sha  # noqa: E402

ROLE = ("/usr/local/bin/python3.12", "-I", "-B", "-S", "/inputs/lab/run_lab_role.py")
WORK_TMPFS = (("/work", "rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=0,gid=0"),)
CLIENT_TMPFS = (("/work", "rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=1000,gid=1000"),)
READY_PG = 'test "$(cat /proc/1/comm)" = postgres && pg_isready -U vault_n0_admin -d postgres'
RESTORE_ENV = (
    "/usr/bin/env",
    "-i",
    "PATH=/usr/local/bin:/usr/bin:/bin",
    "PGCONNECT_TIMEOUT=3",
    "LC_ALL=C.UTF-8",
)


def wait(lab, item, spec, argv, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = lab.exec(item, spec, *argv, timeout=4, stdout_cap=8192)
        if result.returncode == 0 and not result.stderr:
            return
        time.sleep(0.15)
    raise ValueError("vault_lab_readiness")


def staged_sql(lab, item, spec, name, seconds):
    need(name in {"pg.sql", "seed.sql"})
    path = "/work/" + name
    wait(lab, item, spec, ("/usr/bin/test", "-f", path + ".ready"), seconds)
    result = lab.exec(item, spec, "/bin/cat", path, stdout_cap=200 * 1024)
    need(result.returncode == 0 and not result.stderr and result.stdout)
    return result.stdout


def run_pg(lab, item, spec, sql):
    state = lab.container_profile(item, spec)["State"]
    need(state["Running"] is True and state["OOMKilled"] is False)
    return lab.engine.run(
        *pg_bootstrap.exec_args(item["identity"]), data=sql, timeout=20, stdout_cap=8192
    )


def create(lab, consumer, pg, descriptor_sha, *, restore=False):
    settings = postgres_stage.profile()
    need(settings["image"] == POSTGRES_IMAGE and settings["user"] == "999:999")
    database = "vault_n0_lab_" + lab.reservation.removeprefix("pv-")
    preparer = (*ROLE, "preparer", "--database", database, "--input-sha256", descriptor_sha)
    client = (*ROLE, "client", "--input-sha256", descriptor_sha, "--test-sha256", TEST_SHA)
    if restore:
        preparer = (*preparer, "--restore")
        client = (*ROLE, "restore-hold")
    roles = (
        Container(
            consumer,
            "preparer",
            "0:0",
            preparer,
            (
                Volume("postgres", "/stage/pg", False),
                Volume("server", "/stage/server", False),
                Volume("client", "/stage/client", False),
            ),
            WORK_TMPFS,
            chown=True,
        ),
        Container(
            pg,
            "postgres",
            "999:999",
            tuple(settings["command"]),
            (Volume("postgres", "/lab"),),
            tuple(settings["tmpfs"].items()),
            tuple(f"{key}={value}" for key, value in settings["environment"].items()),
            address="10.253.249.2",
            alias="vault-n0-db.test",
        ),
        Container(
            consumer,
            "server",
            "1000:1000",
            (*ROLE, "server"),
            (Volume("server", "/lab"),),
            address="10.253.249.3",
            alias="vault-n0.test",
        ),
        Container(
            consumer,
            "client",
            "1000:1000",
            client,
            (Volume("client", "/lab"),),
            CLIENT_TMPFS,
            address="10.253.249.4",
        ),
    )
    return [(lab.create_container(spec), spec) for spec in roles]


def bootstrap_lab(lab, report, *, restore):
    work = lab.work
    stage = work / "verified-consumer-context"
    report["phase"] = "image_binding"
    descriptor_sha = sha(read_regular(stage / "descriptor.json", 65536))
    consumer = lab.image(read_regular(work / "vault-consumer.iid", 128).decode("ascii").strip())
    postgres = lab.image(POSTGRES_IMAGE, pull=True)
    report["phase"] = "role_reservation"
    lab.create_network()
    for role in ("postgres", "server", "client"):
        lab.create_volume(role)
    prepare, pg, server, client = create(lab, consumer, postgres, descriptor_sha, restore=restore)
    report["phase"] = "postgres_staging"
    lab.start(*prepare)
    bootstrap = staged_sql(lab, *prepare, "pg.sql", 45)
    report["phase"] = "postgres_startup"
    lab.start(*pg)
    wait(lab, *pg, ("/bin/sh", "-ec", READY_PG), 55)
    report["phase"] = "postgres_provisioning"
    result = run_pg(lab, *pg, bootstrap)
    pg_bootstrap.require_success(result.returncode, result.stdout)
    report["empty_cluster_verified"] = True
    receipt = (
        "umask 077; set -C; cat > /work/bootstrap.pending; "
        "mv /work/bootstrap.pending /work/bootstrap.receipt"
    )
    acknowledged = lab.exec(*prepare, "/bin/sh", "-ec", receipt, data=result.stdout)
    need(acknowledged.returncode == 0 and not acknowledged.stderr)
    report["phase"] = "slot_staging"
    seed = staged_sql(lab, *prepare, "seed.sql", 12)
    result = run_pg(lab, *pg, seed)
    postgres_stage.require_commissioned(result.returncode, result.stdout)
    control = None
    if restore:
        received = lab.exec(*prepare, "/bin/cat", "/work/restore-control.json", stdout_cap=8192)
        need(received.returncode == 0 and not received.stderr and received.stdout)
        control = json.loads(received.stdout)
        need(type(control) is dict and set(control) == {"plan", "expires_at"})
    finished = lab.exec(*prepare, "/usr/bin/touch", "/work/finished")
    need(finished.returncode == 0 and not finished.stderr)
    need(lab.engine.checked("container", "wait", prepare[0]["identity"], timeout=5) == b"0\n")
    state = lab.container_profile(*prepare)["State"]
    need(state["Status"] == "exited" and state["ExitCode"] == 0 and state["OOMKilled"] is False)
    report["phase"] = "server_startup"
    lab.start(*server)
    probe = (
        "/opt/vault/bin/python",
        "-I",
        "-B",
        "-c",
        'import socket; socket.create_connection(("10.253.249.3", 9443), 1).close()',
    )
    wait(lab, *server, probe, 7)
    return pg, client, descriptor_sha, control


def run_restore(lab, report, postgres, client, descriptor_sha, plan, expires):
    import adapter_v2
    import schema
    from lab import restore_sql

    raw = read_regular(lab.work / "verified-consumer-context/descriptor.json", 65536)
    need(sha(raw) == descriptor_sha)
    descriptor = adapter_v2.descriptor(schema.parse(raw, 65536))
    sql = read_regular(ROOT.parents[1] / "components/vault/runtime/sql/schema.sql", 65536)
    need(sha(sql) == descriptor["sql_sha256"])
    original = "vault_n0_lab_" + lab.reservation.removeprefix("pv-")
    need(type(plan) is dict and plan.get("original_database") == original)
    need(postgres[1].user == "999:999" and postgres[1].role == "postgres")
    need(client[1].user == "1000:1000" and client[1].role == "client")
    primitives = restore_sql.primitives()
    lab.start(*client)

    def timeout():
        remaining = expires - time.time()
        need(remaining > 0)
        return min(8, remaining)

    def pg(argv, *, data, stdout_cap):
        need(argv[0] in {"psql", "pg_dump", "pg_restore"})
        return lab.exec(
            *postgres,
            "/bin/sh",
            "-ec",
            'test "$(cat /proc/1/comm)" = postgres; exec "$@"',
            "postgres-restore",
            *RESTORE_ENV,
            *argv,
            data=data,
            timeout=timeout(),
            stdin_cap=restore_sql.MAX_DUMP,
            stdout_cap=stdout_cap,
        )

    def probe(phase):
        result = lab.exec(
            *client,
            *ROLE,
            "restore-probe",
            "--phase",
            phase,
            "--input-sha256",
            descriptor_sha,
            "--test-sha256",
            TEST_SHA,
            timeout=timeout(),
            stdout_cap=8192,
        )
        need(not result.stderr)
        packet = schema.parse(result.stdout, 8192)
        need(packet.get("authority") is False)
        if result.returncode != 0:
            stage, name = packet.get("stage"), packet.get("exception")
            if (
                packet.get("error") == "restore_probe_refused"
                and stage in restore_probe.STAGES
                and name in {"ValueError", "OperationalError", "Refusal", "Other"}
            ):
                report["restore_probe_failure"] = {"stage": stage, "exception": name}
            raise ValueError("vault_restore_probe_refused")
        need(set(packet) == {"schema", "phase", "observations", "authority"})
        need(packet["schema"] == "pamolive.vault.restore-step/1" and packet["phase"] == phase)
        return packet["observations"]

    try:
        report["restore"] = restore_sql.run_restore(
            plan,
            sql,
            descriptor,
            primitives=primitives,
            pg=pg,
            probe=probe,
            expires=expires,
        )
    except restore_sql.RestoreRefused as error:
        report["phase"] = "restore_" + error.phase
        raise


def run(lab, report, *, restore=False):
    pg, client, descriptor_sha, control = bootstrap_lab(lab, report, restore=restore)
    if restore:
        report["phase"] = "restore_inputs"
        expires = control["expires_at"]
        need(type(expires) is int)
        remaining = expires - time.time()
        need(0 < remaining <= 40)
        engine = lab.engine
        original_deadline = engine.deadline
        # Ownership inspections and subprocesses share the same restore window.
        engine.deadline = min(original_deadline, engine.clock() + remaining)
        try:
            run_restore(lab, report, pg, client, descriptor_sha, control["plan"], expires)
        finally:
            engine.deadline = original_deadline
        report["phase"] = "complete"
        return
    report["phase"] = "client_tests"
    result = lab.start(*client, attach=True, timeout=25, stdout_cap=8192)
    need(result.returncode == 0 and not result.stderr)
    child = json.loads(result.stdout)
    tests = {
        "run": 10,
        "failures": 0,
        "errors": 0,
        "skips": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
    }
    need(child["ok"] is True and child["tests"] == tests and child["authorized"] is False)
    need(child["installed_input_sha256"] == descriptor_sha and child["test_lab_sha256"] == TEST_SHA)
    report["tests"] = tests
    report["phase"] = "complete"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--restore", action="store_true")
    args = parser.parse_args()
    report = {
        "schema": "pamolive.vault-synthetic-installed-lab/1",
        "phase": "reservation",
        "tests": None,
        "empty_cluster_verified": False,
        "cleaned_up": False,
        "ok": False,
        "authority": False,
    }
    lab = None
    try:
        lab = Lab(args.work)
        run(lab, report, restore=args.restore)
    except Exception:
        pass
    finally:
        if lab is not None:
            report["cleaned_up"] = lab.cleanup()
    report["ok"] = report["phase"] == "complete" and report["cleaned_up"]
    if lab is not None:
        load("controller.py").atomic(args.work / "lab-public.json", report)
    print(json.dumps(report))
    return 0 if report["ok"] else 42


if __name__ == "__main__":
    raise SystemExit(main())
