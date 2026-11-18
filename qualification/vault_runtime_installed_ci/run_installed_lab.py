"""Run the ten installed tests in the reserved Vault and PostgreSQL laboratory."""

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from consumer_inputs import TEST_SHA  # noqa: E402
from lab import pg_bootstrap, postgres_stage  # noqa: E402
from lab_docker import POSTGRES_IMAGE, Container, Lab, Volume  # noqa: E402
from support import load, need, read_regular, sha  # noqa: E402

ROLE = ("/usr/local/bin/python3.12", "-I", "-B", "-S", "/inputs/lab/run_lab_role.py")
WORK_TMPFS = (("/work", "rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=0,gid=0"),)
CLIENT_TMPFS = (("/work", "rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=1000,gid=1000"),)
READY_PG = 'test "$(cat /proc/1/comm)" = postgres && pg_isready -U vault_n0_admin -d postgres'


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


def create(lab, consumer, pg, descriptor_sha):
    settings = postgres_stage.profile()
    need(settings["image"] == POSTGRES_IMAGE and settings["user"] == "999:999")
    database = "vault_n0_lab_" + lab.reservation.removeprefix("pv-")
    roles = (
        Container(
            consumer,
            "preparer",
            "0:0",
            (*ROLE, "preparer", "--database", database, "--input-sha256", descriptor_sha),
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
            (*ROLE, "client", "--input-sha256", descriptor_sha, "--test-sha256", TEST_SHA),
            (Volume("client", "/lab"),),
            CLIENT_TMPFS,
            address="10.253.249.4",
        ),
    )
    return [(lab.create_container(spec), spec) for spec in roles]


def run(lab, report):
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
    prepare, pg, server, client = create(lab, consumer, postgres, descriptor_sha)
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
        run(lab, report)
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
