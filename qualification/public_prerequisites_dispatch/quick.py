"""Dedicated disposable public N0: two reads + roots, one PG pull, received PG R4."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
import types
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
BOUNDED_SHA = "98233b610f2d53dfd698d0d91f61f3d3ebcb1693a847983f0472f89a885f414f"
PUSH_REF = "refs/heads/agent/ci-public-observer-diagnostics-ecfe"
PG_ASSETS_SHA = "44f70509317652dd1d042aedab0f4281cbd15037a707691e84de64f027f9a81f"
PG_MANIFEST = (
    "docker.io/library/postgres@sha256:"
    "6f7593c161689b6b02c78668b314af7da8811b592c5519108c57a49d0b6ad788"
)
FILES = {
    "engine/collector.py",
    "engine/containerd_public.py",
    "engine/bounded_io.py",
    "pg/owner.py",
    "pg/assets.json",
    "pg/probe.py",
    "pg/bindings.json",
    "pg/data/profile.json",
    "pg/data/config.json",
    "pg/data/amd64-manifest.json",
    "pg/data/index.reference.json",
    "pg/helpers/bounded_io.py",
    "pg/helpers/lease_support.py",
    "pg/helpers/legacy.py",
    "pg/helpers/linux.py",
}
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C"}


def need(value, code="QUICK_REFUSED"):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, maximum):
    path = Path(path).absolute()
    for parent in path.parents:
        row = parent.lstat()
        need(stat.S_ISDIR(row.st_mode) and not getattr(row, "st_file_attributes", 0) & 1024)
    before = path.lstat()

    def identity(row):
        need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and 0 < row.st_size <= maximum)
        need(not getattr(row, "st_file_attributes", 0) & 1024)
        return row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_size, row.st_mtime_ns

    wanted = identity(before)
    fd = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0),
    )
    try:
        opened = os.fstat(fd)
        need(identity(opened) == wanted)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after, final = os.fstat(fd), path.lstat()
        need(identity(after) == identity(final) == wanted and len(raw) == before.st_size)
        need(opened.st_ctime_ns == after.st_ctime_ns and before.st_ctime_ns == final.st_ctime_ns)
        return raw
    finally:
        os.close(fd)


def parse(raw):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, "DUPLICATE_JSON")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))


def load(name, raw, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def source_path(name):
    # Fixed same-HEAD sibling mapping; never supplied by metadata, CLI or daemon.
    need(name in FILES, "SOURCE_NAME")
    if name.startswith("pg/"):
        return HERE.parent / "public_pg_identity_probe" / name.removeprefix("pg/")
    return HERE / name


def capture(expected):
    need(re.fullmatch(r"[0-9a-f]{64}", expected), "PAYLOAD_PIN")
    raw = regular(HERE / "payload.json", 16384)
    need(sha(raw) == expected, "PAYLOAD_CHANGED")
    value = parse(raw)
    need(
        set(value) == {"schema", "files", "authority"}
        and value["schema"] == "public-prerequisites-payload/1"
        and value["authority"] is False
        and set(value["files"]) == FILES,
        "PAYLOAD_SCHEMA",
    )
    buffers = {}
    for name, row in value["files"].items():
        need(
            set(row) == {"bytes", "sha256"}
            and type(row["bytes"]) is int
            and 0 < row["bytes"] <= 65536,
            "PAYLOAD_ROW",
        )
        data = regular(source_path(name), 65536)
        need(len(data) == row["bytes"] and sha(data) == row["sha256"], "SOURCE_CHANGED")
        buffers[name] = data
    need(
        sha(buffers["engine/bounded_io.py"]) == BOUNDED_SHA
        and sha(buffers["pg/assets.json"]) == PG_ASSETS_SHA,
        "INHERITED_PINS",
    )
    return buffers


def durable(path, value, cap=16384):
    raw = (json.dumps(value, allow_nan=False, sort_keys=True) + "\n").encode()
    need(len(raw) <= cap, "PUBLIC_CAP")
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        need(stream.write(raw) == len(raw), "SHORT_WRITE")
        stream.flush()
        os.fsync(stream.fileno())


def campaign(observe, pull, pg, save, clock=time.monotonic, *, started=None):
    """Finite three-phase seam. No retries; no mutation after a failed prerequisite."""
    started = clock() if started is None else started
    packet = {
        "schema": "public-prerequisites-dispatch-N0-DATA/1",
        "state": "PENDING",
        "phases": {},
        "profile_accepted": False,
        "operational_GO": False,
        "authority": False,
    }
    save("intent", packet)
    for name, action, required in (
        ("observation", observe, 80),
        ("pull", pull, 190),
        ("pg", pg, 130),
    ):
        try:
            need(235 - (clock() - started) >= required, "DEADLINE_RESERVE")
            value = action()
            need(type(value) is dict and type(value.get("complete")) is bool, "PHASE_PACKET")
            packet["phases"][name] = value
            save(name, value)
            if not value["complete"]:
                packet["state"] = "FAILED_OR_UNKNOWN"
                break
        except BaseException:
            packet["phases"][name] = {"complete": False, "state": "UNKNOWN_OR_REFUSED"}
            save(name + "-unknown", packet["phases"][name])
            packet["state"] = "FAILED_OR_UNKNOWN"
            break
    else:
        packet["deadline_exceeded"] = clock() - started > 235
        packet["state"] = "FAILED_OR_UNKNOWN" if packet["deadline_exceeded"] else "DATA_COMPLETE"
    save("public-report", packet)
    return packet


def pull_public(work, owner, bounded, public):
    owner.verify_cli()  # Exact 3e898 file/FD/ctime/metadata gate BEFORE registry operation.
    config = work / "pull-config"
    config.mkdir(mode=0o700)
    with (config / "config.json").open("xb") as stream:
        os.chmod(stream.name, 0o600)
        need(stream.write(b'{"auths":{},"proxies":{}}\n') == 26, "CONFIG_WRITE")
    command = [
        "/usr/bin/docker",
        "--host",
        "unix:///var/run/docker.sock",
        "--config",
        str(config),
        "pull",
        "--platform",
        "linux/amd64",
        "--quiet",
        PG_MANIFEST,
    ]
    durable(
        work / "pull-intent.json",
        {
            "state": "PENDING",
            "operation": "one-public-PG-manifest-pull",
            "manifest": PG_MANIFEST,
            "CLI_sha256": owner.CLI_FACTS["sha256"],
        },
    )
    try:
        result = bounded.run_capped(
            command,
            env=ENV | {"DOCKER_API_VERSION": "1.52"},
            cwd=str(work),
            timeout=55,
            stdout_cap=4096,
            stderr_cap=4096,
            on_spawn=lambda pid: durable(work / "pull-pid.json", {"state": "PENDING", "pid": pid}),
        )
        facts = public.public_facts(result)
        durable(work / "pull-process.json", facts)
        owner.verify_cli()
        confirmed = public.h1(result)
        packet = {
            "complete": bool(confirmed and result.ok and result.stderr == b""),
            "state": "CLIENT_COMPLETED"
            if confirmed and result.ok and result.stderr == b""
            else "FAILED_OR_UNKNOWN",
            "process": facts,
            "image_identity_admitted_by_pull_stdout": False,
            "daemon_background_completion_proved": False,
        }
        durable(work / "pull-result.json", packet)
        return packet
    except BaseException:
        durable(work / "pull-unknown.json", {"state": "UNKNOWN", "complete": False})
        raise


def event_guard(environ):
    # A new workflow need not be registered on main: bootstrap only this push branch.
    need(
        environ.get("GITHUB_REPOSITORY") == "pamolive/PamOlive-Platform"
        and environ.get("GITHUB_JOB") == "public_prerequisites"
        and environ.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch"}
        and environ.get("GITHUB_REF") == PUSH_REF,
        "DISPOSABLE_EVENT_REF_REPO_ONLY",
    )


def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload-sha", required=True)
    parser.add_argument("--query-mode", choices=("prerequisites-only",), required=True)
    parser.add_argument("--github-hosted-disposable-public-read", action="store_true")
    args = parser.parse_args()
    need(args.github_hosted_disposable_public_read, "EXPLICIT_SCOPE")
    context_keys = {
        "GITHUB_ACTIONS",
        "CI",
        "RUNNER_ENVIRONMENT",
        "RUNNER_TEMP",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_EVENT_NAME",
        "GITHUB_REF",
        "GITHUB_REPOSITORY",
        "GITHUB_JOB",
        "GITHUB_SHA",
    }
    need(
        set(os.environ) == set(ENV) | context_keys
        and all(os.environ[k] == v for k, v in ENV.items()),
        "CLOSED_CALLER_ENV",
    )
    event_guard(os.environ)
    buffers = capture(args.payload_sha)
    owner = load("_quick_pg_owner", buffers["pg/owner.py"], source_path("pg/owner.py"))
    revision = os.environ.get("GITHUB_SHA", "")
    need(re.fullmatch(r"[0-9a-f]{40}", revision), "EXACT_REVISION")
    run, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    root = Path(os.environ["RUNNER_TEMP"]).absolute()
    pg_work = root / ("pamolive-pg-identity-" + run + "-" + attempt)
    owner.ci_guard(pg_work)
    os.umask(0o077)
    work = root / ("public-prerequisites-" + run + "-" + attempt)
    work.mkdir(mode=0o700)
    context = {
        "run": run,
        "attempt": attempt,
        "head": revision,
        "job": "public_prerequisites",
        "event": os.environ["GITHUB_EVENT_NAME"],
        "ref": os.environ["GITHUB_REF"],
        "phase": "public-prerequisite-N0",
        "nonce": uuid.uuid4().hex,
        "issued_unix": int(time.time()),
        "payload_sha256": args.payload_sha,
        "profile_accepted": False,
    }
    durable(work / "context.json", context)
    bounded = load("_quick_bounded", buffers["engine/bounded_io.py"], HERE / "engine/bounded_io.py")
    engine = load("_quick_engine", buffers["engine/collector.py"], HERE / "engine/collector.py")
    public = engine.public_module()

    def observe():
        tool = engine.binary_record()
        report = engine.collect_two(work / "engine", bounded.run_capped, tool)
        engine.collect_two_prerequisites(
            work / "engine", report, bounded.run_capped, buffers["engine/bounded_io.py"]
        )
        try:
            after = engine.binary_record()
        except (ValueError, OSError):
            after = None
        rc = engine.finalize_two(work / "engine", report, after)
        return {
            "complete": rc == 0,
            "schema": report["schema"],
            "query_count": len(report["queries"]),
            "profile_accepted": False,
        }

    def pg():
        # Same process: do not put the lease-owning driver under a kill-on-timeout wrapper.
        previous = sys.argv
        try:
            sys.argv = [
                str(source_path("pg/owner.py")),
                "run",
                "--assets-sha",
                PG_ASSETS_SHA,
                "--work",
                str(pg_work),
            ]
            rc = owner.main()
        finally:
            sys.argv = previous
        report = parse(regular(pg_work / "public-report.json", 65536))
        return {
            "complete": rc == 0
            and report.get("ok") is True
            and report.get("resources_released") is True,
            "resources_released": report.get("resources_released") is True,
            "profile_accepted": False,
        }

    packet = campaign(
        observe,
        lambda: pull_public(work, owner, bounded, public),
        pg,
        lambda name, value: durable(work / (name + ".json"), value),
        started=started,
    )
    return 0 if packet["state"] == "DATA_COMPLETE" else 42


if __name__ == "__main__":
    try:
        exit_code = main()
    except BaseException:
        print('{"state":"FAILED_OR_UNKNOWN","operational_GO":false}')
        exit_code = 42
    raise SystemExit(exit_code)
