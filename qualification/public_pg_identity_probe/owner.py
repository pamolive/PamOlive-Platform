"""Pinned Linux CI owner for one bounded public getent observation, no SQL."""

import argparse
import ast
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
CLI = Path("/usr/bin/docker")
CLI_FACTS = {
    "path": "/usr/bin/docker",
    "file_type": "regular",
    "uid": 0,
    "gid": 0,
    "mode": 0o755,
    "bytes": 45526415,
    "sha256": "3e898b1e7498b1bf98ec29a3d2ce77f9f09dd357e0b8dbf6ca69b463a871de88",
}
HELPERS = {
    "legacy.py": "7f3bfa46307673ba51c3a21fa3b70171ab9f931547e1903adce2fc02a29e02ce",
    "linux.py": "40f5bbc845457ed18bf893fbb5d04eb90c6af0959077b0667a3dae3717120b80",
    "bounded_io.py": "98233b610f2d53dfd698d0d91f61f3d3ebcb1693a847983f0472f89a885f414f",
    "lease_support.py": "cbcb33ec203a47e9138119ee039255c4ce751c62cbf8208f918ab8efc730f07a",
}
FILES = {
    "probe.py",
    "bindings.json",
    "data/profile.json",
    "data/config.json",
    "data/amd64-manifest.json",
    "data/index.reference.json",
    *("helpers/" + name for name in HELPERS),
}
INFO_TEMPLATE = (
    '{"DockerRootDir":{{json .DockerRootDir}},"Driver":{{json .Driver}},'
    '"DriverStatus":{{json .DriverStatus}}}'
)


def need(value, code="OWNER_REFUSED"):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))


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


def capture(expected_sha):
    need(type(expected_sha) is str and re.fullmatch("[a-f0-9]{64}", expected_sha))
    raw = regular(HERE / "assets.json", 16384)
    need(sha(raw) == expected_sha, "ROOT_ASSETS_SHA256")
    manifest = parse(raw)
    need(type(manifest) is dict and set(manifest) == {"schema", "files", "authority"})
    need(manifest["schema"] == "W-PG-public-owner-assets/1" and manifest["authority"] is False)
    need(type(manifest["files"]) is dict and set(manifest["files"]) == FILES)
    buffers = {}
    for name, row in manifest["files"].items():
        need(type(row) is dict and set(row) == {"bytes", "sha256"})
        need(type(row["bytes"]) is int and 0 < row["bytes"] <= 128 * 1024)
        value = regular(HERE / name, row["bytes"])
        need(len(value) == row["bytes"] and sha(value) == row["sha256"], "ROOT_ASSET_CHANGED")
        buffers[name] = value
    for name, digest in HELPERS.items():
        need(sha(buffers["helpers/" + name]) == digest, "RECEIVED_HELPER_PIN")
    binding = parse(buffers["bindings.json"])
    need(set(binding) == {"files", "operational_GO"} and binding["operational_GO"] is False)
    need(set(binding["files"]) == FILES - {"probe.py", "bindings.json"})
    for name, row in binding["files"].items():
        need(row == {"bytes": len(buffers[name]), "sha256": sha(buffers[name])}, "PUBLIC_BINDING")
    return buffers


def load(name, raw, filename):
    module = types.ModuleType(name)
    module.__file__ = str(HERE / filename)
    sys.modules[name] = module
    exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


def verify_cli():
    for parent in CLI.parents:
        need(stat.S_ISDIR(parent.lstat().st_mode), "CLI_PARENT_ALIAS")

    def identity(row):
        need(
            stat.S_ISREG(row.st_mode)
            and row.st_nlink == 1
            and row.st_uid == CLI_FACTS["uid"]
            and row.st_gid == CLI_FACTS["gid"]
            and stat.S_IMODE(row.st_mode) == CLI_FACTS["mode"]
            and row.st_size == CLI_FACTS["bytes"],
            "CLI_EXACT_METADATA",
        )
        return (
            row.st_dev,
            row.st_ino,
            row.st_mode,
            row.st_nlink,
            row.st_uid,
            row.st_gid,
            row.st_size,
            row.st_mtime_ns,
        )

    before = CLI.lstat()
    wanted = identity(before)
    fd = os.open(CLI, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        need(identity(opened) == wanted, "CLI_FD_IDENTITY")
        digest, total = hashlib.sha256(), 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while block := stream.read(min(65536, CLI_FACTS["bytes"] + 1 - total)):
                total += len(block)
                need(total <= CLI_FACTS["bytes"], "CLI_READ_BUDGET")
                digest.update(block)
        after, final = os.fstat(fd), CLI.lstat()
        need(
            identity(after) == identity(final) == wanted and total == CLI_FACTS["bytes"],
            "CLI_CHANGED",
        )
        need(
            opened.st_ctime_ns == after.st_ctime_ns and before.st_ctime_ns == final.st_ctime_ns,
            "CLI_CHANGED",
        )
        need(digest.hexdigest() == CLI_FACTS["sha256"], "CLI_SHA256")
    finally:
        os.close(fd)


def ci_guard(work):
    need(sys.platform == "linux" and os.getuid() > 0 and os.getgid() > 0, "LINUX_NONROOT_ONLY")
    need(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("CI") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "GITHUB_HOSTED_CI_ONLY",
    )
    forbidden = {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
    }
    need(
        not forbidden & set(os.environ) and not any(k.startswith("DOCKER_") for k in os.environ),
        "AMBIENT_OVERRIDE_REFUSED",
    )
    run, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    need(re.fullmatch(r"[1-9][0-9]{0,19}", run) and re.fullmatch(r"[1-9][0-9]{0,3}", attempt))
    root = Path(os.environ["RUNNER_TEMP"]).absolute()
    for path in (root, *root.parents):
        need(stat.S_ISDIR(path.lstat().st_mode), "RUNNER_TEMP_ALIAS")
    need(work == root / ("pamolive-pg-identity-" + run + "-" + attempt), "EXACT_NEW_WORK_PATH")
    return root


def command_allowed(probe, state, args):
    probe.legacy_reservation_view(state)
    name = state["run"] + "-stage0"
    if args in (
        ["version", "--format", probe.VERSION_TEMPLATE],
        ["info", "--format", INFO_TEMPLATE],
        ["image", "inspect", probe.IMAGE],
        [
            "container",
            "ls",
            "-a",
            "--no-trunc",
            "--filter",
            "name=^/" + name + "$",
            "--format",
            "{{.ID}}",
        ],
    ):
        return
    if args == [
        "create",
        "--name",
        name,
        "--label",
        probe.LABEL + "=" + state["run"],
        *probe.arguments(),
    ]:
        need(state.get("metadata_verified") is True, "METADATA_BEFORE_CREATE")
        need(state.get("owner_cleaning") is False, "NO_CREATE_DURING_CLEANUP")
        item = state.get("legacy_reservation", {})
        need(item.get("attempted") is True and item.get("outcome") == "pending", "CREATE_INTENT")
        return
    if len(args) == 2 and args[0] == "inspect" and re.fullmatch("[a-f0-9]{64}", args[1]):
        return  # Read-only ownership check, including a foreign exact-name collision.
    item = state.get("legacy_reservation", {})
    cid = item.get("cid")
    need(type(cid) is str and re.fullmatch("[a-f0-9]{64}", cid), "NO_OWNED_CID")
    need(
        item.get("image_config") == probe.MANIFEST
        and item.get("run") == state["run"]
        and item.get("name") == name
        and item.get("user") == "0:0",
        "OWNED_MANIFEST_RECORD",
    )
    need(
        args in (["start", "--attach", cid], ["stop", "--time", "5", cid], ["rm", cid]),
        "CLOSED_GETENT_ARGV_ONLY",
    )
    probe.require_create_ack(state, cid)
    need(state.get("metadata_verified") is True, "METADATA_BEFORE_MUTATION")
    if args[0] == "start":
        need(
            state.get("owner_cleaning") is False
            and state.get("started") is True
            and item.get("outcome") == "confirmed"
            and state.get("start_profile_cid") == cid,
            "ONE_GETENT_START_INTENT",
        )
    else:
        need(state.get("owner_cleaning") is True, "OWNED_CLEANUP_ONLY")


def checked_runner(probe, state, work, bounded):
    prefix = [
        "/usr/bin/docker",
        "--host",
        "unix:///var/run/docker.sock",
        "--config",
        str(work / "docker-config"),
    ]

    def run(argv, **options):
        need(argv[:5] == prefix, "LOCAL_ENGINE_PREFIX")
        command_allowed(probe, state, argv[5:])
        need(set(options) == {"cwd", "env", "timeout", "stdout_cap", "stderr_cap"})
        need(
            options["env"]
            == {
                "PATH": "/usr/bin:/bin",
                "HOME": str(work / "home"),
                "LANG": "C",
                "LC_ALL": "C",
                "DOCKER_API_VERSION": "1.52",
            }
            and options["cwd"] == str(work),
            "CLOSED_SUBPROCESS_ENV",
        )
        need(
            options["stderr_cap"] == 4096
            and options["stdout_cap"] == (4096 if argv[5:7] == ["start", "--attach"] else 32768),
            "CLOSED_IO_CAPS",
        )
        verify_cli()
        end = state["cleanup_deadline"] if state.get("owner_cleaning") else state["work_deadline"]
        remaining = end - time.monotonic()
        need(remaining > 0, "DEADLINE_AFTER_CLI_CHECK")
        options["timeout"] = min(options["timeout"], remaining, 15)
        result = bounded.run_capped(argv, **options)
        verify_cli()
        return result

    return run


def received_lease(raw, probe, path, state, save):
    tree = ast.parse(raw)
    (lease,) = [
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Lease"
    ]
    scope = {"os": os, "uuid": uuid, "m": probe, "safe_file": regular}
    exec(
        compile(
            ast.Module(body=[lease], type_ignores=[]), "received-byte-exact-Lease-body", "exec"
        ),
        scope,
    )
    actual = scope["Lease"](path, state["run"])

    class DurableLease:
        def acquire(self):
            state["lease"] = {
                "token": actual.token.decode("ascii"),
                "identity": None,
                "held": False,
                "acquire_attempted": True,
            }
            save()
            try:
                actual.acquire()
            finally:
                state["lease"].update(
                    identity=list(actual.identity) if actual.identity else None, held=actual.held
                )
                save()

        def release(self, safe):
            result = actual.release(safe)
            state["lease"]["held"] = actual.held
            save()
            return result

        def restore(self):
            value = state["lease"]
            token = value["token"]
            need(
                value["held"] is True
                and type(token) is str
                and re.fullmatch("ZLIB_CONTROL:" + state["run"] + ":[a-f0-9]{32}", token),
                "OWNED_LEASE",
            )
            identity = value["identity"]
            need(
                type(identity) is list
                and len(identity) == 2
                and all(type(n) is int and n >= 0 for n in identity),
                "OWNED_LEASE_IDENTITY",
            )
            actual.token, actual.identity, actual.held = (
                token.encode("ascii"),
                tuple(identity),
                True,
            )

    return DurableLease()


def public_context(probe, state, report):
    fields = {
        "operation",
        "spawn_attempted",
        "pid",
        "returncode",
        "reason",
        "exception_type",
        "killed_owned_child",
        "owned_child_reaped",
        "drains_complete",
        "cleanup_exception_type",
    }
    return {
        **report,
        "CLI_expected": CLI_FACTS,
        "operation_api": "1.52",
        "historical_d47_discovery_api": "1.54",
        "CLI_matches_required_profile_when_ok": report.get("ok") is True,
        "IO": [{k: v for k, v in row.items() if k in fields} for row in state["IO"]],
        "IO_total": state["IO_total"],
        "IO_uncertain": state["IO_uncertain"],
        "source_assets_sha256": state["assets_sha256"],
        "legacy_reservation_image_key_semantics": "manifest digest only, not config digest",
        "image_manifest": probe.MANIFEST,
        "image_config": probe.CONFIG,
        "storage_qualification_received": False,
        "operational_GO": False,
        "inspect_diagnostics": state.get("inspect_diagnostics", []),
        "inspect_refusals": state.get("inspect_refusals", []),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("run", "cleanup"))
    parser.add_argument("--assets-sha", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    buffers = capture(args.assets_sha)
    probe = load("_getent_probe", buffers["probe.py"], "probe.py")
    profile = probe.verify_public_binding(buffers)
    work = args.work.absolute()
    root = ci_guard(work)
    os.umask(0o077)
    verify_cli()  # Received CLI identity before creating the private journal or lease.
    legacy = load("_getent_legacy", buffers["helpers/legacy.py"], "helpers/legacy.py")
    linux = load("_getent_linux", buffers["helpers/linux.py"], "helpers/linux.py")
    bounded = load("_getent_bounded", buffers["helpers/bounded_io.py"], "helpers/bounded_io.py")
    now = time.monotonic()
    if args.mode == "run":
        need(not work.exists(), "NO_REPLAY_OR_REUSE")
        work.mkdir(mode=0o700)
        os.chmod(work, 0o700)
        for name in ("home", "docker-config"):
            (work / name).mkdir(mode=0o700)
            os.chmod(work / name, 0o700)
        (work / "docker-config/config.json").write_bytes(b'{"auths":{},"proxies":{}}\n')
        os.chmod(work / "docker-config/config.json", 0o600)
        state = {
            "schema": "W-PG-identity-owner-state/1",
            "run": "w-pg-id-" + uuid.uuid4().hex,
            "work": str(work),
            "assets_sha256": args.assets_sha,
            "image_manifest": probe.MANIFEST,
            "image_config": probe.CONFIG,
            "user": "0:0",
            "IO": [],
            "IO_total": 0,
            "IO_uncertain": False,
            "started": False,
            "pull": "not_attempted",
            "work_deadline": now + 90,
            "cleanup_deadline": now + 120,
            "metadata_verified": False,
            "owner_cleaning": False,
            "cleanup_attempts": 0,
        }
    else:
        state = parse(regular(work / "state.json", 256 * 1024))
        need(
            state["schema"] == "W-PG-identity-owner-state/1"
            and state["work"] == str(work)
            and state["assets_sha256"] == args.assets_sha,
            "EXACT_RECOVERY_SUBJECT",
        )
        probe.legacy_reservation_view(state)
        attempts = state["cleanup_attempts"]
        need(type(attempts) is int and 0 <= attempts < 2, "BOUNDED_EXPLICIT_RECOVERY_ONLY")
        state["cleanup_attempts"] = attempts + 1
        # A new cleanup-only window preserves the entire ledger and uncertainty.
        state.update(work_deadline=now + 1, cleanup_deadline=now + 30, owner_cleaning=True)

    def save():
        legacy.atomic(work / "state.json", state)
        os.chmod(work / "state.json", 0o600)

    save()
    lease = received_lease(
        buffers["helpers/lease_support.py"],
        probe,
        root / ".pamolive-public-pg-identity-ci.lock",
        state,
        save,
    )
    client = probe.make_client(
        legacy,
        linux,
        bounded,
        work,
        state,
        save,
        profile,
        runner=checked_runner(probe, state, work, bounded),
    )
    try:
        if args.mode == "run":
            report = probe.observe(client, legacy, linux, lease, state, save, profile)
        else:
            lease.restore()
            client.cleaning = True
            probe.verify_version(client.json("version", "--format", probe.VERSION_TEMPLATE))
            probe.verify_store(client.info())
            state["metadata_verified"] = True
            save()
            cleanup = probe.reconcile_owned(client, legacy, state, save)
            safe = cleanup.get("released") is True and linux.io_history_released(state)
            status = lease.release(safe)
            report = {
                "schema": "pamolive.W-public-PG-identity-cleanup-DATA/1",
                "ok": False,
                "measurement": None,
                "resources_released": safe and status.get("released") is True,
                "container_released": cleanup.get("released") is True,
                "clients_released": linux.io_history_released(state),
                "commissioned": False,
                "PGDATA_ownership_measured": False,
                "authority": False,
            }
    except BaseException:
        # Retain journal/lease and no measurement on an incomplete owner path.
        report = {
            "schema": "pamolive.W-public-PG-identity-DATA/1",
            "ok": False,
            "measurement": None,
            "failure": "OWNER_FAILED_OR_UNKNOWN",
            "resources_released": False,
            "commissioned": False,
            "PGDATA_ownership_measured": False,
            "authority": False,
        }
    finally:
        save()
    report = public_context(probe, state, report)
    target = work / (
        "public-report.json"
        if args.mode == "run"
        else "cleanup-public-report-" + str(state["cleanup_attempts"]) + ".json"
    )
    need(not target.exists(), "NO_PUBLIC_REPORT_REWRITE")
    raw = (json.dumps(report, indent=2, allow_nan=False) + "\n").encode()
    need(len(raw) <= 64 * 1024, "PUBLIC_REPORT_BUDGET")
    with target.open("xb") as stream:
        os.chmod(target, 0o600)
        stream.write(raw)
    print(
        json.dumps(
            {
                "ok": report["ok"],
                "resources_released": report["resources_released"],
                "operational_GO": False,
            }
        )
    )
    return 0 if report["ok"] or args.mode == "cleanup" and report["resources_released"] else 42


if __name__ == "__main__":
    raise SystemExit(main())
