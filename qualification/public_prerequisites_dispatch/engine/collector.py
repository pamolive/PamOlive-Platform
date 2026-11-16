"""Versioned read-only Engine DATA: original four and explicit version/info only."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLI = Path("/usr/bin/docker")
BOUNDED_SHA = "98233b610f2d53dfd698d0d91f61f3d3ebcb1693a847983f0472f89a885f414f"
PUBLIC_SHA = "7682097d1fe20e67880a30c450d2480413b72be205337a4e8294ea7f3f16f4e5"
PG = (
    "docker.io/library/postgres@sha256:"
    "6f7593c161689b6b02c78668b314af7da8811b592c5519108c57a49d0b6ad788"
)
VERSION = (
    '{"client_version":{{json .Client.Version}},"client_api":{{json .Client.APIVersion}},'
    '"client_os":{{json .Client.Os}},"client_arch":{{json .Client.Arch}},'
    '"server_version":{{json .Server.Version}},"server_api_max":{{json .Server.APIVersion}},'
    '"server_api_min":{{json .Server.MinAPIVersion}},'
    '"server_git_commit":{{json .Server.GitCommit}},'
    '"server_os":{{json .Server.Os}},"server_arch":{{json .Server.Arch}},'
    '"containerd":[{{$first := true}}{{range .Server.Components}}{{if eq .Name "containerd"}}'
    "{{if not $first}},{{end}}{{$first = false}}"
    '{"version":{{json .Version}},"revision":{{json (index .Details "GitCommit")}}}'
    "{{end}}{{end}}]}"
)
INFO = (
    '{"driver":{{json .Driver}},"driver_status":{{json .DriverStatus}},'
    '"root":{{json .DockerRootDir}},"containerd":{{json .Containerd}}}'
)
CONFIG_FIELDS = (
    "User",
    "WorkingDir",
    "Labels",
    "Volumes",
    "Entrypoint",
    "Cmd",
    "StopSignal",
    "ExposedPorts",
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def public_source():
    path = HERE / "containerd_public.py"
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 32768)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        need(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and (opened.st_dev, opened.st_ino, opened.st_size)
            == (info.st_dev, info.st_ino, info.st_size)
        )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(32769)
        need(len(raw) == opened.st_size and len(raw) <= 32768 and sha(raw) == PUBLIC_SHA)
        after = path.lstat()
        need(
            (after.st_dev, after.st_ino, after.st_size) == (info.st_dev, info.st_ino, info.st_size)
        )
    finally:
        os.close(fd)
    return raw


def public_module():
    module = type(sys)("_containerd_public")
    exec(
        compile(public_source(), "containerd_public.py", "exec", dont_inherit=True),
        module.__dict__,
    )
    return module


def need(value):
    if not value:
        raise ValueError("PUBLIC_METADATA_REFUSED")


def image_template():
    parts = [
        '"Id":{{json .Id}}',
        '"Os":{{json .Os}}',
        '"Architecture":{{json .Architecture}}',
        '"RootFS":{{json .RootFS}}',
        '"RepoDigests":{{json .RepoDigests}}',
    ]
    for name in CONFIG_FIELDS:
        found = "$p" + name
        parts.append(
            '"' + name + '":{"present":{{' + found + " := false}}"
            '{{range $k,$v := .Config}}{{if eq $k "'
            + name
            + '"}}{{'
            + found
            + " = true}}{{end}}{{end}}"
            "{{" + found + '}},"value":{{json (index .Config "' + name + '")}}}'
        )
    return "{" + ",".join(parts) + "}"


COMMANDS = (
    ("version", ["version", "--format", VERSION]),
    ("info", ["info", "--format", INFO]),
    ("postgres", ["image", "inspect", PG, "--format", image_template()]),
    (
        "application",
        ["image", "inspect", "pamolive-platform:ci", "--format", image_template()],
    ),
)


def parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 32768)

    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result)
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))


def redact_value(value):
    return {"redacted": True}


def safe_field(name, value):
    if value is None:
        return None
    if (
        name == "User"
        and type(value) is str
        and re.fullmatch(r"(?:[0-9]{1,10}(?::[0-9]{1,10})?|postgres)?", value)
    ):
        return value
    if name == "WorkingDir" and value in ("", "/", "/app", "/var/lib/postgresql"):
        return value
    if name == "Cmd" and value in (["postgres"], ["python", "deploy/runtime.py"]):
        return value
    if name == "Entrypoint" and value in ([], ["docker-entrypoint.sh"]):
        return value
    if name == "StopSignal" and value in ("SIGINT", "SIGTERM"):
        return value
    if name == "Volumes" and value in ({}, {"/var/lib/postgresql/data": {}}):
        return value
    if (
        name == "ExposedPorts"
        and type(value) is dict
        and len(value) <= 8
        and all(
            re.fullmatch(r"[0-9]{1,5}/(?:tcp|udp)", key) and item == {}
            for key, item in value.items()
        )
    ):
        return value
    if name == "Labels" and type(value) is dict and len(value) <= 16:
        if not set(value) <= {
            "org.opencontainers.image.source",
            "org.opencontainers.image.revision",
            "io.pamolive.source.license",
        }:
            return redact_value(value)
        result = {}
        for key, item in value.items():
            need(type(key) is str and re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", key))
            public = (
                key == "org.opencontainers.image.source"
                and item == "https://github.com/pamolive/PamOlive-Platform"
                or key == "org.opencontainers.image.revision"
                and type(item) is str
                and re.fullmatch("[a-f0-9]{40}", item)
                or key == "io.pamolive.source.license"
                and item == "AGPL-3.0-or-later"
            )
            result[key] = item if public else redact_value(item)
        return result
    return redact_value(value)


def project(name, value):
    need(type(value) is dict)
    if name == "version":
        keys = {
            "client_version",
            "client_api",
            "client_os",
            "client_arch",
            "server_version",
            "server_git_commit",
            "server_api_max",
            "server_api_min",
            "server_os",
            "server_arch",
            "containerd",
        }
        need(set(value) == keys)
        result = {}
        for key, item in value.items():
            if key == "containerd":
                try:
                    result[key] = public_module().component(item)
                except (ValueError, TypeError):
                    result[key] = redact_value(item)
                continue
            valid = type(item) is str and (
                key.endswith("_version")
                and re.fullmatch(r"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}(?:-(?:ce|ee))?", item)
                or key == "server_git_commit"
                and re.fullmatch(r"[a-f0-9]{7,40}", item)
                or "_api" in key
                and re.fullmatch(r"1\.[0-9]{1,3}", item)
                or key.endswith("_os")
                and item in {"linux", "windows", "darwin"}
                or key.endswith("_arch")
                and item in {"amd64", "arm64", "arm", "386"}
            )
            result[key] = item if valid else redact_value(item)
        return result
    if name == "info":
        need(set(value) == {"driver", "driver_status", "root", "containerd"})
        try:
            containerd = public_module().endpoint(value["containerd"])
        except (ValueError, TypeError):
            containerd = redact_value(value["containerd"])
        rows = value["driver_status"]
        need(
            rows is None
            or type(rows) is list
            and len(rows) <= 32
            and all(
                type(row) is list
                and len(row) == 2
                and all(type(item) is str and len(item) <= 256 for item in row)
                for row in rows
            )
        )
        # Keep only storage-type metadata, no arbitrary driver status value.
        known = {
            "driver-type",
            "Backing Filesystem",
            "Supports d_type",
            "Native Overlay Diff",
            "userxattr",
            "Using metacopy",
            "Supports shifting",
        }
        status = (
            None
            if rows is None
            else [
                [
                    key if key in known else redact_value(key),
                    item
                    if key == "driver-type" and item == "io.containerd.snapshotter.v1"
                    else redact_value(item),
                ]
                for key, item in rows
            ]
        )
        return {
            "containerd": containerd,
            "driver": value["driver"]
            if type(value["driver"]) is str
            and value["driver"]
            in {
                "overlay2",
                "overlayfs",
                "vfs",
                "btrfs",
                "zfs",
                "aufs",
                "windowsfilter",
                "fuse-overlayfs",
            }
            else redact_value(value["driver"]),
            "driver_status": status,
            "root": "/var/lib/docker"
            if value["root"] == "/var/lib/docker"
            else redact_value(value["root"]),
        }
    need(name in {"postgres", "application"})
    need(set(value) == {"Id", "Os", "Architecture", "RootFS", "RepoDigests", *CONFIG_FIELDS})
    need(type(value["Id"]) is str and re.fullmatch("sha256:[a-f0-9]{64}", value["Id"]))
    need(value["Os"] in {"linux", "windows"} and value["Architecture"] in {"amd64", "arm64"})
    root = value["RootFS"]
    need(type(root) is dict and set(root) == {"Type", "Layers"} and root["Type"] == "layers")
    need(
        type(root["Layers"]) is list
        and len(root["Layers"]) <= 64
        and all(
            type(item) is str and re.fullmatch("sha256:[a-f0-9]{64}", item)
            for item in root["Layers"]
        )
    )
    digests = value["RepoDigests"]
    need(
        digests is None
        or type(digests) is list
        and len(digests) <= 8
        and all(type(item) is str and len(item) <= 512 for item in digests)
    )
    result = {key: value[key] for key in ("Id", "Os", "Architecture", "RootFS", "RepoDigests")}
    if digests is not None:
        result["RepoDigests"] = [
            item
            if re.fullmatch(
                r"(?:docker\.io/)?(?:library/)?(?:postgres|pamolive-platform)@sha256:[a-f0-9]{64}",
                item,
            )
            else redact_value(item)
            for item in digests
        ]
    for field in CONFIG_FIELDS:
        row = value[field]
        need(
            type(row) is dict and set(row) == {"present", "value"} and type(row["present"]) is bool
        )
        need(row["present"] or row["value"] is None)
        result[field] = {
            "present": row["present"],
            "value": safe_field(field, row["value"]),
        }
    return result


def binary_record(path=CLI):
    for parent in path.parents:
        need(stat.S_ISDIR(parent.lstat().st_mode))
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and 0 < before.st_size <= 128 * 1024**2
    )
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)

        def ident(row):
            return (
                row.st_dev,
                row.st_ino,
                row.st_size,
                row.st_mode,
                row.st_mtime_ns,
                row.st_uid,
                row.st_gid,
            )

        need(ident(before) == ident(opened))
        digest, total = hashlib.sha256(), 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while block := stream.read(min(65536, 128 * 1024**2 + 1 - total)):
                total += len(block)
                need(total <= 128 * 1024**2)
                digest.update(block)
        after, final = os.fstat(fd), path.lstat()
        need(ident(after) == ident(final) == ident(before) and total == before.st_size)
        return {
            "path": "/usr/bin/docker",
            "bytes": total,
            "sha256": digest.hexdigest(),
            "file_type": "regular",
            "uid": before.st_uid,
            "gid": before.st_gid,
            "mode": stat.S_IMODE(before.st_mode),
        }
    finally:
        os.close(fd)


def _collect(work, runner, tool, commands):
    work.mkdir(mode=0o700)
    os.chmod(work, 0o700)
    for name in ("home", "docker-config"):
        (work / name).mkdir(mode=0o700)
        os.chmod(work / name, 0o700)
    (work / "docker-config/config.json").write_bytes(b'{"auths":{},"proxies":{}}\n')
    os.chmod(work / "docker-config/config.json", 0o600)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(work / "home"),
        "LANG": "C",
        "LC_ALL": "C",
    }
    prefix = [
        "/usr/bin/docker",
        "--host",
        "unix:///var/run/docker.sock",
        "--config",
        str(work / "docker-config"),
    ]
    records = {}
    for name, arguments in commands:
        result = runner(
            prefix + arguments,
            env=env,
            cwd=str(work),
            timeout=15,
            stdout_cap=32768,
            stderr_cap=4096,
        )
        facts = result.facts()
        confirmed = (
            facts["spawn_attempted"] is True
            and type(facts["pid"]) is int
            and facts["pid"] > 0
            and type(facts["returncode"]) is int
            and facts["owned_child_reaped"] is True
            and facts["drains_complete"] is True
            and facts["cleanup_exception_type"] is None
            and facts["exception_type"] is None
            and facts["killed_owned_child"] is False
            and facts["reason"] in (None, "nonzero_exit")
        )
        row = {
            "process": {
                key: value
                for key, value in facts.items()
                if key not in {"stdout_bytes", "stderr_bytes"}
            },
            "data": None,
            "projection_status": "FAILED_OR_UNKNOWN",
            "stderr_class": stderr_class(result.stderr),
        }
        if confirmed and result.ok and result.stderr == b"":
            try:
                row["data"] = project(name, parse(result.stdout))
                row["projection_status"] = "DATA_ONLY"
            except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
                pass
        records[name] = row
        if not confirmed:
            break
    for name, _arguments in commands:
        records.setdefault(
            name,
            {
                "process": None,
                "data": None,
                "projection_status": "NOT_ATTEMPTED_AFTER_UNKNOWN",
                "stderr_class": "not_observed",
            },
        )
    report = {
        "tool": tool,
        "queries": records,
        "queries_projected": all(
            row["projection_status"] == "DATA_ONLY" for row in records.values()
        ),
        "all_clients_reaped_drained": all(
            row["process"] is not None
            and row["process"]["owned_child_reaped"] is True
            and row["process"]["drains_complete"] is True
            for row in records.values()
        ),
        "bootstrap_TCB": (
            "GitHub-hosted runner image + reviewed pinned checkout/setup actions + "
            "installed Docker CLI/Engine + host Python stdlib; "
            "hashes are observations, not attestation."
        ),
        "config_Env_collected": False,
        "container_queries": False,
        "getent_executed": False,
        "private_inputs": False,
        "profile_accepted": False,
        "operational_GO": False,
        "authority": False,
    }
    return report


def collect(work, runner, tool):
    report = _collect(work, runner, tool, COMMANDS)
    report["schema"] = "W-A1-public-Engine-DATA/1"
    report["four_queries_projected"] = report.pop("queries_projected")
    return report


def collect_two(work, runner, tool):
    report = _collect(work, runner, tool, COMMANDS[:2])
    report["schema"] = "W-A1-public-version-info-DATA/2"
    report["two_queries_projected"] = report.pop("queries_projected")
    return report


def stderr_class(raw):
    if raw == b"":
        return "empty"
    if b"No such image" in raw or b"no such image" in raw:
        return "local_image_absent"
    if b"template" in raw and (b"error" in raw or b"executing" in raw):
        return "template_error"
    if b"connect" in raw or b"permission denied" in raw or b"API version" in raw:
        return "engine_access_failed"
    return "unclassified"


def finalize(work, report, tool_after):
    report["tool_unchanged"] = tool_after is not None and tool_after == report["tool"]
    report["four_queries_received"] = (
        report["four_queries_projected"]
        and report["all_clients_reaped_drained"]
        and report["tool_unchanged"]
    )
    report["all_prerequisites_received"] = (
        report["four_queries_received"]
        and report.get("containerd_prerequisites", {}).get("status") == "COMPLETE"
    )
    path = work / "public-report.json"
    need(not path.exists())
    raw = json.dumps(report, indent=2, allow_nan=False).encode() + b"\n"
    need(len(raw) <= 128 * 1024)
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(raw)
    return 0 if report["all_prerequisites_received"] else 42


def durable(work, ordinal, row):
    raw = json.dumps(row, allow_nan=False, sort_keys=True).encode() + b"\n"
    need(len(raw) <= 16384)
    with (work / ("root-read-" + ordinal + ".json")).open("xb") as stream:
        os.chmod(stream.name, 0o600)
        need(stream.write(raw) == len(raw))
        stream.flush()
        os.fsync(stream.fileno())


def _collect_prerequisites(work, report, runner, bounded_raw, *, ready, measure=None, python=None):
    cp = public_module()
    row = {
        "status": "NOT_ATTEMPTED",
        "process": None,
        "data": None,
        "tools": None,
        "tools_unchanged": False,
        "failure": None,
        "profile_accepted": False,
        "operational_GO": False,
    }
    report["containerd_prerequisites"] = row
    if not ready:
        return
    version, info = (report["queries"][name]["data"] for name in ("version", "info"))
    stage = "version_info"
    try:
        cp.component([version["containerd"]])
        address = cp.endpoint(info["containerd"])["Address"]
        need(
            info["driver"] == "overlayfs"
            and info["root"] == "/var/lib/docker"
            and info["driver_status"] == [["driver-type", "io.containerd.snapshotter.v1"]]
        )
        stage = "bounded_source"
        need(sha(bounded_raw) == BOUNDED_SHA)
        measure = cp.tool_record if measure is None else measure
        python = "/usr/bin/python3.14" if python is None else python
        need(python == "/usr/bin/python3.14")
        tools = {}
        row["tools"] = tools
        for name, path in (
            ("sudo", "/usr/lib/cargo/bin/sudo"),
            ("env", "/usr/lib/cargo/bin/coreutils/env"),
            ("python", python),
        ):
            stage = name + "_tool_before"
            tools[name] = measure(path)
        stage = "payload"
        payload = bounded_raw + b"\n" + public_source() + b"\nraise SystemExit(root_main())\n"
        need(len(payload) <= 65536)
        command = [
            "/usr/lib/cargo/bin/sudo",
            "-n",
            "--",
            "/usr/lib/cargo/bin/coreutils/env",
            "-i",
            "PATH=/usr/bin:/bin",
            "HOME=/nonexistent",
            "LANG=C",
            "LC_ALL=C",
            python,
            "-I",
            "-B",
            "-S",
            "-c",
            payload.decode("utf-8"),
            address,
        ]
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
        }
        durable(
            work,
            "intent",
            {
                "state": "PENDING",
                "operation": "containerd-public-roots",
                "payload_sha256": sha(payload),
                "tools": tools,
            },
        )
        row["status"] = "UNKNOWN"

        def spawned(pid):
            need(type(pid) is int and pid > 0)
            durable(work, "pid", {"state": "PENDING", "pid": pid})

        stage = "root_process"
        result = runner(
            command,
            env=env,
            cwd="/",
            timeout=45,
            stdout_cap=16384,
            stderr_cap=4096,
            on_spawn=spawned,
        )
        row["process"] = cp.public_facts(result)
        after = {}
        for name, path in (
            ("sudo", "/usr/lib/cargo/bin/sudo"),
            ("env", "/usr/lib/cargo/bin/coreutils/env"),
            ("python", python),
        ):
            stage = name + "_tool_after"
            after[name] = measure(path)
        row["tools_unchanged"] = tools == after
        if not cp.h1(result) or not row["tools_unchanged"]:
            row["failure"] = {
                "stage": "root_process" if not cp.h1(result) else "reader_tools_after",
                "code": "UNKNOWN_H1" if not cp.h1(result) else "TOOL_CHANGED",
            }
            return
        if not result.ok or result.stderr != b"":
            row["status"] = (
                "PERMISSION_REFUSED"
                if b"permission denied" in result.stderr.lower()
                or b"password is required" in result.stderr.lower()
                else "CHILD_REFUSED"
            )
            row["failure"] = {"stage": "root_process", "code": "CHILD_REFUSED"}
            # A confirmed nonzero child may still provide a typed public refusal.
            if result.stderr == b"":
                try:
                    diagnostic = cp.refusal_diagnostic(parse(result.stdout))
                    row["status"] = diagnostic["status"]
                    row["diagnostic"] = diagnostic
                except (ValueError, TypeError, KeyError):
                    pass
            return
        stage = "root_packet"
        row["data"] = cp.validate_packet(parse(result.stdout))
        row["status"] = "COMPLETE"
    except (ValueError, OSError, TypeError, KeyError, UnicodeError) as error:
        code = (
            error.code
            if isinstance(error, cp.ToolRefusal) and error.code in cp.TOOL_FAILURES
            else "READ_REFUSED"
        )
        row["failure"] = {"stage": stage, "code": code}
        # PENDING, if it exists, is never erased; no later query heals UNKNOWN.
        if row["status"] != "UNKNOWN":
            row["status"] = "PRECONDITION_REFUSED"
    finally:
        durable(
            work,
            "result",
            {
                "state": row["status"],
                "process": row["process"],
                "tools_unchanged": row["tools_unchanged"],
                "failure": row["failure"],
            },
        )


def collect_prerequisites(work, report, runner, bounded_raw, *, measure=None, python=None):
    ready = (
        report["schema"] == "W-A1-public-Engine-DATA/1"
        and set(report["queries"]) == {name for name, _ in COMMANDS}
        and report["four_queries_projected"]
        and report["all_clients_reaped_drained"]
    )
    return _collect_prerequisites(
        work, report, runner, bounded_raw, ready=ready, measure=measure, python=python
    )


def collect_two_prerequisites(work, report, runner, bounded_raw, *, measure=None, python=None):
    ready = (
        report["schema"] == "W-A1-public-version-info-DATA/2"
        and set(report["queries"]) == {"version", "info"}
        and "four_queries_projected" not in report
        and report["two_queries_projected"]
        and report["all_clients_reaped_drained"]
    )
    return _collect_prerequisites(
        work, report, runner, bounded_raw, ready=ready, measure=measure, python=python
    )


def finalize_two(work, report, tool_after):
    need(
        report["schema"] == "W-A1-public-version-info-DATA/2"
        and "four_queries_projected" not in report
    )
    report["tool_unchanged"] = tool_after is not None and tool_after == report["tool"]
    report["two_queries_received"] = (
        report["two_queries_projected"]
        and report["all_clients_reaped_drained"]
        and report["tool_unchanged"]
    )
    report["all_prerequisites_received"] = (
        report["two_queries_received"]
        and report.get("containerd_prerequisites", {}).get("status") == "COMPLETE"
    )
    raw = json.dumps(report, indent=2, allow_nan=False).encode() + b"\n"
    need(len(raw) <= 128 * 1024)
    with (work / "public-report.json").open("xb") as stream:
        os.chmod(stream.name, 0o600)
        need(stream.write(raw) == len(raw))
        stream.flush()
        os.fsync(stream.fileno())
    return 0 if report["all_prerequisites_received"] else 42


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--github-hosted-disposable-public-read", action="store_true")
    parser.add_argument("--query-mode", choices=("four", "prerequisites-only"), default="four")
    args = parser.parse_args()
    need(
        os.name == "posix"
        and os.getuid() > 0
        and not args.work.exists()
        and args.github_hosted_disposable_public_read
    )
    tool = binary_record()
    helper = HERE / "bounded_io.py"
    info = helper.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 32768)
    with helper.open("rb") as stream:
        raw = stream.read(32769)
    need(len(raw) <= 32768 and sha(raw) == BOUNDED_SHA)
    spec = importlib.util.spec_from_file_location("_public_engine_bounded", helper)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec(compile(raw, str(helper), "exec", dont_inherit=True), module.__dict__)
    two = args.query_mode == "prerequisites-only"
    report = (collect_two if two else collect)(args.work.absolute(), module.run_capped, tool)
    (collect_two_prerequisites if two else collect_prerequisites)(
        args.work.absolute(), report, module.run_capped, raw
    )
    try:
        after = binary_record()
    except (ValueError, OSError):
        after = None
    return (finalize_two if two else finalize)(args.work, report, after)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError):
        print(
            '{"schema":"W-A1-public-Engine-DATA/1","error":"FAILED_OR_UNKNOWN","operational_GO":false}'
        )
        raise SystemExit(42) from None
