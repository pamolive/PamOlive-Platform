"""Fixed public provider metadata only; no contents, action or historical cause."""

import argparse
import errno
import json
import math
import os
import re
import stat
import sys
import time
from pathlib import PurePosixPath

ROLE_PATHS = {
    "DPKG_QUERY": "/usr/bin/dpkg-query",
    "CHROME_TARGET": "/opt/google/chrome/chrome",
}
ACK = "public-provider-metadata-only-v1"
OUTPUT_NAME = "public-fixture-parents.json"
ENV_KEYS = (
    "GITHUB_ACTIONS",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER_ID",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
    "GITHUB_SHA",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "RUNNER_TEMP",
    "ImageOS",
    "ImageVersion",
)
IDENTITY = ("dev", "ino", "mode", "uid", "gid", "nlink", "mtime_ns", "ctime_ns")


def need(value, code):
    if not value:
        raise ValueError(code)


def budget(clock, deadline):
    now = clock()
    need(type(now) in (int, float) and math.isfinite(now) and now < deadline, "METADATA_BUDGET")


def read(clock, deadline, call, *args, **kwargs):
    budget(clock, deadline)
    try:
        return call(*args, **kwargs)
    finally:
        budget(clock, deadline)


def opened(ops, clock, deadline, name, flags, **kwargs):
    budget(clock, deadline)
    fd = ops.open(name, flags, **kwargs)
    try:
        budget(clock, deadline)
        return fd
    except BaseException:
        ops.close(fd)
        raise


def identity(row):
    result = tuple(getattr(row, "st_" + key) for key in IDENTITY)
    need(all(type(n) is int and 0 <= n < 2**64 for n in result), "METADATA_TYPES")
    return result


def metadata(row):
    identity(row)
    need(
        0 <= row.st_uid < 2**32 and 0 <= row.st_gid < 2**32 and 0 <= row.st_mode < 2**32,
        "METADATA_TYPES",
    )
    kind = (
        "DIRECTORY"
        if stat.S_ISDIR(row.st_mode)
        else "REGULAR"
        if stat.S_ISREG(row.st_mode)
        else "SYMLINK"
        if stat.S_ISLNK(row.st_mode)
        else "OTHER"
    )
    return {
        "type": kind,
        "uid": row.st_uid,
        "gid": row.st_gid,
        "mode": stat.S_IMODE(row.st_mode),
        "nlink": row.st_nlink,
        "group_writable": bool(row.st_mode & 0o020),
        "other_writable": bool(row.st_mode & 0o002),
        "alias": kind == "SYMLINK",
    }


def os_error(error):
    value = getattr(error, "errno", None)
    if type(value) is not int:
        return "OS_ERROR"
    if value == errno.ENOENT:
        return "MISSING"
    if value in (errno.EACCES, errno.EPERM):
        return "PERMISSION_DENIED"
    if value == errno.ELOOP:
        return "ALIAS_OR_PATH"
    if value == errno.ENOTDIR:
        return "NOT_DIRECTORY"
    return "OS_ERROR"


def walk(path, ops, clock, deadline):
    """Every component is fixed; O_PATH never reads a file's contents."""
    need(type(path) is str and path in ROLE_PATHS.values(), "FIXED_ROLE_PATH_REQUIRED")
    nodes, owned, anchors = [], [], []
    current = None
    close_ok = True
    try:
        parts = ("/", *PurePosixPath(path).parts[1:])
        for index, component in enumerate(parts):
            leaf = index == len(parts) - 1
            parent = current
            node = {
                "index": index,
                "kind": "LEAF" if leaf else "PARENT",
                "status": "UNKNOWN",
                "metadata": None,
                "race": False,
            }
            nodes.append(node)
            try:
                before = read(
                    clock, deadline, ops.stat, component, dir_fd=parent, follow_symlinks=False
                )
                node["metadata"] = metadata(before)
                if stat.S_ISLNK(before.st_mode):
                    node["status"] = "ALIAS"
                    break
                if not leaf and not stat.S_ISDIR(before.st_mode):
                    node["status"] = "NOT_DIRECTORY"
                    break
                if leaf and not stat.S_ISREG(before.st_mode):
                    node["status"] = "NOT_REGULAR"
                    break
                flags = ops.O_PATH | ops.O_NOFOLLOW | ops.O_CLOEXEC
                if not leaf:
                    flags |= ops.O_DIRECTORY
                fd = opened(ops, clock, deadline, component, flags, dir_fd=parent)
                owned.append(fd)
                observed = read(clock, deadline, ops.fstat, fd)
                after = read(
                    clock, deadline, ops.stat, component, dir_fd=parent, follow_symlinks=False
                )
                if identity(before) != identity(observed) or identity(before) != identity(after):
                    node.update(status="RACE", race=True)
                    break
                node["status"] = "OBSERVED"
                anchors.append((node, fd, parent, component, identity(before)))
                current = fd
            except OSError as error:
                node["status"] = os_error(error)
                break
            except ValueError as error:
                if error.args == ("METADATA_BUDGET",):
                    raise
                node["status"] = "METADATA_UNKNOWN"
                break
        # Keep all anchors until the final bracket, then close every owned FD.
        for node, fd, parent, component, before in anchors:
            try:
                observed = read(clock, deadline, ops.fstat, fd)
                after = read(
                    clock, deadline, ops.stat, component, dir_fd=parent, follow_symlinks=False
                )
                if identity(observed) != before or identity(after) != before:
                    node.update(status="RACE", race=True)
                    break
            except OSError as error:
                node["status"] = os_error(error)
                break
    finally:
        for fd in reversed(owned):
            try:
                ops.close(fd)
            except OSError:
                close_ok = False
    complete = len(nodes) == len(parts) and all(n["status"] == "OBSERVED" for n in nodes)
    complete = complete and close_ok
    parents = [n for n in nodes if n["kind"] == "PARENT"]
    bad = any(
        n["status"] == "OBSERVED"
        and (
            n["metadata"]["uid"] != 0
            or n["metadata"]["group_writable"]
            or n["metadata"]["other_writable"]
        )
        for n in parents
    )
    compatible = False if bad else True if complete else None
    return {
        "declared_path": path,
        "observation_complete": complete,
        "nodes": nodes,
        "parent_guard_compatible": compatible,
        "metadata_FDs_closed": close_ok,
        "full_tool_guard_verified": False,
    }


def label(value):
    if value is None:
        return {"state": "MISSING", "value": None}
    if type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value):
        return {"state": "RECEIVED_PROVIDER_LABEL_ONLY", "value": value}
    return {"state": "INVALID", "value": None}


def guard(env, ack, ops, platform):
    need(type(env) is dict, "CONTEXT_REQUIRED")
    fixed = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "pamolive/PamOlive-Platform",
        "GITHUB_REPOSITORY_ID": "1449671447",
        "GITHUB_REPOSITORY_OWNER_ID": "305596298",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
    }
    need(
        platform == "linux"
        and type(ack) is str
        and ack == ACK
        and all(type(env.get(key)) is str and env[key] == value for key, value in fixed.items()),
        "DISPOSABLE_GH_NONROOT_REQUIRED",
    )
    uid, euid = ops.getuid(), ops.geteuid()
    need(
        type(uid) is int and type(euid) is int and 0 < uid == euid < 2**32,
        "DISPOSABLE_GH_NONROOT_REQUIRED",
    )
    for key, pattern in (
        ("GITHUB_SHA", r"[a-f0-9]{40}"),
        ("GITHUB_RUN_ID", r"[1-9][0-9]{0,19}"),
        ("GITHUB_RUN_ATTEMPT", r"[1-9][0-9]{0,3}"),
    ):
        need(type(env.get(key)) is str and re.fullmatch(pattern, env[key]), "CONTEXT_REQUIRED")
    return uid


def collect(env, ack, *, ops=os, platform=sys.platform, clock=time.monotonic, wall=time.time):
    start = clock()
    need(type(start) in (int, float) and math.isfinite(start), "METADATA_BUDGET")
    deadline = math.nextafter(start + 30, start)
    need(deadline > start and deadline - start <= 30, "METADATA_BUDGET")
    uid = read(clock, deadline, guard, env, ack, ops, platform)
    as_of = read(clock, deadline, wall)
    need(
        type(as_of) in (int, float) and math.isfinite(as_of) and 0 <= as_of < 2**63, "CLOCK_UNKNOWN"
    )
    packet = {
        "schema": "pamolive.public-fixture-parents-DATA/1",
        "state": "UNAPPROVED_METADATA_ONLY",
        "revision": env["GITHUB_SHA"],
        "run": env["GITHUB_RUN_ID"],
        "attempt": env["GITHUB_RUN_ATTEMPT"],
        "collector_uid": uid,
        "as_of_unix_seconds": int(as_of),
        "repository": "pamolive/PamOlive-Platform",
        "repository_id": "1449671447",
        "repository_owner_id": "305596298",
        "runner_environment": "github-hosted",
        "supplier_labels": {n: label(env.get(n)) for n in ("ImageOS", "ImageVersion")},
        "roles": {},
        "provider_attested": False,
        "historical_dfb_cause_proved": False,
        "process_exit0_is_metadata_transport_only": True,
        "full_tool_guard_verified": False,
        "authority": False,
        "profile_accepted": False,
        "automatic_action_allowed": False,
        "operational_GO": False,
    }
    for role, path in ROLE_PATHS.items():
        budget(clock, deadline)
        packet["roles"][role] = walk(path, ops, clock, deadline)
    packet["observation_complete"] = all(
        r["observation_complete"] for r in packet["roles"].values()
    )
    packet["role_metadata_FDs_closed"] = all(
        r["metadata_FDs_closed"] for r in packet["roles"].values()
    )
    budget(clock, deadline)
    return packet, deadline


def write_public(packet, output, env, deadline, *, ops=os, clock=time.monotonic):
    temp = env.get("RUNNER_TEMP")
    need(
        type(temp) is str
        and len(temp) <= 1024
        and temp.startswith("/")
        and not temp.startswith("//")
        and temp != "/"
        and "\\" not in temp
        and "\x00" not in temp
        and ".." not in PurePosixPath(temp).parts
        and len(PurePosixPath(temp).parts) <= 32
        and str(PurePosixPath(temp)) == temp,
        "PUBLIC_OUTPUT_PATH",
    )
    need(type(output) is str and output == temp + "/" + OUTPUT_NAME, "PUBLIC_OUTPUT_PATH")
    raw = (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(len(raw) <= 16384, "PUBLIC_OUTPUT_CAP")
    fds, target = [], None
    try:
        parent = None
        for component in ("/", *PurePosixPath(temp).parts[1:]):
            before = read(
                clock, deadline, ops.stat, component, dir_fd=parent, follow_symlinks=False
            )
            need(stat.S_ISDIR(before.st_mode), "PUBLIC_PARENT_ALIAS")
            fd = opened(
                ops,
                clock,
                deadline,
                component,
                ops.O_PATH | ops.O_DIRECTORY | ops.O_NOFOLLOW | ops.O_CLOEXEC,
                dir_fd=parent,
            )
            fds.append(fd)
            need(
                identity(read(clock, deadline, ops.fstat, fd))
                == identity(before)
                == identity(
                    read(clock, deadline, ops.stat, component, dir_fd=parent, follow_symlinks=False)
                ),
                "PUBLIC_PARENT_RACE",
            )
            parent = fd
        last = read(clock, deadline, ops.fstat, parent)
        need(
            last.st_uid == packet["collector_uid"] and not last.st_mode & 0o022,
            "PUBLIC_PARENT_OWNER_MODE",
        )
        budget(clock, deadline)  # Before the exclusive public-file creation/commit.
        target = opened(
            ops,
            clock,
            deadline,
            OUTPUT_NAME,
            ops.O_WRONLY | ops.O_CREAT | ops.O_EXCL | ops.O_NOFOLLOW | ops.O_CLOEXEC,
            mode=0o600,
            dir_fd=parent,
        )
        fds.append(target)
        budget(clock, deadline)
        need(ops.write(target, raw) == len(raw), "PUBLIC_SHORT_WRITE")
        ops.fsync(target)
        need(
            identity(read(clock, deadline, ops.fstat, target))
            == identity(
                read(clock, deadline, ops.stat, OUTPUT_NAME, dir_fd=parent, follow_symlinks=False)
            ),
            "PUBLIC_OUTPUT_RACE",
        )
        budget(clock, deadline)
    finally:
        # No unlink/rename/chmod/repair, even if a foreign process swaps the path.
        # The workflow must require collector rc0 and valid JSON; no atomicity claim.
        primary_active = sys.exc_info()[0] is not None
        failed_close = False
        for fd in reversed(fds):
            try:
                ops.close(fd)
            except OSError:
                failed_close = True
        if not primary_active:
            need(not failed_close, "PUBLIC_FD_CLOSE_UNKNOWN")


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--output", required=True)
    parser.add_argument("--disposable-ci-ack", required=True)
    args = parser.parse_args(argv)
    env = {key: os.environ.get(key) for key in ENV_KEYS}
    packet, deadline = collect(env, args.disposable_ci_ack)
    write_public(packet, args.output, env, deadline)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print('{"state":"REFUSED_OR_UNKNOWN","operational_GO":false}')
        raise SystemExit(42) from None
