"""Small build helpers; no command is run at import time."""

import hashlib
import json
import os
import stat
from pathlib import Path

import bounded_io

HERE = Path(__file__).resolve().parent
ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "HOME": "/nonexistent",
    "DEB_BUILD_OPTIONS": "parallel=1",
    "MAKEFLAGS": "-j1",
}


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, cap):
    return bounded_io.read_regular(Path(path), cap)


def write_new(path, raw, mode=0o600):
    path = Path(path)
    with path.open("xb") as stream:
        need(stream.write(raw) == len(raw), "short_write")
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(mode)


def record(path, value):
    write_new(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def command(args, cwd, log, seconds=60, cap=2 * 1024**2, env=None):
    """Owned Linux session, bounded pipes and five seconds reserved for cleanup."""
    need(os.name == "posix" and Path(args[0]).is_absolute(), "linux_absolute_command")
    info = Path(args[0]).stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0, "tool_owner")
    log = Path(log)
    log.mkdir(mode=0o700)
    tool = Path(args[0]).resolve(strict=True)
    tool_hash = sha(read(tool, 64 * 1024**2))
    record(
        log / "intent.json",
        {"state": "PENDING", "argv": args, "tool_target": str(tool), "tool_sha256": tool_hash},
    )
    try:
        result = bounded_io.run_capped(
            args,
            cwd=str(cwd),
            env=ENV if env is None else env,
            timeout=seconds + 5,
            work_timeout=seconds,
            stdout_cap=cap,
            stderr_cap=cap,
            total_cap=2 * cap,
            owned_session=True,
            on_spawn=lambda pid: record(log / "pid.json", {"pid": pid}),
        )
        write_new(log / "stdout", result.stdout)
        write_new(log / "stderr", result.stderr)
        record(log / "result.json", result.facts())
        need(result.ok, "child_failed_or_unknown")
        need(
            Path(args[0]).resolve(strict=True) == tool
            and sha(read(tool, 64 * 1024**2)) == tool_hash,
            "tool_changed",
        )
    except BaseException:
        record(log / "unknown.json", {"state": "UNKNOWN"})
        raise
    return result.stdout


def material_rows():
    value = json.loads((HERE / "materials.json").read_text())
    need(value["schema"] == "pamolive.expat4.materials/1", "manifest_schema")
    rows = value["files"]
    need(len(rows) == 10 and len({r["name"] for r in rows}) == 10, "manifest_count")
    return rows


def check_materials(folder):
    for row in material_rows():
        material(folder, row["name"])


def material(folder, name):
    rows = [row for row in material_rows() if row["name"] == name]
    need(len(rows) == 1, "material_name")
    row = rows[0]
    raw = read(Path(folder) / name, row["bytes"])
    need(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "material_bytes")
    return raw
