"""Public-only containerd prerequisite reads. No config, Server RPC, or mutation.

Imported for pure projections. In the sudo child, run_capped is injected from
the byte-pinned received bounded_io source before root_main is called.
"""

import hashlib
import json
import os
import re
import signal
import stat
import sys
from pathlib import Path

ENDPOINTS = frozenset(
    {
        "/run/containerd/containerd.sock",
        "/var/run/containerd/containerd.sock",
        "/var/run/docker/containerd/containerd.sock",
        "/run/docker/containerd/containerd.sock",
    }
)
TYPES = {
    "io.containerd.content.v1": ("content", "root", "io.containerd.content.v1.content"),
    "io.containerd.snapshotter.v1": (
        "overlayfs",
        "root",
        "io.containerd.snapshotter.v1.overlayfs",
    ),
    "io.containerd.metadata.v1": (
        "bolt",
        "path",
        "io.containerd.metadata.v1.bolt/meta.db",
    ),
}
BASES = ("/var/lib/containerd", "/var/lib/docker/containerd/daemon")
PATHS = frozenset(base + "/" + row[2] for base in BASES for row in TYPES.values())
ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "CONTAINERD_SUPPRESS_DEPRECATION_WARNINGS": "true",
}
STAT_KEYS = {
    "path",
    "kind",
    "device",
    "inode",
    "uid",
    "gid",
    "mode",
    "size",
    "fsid",
    "block_size",
    "blocks",
    "available_blocks",
    "available_bytes",
}
ENV_TOOL = "/usr/lib/cargo/bin/coreutils/env"
TOOL_KEYS = {"path", "bytes", "sha256", "file_type", "uid", "gid", "mode", "nlink"}


def require(value):
    if not value:
        raise ValueError("PUBLIC_PREREQUISITE_REFUSED")


def identity(row):
    return (
        row.st_dev,
        row.st_ino,
        row.st_mode,
        row.st_uid,
        row.st_gid,
        row.st_size,
        row.st_mtime_ns,
        row.st_nlink,
    )


TOOL_FAILURES = frozenset(
    {
        "PATH",
        "MISSING",
        "UNREADABLE",
        "PARENT_UNSAFE",
        "NOT_REGULAR",
        "LINK_COUNT",
        "OWNER",
        "WRITABLE",
        "SIZE",
        "IDENTITY_CHANGED",
    }
)


class ToolRefusal(ValueError):
    def __init__(self, code):
        require(code in TOOL_FAILURES)
        self.code = code
        super().__init__("PUBLIC_TOOL_REFUSED")


def tool_need(value, code):
    if not value:
        raise ToolRefusal(code)


def tool_stat(path):
    try:
        return path.lstat()
    except FileNotFoundError:
        raise ToolRefusal("MISSING") from None
    except PermissionError:
        raise ToolRefusal("UNREADABLE") from None


def tool_record(path):
    """Measure explicit regular executables, never sudo's alternatives symlinks."""
    path = Path(path)
    tool_need(
        str(path) in {"/usr/bin/ctr", "/usr/lib/cargo/bin/sudo", ENV_TOOL, "/usr/bin/python3.14"},
        "PATH",
    )
    for parent in path.parents:
        parent_info = tool_stat(parent)
        tool_need(
            stat.S_ISDIR(parent_info.st_mode)
            and parent_info.st_uid == 0
            and not parent_info.st_mode & 0o022,
            "PARENT_UNSAFE",
        )
    before = tool_stat(path)
    tool_need(stat.S_ISREG(before.st_mode), "NOT_REGULAR")
    tool_need(
        type(before.st_nlink) is int
        and (before.st_nlink >= 1 if str(path) == ENV_TOOL else before.st_nlink == 1),
        "LINK_COUNT",
    )
    tool_need(before.st_uid == 0, "OWNER")
    tool_need(not before.st_mode & 0o022, "WRITABLE")
    tool_need(0 < before.st_size <= 128 * 1024**2, "SIZE")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        tool_need(identity(before) == identity(os.fstat(fd)), "IDENTITY_CHANGED")
        total, digest = 0, hashlib.sha256()
        while True:
            block = os.read(fd, min(65536, 128 * 1024**2 + 1 - total))
            if not block:
                break
            total += len(block)
            tool_need(total <= 128 * 1024**2, "SIZE")
            digest.update(block)
        tool_need(total == before.st_size, "SIZE")
        tool_need(
            identity(before) == identity(os.fstat(fd)) == identity(tool_stat(path)),
            "IDENTITY_CHANGED",
        )
        return {
            "path": str(path),
            "bytes": total,
            "sha256": digest.hexdigest(),
            "file_type": "regular",
            "uid": before.st_uid,
            "gid": before.st_gid,
            "mode": stat.S_IMODE(before.st_mode),
            "nlink": before.st_nlink,
        }
    finally:
        os.close(fd)


def component(value):
    require(type(value) is list and len(value) == 1)
    row = value[0]
    require(type(row) is dict and set(row) == {"version", "revision"})
    require(
        type(row["version"]) is str
        and re.fullmatch(r"v?[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}", row["version"])
    )
    require(type(row["revision"]) is str and re.fullmatch(r"[a-f0-9]{7,40}", row["revision"]))
    return dict(row)


def endpoint(value):
    require(type(value) is dict and set(value) == {"Address", "Namespaces"})
    require(type(value["Address"]) is str and value["Address"] in ENDPOINTS)
    require(value["Namespaces"] == {"Containers": "moby", "Plugins": "plugins.moby"})
    return {"Address": value["Address"], "Namespaces": dict(value["Namespaces"])}


def ctr_command(address):
    require(address in ENDPOINTS)
    return [
        "/usr/bin/ctr",
        "--address",
        address,
        "--namespace",
        "moby",
        "--connect-timeout",
        "3s",
        "--timeout",
        "5s",
        "plugins",
        "ls",
        "--detailed",
        *["type==" + name + ",id==" + row[0] for name, row in TYPES.items()],
    ]


def plugin_exports(raw):
    """Parse bounded tabwriter text; never return ancillary fields or errors."""
    require(type(raw) is bytes and 0 < len(raw) <= 32768)
    text = raw.decode("ascii", errors="strict")
    require(all(char in "\n\t" or 32 <= ord(char) <= 126 for char in text))
    records, row, section = [], None, None
    for line in text.splitlines():
        require(len(line) <= 2048)
        if not line.strip():
            continue
        if line.startswith("Type:"):
            if row is not None:
                records.append(row)
            row = {"type": line[5:].strip(), "exports": {}}
            section = None
            require(len(records) < 3)
        else:
            require(row is not None)
            if line.startswith("ID:"):
                require("id" not in row)
                row["id"] = line[3:].strip()
                section = None
            elif line.startswith("Exports:"):
                require(line[8:].strip() == "" and "exports_seen" not in row)
                row["exports_seen"], section = True, "exports"
            elif line.startswith("Requires:"):
                require(line[9:].strip() == "")
                section = "requires"
            elif line.startswith(("Platforms:", "Capabilities:")):
                section = None
            elif line[0].isspace():
                require(section in {"exports", "requires"})
                if section == "exports":
                    parts = line.split()
                    require(len(parts) == 2 and parts[0] not in row["exports"])
                    require(len(row["exports"]) < 16)
                    row["exports"][parts[0]] = parts[1]
            else:
                require(False)  # Includes Error, unknown headings, malformed framing.
    if row is not None:
        records.append(row)
    require(len(records) == 3)
    result = {}
    for row in records:
        kind = row["type"]
        require(kind in TYPES and kind not in result and row.get("id") == TYPES[kind][0])
        key, suffix = TYPES[kind][1:]
        path = row["exports"].get(key)
        require(type(path) is str and path in {base + "/" + suffix for base in BASES})
        result[kind] = path
    return result


def capacity(path, *, system=os):
    """Bind statvfs to the opened exported inode; no reads or writes of content.

    Walk directories through held dirfds to reject symlink/race substitution.
    Metadata meta.db is opened itself, not its parent filesystem by assumption.
    """
    require(path in PATHS or path == "/var/lib/docker")
    parts, held = path.strip("/").split("/"), []
    try:
        current = system.open("/", system.O_RDONLY | system.O_DIRECTORY | system.O_CLOEXEC)
        held.append(current)
        for index, part in enumerate(parts):
            final_file = index == len(parts) - 1 and path.endswith("/meta.db")
            before = system.stat(part, dir_fd=current, follow_symlinks=False)
            require(stat.S_ISREG(before.st_mode) if final_file else stat.S_ISDIR(before.st_mode))
            flags = system.O_RDONLY | system.O_NOFOLLOW | system.O_CLOEXEC | system.O_NONBLOCK
            if not final_file:
                flags |= system.O_DIRECTORY
            current = system.open(part, flags, dir_fd=current)
            held.append(current)
            info = system.fstat(current)
            require(stat.S_ISREG(info.st_mode) if final_file else stat.S_ISDIR(info.st_mode))
            require(
                (before.st_dev, before.st_ino, before.st_mode)
                == (info.st_dev, info.st_ino, info.st_mode)
            )
        before = system.fstat(current)
        fs = system.fstatvfs(current)
        after = system.fstat(current)

        # meta.db size/mtime may change under the daemon; require stable object/type/ownership.
        def stable(r):
            return (r.st_dev, r.st_ino, r.st_mode, r.st_uid, r.st_gid, r.st_nlink)

        require(stable(before) == stable(after))
        for value in (fs.f_frsize, fs.f_blocks, fs.f_bavail, fs.f_fsid):
            require(type(value) is int and 0 <= value < 2**64)
        require(fs.f_frsize > 0 and fs.f_bavail <= fs.f_blocks)
        return {
            "path": path,
            "kind": "file" if path.endswith("/meta.db") else "directory",
            "device": after.st_dev,
            "inode": after.st_ino,
            "uid": after.st_uid,
            "gid": after.st_gid,
            "mode": stat.S_IMODE(after.st_mode),
            "size": after.st_size,
            "fsid": fs.f_fsid,
            "block_size": fs.f_frsize,
            "blocks": fs.f_blocks,
            "available_blocks": fs.f_bavail,
            "available_bytes": fs.f_bavail * fs.f_frsize,
        }
    finally:
        for fd in reversed(held):
            system.close(fd)


def h1(result):
    facts = result.facts()
    return (
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


def public_facts(result):
    return {
        key: value
        for key, value in result.facts().items()
        if key not in {"stdout_bytes", "stderr_bytes"}
    }


def version_format_diagnostic(raw):
    """Public shape only; never a parser used to authorize a CLI version."""
    result = {"schema": "ctr-version-format-DATA/1", "form": "redacted"}
    require(type(raw) is bytes)
    if len(raw) > 512:
        result["form"] = "over_limit"
    elif not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        result["form"] = "not_single_terminal_lf"
    elif any(byte < 32 or byte > 126 for byte in raw[:-1]):
        result["form"] = "non_printable_ascii"
    else:
        match = re.fullmatch(
            rb"ctr ([A-Za-z0-9./_-]{1,80}) (v?)([0-9]{1,2})\."
            rb"([0-9]{1,2})\.([0-9]{1,3})([A-Za-z0-9+._-]{0,80})\n",
            raw,
        )
        if match is not None:
            package = {
                b"github.com/containerd/containerd/v2": "module_v2",
                b"github.com/containerd/containerd": "module_legacy",
            }.get(match[1], "other_redacted")
            suffix = {b"": "none", b"+unknown": "plus_unknown"}.get(match[6], "other_redacted")
            result.update(
                form="version_line",
                package=package,
                numeric_triplet=[int(match[i]) for i in (3, 4, 5)],
                prefix_v=match[2] == b"v",
                suffix_kind=suffix,
            )
    return result


def validate_version_format(value):
    require(type(value) is dict and value.get("schema") == "ctr-version-format-DATA/1")
    form = value.get("form")
    require(type(form) is str)
    if form in {"redacted", "over_limit", "not_single_terminal_lf", "non_printable_ascii"}:
        require(set(value) == {"schema", "form"})
        return dict(value)
    require(form == "version_line")
    require(
        set(value) == {"schema", "form", "package", "numeric_triplet", "prefix_v", "suffix_kind"}
    )
    require(type(value["package"]) is str)
    require(value["package"] in {"module_v2", "module_legacy", "other_redacted"})
    require(type(value["suffix_kind"]) is str)
    require(value["suffix_kind"] in {"none", "plus_unknown", "other_redacted"})
    require(type(value["prefix_v"]) is bool)
    numbers = value["numeric_triplet"]
    require(type(numbers) is list and len(numbers) == 3)
    require(
        all(
            type(n) is int and 0 <= n <= bound
            for n, bound in zip(numbers, (99, 99, 999), strict=True)
        )
    )
    return dict(value, numeric_triplet=list(numbers))


# These exact package/version pairs were reviewed from primary source, never learned from DATA.
CLI_PAIRS = frozenset(
    (package, prefix + version)
    for package, versions in (
        ("github.com/containerd/containerd/v2", ("2.2.3", "2.4.2")),
        ("containerd", ("2.4.2",)),
        ("containerd.io", ("2.4.2",)),
    )
    for version in versions
    for prefix in ("", "v")
)
CLI_LINE = (
    rb"ctr (github\.com/containerd/containerd/v2|containerd|containerd\.io) "
    rb"(v?[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3})\n"
)


def validate_cli_identity(value, *, reviewed=True):
    require(type(value) is dict and set(value) == {"package", "version"})
    require(type(value["package"]) is str and type(value["version"]) is str)
    require(
        value["package"] in {"github.com/containerd/containerd/v2", "containerd", "containerd.io"}
        and re.fullmatch(r"v?[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}", value["version"])
    )
    if reviewed:
        require((value["package"], value["version"]) in CLI_PAIRS)
    return dict(value)


def inspect_roots(address, runner, measure=tool_record, statter=capacity):
    require(address in ENDPOINTS)
    packet = {
        "schema": "public-containerd-roots/3",
        "status": "UNKNOWN",
        "ctr_process": None,
        "tool": None,
        "tool_unchanged": False,
        "cli_identity": None,
        "version_process": None,
        "exports": None,
        "filesystems": None,
        "profile_accepted": False,
        "authority": False,
        "operational_GO": False,
    }
    try:
        packet["tool"] = measure("/usr/bin/ctr")
        version = runner(
            ["/usr/bin/ctr", "--version"],
            env=dict(ENV),
            cwd="/",
            timeout=3,
            stdout_cap=512,
            stderr_cap=1024,
        )
        packet["version_process"] = public_facts(version)
        packet["tool_unchanged"] = measure("/usr/bin/ctr") == packet["tool"]
        if not h1(version) or not packet["tool_unchanged"]:
            return packet
        if not version.ok or version.stderr != b"":
            packet["status"] = "QUERY_REFUSED"
            return packet
        match = re.fullmatch(CLI_LINE, version.stdout)
        if match is None:
            packet["status"] = "CLI_UNREVIEWED"
            packet["version_format"] = version_format_diagnostic(version.stdout)
            return packet
        packet["cli_identity"] = {
            "package": match[1].decode("ascii"),
            "version": match[2].decode("ascii"),
        }
        if (packet["cli_identity"]["package"], packet["cli_identity"]["version"]) not in CLI_PAIRS:
            packet["status"] = "CLI_UNREVIEWED"
            return packet
        result = runner(
            ctr_command(address),
            env=dict(ENV),
            cwd="/",
            timeout=8,
            stdout_cap=32768,
            stderr_cap=4096,
        )
        packet["ctr_process"] = public_facts(result)
        packet["tool_unchanged"] = measure("/usr/bin/ctr") == packet["tool"]
        if not h1(result):
            return packet
        if not result.ok or result.stderr != b"":
            packet["status"] = (
                "PERMISSION_REFUSED"
                if b"permission denied" in result.stderr.lower()
                else "QUERY_REFUSED"
            )
            return packet
        exports = plugin_exports(result.stdout)
        filesystems = {kind: statter(path) for kind, path in exports.items()}
        filesystems["docker_root"] = statter("/var/lib/docker")
        packet["exports"], packet["filesystems"] = exports, filesystems
        packet["status"] = "COMPLETE" if packet["tool_unchanged"] else "UNKNOWN"
    except TimeoutError:
        packet["status"] = "UNKNOWN"
    except PermissionError:
        packet["status"] = "PERMISSION_REFUSED"
    except (ValueError, OSError, UnicodeError, KeyError):
        packet["status"] = "DATA_REFUSED"
    return packet


def validate_tool(tool):
    require(
        type(tool) is dict
        and set(tool) == TOOL_KEYS
        and tool["path"] == "/usr/bin/ctr"
        and tool["file_type"] == "regular"
        and type(tool["nlink"]) is int
        and tool["nlink"] == 1
        and type(tool["uid"]) is int
        and tool["uid"] == 0
        and type(tool["gid"]) is int
        and tool["gid"] == 0
        and type(tool["bytes"]) is int
        and 0 < tool["bytes"] <= 128 * 1024**2
        and type(tool["mode"]) is int
        and 0 <= tool["mode"] <= 0o7777
        and tool["mode"] & 0o022 == 0
        and type(tool["sha256"]) is str
        and re.fullmatch("[a-f0-9]{64}", tool["sha256"])
    )
    return dict(tool)


def refusal_diagnostic(value):
    require(type(value) is dict and "cli_version" not in value)
    require(type(value) is dict and value.get("schema") == "public-containerd-roots/3")
    status = value.get("status")
    require(
        status
        in {
            "UNKNOWN",
            "PERMISSION_REFUSED",
            "QUERY_REFUSED",
            "DATA_REFUSED",
            "CLI_UNREVIEWED",
        }
    )
    result = {"status": status}
    if "version_format" in value or value.get("cli_identity") is not None:
        # Every published version observation needs the same closed pre-query
        # context, including typed-but-unreviewed identities, not only format DATA.
        require(status == "CLI_UNREVIEWED")
        if "version_format" in value:
            require(value.get("cli_identity") is None)
        require(
            all(
                value.get(key) is False
                for key in ("profile_accepted", "authority", "operational_GO")
            )
        )
        require(all(value.get(key) is None for key in ("ctr_process", "exports", "filesystems")))
        require(value.get("tool_unchanged") is True)
        validate_tool(value.get("tool"))
        facts = value.get("version_process")
        require(
            type(facts) is dict
            and set(facts)
            == {
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
        )
        require(
            facts["spawn_attempted"] is True
            and type(facts["pid"]) is int
            and 0 < facts["pid"] < 2**31
            and type(facts["returncode"]) is int
            and facts["returncode"] == 0
            and facts["reason"] is None
            and facts["exception_type"] is None
            and facts["killed_owned_child"] is False
            and facts["owned_child_reaped"] is True
            and facts["drains_complete"] is True
            and facts["cleanup_exception_type"] is None
        )
        if "version_format" in value:
            result["version_format"] = validate_version_format(value["version_format"])
    if value.get("tool") is not None:
        result["ctr_tool"] = validate_tool(value["tool"])
    if type(value.get("tool_unchanged")) is bool:
        result["ctr_tool_unchanged"] = value["tool_unchanged"]
    cli = value.get("cli_identity")
    if cli is not None:
        result["cli_identity"] = validate_cli_identity(cli, reviewed=False)
    for name in ("version_process", "ctr_process"):
        facts = value.get(name)
        if type(facts) is not dict:
            continue
        projected = {}
        for key in (
            "spawn_attempted",
            "killed_owned_child",
            "owned_child_reaped",
            "drains_complete",
        ):
            require(type(facts.get(key)) is bool)
            projected[key] = facts[key]
        for key in ("pid", "returncode"):
            item = facts.get(key)
            require(item is None or type(item) is int and -(2**31) <= item < 2**31)
            projected[key] = item
        result[name] = projected
    return result


def validate_packet(value):
    require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "status",
            "ctr_process",
            "tool",
            "tool_unchanged",
            "cli_identity",
            "version_process",
            "exports",
            "filesystems",
            "profile_accepted",
            "authority",
            "operational_GO",
        }
    )
    require(value["schema"] == "public-containerd-roots/3")
    require(
        value["status"]
        in {
            "COMPLETE",
            "UNKNOWN",
            "PERMISSION_REFUSED",
            "QUERY_REFUSED",
            "DATA_REFUSED",
            "CLI_UNREVIEWED",
        }
    )
    require(all(value[key] is False for key in ("profile_accepted", "authority", "operational_GO")))
    # Refused/unknown child packets are not published verbatim: parent retains only status/H1.
    require(value["status"] == "COMPLETE" and value["tool_unchanged"] is True)
    validate_cli_identity(value["cli_identity"])
    validate_tool(value["tool"])
    for facts in (value["version_process"], value["ctr_process"]):
        require(
            type(facts) is dict
            and set(facts)
            == {
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
        )
        require(
            facts["spawn_attempted"] is True
            and type(facts["pid"]) is int
            and facts["pid"] > 0
            and type(facts["returncode"]) is int
            and facts["returncode"] == 0
            and facts["reason"] is None
            and facts["exception_type"] is None
            and facts["cleanup_exception_type"] is None
            and facts["killed_owned_child"] is False
            and facts["owned_child_reaped"] is True
            and facts["drains_complete"] is True
        )
    exports, filesystems = value["exports"], value["filesystems"]
    require(type(exports) is dict and set(exports) == set(TYPES))
    require(type(filesystems) is dict and set(filesystems) == {*TYPES, "docker_root"})
    for kind, row in filesystems.items():
        require(type(row) is dict and set(row) == STAT_KEYS)
        path = "/var/lib/docker" if kind == "docker_root" else exports[kind]
        if kind != "docker_root":
            require(path in {base + "/" + TYPES[kind][2] for base in BASES})
        require(
            row["path"] == path
            and row["kind"] == ("file" if path.endswith("/meta.db") else "directory")
        )
        require(
            all(
                type(row[key]) is int and 0 <= row[key] < 2**64
                for key in STAT_KEYS - {"path", "kind"}
            )
        )
        require(
            row["mode"] <= 0o7777
            and row["block_size"] > 0
            and row["available_blocks"] <= row["blocks"]
            and row["available_bytes"] == row["available_blocks"] * row["block_size"]
        )
    return value


def root_main():
    # This function is reachable only from the byte-pinned -c payload, not at import.
    def expired(_number, _frame):
        raise TimeoutError("PUBLIC_READ_DEADLINE")

    try:
        require(os.name == "posix" and os.getuid() == 0 and len(sys.argv) == 2)
        require(dict(os.environ) == {key: ENV[key] for key in ("PATH", "HOME", "LANG", "LC_ALL")})
        require(sys.executable == "/usr/bin/python3.14")
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 25)
        packet = inspect_roots(sys.argv[1], globals()["run_capped"])
    except BaseException:
        # No traceback, exception text or path escapes this child. Incomplete
        # nested process facts cannot be repaired by reaping the sudo frontend.
        packet = {"schema": "public-containerd-roots/3", "status": "UNKNOWN"}
    finally:
        if os.name == "posix":
            signal.setitimer(signal.ITIMER_REAL, 0)
    raw = json.dumps(packet, allow_nan=False, separators=(",", ":")).encode() + b"\n"
    require(len(raw) <= 16384)
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    return 0 if packet["status"] == "COMPLETE" else 42
