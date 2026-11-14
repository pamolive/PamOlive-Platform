"""Nonsecret, read-only checks of the effective isolated server profile."""

import json
import os
import re
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path, PurePosixPath

try:
    from deploy.runtime import (
        APP_HOME,
        APPLICATION_PATH,
        LOCALE,
        NATIVE_LIBRARIES,
        PYTHON_ENVIRONMENT,
        loader_environment_name,
        removed_environment_name,
    )
except ModuleNotFoundError:
    from runtime import (
        APP_HOME,
        APPLICATION_PATH,
        LOCALE,
        NATIVE_LIBRARIES,
        PYTHON_ENVIRONMENT,
        loader_environment_name,
        removed_environment_name,
    )


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def read_bounded(path, maximum):
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "runtime_probe_budget")
    return raw


def process_fields(status):
    return dict(line.split(":", 1) for line in status.splitlines() if ":" in line)


def check_privileges(fields, uid):
    require(tuple(map(int, fields["Uid"].split())) == (uid,) * 4, "runtime_uid")
    require(tuple(map(int, fields["Gid"].split())) == (uid,) * 4, "runtime_gid")
    require(fields.get("Groups", "missing").strip() == "", "runtime_supplementary_groups")
    require(fields.get("NoNewPrivs", "").strip() == "1", "runtime_no_new_privileges")
    require(
        all(
            int(fields.get(name, "-1").strip(), 16) == 0
            for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")
        ),
        "runtime_capabilities",
    )


def environment_fields(raw):
    values = {}
    for part in raw.split(b"\0"):
        if not part:
            continue
        key, separator, value = part.partition(b"=")
        require(separator and key not in values, "runtime_environment_format")
        values[key] = value
    return {
        key.decode("ascii"): value.decode("utf-8", errors="surrogateescape")
        for key, value in values.items()
    }


def check_environment(environment, role):
    require(
        environment.get("LANG") == LOCALE
        and environment.get("LD_LIBRARY_PATH") == NATIVE_LIBRARIES
        and environment.get("PATH") == APPLICATION_PATH,
        "runtime_public_environment",
    )
    require(
        not any(
            loader_environment_name(name) or (removed_environment_name(name) and name != "LC_ALL")
            for name in environment
        ),
        "runtime_environment_override",
    )
    require(
        all(
            name not in environment or environment[name] == value
            for name, value in PYTHON_ENVIRONMENT.items()
        ),
        "runtime_interpreter_environment",
    )
    if role == "application":
        require(
            environment.get("LC_ALL") == LOCALE and environment.get("HOME") == APP_HOME,
            "runtime_application_locale_home",
        )
    else:
        require(
            role == "native"
            and set(environment)
            <= {"PATH", "LANG", "LD_LIBRARY_PATH", "PYTHONUNBUFFERED", "HOME", "GUACAMOLE_HOME"},
            "runtime_native_environment",
        )
        home = environment.get("HOME", "")
        require(
            home == str(PurePosixPath(home))
            and home == environment.get("GUACAMOLE_HOME")
            and PurePosixPath(home).parent == PurePosixPath("/tmp")
            and PurePosixPath(home).name.startswith("pamolive-engine-"),
            "runtime_native_home",
        )


def check_private_home(path, uid):
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o700
        and info.st_uid == uid
        and info.st_gid == uid,
        "runtime_native_home_permissions",
    )


def check_readonly_directory(path, uid):
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022,
        "runtime_font_home_permissions",
    )


def mount_fields(text):
    result = []
    require(len(text) <= 1024 * 1024, "runtime_mount_budget")
    for line in text.splitlines():
        before, separator, after = line.partition(" - ")
        parts, extra = before.split(), after.split()
        require(separator and len(parts) >= 6 and len(extra) >= 3, "runtime_mount_format")
        target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), parts[4])
        require(
            target.startswith("/") and ".." not in PurePosixPath(target).parts,
            "runtime_mount_target",
        )
        result.append((target, extra[0], set(parts[5].split(",")), set(extra[2].split(","))))
    return result


def check_mounts(text):
    mounts = mount_fields(text)
    roots = [item for item in mounts if item[0] == "/"]
    require(
        len(roots) == 1 and "ro" in roots[0][2] and "rw" not in roots[0][2], "runtime_readonly_root"
    )
    protected = (
        "/app",
        "/opt",
        "/usr",
        "/lib",
        "/lib64",
        "/bin",
        "/sbin",
        "/etc/fonts",
        "/etc/ld.so.cache",
        "/etc/ld.so.preload",
        "/var/cache/fontconfig",
        APP_HOME,
    )
    require(
        not any(
            target != "/"
            and (
                target == prefix
                or target.startswith(prefix + "/")
                or prefix.startswith(target + "/")
            )
            for target, _, _, _ in mounts
            for prefix in protected
        ),
        "runtime_shadow_mount",
    )
    temporary = [item for item in mounts if item[0] == "/tmp"]
    require(
        len(temporary) == 1
        and temporary[0][1] == "tmpfs"
        and "rw" in temporary[0][2]
        and "ro" not in temporary[0][2],
        "runtime_tmpfs",
    )
    sizes = [option[5:] for option in temporary[0][3] if option.startswith("size=")]
    require(len(sizes) == 1, "runtime_tmpfs_size")
    matched = re.fullmatch(r"([1-9][0-9]{0,11})([kKmMgG]?)", sizes[0])
    require(matched is not None, "runtime_tmpfs_size")
    size = int(matched[1]) * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[matched[2].lower()]
    require(size <= 64 * 1024**2, "runtime_tmpfs_size")
    require(
        not any(target.startswith("/tmp/") for target, _, _, _ in mounts), "runtime_tmpfs_shadow"
    )


def check_service_commands(processes, supervisor):
    """Require all three actual supervised services, not merely matching UIDs."""
    found = set()
    for fields, command in processes.values():
        if fields.get("PPid", "").strip() != supervisor or not command:
            continue
        uid = int(fields["Uid"].split()[0])
        python = PurePosixPath(command[0]).name in ("python", "python3", "python3.12")
        if uid == 1000 and python:
            if (
                len(command) == 19
                and command[1:9]
                == [
                    "-m",
                    "uvicorn",
                    "config.asgi:application",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "8000",
                    "--workers",
                ]
                and re.fullmatch(r"[1-9][0-9]{0,2}", command[9])
                and int(command[9]) <= 256
                and command[10:]
                == [
                    "--no-proxy-headers",
                    "--ws-max-size",
                    "65536",
                    "--ws-per-message-deflate",
                    "false",
                    "--limit-concurrency",
                    "256",
                    "--timeout-graceful-shutdown",
                    "10",
                ]
            ):
                found.add("web")
            if command[1:] == ["manage.py", "runjobs"]:
                found.add("jobs")
        if uid == 1001 and len(command) == 10:
            if (
                command[:7]
                == ["/opt/pamolive-guac/sbin/guacd", "-f", "-b", "127.0.0.1", "-l", "4822", "-p"]
                and PurePosixPath(command[7]).name == "guacd.pid"
                and PurePosixPath(command[7]).parent.parent == PurePosixPath("/tmp")
                and PurePosixPath(command[7]).parent.name.startswith("pamolive-engine-")
                and command[8:] == ["-L", "error"]
            ):
                found.add("native")
    require(found == {"web", "jobs", "native"}, "runtime_service_commands")


def role_probe(role, pids, forbidden):
    uid = 1000 if role == "application" else 1001
    require(os.geteuid() == uid and 1 <= len(pids) <= 256, "runtime_probe_role")
    for pid in pids:
        require(type(pid) is str and pid.isdecimal(), "runtime_pid")
        directory = Path("/proc") / pid
        fields = process_fields(read_bounded(directory / "status", 65536).decode())
        check_privileges(fields, uid)
        environment = environment_fields(read_bounded(directory / "environ", 1024 * 1024))
        check_environment(environment, role)
        if role == "native":
            check_private_home(Path(environment["HOME"]), uid)
    for pid in forbidden:
        require(type(pid) is str and pid.isdecimal(), "runtime_pid")
        try:
            read_bounded(Path("/proc") / pid / "environ", 1024 * 1024)
        except (PermissionError, ProcessLookupError):
            pass
        else:
            raise RuntimeError("runtime_native_can_read_application")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--role-probe":
        role, pids, forbidden = json.loads(sys.argv[2])
        role_probe(role, pids, forbidden)
        return
    require(len(sys.argv) == 1 and sys.platform == "linux", "runtime_probe_platform")
    roles, supervisors, commands, processes = {1000: [], 1001: []}, [], {}, {}
    for directory in Path("/proc").iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            fields = process_fields(read_bounded(directory / "status", 65536).decode())
            command = read_bounded(directory / "cmdline", 65536).split(b"\0")
        except (OSError, ProcessLookupError):
            continue
        commands[directory.name] = [
            part.decode("ascii", errors="replace") for part in command if part
        ]
        processes[directory.name] = (fields, commands[directory.name])
        uid = int(fields["Uid"].split()[0])
        if uid in roles:
            check_privileges(fields, uid)
            roles[uid].append(directory.name)
        if (
            len(commands[directory.name]) == 2
            and commands[directory.name][1] in ("deploy/runtime.py", "/app/deploy/runtime.py")
            and PurePosixPath(commands[directory.name][0]).name
            in ("python", "python3", "python3.12")
        ):
            require(uid == 0 and fields.get("NoNewPrivs", "").strip() == "1", "runtime_supervisor")
            supervisors.append((directory.name, fields["PPid"].strip()))
    require(len(supervisors) == 1 and roles[1000] and roles[1001], "runtime_roles_missing")
    pid, parent = supervisors[0]
    check_service_commands(processes, pid)
    if pid != "1":
        init = commands.get("1", [])
        require(
            parent == "1"
            and len(init) >= 2
            and PurePosixPath(init[0]).name in ("docker-init", "tini")
            and init[-2:] == commands[pid],
            "runtime_supervisor_parent",
        )
    check_mounts(read_bounded(Path("/proc/self/mountinfo"), 1024 * 1024).decode())
    require(stat.S_IMODE(Path("/tmp").stat().st_mode) == 0o1777, "runtime_tmpfs_permissions")
    for path, uid in (
        (Path("/etc/fonts"), 0),
        (Path("/usr/share/fonts"), 0),
        (Path(APP_HOME), 1000),
    ):
        check_readonly_directory(path, uid)
    for uid, role in ((1000, "application"), (1001, "native")):
        subprocess.run(
            [
                sys.executable,
                __file__,
                "--role-probe",
                json.dumps([role, roles[uid], roles[1000] if uid == 1001 else []]),
            ],
            check=True,
            timeout=15,
            user=uid,
            group=uid,
            extra_groups=[],
            env={"PATH": APPLICATION_PATH, "LANG": LOCALE},
        )
    with urllib.request.urlopen("http://127.0.0.1:8000/health/", timeout=5) as response:
        require(response.status == 200, "runtime_health")
    print("Runtime profile verified: supervisor, UID/capabilities/NoNewPrivs, read-only paths,")
    print("bounded tmpfs, fixed locale, private native HOME and application-secret separation.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            "Runtime profile check failed; inspect the isolated laboratory privately.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
