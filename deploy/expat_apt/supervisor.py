"""One H1 child driver; Docker target exports DATA even on refusal, CI gates it separately."""

import importlib.util
import json
import os
import sys
import time
from pathlib import Path


def main():
    def need(value):
        if not value:
            raise ValueError("supervisor_refused")

    need(sys.platform == "linux" and os.getuid() == os.geteuid() == 0)
    mode = sys.argv[1]
    need(mode in {"capture", "apply"} and len(sys.argv) == (5 if mode == "capture" else 6))
    root = Path(__file__).parent
    spec = importlib.util.spec_from_file_location("c_transaction", root / "transaction.py")
    t = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = t
    spec.loader.exec_module(t)
    pins_raw = t.read_regular(root / "code-pins.json", 16384)
    need(t.sha(pins_raw) == sys.argv[2])
    pins = json.loads(pins_raw)
    need(t.sha(t.read_regular(root / "supervisor.py", 131072)) == pins["supervisor.py"])
    need(t.sha(t.read_regular(root / "transaction.py", 131072)) == pins["transaction.py"])
    io = t.load("c_supervisor_H1", "bounded_io.py", pins["bounded_io.py"])
    python = Path("/usr/local/bin/python3.12")

    def pin():
        raw = t.read_regular(python, 64 * 1024**2)
        row = python.lstat()
        need(
            row.st_uid == row.st_gid == 0
            and not row.st_mode & 0o6022
            and raw.startswith(b"\x7fELF")
        )
        return t.sha(raw), t.identity(row)

    before = pin()
    audit = Path("/c-supervisor")
    audit.mkdir(mode=0o700)
    t.write_new(audit / "intent.json", b'{"state":"PENDING"}')
    argv = [
        str(python),
        "-I",
        "-B",
        "-S",
        str(root / "transaction.py"),
        "--code-pins-sha",
        sys.argv[2],
        "--policy-sha",
        sys.argv[3],
        "--disposable-buildkit-ack",
        sys.argv[4],
        "--" + mode,
    ]
    if mode == "apply":
        argv.extend(["--approved-material-set-sha", sys.argv[5]])
    horizon = 1840 if mode == "capture" else 940
    packet = {
        "schema": "pamolive.expat-C-supervisor/1",
        "state": "REFUSED_OR_UNKNOWN",
        "resources_released": False,
        "all_OS_descendants_released": False,
        "build_verified": False,
        "materials_complete": False,
        "code_pins_sha256": sys.argv[2],
    }
    try:
        result = io.run_capped(
            argv,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root"},
            cwd="/",
            timeout=horizon,
            work_timeout=horizon - 30,
            deadline=time.monotonic() + horizon,
            stdout_cap=16384,
            stderr_cap=16384,
            total_cap=32768,
            owned_session=True,
            on_spawn=lambda pid: t.write_new(audit / "pid.json", json.dumps({"pid": pid}).encode()),
        )
        facts = result.facts()
        t.write_new(audit / "result.json", json.dumps(facts).encode())
        packet["H1"] = facts
        normal = (
            result.ok
            and result.spawn_attempted is True
            and type(result.pid) is int
            and result.pid > 0
            and type(result.returncode) is int
            and result.returncode == 0
            and result.reason is result.exception_type is result.cleanup_exception_type is None
            and result.owned_child_reaped is True
            and result.drains_complete is True
            and result.killed_owned_child is False
            and pin() == before
        )
        if normal:
            path = (
                Path("/c-capture/result.json")
                if mode == "capture"
                else Path("/expat-apt-proof/result.json")
            )
            raw = t.read_regular(path, 4 * 1024**2)
            body = json.loads(raw)
            expected = (
                "AUTHENTICATED_UNAPPROVED_NOT_INSTALLED"
                if mode == "capture"
                else "AUTHENTICATED_INPUTS_INSTALLED_PACKAGE_STATE_ONLY"
            )
            need(
                body["state"] == expected
                and body["build_verified"] is False
                and body["materials_complete"] is False
            )
            packet.update(state="DRIVER_NORMAL_DATA_ONLY", result_sha256=t.sha(raw))
    except BaseException:
        # Never replace UNKNOWN by a cleanup/build success; no retry or global kill.
        pass
    t.write_new(Path("/c-status.json"), (json.dumps(packet) + "\n").encode())
    # Fixed empty export roots only; no home/key/config traversal or arbitrary glob.
    for name in ("/c-capture", "/c-base", "/expat-apt-proof"):
        path = Path(name)
        if not path.exists():
            path.mkdir(mode=0o700)
    return 0  # Export transport success ONLY; workflow requires packet + raw result checks.


if __name__ == "__main__":
    raise SystemExit(main())
