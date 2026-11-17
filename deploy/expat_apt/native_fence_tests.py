"""Linux-only finite kernel checks, real H172 children, never a material authority."""

import hashlib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path("/opt/expat-apt")
OUT = Path("/c-fence-native")
PYTHON = "/usr/local/bin/python3.12"


def need(value):
    if not value:
        raise ValueError("native_fence_refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def capture_bytes(name, digest, cap=131072):
    path = ROOT / name
    # The supervisor already captured its transaction reader from reviewed source.
    # Repeat a bounded same-FD capture here before compiling either subject module.
    import stat

    for parent in (ROOT, ROOT.parent, Path("/")):
        row = parent.lstat()
        need(stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022)
    before = path.lstat()

    def key(r):
        return (
            r.st_dev,
            r.st_ino,
            r.st_mode,
            r.st_uid,
            r.st_gid,
            r.st_nlink,
            r.st_size,
            r.st_mtime_ns,
            r.st_ctime_ns,
        )

    need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == before.st_gid == 0
        and before.st_nlink == 1
        and not before.st_mode & 0o6022
        and 0 < before.st_size <= cap
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(key(os.fstat(fd)) == key(before))
        raw = b""
        while len(raw) <= cap:
            block = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not block:
                break
            raw += block
        need(
            len(raw) == before.st_size
            and key(os.fstat(fd)) == key(before)
            and key(path.lstat()) == key(before)
            and sha(raw) == digest
        )
    finally:
        os.close(fd)
    return raw


def captured(name, digest):
    raw = capture_bytes(name, digest)
    path = ROOT / name
    scope = {"__name__": "fence_native_subject", "__file__": str(path)}
    exec(compile(raw, str(path), "exec"), scope)
    return scope


def subject_pins(code_sha):
    raw = capture_bytes("code-pins.json", code_sha, 16384)
    need(len(raw) <= 16384 and sha(raw) == code_sha)
    pins = json.loads(raw)
    need(type(pins) is dict and len(pins) == 11)
    return pins


CAPTURE_PHASES = (
    "code_capture_before",
    "code_capture_after",
    "helper_capture_before",
    "helper_capture_after",
    "API_before",
    "API_after",
)
CHECK_PHASES = (
    "GET_before",
    "GET_after",
    "socket_pairs_before",
    "socket_pairs_after",
    "network_escape_before",
    "network_escape_after",
    "holes_before",
    "holes_after",
    "emit_before",
    "emit_after",
)
CHECKPOINT_PHASES = {
    "syscalls": CAPTURE_PHASES
    + ("prepare_before", "prepare_after", "install_before", "install_after")
    + CHECK_PHASES,
    "exec": CAPTURE_PHASES
    + (
        "prepare_before",
        "prepare_after",
        "Python_capture_before",
        "Python_capture_after",
        "install_before",
        "install_after",
        "exec_before",
    ),
    "inherited": CAPTURE_PHASES + CHECK_PHASES,
}
MAX_CHECKPOINTS = 32
MAX_CHECKPOINT_BYTES = 1024
MAX_CASE_CHECKPOINT_BYTES = MAX_CHECKPOINTS * MAX_CHECKPOINT_BYTES


class Checkpoints:
    """Finite diagnostic-only records; no signal handler, PASS or authority."""

    def __init__(self, mode, native_sha, code_sha):
        need(mode in CHECKPOINT_PHASES)
        need(
            all(
                type(value) is str
                and len(value) == 64
                and all(c in "0123456789abcdef" for c in value)
                for value in (native_sha, code_sha)
            )
        )
        self.mode = mode
        self.case = "exec" if mode == "inherited" else mode
        self.native_sha = native_sha
        self.code_sha = code_sha
        self.pid = os.getpid()
        need(type(self.pid) is int and self.pid > 0)
        self.offset = len(CHECKPOINT_PHASES["exec"]) if mode == "inherited" else 0
        self.index = 0

    def __call__(self, phase):
        import stat

        stages = CHECKPOINT_PHASES[self.mode]
        need(self.index < len(stages) and phase == stages[self.index])
        ordinal = self.offset + self.index + 1
        need(1 <= ordinal <= MAX_CHECKPOINTS)
        raw = (
            json.dumps(
                {
                    "schema": "pamolive.fence-native-checkpoint/1",
                    "case": self.case,
                    "mode": self.mode,
                    "ordinal": ordinal,
                    "phase": phase,
                    "pid": self.pid,
                    "code_pins_sha256": self.code_sha,
                    "native_source_sha256": self.native_sha,
                    "diagnostic_only": True,
                    "operational_GO": False,
                },
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        need(
            len(raw) <= MAX_CHECKPOINT_BYTES
            and ordinal * MAX_CHECKPOINT_BYTES <= MAX_CASE_CHECKPOINT_BYTES
        )
        parent = OUT.lstat()
        need(
            stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == parent.st_gid == 0
            and not parent.st_mode & 0o077
        )
        path = OUT / (self.case + "-checkpoint-" + str(ordinal).zfill(2) + ".json")
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            0o400,
        )
        try:
            row = os.fstat(fd)
            need(
                stat.S_ISREG(row.st_mode)
                and row.st_uid == row.st_gid == 0
                and row.st_nlink == 1
                and stat.S_IMODE(row.st_mode) == 0o400
                and row.st_size == 0
            )
            need(os.write(fd, raw) == len(raw))
            os.fsync(fd)
            after = os.fstat(fd)
            named = path.lstat()
            need(
                after == named
                and after.st_dev == row.st_dev
                and after.st_ino == row.st_ino
                and after.st_mode == row.st_mode
                and after.st_uid == after.st_gid == 0
                and after.st_nlink == 1
                and after.st_size == len(raw)
            )
            current = OUT.lstat()
            need(
                current.st_dev == parent.st_dev
                and current.st_ino == parent.st_ino
                and current.st_mode == parent.st_mode
                and current.st_uid == current.st_gid == 0
            )
        finally:
            os.close(fd)
        self.index += 1


def child():
    need(len(sys.argv) == 4 and sys.argv[3] in {"syscalls", "exec", "inherited"})
    native_sha, code_sha, mode = sys.argv[1:]
    need(globals().get("CAPTURED_NATIVE_SHA") == native_sha)
    checkpoint = Checkpoints(mode, native_sha, code_sha)
    checkpoint("code_capture_before")
    pins = subject_pins(code_sha)
    checkpoint("code_capture_after")
    need(pins["native_fence_tests.py"] == native_sha)
    checkpoint("helper_capture_before")
    f = captured("solver_fence.py", pins["solver_fence.py"])
    checkpoint("helper_capture_after")
    checkpoint("API_before")
    api = f["LinuxAPI"]()
    checkpoint("API_after")
    if mode != "inherited":
        checkpoint("prepare_before")
        f["prepare_kernel"](api)
        checkpoint("prepare_after")
        if mode == "exec":
            checkpoint("Python_capture_before")
            fd, raw, _identity = f["captured_file"](
                PYTHON, 64 * 1024**2, keep=True, executable=True
            )
            try:
                checkpoint("Python_capture_after")
                need(fd == 3 and not os.get_inheritable(fd))
                checkpoint("install_before")
                api.install(f["program"]())
                checkpoint("install_after")
                checkpoint("exec_before")
                api.execfd(
                    fd,
                    [PYTHON, "-I", "-B", "-S", "-c", LOADER, native_sha, code_sha, "inherited"],
                    {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
                raise ValueError("native_fence_exec_returned")
            finally:
                os.close(fd)
        checkpoint("install_before")
        api.install(f["program"]())
        checkpoint("install_after")
    checkpoint("GET_before")
    need(api.libc.prctl(39, 0, 0, 0, 0) == 1 and api.libc.prctl(21, 0, 0, 0, 0) == 2)
    checkpoint("GET_after")
    checkpoint("socket_pairs_before")
    # No connection is ever attempted. Even a broken socket filter can only create
    # an unconnected descriptor in this short-lived, network-none test container.
    for domain in (1, 2, 10):
        need(api.denied(41, domain, 1, 0))
        need(api.denied(53, domain, 1, 0, 0))
    checkpoint("socket_pairs_after")
    checkpoint("network_escape_before")
    for nr in sorted(f["NETWORK_DENIED"] - {41, 53} | f["ESCAPE_DENIED"]):
        need(api.denied(nr, 0, 0, 0, 0, 0, 0))
    checkpoint("network_escape_after")
    checkpoint("holes_before")
    holes = sorted(set(range(max(f["KNOWN_SYSCALLS"]) + 1)) - set(f["KNOWN_SYSCALLS"]))
    need(
        holes
        and api.denied(holes[0], 0)
        and api.denied(9999, 0)
        and api.denied(f["X32_BIT"] | 39, 0)
    )
    checkpoint("holes_after")
    checkpoint("emit_before")
    packet = {
        "schema": "pamolive.fence-native-case/1",
        "case": "exec" if mode == "inherited" else mode,
        "PASS": True,
        "pid": os.getpid(),
        "filter_sha256": f["filter_sha"](),
        "network_connections_attempted": 0,
        "build_verified": False,
        "operational_GO": False,
    }
    sys.stdout.write(json.dumps(packet, separators=(",", ":")) + "\n")
    checkpoint("emit_after")


def run(code_sha, pins, transaction):
    need(sys.platform == "linux" and os.getuid() == os.geteuid() == 0)
    need(subject_pins(code_sha) == pins)
    f = captured("solver_fence.py", pins["solver_fence.py"])
    io = transaction.load("fence_native_H172", "bounded_io.py", pins["bounded_io.py"])
    OUT.mkdir(mode=0o700)
    report = {
        "schema": "pamolive.expat-solver-fence-native-DATA/1",
        "state": "REFUSED_OR_UNKNOWN",
        "code_pins_sha256": code_sha,
        "helper_sha256": pins["solver_fence.py"],
        "native_source_sha256": pins["native_fence_tests.py"],
        "filter_sha256": f["filter_sha"](),
        "cases": [],
        "H1": [],
        "build_verified": False,
        "materials_complete": False,
        "all_OS_descendants_released": False,
        "operational_GO": False,
    }
    try:
        raw, before_identity = f["captured_file"](PYTHON, 64 * 1024**2, executable=True)
        before = sha(raw)
        for case in ("syscalls", "exec"):
            prefix = OUT / case
            transaction.write_new(str(prefix) + "-intent.json", b'{"state":"PENDING"}')
            result = io.run_capped(
                [
                    PYTHON,
                    "-I",
                    "-B",
                    "-S",
                    "-c",
                    LOADER,
                    pins["native_fence_tests.py"],
                    code_sha,
                    case,
                ],
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                cwd="/",
                timeout=15,
                work_timeout=10,
                deadline=time.monotonic() + 15,
                stdout_cap=4096,
                stderr_cap=4096,
                total_cap=8192,
                owned_session=True,
                on_spawn=lambda pid: transaction.write_new(
                    str(prefix) + "-pid.json", json.dumps({"pid": pid}).encode()
                ),
            )
            facts = result.facts()
            transaction.write_new(str(prefix) + "-result.json", json.dumps(facts).encode())
            need(
                result.ok is True
                and type(result.pid) is int
                and result.pid > 0
                and result.spawn_attempted
                is result.owned_child_reaped
                is result.drains_complete
                is True
                and type(result.returncode) is int
                and result.returncode == 0
                and result.killed_owned_child is False
                and result.reason is result.exception_type is result.cleanup_exception_type is None
                and result.stderr == b""
                and 0 < len(result.stdout) <= 4096
            )
            value = json.loads(result.stdout)
            need(
                type(value) is dict
                and set(value)
                == {
                    "schema",
                    "case",
                    "PASS",
                    "pid",
                    "filter_sha256",
                    "network_connections_attempted",
                    "build_verified",
                    "operational_GO",
                }
                and value["schema"] == "pamolive.fence-native-case/1"
                and value["case"] == case
                and value["PASS"] is True
                and type(value["pid"]) is int
                and value["pid"] == result.pid
                and value["filter_sha256"] == report["filter_sha256"]
                and type(value["network_connections_attempted"]) is int
                and value["network_connections_attempted"] == 0
                and value["build_verified"] is value["operational_GO"] is False
            )
            after, after_identity = f["captured_file"](PYTHON, 64 * 1024**2, executable=True)
            need(
                sha(after) == before
                and after_identity == before_identity
                and subject_pins(code_sha) == pins
                and sha(capture_bytes("native_fence_tests.py", pins["native_fence_tests.py"]))
                == pins["native_fence_tests.py"]
                and sha(capture_bytes("solver_fence.py", pins["solver_fence.py"]))
                == pins["solver_fence.py"]
            )
            transaction.write_new(str(prefix) + "-public.json", result.stdout)
            report["H1"].append(facts)
            report["cases"].append(case)
        report["state"] = "COMPLETE_DATA_ONLY"
    except BaseException:
        # Transport DATA remains exportable; the capture driver refuses this state.
        pass
    transaction.write_new(OUT / "summary.json", (json.dumps(report) + "\n").encode())
    return 0


LOADER = """import hashlib,os,stat,sys
p='/opt/expat-apt/native_fence_tests.py'
f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
b=os.fstat(f)
def key(r):
 return (r.st_dev,r.st_ino,r.st_mode,r.st_uid,r.st_gid,r.st_nlink,
         r.st_size,r.st_mtime_ns,r.st_ctime_ns)
assert (stat.S_ISREG(b.st_mode) and b.st_uid==b.st_gid==0 and b.st_nlink==1
        and not b.st_mode&0o6022 and 0<b.st_size<=131072)
raw=b''
while len(raw)<=131072:
 chunk=os.read(f,min(65536,131073-len(raw)))
 if not chunk:break
 raw+=chunk
assert len(raw)==b.st_size and key(os.fstat(f))==key(b)==key(os.lstat(p))
os.close(f)
assert hashlib.sha256(raw).hexdigest()==sys.argv[1]
for parent in ('/opt/expat-apt','/opt','/'):
 r=os.lstat(parent);assert stat.S_ISDIR(r.st_mode) and r.st_uid==0 and not r.st_mode&0o022
exec(compile(raw,p,'exec'),{'__name__':'__main__','__file__':p,'CAPTURED_NATIVE_SHA':sys.argv[1]})
"""


if __name__ == "__main__":
    try:
        child()
    except BaseException:
        sys.stderr.write('{"schema":"pamolive.native-fence-failure/1","state":"UNKNOWN"}\n')
        raise SystemExit(42) from None
