"""Future Linux owner boundary. Imported here only for synthetic SOURCE tests."""

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from acquisition_io import remaining

SOURCES = {
    "future_linux": "future_linux.py",
    "source_data": "source_data.py",
    "patch_contracts": "patch_contracts.py",
    "acquisition_io": "acquisition_io.py",
    "acquisition_owner": "acquisition_owner.py",
    "reused_text_helpers": "reused_text_helpers.py",
    "reused_signature_data": "reused_signature_data.py",
    "common": "future_support/common.py",
    "bounded_io": "future_support/bounded_io.py",
}
META = {"dev", "ino", "mode", "uid", "gid", "nlink", "size"}
SECONDS, CLEANUP = 180, 5
LOADER = """import hashlib,importlib.abc,importlib.util,json,sys
p=json.loads(sys.argv[1]); sources=p['sources']
expected=p['trust']['acquisition_runtime']['source_files']
if set(sources)!=set(expected): raise SystemExit(75)
for name,raw in sources.items():
 if hashlib.sha256(raw.encode()).hexdigest()!=expected[name]: raise SystemExit(75)
class Captured(importlib.abc.MetaPathFinder,importlib.abc.Loader):
 def find_spec(self,name,path=None,target=None):
  if name in p['modules']: return importlib.util.spec_from_loader(name,self)
 def create_module(self,spec): return None
 def exec_module(self,module):
  name=p['modules'][module.__name__]; module.__file__=p['root']+'/'+name
  exec(compile(sources[name],module.__file__,'exec'),module.__dict__)
sys.meta_path.insert(0,Captured())
import future_linux
try:
 future_linux.acquisition_worker(p)
except BaseException:
 print('{"state":"UNKNOWN"}'); raise SystemExit(75)
print('{"state":"COMPLETE"}')
"""


def need(value, code):
    if not value:
        raise ValueError(code)


def runtime_contract(role):
    need(
        type(role) is dict
        and set(role) == {"path", "sha256", "metadata", "user_uid", "source_files"},
        "acquisition_runtime_shape",
    )
    name = role["path"]
    need(
        type(name) is str and re.fullmatch(r"/(?:usr/bin|usr/local/bin)/python3\.[0-9]{1,2}", name),
        "acquisition_runtime_exact_ELF_path",
    )
    need(
        type(role["sha256"]) is str and re.fullmatch("[a-f0-9]{64}", role["sha256"]),
        "acquisition_runtime_pin",
    )
    need(
        type(role["metadata"]) is dict
        and set(role["metadata"]) == META
        and all(type(v) is int and v >= 0 for v in role["metadata"].values()),
        "acquisition_runtime_metadata",
    )
    need(
        type(role["user_uid"]) is int and role["user_uid"] > 0,
        "acquisition_unprivileged_uid",
    )
    pins = role["source_files"]
    need(
        type(pins) is dict
        and set(pins) == set(SOURCES.values())
        and all(type(v) is str and re.fullmatch("[a-f0-9]{64}", v) for v in pins.values()),
        "acquisition_source_closed_pins",
    )
    return role


def runtime_role(role, read, deadline, *, running=True):
    runtime_contract(role)
    remaining(deadline)
    path = Path(role["path"])
    # No PATH/env lookup, alias, symlink ancestor, writable parent or binary-only claim.
    for parent in [*reversed(path.parents), path]:
        row = parent.lstat()
        need(
            not stat.S_ISLNK(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022,
            "acquisition_runtime_parent_or_owner",
        )
        need(
            stat.S_ISREG(row.st_mode) if parent == path else stat.S_ISDIR(row.st_mode),
            "acquisition_runtime_type",
        )
        remaining(deadline)
    row = path.lstat()
    actual = {key: getattr(row, "st_" + key) for key in META}
    need(
        actual == role["metadata"]
        and row.st_nlink == 1
        and row.st_mode & 0o111
        and not row.st_mode & 0o6000,
        "acquisition_runtime_metadata_changed",
    )
    raw = read(path, 64 * 1024**2)
    remaining(deadline)
    need(
        raw.startswith(b"\x7fELF") and hashlib.sha256(raw).hexdigest() == role["sha256"],
        "acquisition_runtime_bytes",
    )
    need(os.getuid() == os.geteuid() == role["user_uid"], "acquisition_runtime_user")
    if running:
        need(
            os.readlink("/proc/self/exe") == role["path"] and sys_flags(),
            "acquisition_running_runtime",
        )
    remaining(deadline)
    return actual


def sys_flags():
    import sys

    return (
        sys.flags.isolated == 1
        and sys.flags.no_site == 1
        and sys.flags.dont_write_bytecode == 1
        and sys.flags.ignore_environment == 1
    )


def snapshot(root, role, read, deadline):
    remaining(deadline)
    sources = {}
    for name in SOURCES.values():
        remaining(deadline)
        raw = read(root / name, 131072)
        remaining(deadline)
        need(
            hashlib.sha256(raw).hexdigest() == role["source_files"][name],
            "acquisition_source_changed",
        )
        sources[name] = raw.decode("utf-8", "strict")
    return sources


def supervise(root, materials, work, trust, read, command, record, *, deadline):
    """One H172 owner for DNS, TLS, all bodies, hashes, source verification and snapshots."""
    remaining(deadline)
    role = runtime_contract(trust["acquisition_runtime"])
    work_deadline = deadline - CLEANUP
    remaining(work_deadline)
    runtime_role(role, read, work_deadline)
    captured = snapshot(root, role, read, work_deadline)
    payload = {
        "root": str(root),
        "materials": str(materials),
        "work": str(work / "sequence"),
        "trust": trust,
        "deadline": work_deadline,
        "sources": captured,
        "modules": SOURCES,
    }
    raw = json.dumps(payload, separators=(",", ":"))
    need(len(raw.encode()) <= 110000, "acquisition_captured_argv_budget")
    remaining(work_deadline)
    work.mkdir(mode=0o700)
    try:
        remaining(work_deadline)
        record(work / "acquisition-pending.json", {"state": "PENDING"})
        need(
            snapshot(root, role, read, work_deadline) == captured,
            "acquisition_source_changed",
        )
        runtime_role(role, read, work_deadline)
        left = remaining(work_deadline)
        stdout = command(
            [role["path"], "-I", "-B", "-S", "-c", LOADER, raw],
            work,
            work / "acquisition-owner",
            seconds=left,
            deadline=deadline,
            cap=4096,
        )
        remaining(work_deadline)
        need(stdout == b'{"state":"COMPLETE"}\n', "ACQUISITION_UNKNOWN_WORKER_RESULT")
        runtime_role(role, read, work_deadline)
        need(
            snapshot(root, role, read, work_deadline) == captured,
            "acquisition_source_changed",
        )
        remaining(work_deadline)
        record(
            work / "acquisition-complete.json",
            {"state": "COMPLETE", "universal_cleanup_proved": False},
        )
        remaining(work_deadline)
        return work / "sequence/complete-source"
    except BaseException:
        # Only a fixed UNKNOWN marker can use the existing cleanup slice; never reacquire.
        try:
            remaining(deadline)
            record(
                work / "acquisition-unknown.json",
                {"state": "UNKNOWN", "resources_released": False},
            )
        except BaseException:
            pass
        raise
