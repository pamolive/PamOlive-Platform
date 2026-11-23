"""Qualify the installed amd64 libacl and GNU tar on synthetic regular files."""

import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

LIBDIR = Path("/usr/lib/x86_64-linux-gnu")
SONAME = "libacl.so.1"
BASELINE_SHA256 = "3c03774961231d8485a4dba36ec359a95939a84719799c58cd26173e44bbde90"
VERSIONS = {"baseline": "2.3.2-2+b1", "candidate": "2.4.0-1~pamolive13u1"}
ACL_TYPE_ACCESS = 0x8000
AT_EMPTY_PATH = 0x1000
FIXTURE = b"synthetic named-user ACL fixture\n"


def require(condition):
    if not condition:
        raise ValueError("acl_qualification_mismatch")


def run(*arguments):
    return subprocess.check_output(
        arguments,
        text=True,
        encoding="ascii",
        stderr=subprocess.DEVNULL,
        env={**os.environ, "LC_ALL": "C"},
        timeout=10,
    )


def exported_functions(path):
    exports = set()
    for line in run("readelf", "--wide", "--dyn-syms", path).splitlines():
        fields = line.split()
        if len(fields) < 8 or not re.fullmatch(r"\d+:", fields[0]):
            continue
        _, _, _, kind, binding, visibility, index, name = fields[:8]
        if (
            kind in {"FUNC", "IFUNC"}
            and binding in {"GLOBAL", "WEAK"}
            and visibility in {"DEFAULT", "PROTECTED"}
            and index != "UND"
        ):
            require(re.fullmatch(r"[A-Za-z_]\w{0,95}@{1,2}ACL_1(?:\.[0-9]{1,3}){1,3}", name))
            exports.add(name)
    require(0 < len(exports) <= 128)
    return sorted(exports)


def require_loaded_file(path, identity):
    maps = Path("/proc/self/maps").read_text(encoding="utf-8", errors="surrogateescape")
    found = False
    for line in maps.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not Path(fields[5]).name.startswith("libacl.so."):
            continue
        _, _, _, device, inode, mapped_path = fields
        device_id = os.makedev(*(int(part, 16) for part in device.split(":")))
        require(mapped_path == str(path))
        require(int(inode) == identity.st_ino and device_id == identity.st_dev)
        found = True
    require(found)


def signature(library, name, result, *arguments):
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


@contextmanager
def acl_handle(library, pointer):
    require(pointer)
    try:
        yield pointer
    finally:
        library.acl_free(pointer)


def tar_roundtrip(library, directory, expected):
    source = directory / "source"
    restored = directory / "restored"
    archive = directory / "fixture.tar"
    source.mkdir()
    restored.mkdir()
    name = "fixture"
    original = source / name
    recovered = restored / name
    original.write_bytes(FIXTURE)
    require(library.acl_set_file(os.fsencode(original), ACL_TYPE_ACCESS, expected) == 0)
    with acl_handle(library, library.acl_get_file(os.fsencode(original), ACL_TYPE_ACCESS)) as acl:
        require(library.acl_cmp(expected, acl) == 0)
    run("tar", "--acls", "-cf", archive, "-C", source, name)
    run("tar", "--acls", "-xf", archive, "-C", restored)
    with acl_handle(library, library.acl_get_file(os.fsencode(recovered), ACL_TYPE_ACCESS)) as acl:
        return library.acl_cmp(expected, acl) == 0 and recovered.read_bytes() == FIXTURE


def descriptor_roundtrip(library, directory, expected):
    common_arguments = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint)
    set_acl = signature(
        library, "acl_set_file_at", ctypes.c_int, *common_arguments, ctypes.c_void_p
    )
    get_acl = signature(library, "acl_get_file_at", ctypes.c_void_p, *common_arguments)
    path = directory / "descriptor-fixture"
    with path.open("x+b") as stream:
        stream.write(FIXTURE)
        stream.flush()
        target = (stream.fileno(), b"", AT_EMPTY_PATH, ACL_TYPE_ACCESS)
        require(set_acl(*target, expected) == 0)
        with acl_handle(library, get_acl(*target)) as acl:
            require(library.acl_cmp(expected, acl) == 0)
    with acl_handle(library, library.acl_get_file(os.fsencode(path), ACL_TYPE_ACCESS)) as acl:
        return library.acl_cmp(expected, acl) == 0 and path.read_bytes() == FIXTURE


def qualify(mode, report):
    version = run("dpkg-query", "--show", "--showformat=${Version}", "libacl1:amd64")
    require(version == VERSIONS[mode])
    report["version"] = version
    path = (LIBDIR / SONAME).resolve(strict=True)
    require(path.parent == LIBDIR)
    require(f"Library soname: [{SONAME}]" in run("readelf", "--dynamic", path))
    with path.open("rb") as stream:
        identity = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    report["elf_sha256"] = digest
    if mode == "baseline":
        require(digest == BASELINE_SHA256)
    else:
        require(digest != BASELINE_SHA256)
    library = ctypes.CDLL(SONAME)
    require_loaded_file(path, identity)
    report["loaded"] = True
    report["exports"] = exported_functions(path)

    signature(library, "acl_from_text", ctypes.c_void_p, ctypes.c_char_p)
    signature(library, "acl_free", ctypes.c_int, ctypes.c_void_p)
    signature(library, "acl_cmp", ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    signature(
        library, "acl_set_file", ctypes.c_int, ctypes.c_char_p, ctypes.c_uint, ctypes.c_void_p
    )
    signature(library, "acl_get_file", ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint)
    named_uid = 42424 if os.geteuid() != 42424 else 42425
    text = f"u::rw-,u:{named_uid}:r--,g::---,m::r--,o::---".encode("ascii")
    with TemporaryDirectory(prefix="acl-smoke-") as temporary:
        directory = Path(temporary)
        with acl_handle(library, library.acl_from_text(text)) as expected:
            report["tar_acl_roundtrip"] = tar_roundtrip(library, directory, expected)
            if mode == "candidate":
                report["descriptor_acl_roundtrip"] = descriptor_roundtrip(
                    library, directory, expected
                )


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else None
    report = {
        "version": "",
        "elf_sha256": "",
        "exports": [],
        "loaded": False,
        "tar_acl_roundtrip": False,
        "descriptor_acl_roundtrip": False if mode == "candidate" else None,
    }
    ok = False
    if mode in VERSIONS:
        try:
            qualify(mode, report)
            ok = report["tar_acl_roundtrip"] and (
                mode == "baseline" or report["descriptor_acl_roundtrip"]
            )
        except (AttributeError, OSError, ValueError, subprocess.SubprocessError):
            pass
    public = json.dumps(report, sort_keys=True, separators=(",", ":"))
    print(public)
    if not ok:
        print(public, file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
