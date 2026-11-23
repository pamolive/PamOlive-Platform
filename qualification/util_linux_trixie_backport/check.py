"""Qualify the exact installed Trixie packages and their native interfaces."""

import ctypes
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from abi_data import elf_exports  # noqa: E402

BASELINE = "2.41.5-0+deb13u1"
CANDIDATE = BASELINE + "+pamolive1"
VERSIONS = {
    "bsdutils": "1:",
    "libblkid1": "",
    "liblastlog2-2": "",
    "libmount1": "",
    "libsmartcols1": "",
    "libuuid1": "",
    "login": "1:4.16.0-2+really",
    "mount": "",
    "util-linux": "",
}
LIBS = (
    "libblkid.so.1",
    "liblastlog2.so.2",
    "libmount.so.1",
    "libsmartcols.so.1",
    "libuuid.so.1",
)
COMMANDS = ("findmnt", "mount", "nsenter", "unshare")
LIBDIR = Path("/usr/lib/x86_64-linux-gnu")
BINDIR = Path("/usr/bin")
EVIDENCE = Path("/evidence")
PACKAGE_ARCHIVES = Path("/packages")


def hash_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def installed(version):
    format_string = "${source:Package}|${Version}|${Architecture}|${db:Status-Status}"
    versions = {name: prefix + version for name, prefix in VERSIONS.items()}
    for name, expected in versions.items():
        observed = subprocess.check_output(
            ["/usr/bin/dpkg-query", "-W", "-f=" + format_string, name], timeout=8,
        )
        if observed != f"util-linux|{expected}|amd64|installed".encode("ascii"):
            raise ValueError("util_linux_package_identity")
    return versions


def inspect_libraries():
    libraries, handles = {}, {}
    for name in LIBS:
        path = (LIBDIR / name).resolve(strict=True)
        if path.parent != LIBDIR or not path.is_file():
            raise ValueError("util_linux_library_identity")
        if not 64 <= path.stat().st_size <= 16 * 1024**2:
            raise ValueError("util_linux_library_identity")
        data = path.read_bytes()
        exports = elf_exports(data)
        if exports["soname"] != name:
            raise ValueError("util_linux_soname")
        handles[name] = ctypes.CDLL(name, mode=os.RTLD_LOCAL | os.RTLD_NOW)
        libraries[name] = {**exports, "path": str(path), "sha256": hashlib.sha256(data).hexdigest()}
    mapping_lines = Path("/proc/self/maps").read_text().splitlines()
    mappings = {line.split(maxsplit=5)[-1] for line in mapping_lines}
    if not all(item["path"] in mappings for item in libraries.values()):
        raise ValueError("util_linux_library_mapping")
    handles.clear()
    return libraries


def read_only_commands():
    commands = {}
    for name in COMMANDS:
        path = BINDIR / name
        observed = subprocess.check_output([str(path), "--version"], timeout=8)
        if b"util-linux 2.41.5" not in observed:
            raise ValueError("util_linux_program_version")
        commands[name] = hash_file(path)
    root = subprocess.check_output(
        [
            str(BINDIR / "findmnt"), "--kernel", "--noheadings", "--raw",
            "--output", "TARGET", "--mountpoint", "/",
        ],
        timeout=8,
    )
    if root != b"/\n":
        raise ValueError("util_linux_mount_table_read")
    return commands


def capture(version):
    return {
        "packages": installed(version),
        "libraries": inspect_libraries(),
        "commands": read_only_commands(),
    }


def compare(before, after):
    stock, candidate = before["libraries"], after["libraries"]
    for name in LIBS:
        if stock[name]["symbols"] != candidate[name]["symbols"]:
            raise ValueError("util_linux_export_delta")
    if stock["libmount.so.1"]["sha256"] == candidate["libmount.so.1"]["sha256"]:
        raise ValueError("util_linux_libmount_unchanged")
    for name in ("nsenter", "unshare"):
        if before["commands"][name] == after["commands"][name]:
            raise ValueError("util_linux_program_unchanged")


def record(name, data):
    with (EVIDENCE / name).open("x", encoding="ascii") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(args):
    if args == ["stock"]:
        record("stock.json", capture(BASELINE))
        return
    if args != ["candidate"]:
        raise ValueError("util_linux_mode")
    before = json.loads((EVIDENCE / "stock.json").read_bytes())
    after = capture(CANDIDATE)
    compare(before, after)
    record("candidate.json", after)
    record("qualification.json", {
        "schema": "pamolive.util-linux-trixie-runtime/1",
        "packages": after["packages"],
        "archives": {name: hash_file(PACKAGE_ARCHIVES / (name + ".deb")) for name in VERSIONS},
        "buildinfo_sha256": hash_file(PACKAGE_ARCHIVES / "buildinfo"),
        "test_summary_sha256": hash_file(PACKAGE_ARCHIVES / "test-summary.txt"),
        "stock_sha256": hash_file(EVIDENCE / "stock.json"),
        "candidate_sha256": hash_file(EVIDENCE / "candidate.json"),
        "native_exports_preserved": True,
        "read_only_runtime_verified": True,
    })


if __name__ == "__main__":
    main(sys.argv[1:])
