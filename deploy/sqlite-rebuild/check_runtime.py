"""Verify the reviewed SQLite package and the library loaded in the final runtime."""

import argparse
import ctypes
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

PACKAGE = "libsqlite3-0"
REVISION = "3.54.1-2~pamolive13u1"
PACKAGE_SHA256 = "75e0bc870f5eb3616eac1e3c095f042165d173fa9cb210b24c5a66a1d3dfe0e3"
ELF_SHA256 = "f3efdeb6d18f5168d14511e0aec614f7b84e8daf1c319a77089d58e50d4ff317"
LIBRARY_DIRECTORY = Path("/usr/lib/x86_64-linux-gnu")
LIBRARY = "libsqlite3.so.3.54.1"
SONAME = "libsqlite3.so.0"


def require(condition, code):
    if not condition:
        raise ValueError(code)


def verify_bytes(path, limit, expected):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and 0 < meta.st_size <= limit, "sqlite_file")
        data = stream.read(limit + 1)
        require(
            len(data) == meta.st_size and hashlib.sha256(data).hexdigest() == expected,
            "sqlite_sha256",
        )


def verify_package(path):
    require(path.name == f"{PACKAGE}_{REVISION}_amd64.deb", "sqlite_package_name")
    verify_bytes(path, 4 * 1024**2, PACKAGE_SHA256)


def verify_runtime():
    identity = subprocess.check_output(
        (
            "/usr/bin/dpkg-query", "-W",
            "-f=${Package}|${Source}|${Version}|${Architecture}|${Status}\n", PACKAGE,
        ),
        timeout=5, stderr=subprocess.DEVNULL,
    )
    require(
        identity == f"{PACKAGE}|sqlite3|{REVISION}|amd64|install ok installed\n".encode("ascii"),
        "sqlite_package_identity",
    )
    require(
        {path.name for path in LIBRARY_DIRECTORY.glob("libsqlite3.so.*")} == {SONAME, LIBRARY},
        "sqlite_library_set",
    )
    require(os.readlink(LIBRARY_DIRECTORY / SONAME) == LIBRARY, "sqlite_soname_link")
    library = LIBRARY_DIRECTORY / LIBRARY
    require(stat.S_ISREG(library.lstat().st_mode), "sqlite_library_type")
    verify_bytes(library, 8 * 1024**2, ELF_SHA256)
    import sqlite3

    require(sqlite3.sqlite_version == "3.54.1", "sqlite_linked_version")
    ctypes.CDLL("liblastlog2.so.2")
    with Path("/proc/self/maps").open(encoding="ascii") as stream:
        mapped = {
            line.split()[-1]
            for line in stream
            if "/libsqlite3.so." in line
        }
    require(mapped == {str(library)}, "sqlite_linked_file")
    return {
        "schema": "pamolive.sqlite-runtime/1",
        "package": PACKAGE,
        "version": REVISION,
        "architecture": "amd64",
        "package_sha256": PACKAGE_SHA256,
        "elf_sha256": ELF_SHA256,
        "sqlite_version": sqlite3.sqlite_version,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path)
    args = parser.parse_args()
    try:
        if args.package is None:
            print(json.dumps(verify_runtime(), sort_keys=True))
        else:
            verify_package(args.package)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit("SQLite runtime identity check refused.") from None


if __name__ == "__main__":
    main()
