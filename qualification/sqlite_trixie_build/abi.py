"""Check the runtime library and the SQLite imports of two Trixie consumers."""

import _sqlite3
import ctypes
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

LIB = Path("/usr/lib/x86_64-linux-gnu")
OLD_ELF_SHA = "317d80bf5d592f98a71e14d2330591d6a339f631f37c5977835af748a1f26715"


def require(condition):
    if not condition:
        raise ValueError("sqlite_abi_mismatch")


def elf(path, *options):
    return subprocess.check_output(
        ["readelf", *options, str(path)], text=True, encoding="ascii", timeout=10,
    )


def symbols(path):
    imports, exports = set(), set()
    for line in elf(path, "--wide", "--dyn-syms").splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0][:-1].isdigit():
            continue
        name, separator, version = fields[7].partition("@")
        if not name.startswith("sqlite3") or fields[4] not in {"GLOBAL", "WEAK"}:
            continue
        versioned = name + separator + version.lstrip("@")
        if fields[6] == "UND":
            imports.add(versioned)
        elif fields[5] in {"DEFAULT", "PROTECTED"}:
            exports.add(versioned)
            if version.startswith("@"):
                exports.add(name)
    return imports, exports


def inspect(*, candidate):
    library_path = (LIB / "libsqlite3.so.0").resolve(strict=True)
    require(library_path.parent == LIB)
    feature_version = "3.54.1" if candidate else "3.46.1"
    require(sqlite3.sqlite_version == feature_version)
    require("Library soname: [libsqlite3.so.0]" in elf(library_path, "-d"))
    ctypes.CDLL("liblastlog2.so.2")
    maps = Path("/proc/self/maps").read_text(encoding="ascii").splitlines()
    mapped = {
        line.split()[-1]
        for line in maps
        if re.search(r"/libsqlite3\.so(?:\.|$)", line)
    }
    require(mapped == {str(library_path)})

    _, exported = symbols(library_path)
    consumers = {
        "_sqlite3": Path(_sqlite3.__file__),
        "liblastlog2": LIB / "liblastlog2.so.2",
    }
    for path in consumers.values():
        require("Shared library: [libsqlite3.so.0]" in elf(path, "-d"))
    by_consumer = {name: symbols(path)[0] for name, path in consumers.items()}
    require(all(imports and imports <= exported for imports in by_consumer.values()))
    with library_path.open("rb") as stream:
        library_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    if not candidate:
        require(library_sha == OLD_ELF_SHA)
    return {
        "soname": "libsqlite3.so.0",
        "elf_sha256": library_sha,
        "version": feature_version,
        "consumers": {name: sorted(imports) for name, imports in by_consumer.items()},
        "loaded": True,
    }


def main():
    mode, *args = sys.argv[1:]
    require(mode in {"baseline", "candidate"})
    report = inspect(candidate=mode == "candidate")
    if mode == "candidate":
        before = json.loads(Path(args[0]).read_text(encoding="ascii"))
        require(before["loaded"] is True and before["elf_sha256"] == OLD_ELF_SHA)
        require(before["soname"] == report["soname"] and before["consumers"] == report["consumers"])
        require(before["elf_sha256"] != report["elf_sha256"])
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
