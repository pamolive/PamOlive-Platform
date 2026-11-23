"""Qualify descriptor ACL imports and ordinary tar backup and restore."""

import ctypes
import hashlib
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent))
from smoke import (  # noqa: E402
    ACL_TYPE_ACCESS,
    SONAME,
    acl_handle,
    require,
    run,
    signature,
)

ACL_TYPE_DEFAULT = 0x4000
VERSION = "1.35+dfsg-3.1+pamolive1"
PACKAGE = f"tar_{VERSION}_amd64.deb"
BINARY = Path("/usr/bin/tar")
LEGACY = {"acl_get_file", "acl_set_file", "acl_delete_def_file", "acl_extended_file"}
REQUIRED = {name + "_at@ACL_1.3" for name in LEGACY}


def inspect_imports():
    output = run("/usr/bin/readelf", "--wide", "--dyn-syms", str(BINARY))
    imports = {
        fields[7] for line in output.splitlines()
        if len(fields := line.split()) >= 8 and fields[6] == "UND"
    }
    require(REQUIRED <= imports)
    require(not LEGACY.intersection(name.split("@", 1)[0] for name in imports))
    return sorted(REQUIRED)


def restore_acl(library, root, expected):
    source = root / "source"
    directory = source / "directory"
    directory.mkdir(parents=True)
    file = directory / "data"
    file.write_bytes(b"synthetic tar ACL descriptor round trip\n")
    require(library.acl_set_file(os.fsencode(file), ACL_TYPE_ACCESS, expected) == 0)
    require(library.acl_set_file(os.fsencode(directory), ACL_TYPE_DEFAULT, expected) == 0)
    archive = root / "fixture.tar"
    output = root / "restored"
    output.mkdir()
    run(str(BINARY), "--acls", "-cf", str(archive), "-C", str(source), "directory")
    run(str(BINARY), "--acls", "-xf", str(archive), "-C", str(output))
    restored = output / "directory"
    require((restored / "data").read_bytes() == file.read_bytes())
    for item, acl_type in ((restored, ACL_TYPE_DEFAULT), (restored / "data", ACL_TYPE_ACCESS)):
        with acl_handle(library, library.acl_get_file(os.fsencode(item), acl_type)) as observed:
            require(library.acl_cmp(expected, observed) == 0)

    # Tar may defer opening an empty input until after collecting metadata.
    empty = directory / "empty"
    empty.touch()
    require(library.acl_set_file(os.fsencode(empty), ACL_TYPE_ACCESS, expected) == 0)
    (source / "selected").symlink_to("directory/data")
    (source / "selected-empty").symlink_to("directory/empty")
    output = root / "selected-output"
    output.mkdir()
    run(str(BINARY), "--acls", "--dereference", "-cf", str(archive),
        "-C", str(source), "selected", "selected-empty")
    run(str(BINARY), "--acls", "-xf", str(archive), "-C", str(output))
    for name, original in (("selected", file), ("selected-empty", empty)):
        selected = output / name
        require(not selected.is_symlink() and selected.read_bytes() == original.read_bytes())
        observed = library.acl_get_file(os.fsencode(selected), ACL_TYPE_ACCESS)
        with acl_handle(library, observed) as acl:
            require(library.acl_cmp(expected, acl) == 0)


def main():
    require(run("dpkg-query", "-W", "-f=${Version}", "tar") == VERSION)
    imports = inspect_imports()
    library = ctypes.CDLL(SONAME)
    signature(library, "acl_from_text", ctypes.c_void_p, ctypes.c_char_p)
    signature(library, "acl_free", ctypes.c_int, ctypes.c_void_p)
    signature(library, "acl_cmp", ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    signature(library, "acl_set_file", ctypes.c_int,
              ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p)
    signature(library, "acl_get_file", ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)
    acl_text = b"u::rwx,u:65533:r-x,g::---,m::r-x,o::---"
    with (TemporaryDirectory(prefix="pamolive-tar-acl-") as directory,
          acl_handle(library, library.acl_from_text(acl_text)) as acl):
        restore_acl(library, Path(directory), acl)
    evidence = Path("/evidence")
    package, buildinfo = (evidence / name for name in ("tar.deb", "tar.buildinfo"))
    package_raw = package.read_bytes()
    digest = hashlib.sha256(package_raw).hexdigest()
    declared = f"{digest} {len(package_raw)} {PACKAGE}".encode().split()
    sums = buildinfo.read_bytes().split(b"\nChecksums-Sha256:\n", 1)[1].split(b"\n\n", 1)[0]
    require(sum(row.split() == declared for row in sums.splitlines()) == 1)
    packet = {
        "schema": "pamolive.tar-acl-descriptor-qualification/1",
        "version": VERSION,
        "architecture": "amd64",
        "tar_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(),
        "package_sha256": digest,
        "package_bytes": len(package_raw),
        "buildinfo_sha256": hashlib.sha256(buildinfo.read_bytes()).hexdigest(),
        "descriptor_imports": imports,
        "access_and_default_ACL_roundtrip": True,
        "explicit_dereference_roundtrip": True,
    }
    print(json.dumps(packet, sort_keys=True))


if __name__ == "__main__":
    main()
