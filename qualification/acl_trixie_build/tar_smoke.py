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
    consumer_package_receipt,
    require,
    require_consumer_imports,
    run,
    signature,
)

ACL_TYPE_DEFAULT = 0x4000
VERSION = "1.35+dfsg-3.1+pamolive1"
BINARY = Path("/usr/bin/tar")
LEGACY = {"acl_get_file", "acl_set_file", "acl_delete_def_file", "acl_extended_file"}
REQUIRED = {name + "_at@ACL_1.3" for name in LEGACY}


def restore_acl(library, root, expected):
    source = root / "source"
    directory = source / "directory"
    directory.mkdir(parents=True)
    file = directory / "data"
    file.write_bytes(b"synthetic tar ACL descriptor round trip\n")
    (source / "without-default").mkdir()
    require(library.acl_set_file(os.fsencode(file), ACL_TYPE_ACCESS, expected) == 0)
    require(library.acl_set_file(os.fsencode(directory), ACL_TYPE_DEFAULT, expected) == 0)
    archive = root / "fixture.tar"
    output = root / "restored"
    output.mkdir()
    require(library.acl_set_file(os.fsencode(output), ACL_TYPE_DEFAULT, expected) == 0)
    run(str(BINARY), "--acls", "-cf", str(archive), "-C", str(source),
        "directory", "without-default")
    run(str(BINARY), "--acls", "-xf", str(archive), "-C", str(output))
    restored = output / "directory"
    require((restored / "data").read_bytes() == file.read_bytes())
    for item, acl_type in ((restored, ACL_TYPE_DEFAULT), (restored / "data", ACL_TYPE_ACCESS)):
        with acl_handle(library, library.acl_get_file(os.fsencode(item), acl_type)) as observed:
            require(library.acl_cmp(expected, observed) == 0)
    removed = library.acl_get_file(os.fsencode(output / "without-default"), ACL_TYPE_DEFAULT)
    with acl_handle(library, removed) as observed:
        require(library.acl_entries(observed) == 0)

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

    (source / "ordinary-ancestor").symlink_to("directory", target_is_directory=True)
    output = root / "ancestor-output"
    output.mkdir()
    run(str(BINARY), "--acls", "-cf", str(archive), "-C", str(source),
        "ordinary-ancestor/empty")
    run(str(BINARY), "--acls", "-xf", str(archive), "-C", str(output))
    selected = output / "ordinary-ancestor" / "empty"
    require(selected.stat().st_size == 0)
    observed = library.acl_get_file(os.fsencode(selected), ACL_TYPE_ACCESS)
    with acl_handle(library, observed) as acl:
        require(library.acl_cmp(expected, acl) == 0)


def main():
    require(run("dpkg-query", "-W", "-f=${Version}", "tar") == VERSION)
    imports = require_consumer_imports(BINARY, REQUIRED, LEGACY)
    library = ctypes.CDLL(SONAME)
    signature(library, "acl_from_text", ctypes.c_void_p, ctypes.c_char_p)
    signature(library, "acl_free", ctypes.c_int, ctypes.c_void_p)
    signature(library, "acl_cmp", ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    signature(library, "acl_entries", ctypes.c_int, ctypes.c_void_p)
    signature(library, "acl_set_file", ctypes.c_int,
              ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p)
    signature(library, "acl_get_file", ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)
    acl_text = b"u::rwx,u:65533:r-x,g::---,m::r-x,o::---"
    with (TemporaryDirectory(prefix="pamolive-tar-acl-") as directory,
          acl_handle(library, library.acl_from_text(acl_text)) as acl):
        restore_acl(library, Path(directory), acl)
    packet = {
        "schema": "pamolive.tar-acl-descriptor-qualification/1",
        **consumer_package_receipt("tar", VERSION),
        "tar_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(),
        "descriptor_imports": imports,
        "access_and_default_ACL_roundtrip": True,
        "explicit_dereference_roundtrip": True,
        "inherited_default_removal": True,
        "empty_under_source_ancestor_link": True,
    }
    print(json.dumps(packet, sort_keys=True))


if __name__ == "__main__":
    main()
