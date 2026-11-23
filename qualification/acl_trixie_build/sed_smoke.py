"""Qualify ordinary sed in-place edits using only descriptor ACL imports."""

import ctypes
import errno
import json
import os
import stat
import subprocess
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
VERSION = "4.9-2+deb13u1+pamolive1"
BINARY = Path("/usr/bin/sed")
FAULT_LIBRARY = "/opt/acl-checks/sed-acl-faults.so"
LEGACY = {"acl_get_file", "acl_set_file", "acl_delete_def_file"}
REQUIRED = {"acl_get_fd@ACL_1.0", "acl_set_fd@ACL_1.0"}


def edit_fixtures(library, root, expected):
    source = root / "named-acl"
    plain = root / "plain"
    for path in (source, plain):
        path.write_text("before\n", encoding="ascii")
    plain.chmod(0o1640)
    require(library.acl_set_file(os.fsencode(source), ACL_TYPE_ACCESS, expected) == 0)
    require(library.acl_set_file(os.fsencode(root), ACL_TYPE_DEFAULT, expected) == 0)
    link = root / "selected"
    link.symlink_to(source.name)
    run(str(BINARY), "--follow-symlinks", "-i.bak", "s/before/after/", str(link))
    require(link.is_symlink() and source.read_text(encoding="ascii") == "after\n")
    backup = source.with_suffix(".bak")
    require(backup.read_text(encoding="ascii") == "before\n")
    for path in (source, backup):
        observed = library.acl_get_file(os.fsencode(path), ACL_TYPE_ACCESS)
        with acl_handle(library, observed) as acl:
            require(library.acl_cmp(expected, acl) == 0)

    run(str(BINARY), "-i", "s/before/after/", str(plain))
    require(plain.read_text(encoding="ascii") == "after\n")
    require(stat.S_IMODE(plain.stat().st_mode) == 0o1640)
    observed = library.acl_get_file(os.fsencode(plain), ACL_TYPE_ACCESS)
    with acl_handle(library, observed) as acl:
        require(library.acl_entries(acl) == 3)


def edit_with_acl_errors(library, root, expected):
    plain = root / "mode-fallback"
    plain.write_text("before\n", encoding="ascii")
    require(library.acl_set_file(os.fsencode(plain), ACL_TYPE_ACCESS, expected) == 0)
    require(library.acl_set_file(os.fsencode(root), ACL_TYPE_DEFAULT, expected) == 0)
    mode = stat.S_IMODE(plain.stat().st_mode)
    result = subprocess.run(
        [str(BINARY), "-i", "s/before/after/", str(plain)],
        env={"LC_ALL": "C", "LD_PRELOAD": FAULT_LIBRARY,
             "PAMOLIVE_TEST_SED_ACL_READ_UNSUPPORTED": "1"},
        capture_output=True, text=True, timeout=10, check=True,
    )
    require(result.stderr == "" and plain.read_text(encoding="ascii") == "after\n")
    require(stat.S_IMODE(plain.stat().st_mode) == mode)
    observed = library.acl_get_file(os.fsencode(plain), ACL_TYPE_ACCESS)
    with acl_handle(library, observed) as acl:
        require(library.acl_entries(acl) == 3)

    result = subprocess.run(
        [str(BINARY), "-i", "s/after/final/", str(plain)],
        env={"LC_ALL": "C", "LD_PRELOAD": FAULT_LIBRARY,
             "PAMOLIVE_TEST_SED_ACL_WRITE_DENIED": "1"},
        capture_output=True, text=True, timeout=10, check=True,
    )
    require("preserving permissions" in result.stderr)
    require(os.strerror(errno.EPERM) in result.stderr)
    require(plain.read_text(encoding="ascii") == "final\n")
    require(stat.S_IMODE(plain.stat().st_mode) == mode)


def main():
    require(run("dpkg-query", "-W", "-f=${Version}", "sed") == VERSION)
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
    with (TemporaryDirectory(prefix="pamolive-sed-acl-") as directory,
          acl_handle(library, library.acl_from_text(acl_text)) as acl):
        root = Path(directory)
        fixtures, errors = (root / name for name in ("fixtures", "errors"))
        fixtures.mkdir()
        errors.mkdir()
        edit_fixtures(library, fixtures, acl)
        edit_with_acl_errors(library, errors, acl)

    packet = {
        "schema": "pamolive.sed-acl-descriptor-qualification/1",
        **consumer_package_receipt(BINARY, "sed", VERSION),
        "descriptor_imports": imports,
        "in_place_named_ACL_and_backup": True,
        "ordinary_follow_symlinks": True,
        "mode_and_inherited_ACL_replacement": True,
        "source_ACL_unsupported_mode_fallback": True,
        "destination_ACL_denied_diagnostic": True,
    }
    print(json.dumps(packet, sort_keys=True))


if __name__ == "__main__":
    main()
