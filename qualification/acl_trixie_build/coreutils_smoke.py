"""Compare ordinary coreutils mode and ACL behavior with Debian stock."""

import ctypes
import hashlib
import json
import os
import stat
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
VERSIONS = {"stock": "9.7-3", "candidate": "9.7-3+pamolive1"}
BINARIES = {name: Path("/usr/bin") / name for name in ("cp", "install", "mv")}
LEGACY = {"acl_set_file", "acl_delete_def_file", "acl_get_file", "acl_extended_file"}
REQUIRED = {"acl_set_fd@ACL_1.0", "acl_set_file_at@ACL_1.3", "acl_delete_def_file_at@ACL_1.3"}
SCHEMA = "pamolive.coreutils-acl-descriptor-qualification/1"
OTHER_FILESYSTEM = "/tmp/pamolive-other"


def require_acl(library, path, acl_type, expected):
    observed = library.acl_get_file(os.fsencode(path), acl_type)
    with acl_handle(library, observed) as acl:
        require(library.acl_cmp(expected, acl) == 0)


def require_trivial_acl(library, path):
    observed = library.acl_get_file(os.fsencode(path), ACL_TYPE_ACCESS)
    with acl_handle(library, observed) as acl:
        require(library.acl_entries(acl) == 3)


def copy_fixtures(library, root, expected):
    cp = str(BINARIES["cp"])
    original = root / "original"
    original.mkdir()
    source = original / "data"
    source.write_text("synthetic ACL copy\n", encoding="ascii")
    require(library.acl_set_file(os.fsencode(source), ACL_TYPE_ACCESS, expected) == 0)
    require(library.acl_set_file(os.fsencode(original), ACL_TYPE_DEFAULT, expected) == 0)

    copy = root / "regular-copy"
    run(cp, "-p", str(source), str(copy))
    require(copy.read_bytes() == source.read_bytes())
    require_acl(library, copy, ACL_TYPE_ACCESS, expected)

    recursive = root / "recursive"
    run(cp, "-a", str(original), str(recursive))
    require_acl(library, recursive, ACL_TYPE_DEFAULT, expected)
    require_acl(library, recursive / "data", ACL_TYPE_ACCESS, expected)

    parents = root / "parents"
    parents.mkdir()
    run(cp, "--parents", "-p", "original/data", str(parents), cwd=root)
    require_acl(library, parents / "original", ACL_TYPE_DEFAULT, expected)
    require_acl(library, parents / "original" / "data", ACL_TYPE_ACCESS, expected)

    (original / "link").symlink_to("data")
    for option in ("-L", "-H", "-P"):
        selected = root / option[1]
        run(cp, "-p", option, str(original / "link"), str(selected))
        if option == "-P":
            require(selected.is_symlink() and os.readlink(selected) == "data")
        else:
            require(not selected.is_symlink() and selected.read_bytes() == source.read_bytes())
            require_acl(library, selected, ACL_TYPE_ACCESS, expected)

    destination = root / "destination"
    destination.mkdir()
    require(library.acl_set_file(os.fsencode(destination), ACL_TYPE_DEFAULT, expected) == 0)
    alias = root / "ordinary-parent"
    alias.symlink_to(destination.name, target_is_directory=True)
    folder = alias / "new-directory"
    run(cp, "-R", "--no-preserve=mode", str(original), str(folder))
    require(folder.is_dir())
    require_trivial_acl(library, folder)
    require_acl(library, folder, ACL_TYPE_DEFAULT, expected)

    fifo = root / "source-fifo"
    os.mkfifo(fifo, 0o600)
    output = alias / "copied-fifo"
    run(cp, "-R", "--no-preserve=mode", str(fifo), str(output))
    require(stat.S_ISFIFO(output.stat().st_mode))
    require_trivial_acl(library, output)


def install_fixtures(library, root, expected):
    install = str(BINARIES["install"])
    destination = root / "install-parent"
    destination.mkdir()
    require(library.acl_set_file(os.fsencode(destination), ACL_TYPE_DEFAULT, expected) == 0)
    source = root / "original" / "data"
    installed = destination / "data"
    run(install, "-m", "0641", str(source), str(installed))
    require(installed.read_bytes() == source.read_bytes())
    require(stat.S_IMODE(installed.stat().st_mode) == 0o641)
    require_trivial_acl(library, installed)
    directory = destination / "directory"
    run(install, "-d", "-m", "0711", str(directory))
    require(directory.is_dir() and stat.S_IMODE(directory.stat().st_mode) == 0o711)


def move_fixtures(library, root, other, expected):
    mv = str(BINARIES["mv"])
    source = root / "move-source"
    source.write_text("synthetic ACL move\n", encoding="ascii")
    require(library.acl_set_file(os.fsencode(source), ACL_TYPE_ACCESS, expected) == 0)
    identity = source.stat()
    first = root / "renamed"
    run(mv, str(source), str(first))
    require(not source.exists() and first.stat().st_ino == identity.st_ino)
    require(first.stat().st_dev == identity.st_dev)
    require_acl(library, first, ACL_TYPE_ACCESS, expected)

    require(first.stat().st_dev != other.stat().st_dev)
    contents = first.read_bytes()
    second = other / "copied"
    run(mv, str(first), str(second))
    require(not first.exists() and second.read_bytes() == contents)
    require_acl(library, second, ACL_TYPE_ACCESS, expected)


def main():
    mode = sys.argv[1]
    version = VERSIONS[mode]
    require(run("dpkg-query", "-W", "-f=${Version}", "coreutils") == version)
    library = ctypes.CDLL(SONAME)
    signature(library, "acl_from_text", ctypes.c_void_p, ctypes.c_char_p)
    signature(library, "acl_free", ctypes.c_int, ctypes.c_void_p)
    signature(library, "acl_cmp", ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    signature(library, "acl_entries", ctypes.c_int, ctypes.c_void_p)
    signature(library, "acl_set_file", ctypes.c_int,
              ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p)
    signature(library, "acl_get_file", ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)
    acl_text = b"u::rwx,u:65533:r-x,g::---,m::r-x,o::---"
    with (TemporaryDirectory(prefix="pamolive-coreutils-") as directory,
          TemporaryDirectory(prefix="move-", dir=OTHER_FILESYSTEM) as second,
          acl_handle(library, library.acl_from_text(acl_text)) as acl):
        root = Path(directory)
        copy_fixtures(library, root, acl)
        install_fixtures(library, root, acl)
        move_fixtures(library, root, Path(second), acl)

    result = {
        "schema": SCHEMA,
        "version": version,
        "cases": {
            "cp_regular_and_directory_acl": True,
            "cp_parents_and_link_modes": True,
            "cp_mode_only_directory_and_fifo": True,
            "install_over_inherited_acl_and_install_directory": True,
            "mv_rename_and_cross_filesystem_acl": True,
        },
    }
    if mode == "candidate":
        stock = json.loads(Path("/evidence/coreutils-stock.json").read_text(encoding="ascii"))
        require(stock == {**result, "version": VERSIONS["stock"]})
        result.update(consumer_package_receipt("coreutils", version))
        result["binaries"] = {
            name: {
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "descriptor_imports": require_consumer_imports(binary, REQUIRED, LEGACY),
            }
            for name, binary in BINARIES.items()
        }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
