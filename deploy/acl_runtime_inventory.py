"""Inspect the exact candidate's ACL library and direct ELF consumers without executing them."""

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory

from deploy.jansson_image_absence import _hash_stream, _regular_input
from deploy.qualify_image_scan import BoundedTarInfo
from qualification.debian_138_refresh.verify_refresh import controls

VERSION = "2.4.0-1~pamolive13u1"
ELF_SHA256 = "32d112de5fb4ec3124c7a4b859b738b45e4c4a9db3b3115f167625f082909dd1"
SONAME = "libacl.so.1"
LIBRARY = "/usr/lib/x86_64-linux-gnu/libacl.so.1.2.2400"
STATUS = "/var/lib/dpkg/status"
LEGACY = {"acl_delete_def_file", "acl_extended_file", "acl_get_file", "acl_set_file"}
TOOLS = {"getfacl", "setfacl", "chacl"}
SDK_FILES = {"/usr/include/sys/acl.h", "/usr/include/acl/libacl.h"}
EXCLUDED_PACKAGES = {"acl", "libacl1-dev", "acl-udeb", "libacl1-udeb"}
MAX_ARCHIVE = 2 * 1024**3
MAX_ELF = 64 * 1024**2


class InventoryError(ValueError):
    """A refusal with an internally assigned reason."""


def need(condition, code):
    if not condition:
        raise InventoryError(code)


def acl_symbols(text):
    """Match ACL-versioned functions, including default and older symbol versions."""
    imports, exports = set(), set()
    for row in text.splitlines():
        fields = row.split()
        if len(fields) < 8 or not fields[0][:-1].isdigit():
            continue
        if fields[4] not in {"GLOBAL", "WEAK"}:
            continue
        name, separator, version = fields[7].partition("@")
        if not (
            version.lstrip("@").startswith("ACL_1.")
            or name in LEGACY or name.startswith(("acl_", "perm_copy_"))
        ):
            continue
        versioned = name + separator + version.lstrip("@")
        if fields[6] == "UND":
            imports.add(versioned)
        elif fields[5] in {"DEFAULT", "PROTECTED"} and fields[3] in {"FUNC", "IFUNC"}:
            exports.add(versioned)
            if version.startswith("@"):
                exports.add(name)
    return imports, exports


def readelf(data, target):
    target.write_bytes(data)
    return subprocess.check_output(
        ["/usr/bin/readelf", "--wide", "--dynamic", "--dyn-syms", str(target)],
        encoding="ascii", stderr=subprocess.DEVNULL, timeout=10, env={"LC_ALL": "C"},
    )


def inventory(source, data_file):
    library_hash = None
    exports, consumers, paths = set(), {}, set()
    identity, alias = False, None
    with tarfile.open(fileobj=source, mode="r:", tarinfo=BoundedTarInfo) as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            need(
                not path.is_absolute() and ".." not in path.parts
                and "\\" not in member.name and len(member.name) <= 4096,
                "acl_archive_path",
            )
            name = "/" + path.as_posix().lstrip("/")
            need(name not in paths and len(paths) < 100000, "acl_archive_entry")
            paths.add(name)
            need(path.name not in TOOLS, "acl_runtime_tool")
            need(name not in SDK_FILES and path.name != "libacl.so", "acl_runtime_sdk")
            if name == str(PurePosixPath(LIBRARY).with_name(SONAME)):
                need(member.issym(), "acl_soname_type")
                alias = member.linkname
            elif path.name.startswith("libacl.so."):
                need(name == LIBRARY and member.isfile(), "acl_duplicate_library")
            if not member.isfile():
                continue
            with archive.extractfile(member) as entry:
                if name == STATUS:
                    need(member.size <= 8 * 1024**2, "acl_dpkg_budget")
                    packages = list(controls(entry.read()))
                    need(
                        not any(
                            row.get("Package") in EXCLUDED_PACKAGES
                            and row.get("Status") == "install ok installed" for row in packages
                        ),
                        "acl_runtime_package",
                    )
                    packages = [row for row in packages if row.get("Package") == "libacl1"]
                    need(len(packages) == 1, "acl_dpkg_count")
                    row = packages[0]
                    identity = (
                        row.get("Status") == "install ok installed"
                        and row.get("Architecture") == "amd64"
                        and row.get("Source") in ("acl", f"acl ({VERSION})")
                        and row.get("Version") == VERSION
                    )
                    continue
                header = entry.read(4)
                if header != b"\x7fELF":
                    continue
                need(member.size <= MAX_ELF, "acl_elf_budget")
                data = header + entry.read()
                if name == LIBRARY:
                    library_hash = hashlib.sha256(data).hexdigest()
                    text = readelf(data, data_file)
                    need(f"Library soname: [{SONAME}]" in text, "acl_elf_soname")
                    _, exports = acl_symbols(text)
                elif any(
                    mark in data for mark in (b"libacl.so.1\0", b"acl_", b"perm_copy_", b"ACL_1.")
                ):
                    text = readelf(data, data_file)
                    imports, _ = acl_symbols(text)
                    needed = f"Shared library: [{SONAME}]" in text
                    if needed or imports:
                        consumers[name] = {
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "uid": member.uid,
                            "mode": format(member.mode & 0o7777, "04o"),
                            "direct_dependency": needed,
                            "imports": sorted(imports),
                            "legacy_path_imports": sorted(
                                name for name in imports if name.split("@", 1)[0] in LEGACY
                            ),
                        }
    need(identity and library_hash == ELF_SHA256, "acl_package_identity")
    need(alias == PurePosixPath(LIBRARY).name, "acl_soname_link")
    need(exports and consumers and len(consumers) <= 128, "acl_elf_scope")
    need(
        all(set(item["imports"]) <= exports for item in consumers.values()),
        "acl_missing_abi",
    )
    return {
        "schema": "pamolive.acl-runtime-inventory/1",
        "package_version": VERSION,
        "elf_sha256": library_hash,
        "consumers": consumers,
        "utilities_absent": sorted(TOOLS),
        "sdk_absent": True,
        "legacy_api_migrated": False,
    }


def verify(archive, config_id):
    need(re.fullmatch(r"sha256:[a-f0-9]{64}", config_id), "acl_image_config")
    with (
        TemporaryDirectory(prefix="pamolive-acl-inventory-") as temp,
        _regular_input(archive, MAX_ARCHIVE) as stream,
    ):
        initial = _hash_stream(stream, MAX_ARCHIVE)
        stream.seek(0)
        report = inventory(stream, Path(temp) / "entry.elf")
        need(_hash_stream(stream, MAX_ARCHIVE) == initial, "acl_snapshot_changed")
    return {**report, "image_config_id": config_id, "export_sha256": initial}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--image-config-id", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.archive, args.image_config_id), sort_keys=True))
    except InventoryError as exc:
        raise SystemExit(f"ACL runtime inventory refused ({exc}).") from None
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError):
        raise SystemExit("ACL runtime inventory refused.") from None


if __name__ == "__main__":
    main()
