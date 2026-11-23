"""Inspect the exported root filesystem's Cairo package and direct ELF references."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import time
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory, TemporaryFile

from deploy.jansson_image_absence import _hash_stream, _regular_input
from deploy.qualify_image_scan import BoundedTarInfo
from qualification.debian_138_refresh.verify_refresh import controls

SCHEMA = "pamolive.cairo-runtime-inventory/1"
VERSION = "1.18.4-1+pamolive13u1"
SONAME = "libcairo.so.2"
LIBRARY = PurePosixPath("/usr/lib/x86_64-linux-gnu/libcairo.so.2.11804.4")
ALIAS = LIBRARY.with_name(SONAME)
STATUS = PurePosixPath("/var/lib/dpkg/status")
X_PREFIXES = (
    "libice6",
    "libice-dev",
    "libsm6",
    "libsm-dev",
    "libx11",
    "libxau",
    "libxaw",
    "libxcb",
    "libxcomposite",
    "libxcursor",
    "libxdamage",
    "libxdmcp",
    "libxext",
    "libxfixes",
    "libxfont",
    "libxft",
    "libxinerama",
    "libxkbcommon-x11",
    "libxkbfile",
    "libxmu",
    "libxpm",
    "libxpresent",
    "libxrandr",
    "libxrender",
    "libxres",
    "libxshmfence",
    "libxss",
    "libxtst",
    "libxvmc",
    "libxxf86",
    "x11-",
    "xserver-",
)
X_DIRECTORIES = ("/usr/include/X11", "/usr/include/xcb", "/usr/share/X11")
SDK_DIRECTORIES = ("/usr/include/cairo", "/usr/local/include/cairo")
X_IMPORT_PREFIXES = ("cairo_xlib_", "cairo_xcb_")
ELF_MARKERS = (
    b"libX",
    b"libxcb",
    b"libICE.",
    b"libSM.",
    SONAME.encode("ascii"),
    b"cairo_xlib_",
    b"cairo_xcb_",
)
MAX_ARCHIVE = 2 * 1024**3
MAX_ELF = 64 * 1024**2
MAX_DPKG = 8 * 1024**2
MAX_ENTRIES = 100_000
MAX_ELFS = 8192
MAX_PROBES = 512
MAX_CONSUMERS = 128
MAX_READELF = 16 * 1024**2
MAX_INVENTORY_SECONDS = 70

# Limit readelf's output before it can consume unbounded disk or memory.
READELF = """
import os, resource, sys
soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
limit = min([int(sys.argv[1])] + [value for value in (soft, hard) if value >= 0])
resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
tool = '/usr/bin/readelf'
os.execv(tool, [tool, '--wide', '--dynamic', '--dyn-syms', sys.argv[2]])
"""


class InventoryError(ValueError):
    """A bounded failure code for an archive that did not pass the inventory."""


def require(condition, code):
    if not condition:
        raise InventoryError(code)


def x_library_name(name):
    return name.startswith(("libX", "libxcb", "libICE.", "libSM."))


def x_package(name):
    return (
        name.startswith(X_PREFIXES)
        or name in {"xauth", "xwayland"}
        or bool(re.match(r"libx(?:i|t|v)(?:[0-9]|-)", name))
    )


def check_path_policy(path):
    leaf = path.name
    require(
        not (x_library_name(leaf) and re.search(r"\.(?:so(?:\.|$)|a$|la$)", leaf))
        and not any(path.is_relative_to(root) for root in X_DIRECTORIES),
        "cairo_x_runtime_file",
    )
    require(
        not any(path.is_relative_to(root) for root in SDK_DIRECTORIES)
        and not re.fullmatch(r"cairo(?:[-_][A-Za-z0-9_-]+)?\.(?:h|pc)", leaf)
        and not re.fullmatch(r"libcairo(?:[-_][A-Za-z0-9_-]+)?\.(?:a|la|so)", leaf),
        "cairo_sdk_file",
    )


def check_packages(data):
    rows = controls(data)
    require(
        not any(
            row.get("Status", "").endswith(" installed")
            and (
                x_package(row.get("Package", ""))
                or re.fullmatch(r"libcairo[a-z0-9-]*-dev", row.get("Package", ""))
            )
            for row in rows
        ),
        "cairo_excluded_package",
    )
    cairo = [row for row in rows if row.get("Package") == "libcairo2"]
    require(len(cairo) == 1, "cairo_package_count")
    row = cairo[0]
    require(
        row.get("Status") == "install ok installed"
        and row.get("Architecture") == "amd64"
        and row.get("Source") in ("cairo", f"cairo ({VERSION})")
        and row.get("Version") == VERSION,
        "cairo_package_identity",
    )


def readelf(data, target, timeout):
    target.write_bytes(data)
    with TemporaryFile(dir=target.parent) as output:
        subprocess.run(
            [sys.executable, "-I", "-B", "-S", "-c", READELF, str(MAX_READELF), str(target)],
            stdout=output,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=True,
            env={"LC_ALL": "C"},
        )
        output.seek(0)
        raw = output.read(MAX_READELF)
    require(len(raw) < MAX_READELF, "cairo_readelf_output_budget")
    return raw.decode("ascii")


def elf_references(text):
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^][]+)\]", text)
    require(len(needed) == text.count("(NEEDED)") and len(needed) <= 128, "cairo_elf_needed")
    sonames = re.findall(r"\(SONAME\)\s+Library soname: \[([^][]+)\]", text)
    require(len(sonames) == text.count("(SONAME)") and len(sonames) <= 1, "cairo_elf_soname_table")
    require(
        not any(x_library_name(name.rsplit("/", 1)[-1]) for name in sonames),
        "cairo_x_elf_provider",
    )
    require(
        not any(x_library_name(name.rsplit("/", 1)[-1]) for name in needed),
        "cairo_x_elf_dependency",
    )
    for row in text.splitlines():
        fields = row.split()
        if len(fields) >= 8 and fields[0][:-1].isdigit() and fields[6] == "UND":
            require(not fields[7].startswith(X_IMPORT_PREFIXES), "cairo_x_elf_import")
    return set(needed)


def remaining(deadline):
    seconds = deadline - time.monotonic()
    require(seconds > 0, "cairo_inventory_timeout")
    return seconds


def inventory(source, data_file, expected_sha):
    paths, consumers = set(), {}
    identity = alias = False
    elf_count = probe_count = 0
    library = None
    deadline = time.monotonic() + MAX_INVENTORY_SECONDS
    with tarfile.open(fileobj=source, mode="r:", tarinfo=BoundedTarInfo) as archive:
        for member in archive:
            remaining(deadline)
            path = PurePosixPath(member.name)
            require(
                0 < len(member.name) <= 4096
                and "\\" not in member.name
                and not path.is_absolute()
                and ".." not in path.parts
                and 0 <= member.size <= MAX_ARCHIVE,
                "cairo_archive_path",
            )
            path = PurePosixPath("/") / path
            require(path not in paths and len(paths) < MAX_ENTRIES, "cairo_archive_entry")
            paths.add(path)
            check_path_policy(path)

            if path == ALIAS:
                require(member.issym() and member.linkname == LIBRARY.name, "cairo_soname_link")
                alias = True
            elif path.name.startswith(SONAME + ".") or path.name == SONAME:
                require(
                    path == LIBRARY
                    and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    and member.uid == 0
                    and not member.mode & 0o022,
                    "cairo_elf_path",
                )
            if path == STATUS:
                require(member.isfile() and 0 < member.size <= MAX_DPKG, "cairo_dpkg_budget")
                with archive.extractfile(member) as entry:
                    check_packages(entry.read())
                identity = True
                continue
            if not member.isfile():
                continue

            with archive.extractfile(member) as entry:
                header = entry.read(4)
                if header != b"\x7fELF":
                    require(path != LIBRARY, "cairo_elf_magic")
                    continue
                elf_count += 1
                require(elf_count <= MAX_ELFS and member.size <= MAX_ELF, "cairo_elf_budget")
                data = header + entry.read()
            if path != LIBRARY and not any(marker in data for marker in ELF_MARKERS):
                continue

            probe_count += 1
            require(probe_count <= MAX_PROBES, "cairo_elf_probe_budget")
            text = readelf(data, data_file, min(10, remaining(deadline)))
            needed = elf_references(text)
            if path == LIBRARY:
                require(data[:6] == b"\x7fELF\x02\x01" and data[18:20] == b">\0", "cairo_elf_arch")
                require(f"Library soname: [{SONAME}]" in text, "cairo_elf_soname")
                digest = hashlib.sha256(data).hexdigest()
                require(digest == expected_sha, "cairo_elf_sha256")
                library = {"mode": format(member.mode & 0o7777, "04o"), "uid": member.uid}
            elif SONAME in needed:
                require(len(consumers) < MAX_CONSUMERS, "cairo_consumer_budget")
                consumers[str(path)] = {
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "mode": format(member.mode & 0o7777, "04o"),
                    "uid": member.uid,
                }

    require(identity and alias and library is not None, "cairo_runtime_identity")
    require(consumers, "cairo_consumers_missing")
    return {
        "schema": SCHEMA,
        "verified": True,
        "package_version": VERSION,
        "elf_path": str(LIBRARY),
        "elf_sha256": expected_sha,
        "elf_metadata": library,
        "elf_files_checked": elf_count,
        "elf_files_parsed": probe_count,
        "consumers": consumers,
        "x_runtime_absent": True,
        "sdk_absent": True,
        "scope": "Exported entries, dpkg status, DT_NEEDED and undefined Cairo X backend symbols.",
    }


def verify(archive, config_id, elf_sha256):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", config_id), "cairo_image_config")
    require(re.fullmatch(r"[0-9a-f]{64}", elf_sha256), "cairo_elf_digest_argument")
    with (
        TemporaryDirectory(prefix="pamolive-cairo-inventory-") as temp,
        _regular_input(archive, MAX_ARCHIVE) as stream,
    ):
        initial = _hash_stream(stream, MAX_ARCHIVE)
        stream.seek(0)
        report = inventory(stream, Path(temp) / "entry.elf", elf_sha256)
        require(_hash_stream(stream, MAX_ARCHIVE) == initial, "cairo_snapshot_changed")
    return {**report, "image_config_id": config_id, "export_sha256": initial}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--image-config-id", required=True)
    parser.add_argument("--elf-sha256", required=True)
    args = parser.parse_args()
    try:
        report = verify(args.archive, args.image_config_id, args.elf_sha256)
    except InventoryError as exc:
        raise SystemExit(f"Cairo runtime inventory refused ({exc}).") from None
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError):
        raise SystemExit("Cairo runtime inventory refused.") from None
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
