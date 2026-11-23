"""Verify the runtime archives and paths attributed to the qualified glibc build."""

import argparse
import hashlib
import json
from pathlib import Path

from deploy.native_package_materials import verify_archives

PATH = "/usr/share/pamolive/glibc-trixie/qualification.json"
SHA256 = "17ff8e809479ab52179588a33d037a6f79f76b4ad0ec1357155910c5a908883a"
VERSION = "2.41-12+deb13u5+pamolive1"
RUNTIME_PACKAGES = ("libc6", "libc-bin")
LIB = "/usr/lib/x86_64-linux-gnu/"
LIBC = LIB + "libc.so.6"
LOADER = LIB + "ld-linux-x86-64.so.2"
ALIASES = {"/usr/lib64/ld-linux-x86-64.so.2": "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}
ELF_BY_PACKAGE = {
    "libc6": (LIBC, LOADER, LIB + "libresolv.so.2"),
    "libc-bin": (
        "/usr/bin/getconf", "/usr/bin/getent", "/usr/bin/iconv", "/usr/bin/locale",
        "/usr/bin/localedef", "/usr/bin/pldd", "/usr/bin/zdump",
        "/usr/sbin/iconvconfig", "/usr/sbin/ldconfig", "/usr/sbin/zic",
    ),
}
REVIEWED = Path(__file__).resolve().with_name("glibc-trixie-backport") / "qualification.json"
MAX_RECEIPT = 16 * 1024


def parse(raw):
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_RECEIPT
        or hashlib.sha256(raw).hexdigest() != SHA256
    ):
        raise ValueError("unreviewed_glibc_materials")
    return json.loads(raw)


def load_reviewed():
    with REVIEWED.open("rb") as stream:
        return parse(stream.read(MAX_RECEIPT + 1))


def verify_live_mapping():
    expected = {LIBC.encode("ascii"), LOADER.encode("ascii")}
    names = {path.rsplit(b"/", 1)[-1] for path in expected}
    with Path("/proc/self/maps").open("rb") as stream:
        raw = stream.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise ValueError("glibc_process_maps_budget")
    paths = set()
    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[5].split()[0].rsplit(b"/", 1)[-1] in names:
            paths.add(fields[5])
    if paths != expected:
        raise ValueError("glibc_process_mapping")


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify_archives(
            args.directory, VERSION, RUNTIME_PACKAGES, load_reviewed()["packages"], scope="glibc"
        )
    except (ValueError, OSError):
        parser.exit(1, "Qualified glibc runtime packages refused.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
