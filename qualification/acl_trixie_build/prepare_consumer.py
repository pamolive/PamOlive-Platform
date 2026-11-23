"""Apply a descriptor ACL migration to an exact Debian source package."""

import hashlib
import re
import subprocess
import sys
from pathlib import Path

SOURCE_VERSIONS = {"coreutils": "9.7-3", "sed": "4.9-2+deb13u1", "tar": "1.35+dfsg-3.1"}


def check(root, manifest):
    rows = manifest.read_text(encoding="ascii").splitlines()
    if not 0 < len(rows) <= 6 or len(rows) != len(set(rows)):
        raise ValueError("acl_consumer_materials")
    for line in rows:
        digest, separator, name = line.partition("  ")
        if (
            separator != "  " or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not re.fullmatch(r"(?:(?:lib|src|sed)/)?[A-Za-z0-9_.+-]{1,96}", name)
            or name.rsplit("/", 1)[-1] in {".", ".."}
        ):
            raise ValueError("acl_consumer_materials")
        with (root / name).open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("acl_consumer_source_identity")


def prepare(package, root, inputs):
    source_version = SOURCE_VERSIONS[package]
    version = source_version + "+pamolive1"
    patch_name = f"{package}-descriptor.patch"
    check(inputs, inputs / f"{package}-patch.sha256")
    check(root, inputs / f"{package}-preimage.sha256")
    changelog = root / "debian/changelog"
    original = changelog.read_bytes()
    if not original.startswith(f"{package} ({source_version}) ".encode("ascii")):
        raise ValueError("acl_consumer_debian_version")
    patches = root / "debian/patches"
    with (patches / patch_name).open("xb") as stream:
        stream.write((inputs / patch_name).read_bytes())
    with (patches / "series").open("ab") as stream:
        stream.write(patch_name.encode("ascii") + b"\n")
    subprocess.run(
        ["quilt", "push"], cwd=root, check=True, timeout=15,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "QUILT_PATCHES": "debian/patches",
             "QUILT_PATCH_OPTS": "--fuzz=0"},
    )
    check(root, inputs / f"{package}-postimage.sha256")
    prefix = (
        f"{package} ({version}) trixie; urgency=medium\n\n"
        "  * Use bound file descriptors for Linux POSIX ACL metadata.\n\n"
        " -- PamOlive Build <pamolive-automation@users.noreply.github.com>"
        "  Mon, 23 Nov 2026 00:00:00 +0000\n\n"
    ).encode("ascii")
    changelog.write_bytes(prefix + original)


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in SOURCE_VERSIONS:
        raise SystemExit(42)
    prepare(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))
