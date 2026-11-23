"""Prepare the bounded tar ACL migration on the exact Debian source."""

import hashlib
import re
import subprocess
import sys
from pathlib import Path

SOURCE_VERSION = "1.35+dfsg-3.1"
VERSION = SOURCE_VERSION + "+pamolive1"
PATCH = "tar-descriptor.patch"


def check(root, manifest):
    rows = manifest.read_text(encoding="ascii").splitlines()
    if not 0 < len(rows) <= 6 or len(rows) != len(set(rows)):
        raise ValueError("tar_acl_materials")
    for line in rows:
        digest, separator, name = line.partition("  ")
        if (
            separator != "  " or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not re.fullmatch(r"(?:src/)?[A-Za-z0-9_.+-]{1,96}", name)
            or name.rsplit("/", 1)[-1] in {".", ".."}
        ):
            raise ValueError("tar_acl_materials")
        with (root / name).open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("tar_acl_source_identity")


def prepare(root, inputs):
    check(inputs, inputs / "tar-patch.sha256")
    check(root, inputs / "tar-preimage.sha256")
    changelog = root / "debian/changelog"
    original = changelog.read_bytes()
    if not original.startswith(f"tar ({SOURCE_VERSION}) ".encode("ascii")):
        raise ValueError("tar_debian_version")
    patches = root / "debian/patches"
    with (patches / PATCH).open("xb") as stream:
        stream.write((inputs / PATCH).read_bytes())
    with (patches / "series").open("ab") as stream:
        stream.write(PATCH.encode("ascii") + b"\n")
    subprocess.run(
        ["quilt", "push"], cwd=root, check=True, timeout=15,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "QUILT_PATCHES": "debian/patches",
             "QUILT_PATCH_OPTS": "--fuzz=0"},
    )
    check(root, inputs / "tar-postimage.sha256")
    prefix = (
        f"tar ({VERSION}) trixie; urgency=medium\n\n"
        "  * Use bound file descriptors for Linux POSIX ACL metadata.\n\n"
        " -- PamOlive Build <pamolive-automation@users.noreply.github.com>"
        "  Mon, 23 Nov 2026 00:00:00 +0000\n\n"
    ).encode("ascii")
    changelog.write_bytes(prefix + original)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(42)
    prepare(Path(sys.argv[1]), Path(sys.argv[2]))
