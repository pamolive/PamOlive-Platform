"""Mark the Trixie rebuild without changing upstream source or package rules."""

import sys
from pathlib import Path

SOURCE = "2.4.0-1"
REBUILD = f"{SOURCE}~pamolive13u1"


def adapt(changelog):
    original = changelog.read_bytes()
    if not original.startswith(f"acl ({SOURCE}) ".encode("ascii")):
        raise ValueError("acl_debian_version")
    prefix = (
        f"acl ({REBUILD}) trixie; urgency=medium\n\n"
        "  * Qualify the unmodified Debian source with the Trixie toolchain.\n\n"
        " -- PamOlive Build <pamolive-automation@users.noreply.github.com>"
        "  Mon, 23 Nov 2026 00:00:00 +0000\n\n"
    ).encode("ascii")
    changelog.write_bytes(prefix + original)


if __name__ == "__main__":
    adapt(Path(sys.argv[1]) / "debian/changelog")
