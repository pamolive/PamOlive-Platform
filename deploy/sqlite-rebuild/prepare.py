"""Adapt exactly the secondary Tcl toolchain pin to Debian Trixie."""

import re
import sys
from pathlib import Path

SOURCE_VERSION = "3.54.1-2"
VERSION = f"{SOURCE_VERSION}~pamolive13u1"


def tune(root):
    control = root / "debian/control"
    rules = root / "debian/rules"
    files = {
        control: (rb"(?m)^(Build-Depends: [^\r\n]*\b)tcl9\.1-dev,", rb"\g<1>tcl9.0-dev,"),
        rules: (rb"(?m)^(TCLV_SECONDARY = )9\.1$", rb"\g<1>9.0"),
    }
    updated = {}
    for path, (pattern, replacement) in files.items():
        current = path.read_bytes()
        result, count = re.subn(pattern, replacement, current)
        if count != 1:
            raise ValueError("sqlite_debian_preimage")
        updated[path] = result
    changelog = root / "debian/changelog"
    original = changelog.read_bytes()
    if not original.startswith(f"sqlite3 ({SOURCE_VERSION}) ".encode("ascii")):
        raise ValueError("sqlite_debian_version")
    prefix = (
        f"sqlite3 ({VERSION}) trixie; urgency=medium\n\n"
        "  * Rebuild unchanged SQLite sources with Trixie's Tcl 9.0 SDK.\n\n"
        " -- PamOlive Build <pamolive-automation@users.noreply.github.com>"
        "  Mon, 23 Nov 2026 00:00:00 +0000\n\n"
    ).encode("ascii")
    updated[changelog] = prefix + original
    for path, contents in updated.items():
        path.write_bytes(contents)


if __name__ == "__main__":
    tune(Path(sys.argv[1]))
