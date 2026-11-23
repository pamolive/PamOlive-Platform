"""Capture exact public OpenSSL patches and project their production sources."""

import hashlib
import re
import subprocess
import sys
from pathlib import Path

INPUTS = Path(__file__).resolve().parent
LIMIT = 128 * 1024
PRODUCTION_PATH = rb"(?:crypto|ssl|include|providers)/(?:[A-Za-z0-9_]+/)*[A-Za-z0-9_]+\.[ch]"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def plan():
    text = (INPUTS / "patches.txt").read_text(encoding="ascii").splitlines()
    expected = r"[0-9]{5,6} [0-9a-f]{40}( [0-9a-f]{64}){2}"
    if len(text) != 7 or any(not re.fullmatch(expected, line) for line in text):
        raise ValueError("invalid_patch_plan")
    rows = [line.split() for line in text]
    if len({row[0] for row in rows}) != len(rows):
        raise ValueError("duplicate_advisory")
    return rows


def capture():
    for cve, commit, expected, _ in plan():
        target = Path(f"upstream-{cve}.patch")
        if target.exists():
            raise ValueError("patch_destination_exists")
        subprocess.run([
            "curl", "--proto", "=https", "--tlsv1.2", "--fail", "--silent", "--show-error",
            "--max-time", "45", "--max-filesize", str(LIMIT), "--output", str(target),
            f"https://github.com/openssl/openssl/commit/{commit}.patch",
        ], check=True, timeout=50)
        if sha(target.read_bytes()) != expected:
            raise ValueError("upstream_patch_digest_mismatch")


def projection(raw):
    sections = re.split(rb"(?m)(?=^diff --git a/)", raw)[1:]
    production = []
    for section in sections:
        location = re.match(rb"diff --git a/(\S+) b/(\S+)\n", section)
        if location is None or location[1] != location[2]:
            raise ValueError("patch_path_mismatch")
        path = location[1]
        if path.startswith((b"test/", b"doc/")):
            continue
        if not re.fullmatch(PRODUCTION_PATH, path):
            raise ValueError("patch_path_outside_reviewed_source")
        production.append(section.split(b"\n-- \n", 1)[0].rstrip(b"\n") + b"\n")
    if not production:
        raise ValueError("patch_has_no_production_delta")
    return b"".join(production)


def prepare():
    directory = Path("debian/patches")
    for cve, _, expected, projected in plan():
        with Path(f"/work/upstream-{cve}.patch").open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        if not 0 < len(raw) <= LIMIT or sha(raw) != expected:
            raise ValueError("upstream_patch_digest_mismatch")
        patch = projection(raw)
        if sha(patch) != projected:
            raise ValueError("projected_patch_digest_mismatch")
        name = f"pamolive-CVE-2026-{cve}.patch"
        with (directory / name).open("xb") as stream:
            stream.write(patch)
        with (directory / "series").open("ab") as stream:
            stream.write(name.encode("ascii") + b"\n")


if __name__ == "__main__":
    if sys.argv[1:] == ["acquire"]:
        capture()
    elif sys.argv[1:] == ["prepare"]:
        prepare()
    else:
        raise SystemExit("invalid_patch_request")
