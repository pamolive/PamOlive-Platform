"""Compare the installed Trixie Kerberos exports and exercise the actual SDK."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

CHECKS = Path(__file__).resolve().parent
sys.path.insert(0, str(CHECKS))
from abi_data import capture, compare  # noqa: E402
from verify_refresh import FAMILIES, NATIVE_FILES  # noqa: E402

EVIDENCE = Path("/evidence")
BASELINE, _, _, PACKAGES = FAMILIES["krb5"]
CANDIDATE = BASELINE + "+pamolive1"


def record(name, data):
    with (EVIDENCE / name).open("x", encoding="ascii") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def installed(version):
    template = "${source:Package}|${Version}|${Architecture}|${db:Status-Status}"
    for name in PACKAGES:
        result = subprocess.check_output(["dpkg-query", "-W", "-f=" + template, name], timeout=8)
        if result != f"krb5|{version}|amd64|installed".encode():
            raise ValueError("installed_version_mismatch")
    return capture("/")


def native_smoke():
    binary = EVIDENCE / "sdk-smoke"
    command = [
        "/usr/bin/cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        str(CHECKS / "smoke.c"), "-o", str(binary), "-lkrb5", "-lgssapi_krb5",
    ]
    subprocess.run(command, check=True, timeout=60)
    paths = (*NATIVE_FILES["libc6"], *(NATIVE_FILES[p][0] for p in PACKAGES[:4]))
    result = subprocess.check_output([str(binary), *paths], timeout=10)
    binary.unlink()
    if result != b"debian-138-native-ok\n":
        raise ValueError("sdk_smoke_refused")


def main(args):
    if args == ["stock"]:
        record("stock.json", installed(BASELINE))
        native_smoke()
        return
    if args != ["candidate"]:
        raise ValueError("mode_refused")
    before = json.loads((EVIDENCE / "stock.json").read_bytes())
    after = installed(CANDIDATE)
    abi = compare(before, after)
    if any(abi["candidate_additions"].values()):
        raise ValueError("unexpected_exports_added")
    if (before["libraries"]["libkrb5-3"]["file_sha256"]
            == after["libraries"]["libkrb5-3"]["file_sha256"]):
        raise ValueError("patched_library_unchanged")
    native_smoke()
    record("candidate.json", after)
    record("qualification.json", {
        "schema": "pamolive.krb5-trixie-backport-qualification/1",
        "baseline": BASELINE,
        "candidate": CANDIDATE,
        "abi": abi,
        "sdk_smoke_verified": True,
        "archives": {name: sha(EVIDENCE / (name + ".deb")) for name in PACKAGES},
        "buildinfo_sha256": sha(EVIDENCE / "buildinfo"),
        "skipped_tests": (EVIDENCE / "skipped-tests.txt").read_text().splitlines(),
    })


if __name__ == "__main__":
    main(sys.argv[1:])
