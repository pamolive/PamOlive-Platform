"""Bind compatible ACL qualification results to the actual Debian build output."""

import hashlib
import json
import re
import sys
from pathlib import Path

OLD = "2.3.2-2+b1"
NEW = "2.4.0-1~pamolive13u1"
PACKAGE = f"libacl1_{NEW}_amd64.deb"
NEW_API = {
    "acl_delete_def_file_at",
    "acl_extended_file_at",
    "acl_get_file_at",
    "acl_set_file_at",
}
REPORT_FIELDS = {
    "version", "elf_sha256", "exports", "loaded", "tar_acl_roundtrip", "descriptor_acl_roundtrip",
}


def need(condition):
    if not condition:
        raise ValueError("acl_qualification_refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def payload(directory, name, cap):
    path = directory / name
    need(path.is_file() and not path.is_symlink())
    with path.open("rb") as stream:
        raw = stream.read(cap + 1)
    need(0 < len(raw) <= cap)
    return raw


def native(raw, version, expected_descriptor):
    value = json.loads(raw)
    need(set(value) == REPORT_FIELDS and value["version"] == version)
    need(value["loaded"] is True and value["tar_acl_roundtrip"] is True)
    need(value["descriptor_acl_roundtrip"] is expected_descriptor)
    need(re.fullmatch(r"[a-f0-9]{64}", value["elf_sha256"]))
    exports = value["exports"]
    need(type(exports) is list and 0 < len(exports) <= 128 and exports == sorted(set(exports)))
    need(all(
        re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,95}@{1,2}ACL_1\.[0-9]+", name)
        for name in exports
    ))
    return value


def compare(directory):
    baseline = native(payload(directory, "baseline.json", 16384), OLD, None)
    candidate = native(payload(directory, "candidate.json", 16384), NEW, True)
    old = set(baseline["exports"])
    new = set(candidate["exports"])
    need(old < new and baseline["elf_sha256"] != candidate["elf_sha256"])
    need(NEW_API <= {
        symbol.split("@", 1)[0] for symbol in new - old if symbol.endswith("@ACL_1.3")
    })

    buildinfo = payload(directory, "buildinfo", 65536)
    package = payload(directory, "libacl1.deb", 256 * 1024)
    record = f"{sha(package)} {len(package)} {PACKAGE}".encode("ascii").split()
    checksums = buildinfo.split(b"\nChecksums-Sha256:\n", 1)
    need(len(checksums) == 2)
    checksum_rows = checksums[1].split(b"\n\n", 1)[0].splitlines()
    need(sum(line.split() == record for line in checksum_rows) == 1)
    return {
        "schema": "pamolive.acl-trixie-qualification/1",
        "architecture": "amd64",
        "package_version": NEW,
        "package_sha256": sha(package),
        "buildinfo_sha256": sha(buildinfo),
        "elf_sha256": candidate["elf_sha256"],
        "legacy_exports_preserved": len(old),
        "candidate_exports": len(new),
        "tar_acl_roundtrip": True,
        "descriptor_acl_roundtrip": True,
    }


if __name__ == "__main__":
    try:
        print(json.dumps(compare(Path(sys.argv[1])), sort_keys=True))
    except (IndexError, KeyError, OSError, TypeError, ValueError):
        raise SystemExit("ACL package qualification refused.") from None
