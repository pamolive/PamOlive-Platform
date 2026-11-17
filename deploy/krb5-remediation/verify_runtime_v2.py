"""Closed v2 runtime hook prepared for later Root-admitted product integration."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from abi_data import LIBRARIES, capture
from common import command, read, record
from profile_v2 import admit_build
from source_model import VERSION, json_value, need, sha


def main(profile, build_evidence, output):
    profile, build_evidence, output = Path(profile), Path(build_evidence), Path(output)
    output.mkdir(mode=0o700)
    raw = read(profile, 4 * 1024**2)
    decision, before, candidate, compared = admit_build(json_value(raw), build_evidence)
    actual = capture(Path("/"))
    need(actual == candidate, "runtime_provider_bytes_not_same_build")
    versions = command(
        [
            "/usr/bin/dpkg-query",
            "--show",
            "--showformat=${Package}\t${Version}\n",
            *sorted(LIBRARIES),
        ],
        output,
        output / "packages",
    )
    need(
        sorted(versions.decode().splitlines()) == [p + "\t" + VERSION for p in sorted(LIBRARIES)],
        "runtime_version",
    )
    record(
        output / "RUNTIME-v2.json",
        {
            "schema": "pamolive.krb5-runtime-verification/2",
            "version": VERSION,
            "verified": True,
            "compilation_attestation": False,
            "profile_sha256": sha(raw),
            "Root_profile": json_value(raw),
            "candidate_ABI": candidate,
            "active_ABI": actual,
            "decision": decision,
            "old_ABI": before,
            "old_ABI_comparison": compared,
            "old_ABI_exports_preserved": True,
            "product_scan_qualification": False,
            "operational_GO": False,
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 4, "usage_profile_build_evidence_new_output")
    main(*sys.argv[1:])
