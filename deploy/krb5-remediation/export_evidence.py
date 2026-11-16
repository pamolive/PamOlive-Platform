"""Copy a finite public receipt/log allowlist, never source/ELF/key-home trees."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import read, record, write_new
from source_model import json_value, need, sha

LEAVES = ("intent.json", "pid.json", "result.json", "unknown.json", "stdout", "stderr")
BUILD_JSON = (
    "ABI-before.json",
    "ABI-candidate.json",
    "ABI-comparison-DATA.json",
    "BUILD-DATA.json",
    "ASN1-six-cases.json",
)
LOGS = (
    "baseline-packages",
    "keyring-probe",
    "dpkg-buildpackage",
    "ASN1-six-cases",
    "authentication/archive/archive-verify",
    "authentication/mit-import",
    "authentication/mit-keys",
    "authentication/mit-verify",
    *[f"patch-{i:02d}" for i in range(1, 12)],
    "unpack-libkrb5-3",
    "unpack-libk5crypto3",
    "unpack-libkrb5support0",
    "unpack-libgssapi-krb5-2",
    "TLS-hostname/compile",
    "TLS-hostname/run",
)


def main(build, target, consumer=False):
    build, target = Path(build), Path(target)
    target.mkdir(mode=0o700)
    rows, total = [], 0
    incomplete = False
    qualification_raw = None
    if consumer:
        qualification_raw = read(build / "QUALIFICATION-DATA.json", 4 * 1024**2)
        qualification = json_value(qualification_raw)
        need(
            qualification["status"]
            in {
                "CANDIDATE_MEASUREMENT_COMPLETE",
                "ABI_PRECONDITION_REFUSED",
                "MEASUREMENT_FAILED_OR_UNKNOWN",
            },
            "consumer_status",
        )
        incomplete = qualification["status"] != "CANDIDATE_MEASUREMENT_COMPLETE"

    def copied(source, name, cap, captured=None):
        nonlocal total
        raw = read(source, cap) if captured is None else captured
        need(len(raw) <= cap, "public_evidence_file_cap")
        total += len(raw)
        need(total <= 128 * 1024**2, "public_evidence_total_cap")
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(path, raw, 0o444)
        rows.append({"name": name, "bytes": len(raw), "sha256": sha(raw)})

    for name in (
        ("QUALIFICATION-DATA.json", "consumer/CONSUMER-DATA.json") if consumer else BUILD_JSON
    ):
        if (
            consumer
            and incomplete
            and name == "consumer/CONSUMER-DATA.json"
            and not (build / name).exists()
            and not (build / name).is_symlink()
        ):
            continue
        copied(
            build / name,
            name,
            4 * 1024**2,
            qualification_raw if name == "QUALIFICATION-DATA.json" else None,
        )
    if not consumer:
        copied(build / "work/authentication/AUTHENTICATED.json", "AUTHENTICATED.json", 256 * 1024)
        copied(build / "work/TLS-hostname/TLS-HOSTNAME-DATA.json", "TLS-HOSTNAME-DATA.json", 65536)
    logs = (
        (
            "installed-packages",
            "compile-GSS-consumer",
            "GSS-consumer-worker",
            "install-candidate",
            "consumer/mechanisms",
            "consumer/silent-kdc",
        )
        if consumer
        else LOGS
    )
    for log in logs:
        folder = (build if consumer else build / "work") / log
        if incomplete and not folder.exists() and not folder.is_symlink():
            continue
        for leaf in LEAVES:
            source = folder / leaf
            if leaf == "unknown.json" and not source.exists() and not source.is_symlink():
                continue
            if incomplete and not source.exists() and not source.is_symlink():
                continue
            copied(
                source,
                "logs/" + log + "/" + leaf,
                8 * 1024**2 if leaf in {"stdout", "stderr"} else 65536,
            )
    record(
        target / "PUBLIC-FILES.json",
        {
            "schema": "pamolive.krb5-public-files/1",
            "files": rows,
            "total_bytes": total,
            "source_ELF_deb_keyhome_exported": False,
            "operational_GO": False,
        },
    )


if __name__ == "__main__":
    need(
        len(sys.argv) in {3, 4} and (len(sys.argv) == 3 or sys.argv[3] == "--consumer"),
        "usage_build_new_public_out_optional_consumer",
    )
    main(*sys.argv[1:3], consumer=len(sys.argv) == 4)
