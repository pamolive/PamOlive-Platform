"""Fail the CI gate AFTER the bounded public DATA TAR has been preserved."""

import io
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import read
from source_model import json_value, need, safe_name


def gate(source, consumer):
    need(
        source.get("schema") == "pamolive.krb5-upgrade-build-DATA/1"
        and source.get("authentication", {}).get("both_source_chains_authenticated") is True
        and source.get("ABI_comparison", {}).get("all_old_exports_preserved") is True
        and source.get("tests_enabled") is True
        and source.get("candidate_profile_v2_admitted") is False
        and source.get("product_admission") is False
        and source.get("operational_GO") is False,
        "source_or_ABI_gate_failed",
    )
    need(
        consumer.get("schema") == "pamolive.krb5-candidate-DATA/1"
        and consumer.get("status") == "CANDIDATE_MEASUREMENT_COMPLETE"
        and consumer.get("runtime_SDK_same_build") is True
        and consumer.get("product_profile_v2_admitted") is False
        and consumer.get("operational_GO") is False,
        "consumer_gate_failed_or_unknown",
    )


def main(path):
    path = Path(path)
    raw_archive = read(path, 256 * 1024**2)
    with tarfile.open(fileobj=io.BytesIO(raw_archive), mode="r:") as archive:
        members = {}
        for i, info in enumerate(archive):
            need(i < 1024 and info.name not in members, "DATA_archive_count_duplicates")
            name = safe_name(info.name.rstrip("/") if info.isdir() else info.name)
            need(info.isdir() or info.isreg(), "DATA_archive_link_or_special")
            need(
                name.split("/", 1)[0] in {"source-build", "candidate-consumer"},
                "DATA_archive_scope",
            )
            members[info.name] = info
        values = []
        for name in ("source-build/BUILD-DATA.json", "candidate-consumer/QUALIFICATION-DATA.json"):
            info = members[name]
            need(info.isreg() and 0 <= info.size <= 4 * 1024**2, "DATA_report_type_cap")
            stream = archive.extractfile(info)
            need(stream is not None, "DATA_report_missing")
            raw = stream.read(info.size + 1)
            need(len(raw) == info.size, "DATA_report_bytes")
            values.append(json_value(raw))
    gate(*values)


if __name__ == "__main__":
    need(len(sys.argv) == 2, "usage_preserved_DATA_tar")
    main(sys.argv[1])
