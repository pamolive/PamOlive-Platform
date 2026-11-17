"""Separate v2 candidate gate. Nothing promotes DATA or rewrites legacy v1."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from abi_data import LIBRARIES, bind_old_product_baseline, canonical, compare, digest
from common import read
from policy import MATERIALS, PATCH_PLAN_SHA256
from source_model import PURPOSE, VERSION, json_value, need


def admit(profile, candidate):
    compare(candidate, candidate)  # Strict tuple types/keys, including data-size and visibility.
    need(
        set(profile)
        == {
            "schema",
            "version",
            "purpose",
            "admitted",
            "source_sha256",
            "packaging_sha256",
            "libraries",
            "operational_GO",
            "patch_plan_sha256",
        },
        "v2_profile_fields",
    )
    need(
        profile["schema"] == "pamolive.Root.krb5-runtime-profile/2"
        and profile["version"] == VERSION
        and profile["purpose"] == PURPOSE
        and profile["admitted"] is True
        and profile["operational_GO"] is False,
        "v2_not_admitted",
    )
    need(
        profile["source_sha256"] == MATERIALS["krb5-1.22.3.tar.gz"][1]
        and profile["packaging_sha256"] == MATERIALS["krb5_1.22.1-3.debian.tar.xz"][1],
        "v2_source_binding",
    )
    need(profile["patch_plan_sha256"] == PATCH_PLAN_SHA256, "v2_adaptation_binding")
    need(
        set(profile["libraries"]) == set(candidate["libraries"]) == set(LIBRARIES), "v2_library_set"
    )
    for package, row in candidate["libraries"].items():
        need(
            type(row["exported_symbols"]) is int
            and row["exported_symbols"] == len(row["symbols"])
            and row["abi_sha256"] == digest(canonical(sorted(row["symbols"])).encode()),
            "v2_candidate_ABI_digest",
        )
        expected = profile["libraries"][package]
        need(
            set(expected) == {"soname", "abi_sha256", "exported_symbols", "symbols"},
            "v2_exact_export_profile",
        )
        need(
            canonical(expected) == canonical({key: row[key] for key in expected}),
            "v2_unreviewed_exports",
        )
    return {"profile_v2_admitted": True, "product_build_gate": True, "operational_GO": False}


def admit_build(profile, folder):
    folder = Path(folder)
    before = json_value(read(folder / "ABI-before.json", 4 * 1024**2))
    candidate = json_value(read(folder / "ABI-candidate.json", 4 * 1024**2))
    reported = json_value(read(folder / "ABI-comparison-DATA.json", 4 * 1024**2))
    bind_old_product_baseline(before)
    compared = compare(before, candidate)
    need(canonical(compared) == canonical(reported), "v2_comparison_binding")
    return admit(profile, candidate), before, candidate, compared


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_Root_profile_build_evidence_folder")
    admit_build(json_value(read(Path(sys.argv[1]), 4 * 1024**2)), Path(sys.argv[2]))
