"""Separate v2 CycloneDX DATA; no scanner result, VEX, suppression or WOT claim."""

import argparse
import hashlib
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from abi_data import LIBRARIES
from common import read, record
from policy import MATERIALS
from profile_v2 import admit
from source_model import VERSION, json_value, need

from deploy import native_sbom as standard

PREFIX = "urn:pamolive:krb5-upgrade-v2:"


def export(report, image_id, report_sha256):
    need(
        report.get("schema") == "pamolive.krb5-runtime-verification/2"
        and report.get("verified") is True
        and report.get("compilation_attestation") is False
        and report.get("version") == VERSION
        and report.get("old_ABI_exports_preserved") is True
        and report.get("active_ABI") == report.get("candidate_ABI"),
        "v2_runtime_report",
    )
    admit(report["Root_profile"], report["active_ABI"])
    need(
        re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
        and re.fullmatch(r"[0-9a-f]{64}", report_sha256),
        "v2_SBOM_binding",
    )
    source = PREFIX + "source:1.22.3"
    packaging = PREFIX + "packaging:1.22.1-3"
    components = [
        {
            "type": "library",
            "bom-ref": source,
            "name": "mit-krb5",
            "version": "1.22.3",
            "purl": "pkg:generic/mit-krb5@1.22.3",
            "hashes": [{"alg": "SHA-256", "content": MATERIALS["krb5-1.22.3.tar.gz"][1]}],
        },
        {
            "type": "data",
            "bom-ref": packaging,
            "name": "krb5-Debian-packaging",
            "version": "1.22.1-3",
            "hashes": [{"alg": "SHA-256", "content": MATERIALS["krb5_1.22.1-3.debian.tar.xz"][1]}],
        },
    ]
    dependencies = [{"ref": source, "dependsOn": []}, {"ref": packaging, "dependsOn": [source]}]
    for package in sorted(LIBRARIES):
        row = report["active_ABI"]["libraries"][package]
        ref = PREFIX + package + ":" + VERSION
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": package,
                "version": VERSION,
                "purl": "pkg:deb/debian/"
                + package
                + "@"
                + quote(VERSION, safe="")
                + "?arch=amd64&distro=debian-13",
                "hashes": [{"alg": "SHA-256", "content": row["file_sha256"]}],
                "properties": [
                    {"name": "pamolive:hash-scope", "value": "active shared-library bytes"},
                    {"name": "pamolive:abi-sha256", "value": row["abi_sha256"]},
                ],
            }
        )
        dependencies.append({"ref": ref, "dependsOn": [source, packaging]})
    value = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, image_id + report_sha256)),
        "metadata": {
            "properties": [
                {"name": "pamolive:image-identity-kind", "value": "image_config"},
                {"name": "pamolive:image-identity", "value": image_id},
                {"name": "pamolive:report-sha256", "value": report_sha256},
                {"name": "pamolive:compilation-attestation", "value": "false"},
                {"name": "pamolive:scanner-finding-adjudication", "value": "none"},
            ]
        },
        "components": components,
        "dependencies": dependencies,
    }
    refs = {row["bom-ref"] for row in components}
    need(
        len(refs) == len(components)
        and all(row["ref"] in refs and set(row["dependsOn"]) <= refs for row in dependencies),
        "v2_SBOM_graph",
    )
    standard.validate_schema(value)  # Real Linux toolchain mandatory; no Windows bypass.
    return value


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--image-config", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = read(args.report, 8 * 1024**2)
    value = export(json_value(raw), args.image_config, hashlib.sha256(raw).hexdigest())
    record(args.output, value)


if __name__ == "__main__":
    main()
