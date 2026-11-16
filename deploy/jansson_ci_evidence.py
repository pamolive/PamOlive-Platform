"""Offline Jansson DATA bindings, after full Platform/native-test execution."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from deploy import jansson_image_absence as migration
from deploy import qualified_image
from deploy import qualify_image_scan as gate
from deploy.jansson_oracle_identity import STEMS

PRODUCT_PATHS = {
    "Dockerfile",
    "deploy/build-freerdp.sh",
    "deploy/freerdp-jansson-compat.patch",
    "deploy/jansson_image_absence.py",
    "deploy/native_inventory.py",
    "deploy/native_sbom.py",
    "deploy/qualify_image_scan.py",
    "tests/fixtures/json_backend_reference.c",
    "tests/fixtures/winpr_jansson_regression.c",
    "tests/test_jansson_image_absence.py",
    "tests/test_jansson_input_binding.py",
    "tests/test_jansson_sbom.py",
    "tests/test_native_inventory.py",
    "tests/test_native_sbom.py",
}
WIRING_PATHS = {
    ".github/workflows/ci.yml",
    "deploy/jansson_ci_evidence.py",
    "deploy/jansson-ci-product-pins.json",
    "tests/test_jansson_ci_evidence.py",
    "deploy/jansson_oracle_identity.py",
    "tests/test_jansson_oracle_identity.py",
}
ORACLES = {"json-reference.jsonl", "winpr-jansson-build.json", "winpr-jansson-runtime.json"}
IDENTITIES = {"build-identity.json", "runtime-identity.json", "reference-identity.json"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def capture(path, cap):
    with migration._regular_input(path, cap) as stream:
        raw = stream.read(cap + 1)
        gate.require(len(raw) <= cap, "jansson_evidence_budget")
    return raw


def source_binding(context, receipt, revision, executed_root=None):
    gate.require(re.fullmatch(r"[a-f0-9]{40}", revision) is not None, "jansson_revision")
    raw = capture(receipt, 4 * 1024**2)
    value = gate.json_bytes(raw, 4 * 1024**2)
    gate.require(
        value.get("schema") == "pamolive.committed-build-context.v1"
        and value.get("revision") == revision
        and isinstance(value.get("files"), dict),
        "jansson_context_receipt",
    )
    pins_raw = capture(context / "deploy/jansson-ci-product-pins.json", 32768)
    pins = gate.json_bytes(pins_raw, 32768)
    gate.require(set(pins) == PRODUCT_PATHS, "jansson_product_closure")
    rows = {}
    executed_root = Path(__file__).resolve().parents[1] if executed_root is None else executed_root
    for name in sorted(PRODUCT_PATHS | WIRING_PATHS):
        body = capture(context / name, 4 * 1024**2)
        digest = sha(body)
        gate.require(value["files"].get(name) == digest, "jansson_context_source")
        if name in pins:
            gate.require(pins[name] == digest, "jansson_reviewed_source")
        # Refuse running an older checkout helper/import than the built context.
        gate.require(capture(executed_root / name, 4 * 1024**2) == body, "jansson_executed_source")
        rows[name] = digest
    return {"revision": revision, "context_receipt_sha256": sha(raw), "files": rows}


def validate_oracles(buffers):
    gate.require(set(buffers) == ORACLES, "jansson_oracle_closure")
    expected = {
        "schema": "pamolive.winpr-jansson-regression.v1",
        "passed": True,
        "backend": "jansson 2.14",
        "network": False,
    }
    for name in ORACLES - {"json-reference.jsonl"}:
        value = gate.json_bytes(buffers[name], 4096)
        gate.require(
            value == expected
            and type(value.get("passed")) is bool
            and type(value.get("network")) is bool,
            "jansson_native_oracle",
        )
    raw = buffers["json-reference.jsonl"]
    gate.require(len(raw) <= 32768 and raw.endswith(b"\n"), "jansson_reference_budget")
    lines = raw.splitlines()
    gate.require(len(lines) == 18 and all(lines), "jansson_reference_count")
    rows = [gate.json_bytes(line, 4096) for line in lines]
    for index, row in enumerate(rows[:15]):
        gate.require(
            set(row) == {"case", "cjson", "jansson_default", "winpr_guarded"}
            and type(row["case"]) is int
            and row["case"] == index
            and all(
                type(row[key]) is bool for key in ("cjson", "jansson_default", "winpr_guarded")
            ),
            "jansson_reference_shape",
        )
        gate.require(row["winpr_guarded"] is (index in {0, 9}), "jansson_reference_guard")
    gate.require(
        rows[15].keys() == {"case", "cjson", "winpr_guarded"}
        and rows[15]["case"] == "embedded_NUL"
        and type(rows[15]["cjson"]) is bool
        and rows[15]["winpr_guarded"] is False,
        "jansson_reference_nul",
    )
    gate.require(
        rows[16] == {"case": "depth64", "cjson": True, "winpr_guarded": True}
        and rows[17] == {"case": "depth4096", "winpr_guarded_rejected": True},
        "jansson_reference_depth",
    )
    gate.require(
        all(type(rows[16][key]) is bool for key in ("cjson", "winpr_guarded"))
        and type(rows[17]["winpr_guarded_rejected"]) is bool,
        "jansson_reference_boolean",
    )
    return {
        name: {"bytes": len(body), "sha256": sha(body)} for name, body in sorted(buffers.items())
    }


def provider_binding(identities, oracles, native_manifest):
    gate.require(set(identities) == IDENTITIES, "jansson_identity_closure")
    native = gate.json_bytes(native_manifest, gate.MAX_JSON)
    provider_rows = [row for row in native["files"] if Path(row["path"]).name.startswith(STEMS)]
    files = {
        row["path"]: row["sha256"]
        for row in native["files"]
        if Path(row["path"]).name.startswith(STEMS)
    }
    gate.require(files and len(files) == len(provider_rows) <= 8, "jansson_native_provider")
    gate.require(
        all(
            Path(path).name.startswith(STEMS)
            and Path(path).parent.as_posix() == "/opt/pamolive-freerdp/lib"
            and re.fullmatch(r"[a-f0-9]{64}", digest) is not None
            for path, digest in files.items()
        ),
        "jansson_provider_shape",
    )
    binaries = []
    parser_files = None
    for case, output in (
        ("build", "winpr-jansson-build.json"),
        ("runtime", "winpr-jansson-runtime.json"),
        ("reference", "json-reference.jsonl"),
    ):
        value = gate.json_bytes(identities[case + "-identity.json"], 16384)
        gate.require(
            set(value)
            == {
                "schema",
                "case",
                "provider_files",
                "aliases",
                "binary_sha256",
                "oracle_sha256",
                "jansson_files",
            }
            and value["schema"] == "pamolive.jansson-oracle-identity/1"
            and value["case"] == case
            and value["provider_files"] == files
            and value["oracle_sha256"] == sha(oracles[output])
            and re.fullmatch(r"[a-f0-9]{64}", value["binary_sha256"]) is not None,
            "jansson_provider_binding",
        )
        current_parser = value["jansson_files"]
        gate.require(
            isinstance(current_parser, dict)
            and len(current_parser) == 1
            and all(
                Path(path).parent.as_posix() == "/usr/lib/x86_64-linux-gnu"
                and Path(path).name.startswith("libjansson.so.")
                and re.fullmatch(r"[a-f0-9]{64}", digest) is not None
                for path, digest in current_parser.items()
            ),
            "jansson_parser_shape",
        )
        gate.require(
            parser_files is None or parser_files == current_parser,
            "jansson_parser_changed_between_oracles",
        )
        parser_files = current_parser
        gate.require(
            isinstance(value["aliases"], dict)
            and 1 <= len(value["aliases"]) <= 32
            and set(value["aliases"].values()) == set(files)
            and all(
                Path(name).name.startswith(STEMS)
                and name.startswith("/opt/pamolive-freerdp/lib/")
                and "/" not in name.removeprefix("/opt/pamolive-freerdp/lib/")
                for name in value["aliases"]
            ),
            "jansson_provider_alias",
        )
        if case != "reference":
            binaries.append(value["binary_sha256"])
    gate.require(binaries[0] == binaries[1], "jansson_runtime_binary")
    return {name: sha(raw) for name, raw in sorted(identities.items())}


def dpkg_projection(status, metadata):
    """Package inventory only; not an independent scanner or vulnerability SBOM."""
    gate.require(isinstance(status, bytes) and len(status) <= 4 * 1024**2, "jansson_dpkg_budget")
    packages = {}
    for paragraph in status.decode("utf-8").split("\n\n"):
        fields = {}
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")):
                continue
            key, separator, value = line.partition(": ")
            if key in {"Package", "Version", "Architecture", "Status"}:
                gate.require(separator and key not in fields, "jansson_dpkg_duplicate")
                fields[key] = value
        if fields.get("Status") != "install ok installed":
            continue
        name, version, arch = (
            fields.get(key, "") for key in ("Package", "Version", "Architecture")
        )
        gate.require(
            re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", name) is not None
            and name not in packages
            and 1 <= len(version) <= 256
            and re.fullmatch(r"[A-Za-z0-9.+:~_-]+", version) is not None
            and arch in {"amd64", "all"},
            "jansson_dpkg_shape",
        )
        packages[name] = version
        gate.require(len(packages) <= 10000, "jansson_dpkg_count")
    gate.require(packages.get("libjansson4") == "2.14-2+b3", "jansson_dpkg_version")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "properties": [
                {"name": "pamolive:kind", "value": "dpkg-inventory-projection-not-scanner"},
                {"name": "pamolive:image-config", "value": metadata["image_id"]},
                {"name": "pamolive:archive-sha256", "value": metadata["archive_sha256"]},
            ]
        },
        "components": [
            {"type": "library", "name": name, "version": version}
            for name, version in sorted(packages.items())
        ],
    }


def receive(context, context_receipt, bundle, oracles, output, revision):
    output.mkdir(mode=0o700)
    sources = source_binding(context, context_receipt, revision)
    gate.require(
        {item.name for item in oracles.iterdir()} == ORACLES | IDENTITIES, "jansson_export_closure"
    )
    buffers = {name: capture(oracles / name, 32768) for name in ORACLES}
    identities = {name: capture(oracles / name, 16384) for name in IDENTITIES}
    oracle_pins = validate_oracles(buffers)
    native_raw = capture(output.parent / "native-manifest.json", gate.MAX_JSON)
    provider_pins = provider_binding(identities, buffers, native_raw)
    metadata = qualified_image.verify_bundle(bundle, revision)
    archive = bundle / qualified_image.ARCHIVE
    with migration._regular_input(archive, migration.ARCHIVE_LIMIT) as stream:
        archive_digest = migration._hash_stream(stream, migration.ARCHIVE_LIMIT)
        gate.require(archive_digest == metadata["archive_sha256"], "jansson_archive_binding")
        stream.seek(0)
        facts = gate.archive_facts(
            None,
            [],
            read_paths=["/var/lib/dpkg/status", "/opt/pamolive-native-manifest.json"],
            archive_stream=stream,
        )
        status = facts.captured.get("/var/lib/dpkg/status")
        gate.require(
            facts.captured.get("/opt/pamolive-native-manifest.json") == native_raw,
            "jansson_archived_native_manifest",
        )
        for row in gate.json_bytes(native_raw, gate.MAX_JSON)["files"]:
            if Path(row["path"]).name.startswith(STEMS):
                gate.require(
                    facts[1].get(row["path"], {}).get("sha256") == row["sha256"],
                    "jansson_archived_provider",
                )
        parsers = gate.json_bytes(identities["runtime-identity.json"], 16384)["jansson_files"]
        for path, digest in parsers.items():
            gate.require(facts[1].get(path, {}).get("sha256") == digest, "jansson_archived_parser")
        gate.require(
            migration._hash_stream(stream, migration.ARCHIVE_LIMIT) == archive_digest,
            "jansson_projection_archive_changed",
        )
    projection = dpkg_projection(status, metadata)
    projection_raw = (json.dumps(projection, sort_keys=True, indent=2) + "\n").encode()
    report = migration.examine(archive, gate.json_bytes(projection_raw, gate.MAX_JSON))
    gate.require(
        report["archive_sha256"] == metadata["archive_sha256"]
        and report["image_config_id"] == metadata["image_id"],
        "jansson_absence_image_binding",
    )
    # Recheck source/context after reading the archive; never admit a late drift.
    gate.require(
        source_binding(context, context_receipt, revision) == sources, "jansson_source_changed"
    )
    result = {
        "schema": "pamolive.jansson-ci-evidence/1",
        "source": sources,
        "qualified_image": metadata,
        "oracles": oracle_pins,
        "physical_absence": report,
        "oracle_identity_sha256": provider_pins,
        "native_manifest_sha256": sha(native_raw),
        "dpkg_status_sha256": sha(status),
        "os_package_projection_sha256": sha(projection_raw),
        "full_Platform_P0_and_scans_required": True,
        "CVE_closed": False,
        "operational_GO": False,
        "Docker_H1_inferred": False,
    }
    for name, body in {
        **buffers,
        **identities,
        "os-packages.cdx.json": projection_raw,
        "report.json": (json.dumps(result, indent=2) + "\n").encode(),
    }.items():
        with (output / name).open("xb") as stream:
            gate.require(stream.write(body) == len(body), "jansson_evidence_short_write")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("context", "context-receipt", "bundle", "oracles", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    receive(
        args.context, args.context_receipt, args.bundle, args.oracles, args.output, args.revision
    )


if __name__ == "__main__":
    main()
