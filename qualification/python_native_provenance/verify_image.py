"""Replay the wheel build evidence against the final files in a qualified image."""

import argparse
import re
import tarfile
from pathlib import Path

from deploy import python_materials as materials
from deploy import qualified_image
from deploy import qualify_image_scan as gate
from qualification.python_native_provenance import validate_observations as compiler

PREFIX = "/usr/share/pamolive/python-materials/"
SITE_PACKAGES = "/usr/local/lib/python3.12/site-packages/"
BUILD = PREFIX + "compiler-build.json"
OBSERVATIONS = PREFIX + "compiler-observations.json"
DERIVED = PREFIX + "derived-manifest.json"
INPUTS = PREFIX + "python-materials.linux-amd64.json"
EXTENSIONS = frozenset(
    SITE_PACKAGES + path for paths in materials.SO_PATHS.values() for path in paths
)
RECEIPTS = frozenset({BUILD, OBSERVATIONS, DERIVED, INPUTS})
READ_PATHS = RECEIPTS | EXTENSIONS
SCHEMA = "pamolive.python-native-image/1"
VERSION = re.compile(r"[0-9][A-Za-z0-9.+:~\-]{0,126}\Z")


def read_public_file(facts, name, modes):
    attrs = facts.attributes.get(name)
    compiler.require(
        attrs is not None and attrs["mode"] in modes and attrs == {
            "uid": 0, "gid": 0, "mode": attrs["mode"], "has_capability": False,
        },
        "compiler_image_file_attributes",
    )
    return facts.captured[name]


def package_names(versions):
    names = []
    compiler.require(type(versions) is list and len(versions) == len(compiler.SDK_PACKAGES),
                     "compiler_sdk_versions")
    for row in versions:
        compiler.require(type(row) is str and len(row) <= 160, "compiler_sdk_version")
        package, _, version = row.partition("=")
        compiler.require(VERSION.fullmatch(version), "compiler_sdk_version")
        names.append(package.removesuffix(":amd64"))
    return names


def inspect_facts(facts, metadata, input_manifest, input_sha):
    build, observations, derived, inputs = (
        read_public_file(facts, path, {0o444}) for path in (BUILD, OBSERVATIONS, DERIVED, INPUTS)
    )
    compiler.require(materials.sha(inputs) == input_sha, "compiler_image_input_manifest")
    wheels = compiler.wheel_rows(derived, input_manifest, input_sha)
    checks = {
        "schema": compiler.BUILD_SCHEMA,
        "compiler_calls": 15,
        "extensions": compiler.replay(observations, wheels),
        "derived_manifest_sha256": materials.sha(derived),
        "observations_sha256": materials.sha(observations),
        "product_image_measured": False,
        "policy_disposition": None,
    }
    receipt = gate.json_bytes(build, maximum=materials.MAX_JSON)
    compiler.require(set(receipt) == checks.keys() | {"sdk_versions"}
                     and type(receipt["compiler_calls"]) is int
                     and receipt["product_image_measured"] is False
                     and all(receipt[key] == value for key, value in checks.items()),
                     "compiler_image_build_receipt")
    versions = receipt["sdk_versions"]
    compiler.require(set(package_names(versions)) == set(compiler.SDK_PACKAGES),
                     "compiler_sdk_packages")

    def installed_elf(path):
        absolute = SITE_PACKAGES + path
        row = facts.entries.get(absolute, {})
        compiler.require(row.get("type") == "elf" and row.get("class") == 64
                         and row.get("machine") == 62, "compiler_image_elf")
        return read_public_file(facts, absolute, {0o644, 0o755})

    return {
        "schema": SCHEMA,
        "revision": metadata["revision"],
        "image_config_id": metadata["image_id"],
        "archive_sha256": metadata["archive_sha256"],
        "input_manifest_sha256": input_sha,
        "compiler_build_sha256": materials.sha(build),
        "derived_manifest_sha256": checks["derived_manifest_sha256"],
        "observations_sha256": checks["observations_sha256"],
        "compiler_calls": checks["compiler_calls"],
        "sdk_versions": versions,
        "extensions": compiler.inspect_extensions(checks["extensions"], installed_elf),
        "product_image_measured": True,
        "policy_disposition": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        repo = Path(__file__).resolve().parents[2]
        manifest, input_sha = materials.load_manifest(
            repo / "deploy/python-materials.linux-amd64.json"
        )
        metadata = qualified_image.verify_bundle(args.bundle, args.revision)
        _, facts = gate.bound_archive_facts(
            args.bundle / qualified_image.ARCHIVE, metadata, [],
            read_paths=sorted(READ_PATHS), attribute_paths=sorted(READ_PATHS),
        )
        report = inspect_facts(facts, metadata, manifest, input_sha)
        with args.output.open("x", encoding="ascii", newline="\n") as stream:
            stream.write(gate.canonical(report) + "\n")
    except (KeyError, TypeError, OSError, ValueError, tarfile.TarError):
        raise SystemExit("Python native product evidence refused.") from None


if __name__ == "__main__":
    main()
