"""Measure the package-level runtime delta of an exact glibc lab artifact."""

import argparse
import hashlib
import json
import tarfile
from pathlib import Path

from deploy.expat_apt import materials
from deploy.jansson_image_absence import _regular_input
from qualification.glibc_trixie_backport.check import CANDIDATE, LIBC, LOADER, STOCK

RUNTIME_PACKAGES = ("libc6", "libc-bin")
STOCK_HASHES = Path(__file__).resolve().parents[2] / "deploy/glibc-trixie-backport/stock.sha256"
ARCHIVE_LIMIT = 16 * 1024**2
RECEIPT_LIMIT = 128 * 1024


def read_pinned(path, expected, limit):
    materials.need(isinstance(expected, str) and materials.SHA.fullmatch(expected), "digest_format")
    with _regular_input(path, limit) as stream:
        raw = stream.read(limit + 1)
        materials.need(0 < len(raw) <= limit, "input_budget")
        materials.need(hashlib.sha256(raw).hexdigest() == expected, "input_digest")
        return raw


def stock_checksums():
    checksums = {}
    for line in STOCK_HASHES.read_text(encoding="ascii").splitlines():
        digest, name = line.split()
        materials.need(name not in checksums and materials.SHA.fullmatch(digest), "stock_manifest")
        checksums[name] = digest
    return checksums


def package_projection(raw, package, version):
    control, paths = materials.deb(raw, payload=True)
    materials.need(
        materials.package_identity(control) == (package, version, "amd64")
        and control.get("Source") == "glibc",
        "runtime_package_identity",
    )
    return paths


def runtime_inventory(folder, qualification_sha256):
    receipt_raw = read_pinned(folder / "qualification.json", qualification_sha256, RECEIPT_LIMIT)
    receipt = materials.json_data(receipt_raw)
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    materials.need(
        isinstance(receipt, dict)
        and canonical.encode("ascii") == receipt_raw
        and receipt.get("schema") == "pamolive.glibc-trixie-backport-qualification/1"
        and receipt.get("status") == "QUALIFIED"
        and receipt.get("scope") == "installed-abi-and-positive-smoke"
        and receipt.get("versions") == {"stock": STOCK, "candidate": CANDIDATE}
        and receipt.get("product_image_verified") is False
        and receipt.get("release_admitted") is False,
        "qualification_receipt",
    )
    stock = stock_checksums()
    projections = {}
    for role, version, prefix in (("stock", STOCK, "stock-"), ("candidate", CANDIDATE, "")):
        read_pinned(folder / f"{role}.json", receipt[f"{role}_sha256"], RECEIPT_LIMIT)
        packages = projections[role] = {}
        for package in RUNTIME_PACKAGES:
            name = f"{prefix}{package}.deb"
            digest = receipt["materials_sha256"][name]
            if role == "stock":
                materials.need(stock[name] == digest, "reference_package_digest")
            raw = read_pinned(folder / name, digest, ARCHIVE_LIMIT)
            packages[package] = {
                "archive_sha256": digest,
                "version": version,
                "paths": package_projection(raw, package, version),
            }

    libc = projections["candidate"]["libc6"]["paths"]
    for path in (LIBC, LOADER):
        row = libc.get(path.lstrip("/"), {})
        materials.need(
            row.get("type") == "file" and row["sha256"] == receipt["installed_elf_sha256"][path],
            "candidate_installed_elf",
        )

    delta = {}
    for package in RUNTIME_PACKAGES:
        baseline = projections["stock"][package]["paths"]
        candidate = projections["candidate"][package]["paths"]
        delta[package] = {
            "added": sorted(candidate.keys() - baseline.keys()),
            "removed": sorted(baseline.keys() - candidate.keys()),
            "changed": sorted(
                path
                for path in baseline.keys() & candidate.keys()
                if baseline[path] != candidate[path]
            ),
        }
    return {
        "schema": "pamolive.glibc-runtime-package-inventory/1",
        "qualification_sha256": qualification_sha256,
        "packages": projections,
        "delta": delta,
        "product_image_verified": False,
        "release_admitted": False,
    }


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--qualification-sha256", required=True)
    args = parser.parse_args()
    try:
        result = runtime_inventory(args.folder, args.qualification_sha256)
    except (OSError, ValueError, KeyError, TypeError, EOFError, tarfile.TarError):
        parser.exit(42, "REFUSED: glibc runtime package inventory inputs failed verification\n")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
