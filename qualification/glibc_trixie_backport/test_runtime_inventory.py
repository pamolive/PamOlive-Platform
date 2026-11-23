"""Offline tests for comparing the exact runtime packages in a lab receipt."""

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from qualification.glibc_trixie_backport import runtime_inventory as inventory
from tests.test_expat_apt import deb


def digest(data):
    return hashlib.sha256(data).hexdigest()


class RuntimeInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="glibc-inventory-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.materials = {}
        self.stock = {}
        self.receipt = {
            "schema": "pamolive.glibc-trixie-backport-qualification/1",
            "status": "QUALIFIED",
            "scope": "installed-abi-and-positive-smoke",
            "versions": {"stock": inventory.STOCK, "candidate": inventory.CANDIDATE},
            "materials_sha256": self.materials,
            "product_image_verified": False,
            "release_admitted": False,
        }
        for role, version, prefix in (
            ("stock", inventory.STOCK, "stock-"),
            ("candidate", inventory.CANDIDATE, ""),
        ):
            libc = b"synthetic-stock-libc" if prefix else b"synthetic-candidate-libc"
            loader = b"synthetic-loader"
            self.receipt[f"{role}_sha256"] = self.write(f"{role}.json", b"{}\n")
            for package, entries in (
                ("libc6", [(inventory.LIBC[1:], libc), (inventory.LOADER[1:], loader)]),
                ("libc-bin", [("usr/bin/getent", b"synthetic-getent")]),
            ):
                filename = f"{prefix}{package}.deb"
                raw = deb(package, version, b"Source: glibc\n", payload_entries=entries)
                self.materials[filename] = self.write(filename, raw)
                if prefix:
                    self.stock[filename] = self.materials[filename]
            if role == "candidate":
                self.receipt["installed_elf_sha256"] = {
                    inventory.LIBC: digest(libc),
                    inventory.LOADER: digest(loader),
                }

    def write(self, name, data):
        (self.root / name).write_bytes(data)
        return digest(data)

    def measure(self):
        raw = (json.dumps(self.receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
        qualification_sha256 = self.write("qualification.json", raw)
        with patch.object(inventory, "stock_checksums", return_value=self.stock):
            return inventory.runtime_inventory(self.root, qualification_sha256)

    def test_measures_changed_members_without_admitting_an_image(self):
        result = self.measure()
        self.assertEqual(
            result["delta"]["libc6"],
            {
                "added": [],
                "removed": [],
                "changed": [inventory.LIBC[1:]],
            },
        )
        self.assertEqual(result["delta"]["libc-bin"], {"added": [], "removed": [], "changed": []})
        self.assertEqual(
            result["packages"]["candidate"]["libc6"]["archive_sha256"], self.materials["libc6.deb"]
        )
        self.assertIs(result["product_image_verified"], False)
        self.assertIs(result["release_admitted"], False)

    def test_refuses_an_archive_or_reference_pin_that_does_not_match(self):
        self.stock["stock-libc6.deb"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "reference_package_digest"):
            self.measure()
        self.stock["stock-libc6.deb"] = self.materials["stock-libc6.deb"]
        self.write("libc6.deb", b"different synthetic archive")
        with self.assertRaisesRegex(ValueError, "input_digest"):
            self.measure()

    def test_package_name_and_installed_identity_must_match_their_evidence(self):
        raw = deb("libc6", inventory.CANDIDATE, b"Source: glibc\n")
        with self.assertRaisesRegex(ValueError, "runtime_package_identity"):
            inventory.package_projection(raw, "libc-bin", inventory.CANDIDATE)
        self.receipt["installed_elf_sha256"][inventory.LOADER] = "0" * 64
        with self.assertRaisesRegex(ValueError, "candidate_installed_elf"):
            self.measure()
