"""Installed RECORD mapping using filesystem data fixtures, never pip/install."""

import json
import tempfile
import unittest
from pathlib import Path

import phase2_fixtures as fixture
import records
import wheel_gate
from support import ROOT


class RecordTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.repository = self.directory / "repository"
        self.repository.mkdir()
        fixture.skeleton(self.repository)

    def installed(self, kind):
        raw, files, _ = fixture.fixture(kind)
        wheel = self.directory / (kind + ".whl")
        wheel.write_bytes(raw)
        inventory = wheel_gate.validate(
            raw, ROOT / "inputs" / kind, kind, repository=self.repository
        )
        prefix = self.directory / kind
        prefix.mkdir()
        written, record = fixture.install_data(prefix, inventory, wheel, files)
        return prefix, inventory, wheel, written, record

    def test_three_RECORDs_and_only_known_SQL_data_relocation(self):
        for kind, count in (("runtime", 17), ("verifier", 16), ("contracts", 11)):
            prefix, inventory, wheel, _, _ = self.installed(kind)
            result = records.check(prefix, inventory, wheel)
            self.assertEqual(result["files_checked"], count)
            self.assertEqual(result["SQL_only_known_data_relocation"], kind == "runtime")

    def test_changed_file_despite_RECORD_update_refuses_source_binding(self):
        prefix, inventory, wheel, written, _ = self.installed("contracts")
        name = next(name for name in written if name.endswith("contracts.py"))
        (prefix / name).write_bytes(b"PUBLIC_MUTATION")
        with self.assertRaises(ValueError):
            records.check(prefix, inventory, wheel)

    def test_extra_package_file_or_PTH_refuses_even_without_RECORD_row(self):
        prefix, inventory, wheel, _, _ = self.installed("contracts")
        for relative in ("pamolive_vault_contracts/extra.py", "extra.pth"):
            path = prefix / "lib/python3.12/site-packages" / relative
            path.write_bytes(b"PUBLIC_EXTRA")
            with self.assertRaises(ValueError):
                records.check(prefix, inventory, wheel)
            path.unlink()

    def test_wrong_SQL_parent_traversal_refuses_before_foreign_read(self):
        prefix, inventory, wheel, _, record = self.installed("runtime")
        record.write_bytes(record.read_bytes().replace(b"../../../share/", b"../../../../share/"))
        with self.assertRaises(ValueError):
            records.check(prefix, inventory, wheel)

    def test_direct_url_exact_file_URI_and_hash_no_network_fallback(self):
        prefix, inventory, wheel, _, _ = self.installed("contracts")
        path = prefix / "lib/python3.12/site-packages" / inventory["info"] / "direct_url.json"
        original = path.read_bytes()
        for wrong in (
            {"url": "https://public.invalid/foreign.whl"},
            {**json.loads(original), "url": wheel.parent.as_uri()},
            {**json.loads(original), "extra": "PUBLIC_EXTRA"},
        ):
            path.write_bytes(json.dumps(wrong).encode())
            with self.assertRaises(ValueError):
                records.check(prefix, inventory, wheel)

    def test_missing_REQUESTED_or_license_refuses(self):
        prefix, inventory, wheel, _, _ = self.installed("contracts")
        base = prefix / "lib/python3.12/site-packages" / inventory["info"]
        for name in ("REQUESTED", "licenses/LICENSE"):
            path = base / name
            raw = path.read_bytes()
            path.unlink()
            with self.assertRaises((ValueError, OSError)):
                records.check(prefix, inventory, wheel)
            path.write_bytes(raw)
