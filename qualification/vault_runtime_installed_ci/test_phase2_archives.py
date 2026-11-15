"""Synthetic ZIPs with refreshed RECORD; no wheel backend/build invocation."""

import tempfile
import unittest
from pathlib import Path

import phase2_fixtures as fixture
import wheel_gate
from support import ROOT


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name)
        fixture.skeleton(self.repository)

    def test_all_three_closed_sources_notices_metadata_and_RECORD(self):
        for kind, expected in (("runtime", 14), ("verifier", 13), ("contracts", 8)):
            raw, _, _ = fixture.fixture(kind)
            fact = wheel_gate.validate(
                raw, ROOT / "inputs" / kind, kind, repository=self.repository
            )
            self.assertEqual(len(fact["files"]) + 1, expected)
            self.assertTrue(fact["wheel_RECORD_checked"])
            self.assertTrue(fact["source_notice_metadata_exact"])

    def test_foreign_file_or_module_refuses_even_with_fresh_RECORD(self):
        for kind in wheel_gate.PACKAGES:
            _, files, info = fixture.fixture(kind)
            files["FORBIDDEN_PUBLIC_EXTRA"] = b"PUBLIC EXTRA"
            with self.assertRaises(ValueError):
                wheel_gate.validate(
                    fixture.packed(files, info),
                    ROOT / "inputs" / kind,
                    kind,
                    repository=self.repository,
                )

    def test_opaque_WHEEL_unixfrom_and_unknown_metadata_refuse(self):
        for kind in wheel_gate.PACKAGES:
            _, files, info = fixture.fixture(kind)
            for member, mutate in (
                ("WHEEL", lambda value: value + b"OPAQUE"),
                ("WHEEL", lambda value: b"From PUBLIC_ENVELOPE\n" + value),
                ("METADATA", lambda value: b"From PUBLIC_ENVELOPE\n" + value),
                ("METADATA", lambda value: b"Unknown: PUBLIC_EXTRA\n" + value),
            ):
                changed = {**files, info + "/" + member: mutate(files[info + "/" + member])}
                with self.subTest(kind=kind, member=member), self.assertRaises(ValueError):
                    wheel_gate.validate(
                        fixture.packed(changed, info),
                        ROOT / "inputs" / kind,
                        kind,
                        repository=self.repository,
                    )

    def test_modified_code_license_or_SQL_refuses_with_valid_archive_RECORD(self):
        for kind in wheel_gate.PACKAGES:
            _, files, info = fixture.fixture(kind)
            for name in [
                path
                for path in files
                if "/licenses/" in path or path.endswith(".py") or path.endswith(".sql")
            ]:
                changed = {**files, name: files[name] + b"PUBLIC_CHANGED"}
                with self.assertRaises(ValueError):
                    wheel_gate.validate(
                        fixture.packed(changed, info),
                        ROOT / "inputs" / kind,
                        kind,
                        repository=self.repository,
                    )
