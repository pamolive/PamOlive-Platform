"""Check that the native receipt only describes the source actually built."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from qualification.openssl_trixie_backport.check import dane_source_inputs

INPUTS = Path(__file__).resolve().parent
DANE_INPUTS = (
    "dane.patch", "dane-preimage.sha256", "postimage.sha256", "dane-provenance.json",
)


class DANEManifestTests(unittest.TestCase):
    def test_source_pins_match(self):
        result = dane_source_inputs(INPUTS)
        self.assertEqual(result["source_status"], "proposed_upstream")
        self.assertEqual(result["advisory"], "CVE-2026-84786")

    def test_refuses_mismatched_source_metadata(self):
        for name in DANE_INPUTS:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                for material in DANE_INPUTS:
                    shutil.copyfile(INPUTS / material, root / material)
                selected = root / name
                if name.endswith(".json"):
                    receipt = json.loads(selected.read_bytes())
                    receipt["source_status"] = "release"
                    selected.write_text(json.dumps(receipt), encoding="ascii")
                elif name.endswith(".sha256"):
                    selected.write_bytes(selected.read_bytes().replace(
                        b"crypto/x509/x509_vfy.c", b"crypto/x509/other.c",
                    ))
                else:
                    selected.write_bytes(selected.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "dane_source_metadata_mismatch"):
                    dane_source_inputs(root)
