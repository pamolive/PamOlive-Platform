"""Synthetic configuration checks for historical event-proof verification keys."""

import json
import os
import runpy
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured

ROOT = Path(__file__).resolve().parents[1]
CURRENT = "synthetic-current-signing-key-for-local-tests-0001"
HISTORICAL = "synthetic-historical-evidence-key-for-local-tests-0001"


class EvidenceVerificationKeyConfigurationTests(TestCase):
    def load(self, raw=None):
        values = {"SECRET_KEY": CURRENT}
        if raw is not None:
            values["PAMOLIVE_EVIDENCE_VERIFICATION_KEYS"] = raw
        with patch.dict(os.environ, values, clear=True):
            return runpy.run_path(str(ROOT / "config/settings.py"))

    def test_absent_and_explicit_empty_lists_are_distinct_valid_configurations(self):
        self.assertEqual(self.load()["PAMOLIVE_EVIDENCE_VERIFICATION_KEYS"], ())
        self.assertEqual(self.load("[]")["PAMOLIVE_EVIDENCE_VERIFICATION_KEYS"], ())

    def test_valid_historical_values_are_preserved_exactly_without_django_fallback(self):
        spaced = " " + HISTORICAL + " "
        # Earlier installations could have a shorter SECRET_KEY. It is accepted
        # for verification only; all new signatures still use the current key.
        short_legacy = "legacy-key"
        config = self.load(json.dumps([HISTORICAL, spaced, short_legacy]))
        self.assertEqual(
            config["PAMOLIVE_EVIDENCE_VERIFICATION_KEYS"],
            (HISTORICAL, spaced, short_legacy),
        )
        self.assertNotIn("SECRET_KEY_FALLBACKS", config)

    def test_blank_malformed_duplicate_current_and_nonprintable_values_fail_closed(self):
        invalid = (
            "",
            "null",
            "{}",
            '"string"',
            json.dumps([""]),
            json.dumps([" " * 40]),
            json.dumps([HISTORICAL + "\n"]),
            json.dumps([HISTORICAL, HISTORICAL]),
            json.dumps([CURRENT]),
        )
        for raw in invalid:
            with self.subTest(raw_length=len(raw)):
                with self.assertRaisesRegex(
                    ImproperlyConfigured, "PAMOLIVE_EVIDENCE_VERIFICATION_KEYS"
                ):
                    self.load(raw)
