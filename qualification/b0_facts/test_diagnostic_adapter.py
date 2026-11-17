"""Pure validation of the optional failure-only hashed-directory diagnostic."""

import copy
import unittest
from pathlib import Path

import adapter as A

ROOT = Path(__file__).resolve().parent


def diagnostic():
    return {
        "code": "B0_FACTS_DIRECTORY_ENTRY_REFUSED",
        "directory_context": "sources_list_d",
        "basename_status": "hashed",
        "basename_utf8_bytes": 7,
        "basename_sha256": "a" * 64,
    }


def failure():
    return {
        "schema": "pamolive.b0-d0-public-facts/1",
        "phase": A.PHASE,
        "ok": False,
        "code": "B0_FACTS_DIRECTORY_ENTRY_REFUSED",
        "stage0_passed": False,
        "primary_fingerprints": None,
        "subkey_fingerprints": None,
        "authority": False,
        "release_qualified": False,
    }


class DiagnosticAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, _, _ = A.context(ROOT, A.digest((ROOT / "facts-assets.json").read_bytes()))

    def reject(self, value):
        with self.assertRaises(self.module.Refusal):
            A.validate_evidence(self.module, value)

    def test_old_failure_and_both_contexts(self):
        old = failure()
        self.assertIs(A.validate_evidence(self.module, old), old)
        for context in ("sources_list_d", "trusted_gpg_d"):
            row = {
                **old,
                "directory_entry_diagnostic": {**diagnostic(), "directory_context": context},
            }
            self.assertIs(A.validate_evidence(self.module, row), row)
            self.assertLess(len(A.bounded_json(row)), 1024)

    def test_unknown_enum_only_nulls(self):
        row = {
            **failure(),
            "directory_entry_diagnostic": {
                **diagnostic(),
                "basename_status": "unavailable_or_refused",
                "basename_utf8_bytes": None,
                "basename_sha256": None,
            },
        }
        self.assertIs(A.validate_evidence(self.module, row), row)
        for name, value in (("basename_utf8_bytes", 0), ("basename_sha256", "a" * 64)):
            changed = copy.deepcopy(row)
            changed["directory_entry_diagnostic"][name] = value
            self.reject(changed)

    def test_each_key_required_extra_private_fields_refused(self):
        for key in diagnostic():
            changed = diagnostic()
            del changed[key]
            self.reject({**failure(), "directory_entry_diagnostic": changed})
        for key in ("raw_name", "path", "content", "URI", "key"):
            self.reject(
                {**failure(), "directory_entry_diagnostic": {**diagnostic(), key: "PRIVATE"}}
            )

    def test_wrong_type_context_code_hash_and_length(self):
        changes = {
            "code": ["B0_FACTS_STAT_REFUSED", None],
            "directory_context": ["/etc/apt/sources.list.d", "unknown", None, []],
            "basename_status": ["approved", True],
            "basename_utf8_bytes": [True, 0, -1, 513, 7.0, "7", None],
            "basename_sha256": ["A" * 64, "a" * 63, "a" * 65, "PRIVATE", None, 1],
        }
        for key, values in changes.items():
            for value in values:
                self.reject(
                    {**failure(), "directory_entry_diagnostic": {**diagnostic(), key: value}}
                )

    def test_only_directory_failure_can_have_diagnostic(self):
        self.reject(
            {
                **failure(),
                "code": "B0_FACTS_STAT_REFUSED",
                "directory_entry_diagnostic": diagnostic(),
            }
        )
        self.reject({**failure(), "ok": True, "directory_entry_diagnostic": diagnostic()})
        self.reject({**failure(), "directory_entry_diagnostic": None})


# No main: imported only by the guarded pure unittest loader.
