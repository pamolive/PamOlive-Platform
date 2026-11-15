"""Closed error identities/types only; synthetic callback/suite boundaries, no packages."""

import ast
import copy
import io
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import installed_runner
import schema
from support import ROOT, sha
from test_seam import EXPECTED, INPUT, SQL, packet


class DiagnosticTests(unittest.TestCase):
    def result(self):
        return installed_runner.ErrorResult(io.StringIO(), False, 0)

    def test_original_52_ids_match_only_unchanged_public_runtime_methods(self):
        directory = ROOT.parents[1] / "components/vault/runtime/tests"
        names = set()
        for module in ("test_runtime", "test_ro_slot", "test_r2_boundaries"):
            for cls in ast.parse((directory / (module + ".py")).read_bytes()).body:
                if isinstance(cls, ast.ClassDef):
                    names.update(
                        module + "." + cls.name + "." + node.name
                        for node in cls.body
                        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
                    )
        self.assertEqual(len(names), 52)
        self.assertEqual(names, schema.TEST_IDS)

    def test_real_addError_never_formats_exception_or_traceback(self):
        class Sensitive(Exception):
            def __str__(self):
                raise AssertionError("exception text must never be requested")

        result = self.result()
        name = sorted(schema.TEST_IDS)[0]
        with patch.object(
            result, "_exc_info_to_string", side_effect=AssertionError("no traceback")
        ):
            result.addError(SimpleNamespace(id=lambda: name), (Sensitive, Sensitive(), None))
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0][1], "")
        self.assertEqual(result.diagnostics, [{"test_id": name, "exception_type": "Other"}])

    def test_diagnostics_bounded_eight_unique_ids_with_all_errors_counted(self):
        result = self.result()
        names = sorted(schema.TEST_IDS)[:9]
        for name in names + names[:1]:
            result.addError(
                SimpleNamespace(id=lambda: name), (ValueError, ValueError("PRIVATE CANARY"), None)
            )
        self.assertEqual(len(result.errors), 10)
        self.assertEqual(len(result.diagnostics), 8)
        self.assertEqual({row["test_id"] for row in result.diagnostics}, set(names[:8]))
        schema.diagnostics(result.diagnostics)
        self.assertNotIn("PRIVATE CANARY", schema.encode(result.diagnostics).decode())

    def test_unknown_or_long_or_nonstring_ids_never_exported(self):
        result = self.result()
        for name in ("setUpClass (foreign)", "PRIVATE CANARY" * 300, None, True):
            result.addError(SimpleNamespace(id=lambda: name), (ValueError, ValueError(), None))
        self.assertEqual(len(result.errors), 4)
        self.assertEqual(result.diagnostics, [])

    def test_schema_refuses_extra_raw_fields_ids_types_and_duplicates(self):
        row = {"test_id": sorted(schema.TEST_IDS)[0], "exception_type": "FileNotFoundError"}
        schema.diagnostics([row])
        for value in (
            None,
            {},
            [row] * 2,
            [row] * 9,
            [{**row, "message": "PRIVATE CANARY"}],
            [{**row, "test_id": "foreign"}],
            [{**row, "test_id": True}],
            [{**row, "exception_type": "raw unknown exception"}],
            [{**row, "exception_type": True}],
        ):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                schema.diagnostics(value)

    def test_child_v2_missing_diagnostics_is_never_promoted(self):
        value = packet()["child"]
        value["schema"] = "pamolive.vault-runtime-installed-child/2"
        value.pop("test_errors")
        with self.assertRaises(ValueError):
            schema.child(value, EXPECTED)
        value["test_errors"] = []
        with self.assertRaises(ValueError):
            schema.child(value, EXPECTED)

    def test_success_cannot_include_error_diagnostic_or_inconsistent_count(self):
        row = {"test_id": sorted(schema.TEST_IDS)[0], "exception_type": "FileNotFoundError"}
        for success in (True, False):
            value = packet(success)["child"]
            value["test_errors"] = [row]
            with self.assertRaises(ValueError):
                schema.child(value, EXPECTED)

    def test_valid_failed_v3_recanonicalized_packet_remains_failure(self):
        value = packet(False)
        value["child"]["tests"]["errors"] = 1
        value["child"]["test_errors"] = [
            {"test_id": sorted(schema.TEST_IDS)[0], "exception_type": "FileNotFoundError"}
        ]
        raw = schema.encode(value["child"])
        value["child_sha256"], value["child_bytes"] = sha(raw), len(raw)
        schema.packet(value, EXPECTED, 42, expected_input_sha256=INPUT, expected_sql_sha256=SQL)
        changed = copy.deepcopy(value)
        changed["ok"] = True
        with self.assertRaises(ValueError):
            schema.packet(
                changed, EXPECTED, 0, expected_input_sha256=INPUT, expected_sql_sha256=SQL
            )

    def test_real_suite_callback_retains_known_id_and_type_without_message(self):
        name = sorted(schema.TEST_IDS)[0]

        class Synthetic(unittest.TestCase):
            def id(self):
                return name

            def test_error(self):
                raise FileNotFoundError("PRIVATE CANARY")

        modules = {
            key: ModuleType(key) for key in ("test_runtime", "test_ro_slot", "test_r2_boundaries")
        }
        modules["test_runtime"].Synthetic = Synthetic

        def importer(key):
            if key in schema.MODULES:
                return SimpleNamespace(__file__=str(Path(sys.prefix) / key / "__init__.py"))
            return modules[key]

        counts, diagnostics = installed_runner.suite_tests(
            Path("/synthetic-stage"), importer=importer
        )
        self.assertEqual(counts, {"run": 1, "failures": 0, "errors": 1, "skips": 0})
        self.assertEqual(diagnostics, [{"test_id": name, "exception_type": "FileNotFoundError"}])
        self.assertNotIn("PRIVATE CANARY", schema.encode(diagnostics).decode())

    def test_diagnostic_array_does_not_relax_other_child_guards(self):
        base = packet(False)["child"]
        base["tests"]["errors"] = 1
        base["test_errors"] = [{"test_id": sorted(schema.TEST_IDS)[0], "exception_type": "Other"}]
        schema.child(base, EXPECTED)
        for key, value in (
            ("authority", True),
            ("schema", "unknown"),
            ("elapsed_seconds", 10**400),
        ):
            changed = {**base, key: value}
            with self.assertRaises(ValueError):
                schema.child(changed, EXPECTED)
