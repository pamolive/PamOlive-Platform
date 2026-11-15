"""Pure schema/input contracts; no package code, venv or installed suite run."""

import copy
import json
import unittest
from unittest.mock import patch

import adapter_v2
import entrypoint_v2
import schema
from support import sha
from test_seam import EXPECTED, INPUT, SOURCE, SQL, packet


def descriptor():
    return {
        "schema": "pamolive.vault-runtime-installed-input/2",
        "distributions": adapter_v2.distributions(),
        "module_files": {
            module: dict.fromkeys(names, "1" * 64) for module, names in adapter_v2.CODE.items()
        },
        "stage_files": dict.fromkeys(adapter_v2.STAGE, "2" * 64),
        "source_sha256": SOURCE,
        "sql_sha256": adapter_v2.SQL_SHA,
    }


class ContractTests(unittest.TestCase):
    def test_descriptor_fixed16_distributions_and8_3_6_closed_modules(self):
        value = descriptor()
        self.assertIs(adapter_v2.descriptor(value), value)
        self.assertEqual(len(value["distributions"]), 16)
        self.assertNotIn("psycopg", value["distributions"])
        for mutate in (
            lambda item: item.update(extra=False),
            lambda item: item["distributions"].update(django="6.0"),
            lambda item: item["distributions"].pop("h11"),
            lambda item: item["module_files"]["pamolive_vault_runtime"].update(extra="1" * 64),
            lambda item: item["module_files"]["pamolive_vault_runtime"].pop("slot.py"),
            lambda item: item["stage_files"].pop("tests/history/r1/transport.py"),
            lambda item: item.update(sql_sha256="3" * 64),
        ):
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.assertRaises(ValueError):
                adapter_v2.descriptor(changed)

    def test_input_JSON_prebudget_before_loads_duplicates_and_nonfinite(self):
        for raw in (
            b"[" * 13 + b"]" * 13,
            b"[" + b"0," * 8200 + b"0]",
            b"x" * (schema.MAX_CHILD + 1),
        ):
            with patch.object(
                schema.json, "loads", side_effect=AssertionError("prebudget missing")
            ) as loads:
                with self.assertRaises(ValueError):
                    schema.parse(raw)
                loads.assert_not_called()
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e9999}'):
            with self.assertRaises(ValueError):
                schema.parse(raw)
        value = {"escaped": '[\\"{}]', "unicode": "e\u0301"}
        self.assertEqual(schema.parse(schema.encode(value)), value)

    def test_child_unknown_fields_wrong_types_and_elapsed_extremes_refuse(self):
        base = packet()["child"]
        for field, bad in (
            ("elapsed_seconds", 10**400),
            ("elapsed_seconds", -(10**400)),
            ("elapsed_seconds", float("nan")),
            ("elapsed_seconds", float("inf")),
            ("elapsed_seconds", True),
            ("authority", 0),
            ("state", "INSTALLED_VERIFIER_30_TESTS_PASS"),
            ("failure_code", "raw unknown error"),
        ):
            value = copy.deepcopy(base)
            value[field] = bad
            with self.subTest(field=field, kind=type(bad).__name__), self.assertRaises(ValueError):
                schema.child(value, EXPECTED)
        for key in ("stdout", "stderr", "logs", "password", "env", "nonce", "SQL"):
            value = {**base, key: "FORBIDDEN_SYNTHETIC"}
            with self.assertRaises(ValueError):
                schema.child(value, EXPECTED)

    def test_testcounts_skips_attempts_missingproofs_are_not_success(self):
        base = packet()["child"]
        for key, bad in (("run", 30), ("skips", 1), ("failures", 1), ("errors", True)):
            value = copy.deepcopy(base)
            value["tests"][key] = bad
            with self.assertRaises(ValueError):
                schema.child(value, EXPECTED)
        for field, bad in (
            ("installed", None),
            ("venv", None),
            ("attempts", {"import.driver": 1}),
            ("probes", {}),
        ):
            value = {**base, field: bad}
            with self.assertRaises(ValueError):
                schema.child(value, EXPECTED)

    def test_canonical_child_packet_transfer_and_failed_diagnostic_remain_distinct(self):
        for success in (True, False):
            raw = schema.encode(packet(success)["child"])
            code, outer = entrypoint_v2.export_child(
                raw,
                0 if success else 1,
                EXPECTED,
                source_sha256=SOURCE,
                expected_input_sha256=INPUT,
                expected_sql_sha256=SQL,
            )
            value = schema.parse(outer, schema.MAX_PACKET)
            self.assertEqual(value["ok"], success)
            self.assertEqual(code, 0 if success else 42)
            self.assertEqual(value["child_sha256"], sha(raw))
            for wrong in (
                b"prefix" + raw,
                raw + b"rawlogs",
                json.dumps(packet(success)["child"]).encode(),
            ):
                with self.assertRaises(ValueError):
                    entrypoint_v2.export_child(
                        wrong,
                        0 if success else 1,
                        EXPECTED,
                        source_sha256=SOURCE,
                        expected_input_sha256=INPUT,
                        expected_sql_sha256=SQL,
                    )

    def test_sql_child_and_descriptor_binding_not_derived_from_packet(self):
        value = packet()
        for field in ("child_bytes", "child_sha256", "source_sha256"):
            changed = copy.deepcopy(value)
            changed[field] = 1 if field == "child_bytes" else "1" * 64
            if field == "source_sha256":
                continue  # Exact external source binding is tested through host_seam.
            with self.assertRaises(ValueError):
                schema.packet(
                    changed, EXPECTED, 0, expected_input_sha256=INPUT, expected_sql_sha256=SQL
                )
