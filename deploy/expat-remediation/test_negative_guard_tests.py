"""Fake processes only; exercise the actual refusal consumer and closed argv."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import negative_guard_tests as guard
from common import record, sha, write_new

PIN = {"target": "/usr/bin/compiler-real", "identity": [1, 2, 3], "sha256": "a" * 64}


def facts():
    return {
        "spawn_attempted": True,
        "pid": 123,
        "returncode": 1,
        "reason": "nonzero_exit",
        "exception_type": None,
        "killed_owned_child": False,
        "owned_child_reaped": True,
        "drains_complete": True,
        "cleanup_exception_type": None,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }


def diagnostic(case, header, secondary=False):
    return {
        "kind": "error",
        "children": [],
        "locations": [
            {
                "caret": {
                    "file": str(header),
                    "line": 34 if secondary else guard.GUARD_LINES[case],
                    "column": 1,
                }
            }
        ],
        "message": guard.SECONDARY if secondary else guard.GUARDS[case],
    }


class NegativeGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.header = self.root / guard.HEADER
        self.case = "c99"
        self.rows = [diagnostic(self.case, self.header)]
        self.facts = facts()
        self.raw = None
        self.exception = ValueError("child_failed_or_unknown")
        self.stdout = b""
        self.missing = None
        self.intent_change = False
        self.pid_change = False
        self.unknown_change = False
        self.calls = []

    def command(self, args, cwd, log, **kwargs):
        self.calls.append((args, cwd, log, kwargs))
        log.mkdir(mode=0o700)
        err = self.raw if self.raw is not None else json.dumps(self.rows).encode()
        value = copy.deepcopy(self.facts)
        value["stdout_bytes"], value["stderr_bytes"] = len(self.stdout), len(err)
        intent = {
            "state": "PENDING",
            "argv": args,
            "tool_target": PIN["target"],
            "tool_sha256": "b" * 64 if self.intent_change else PIN["sha256"],
        }
        record(log / "intent.json", intent)
        record(log / "pid.json", {"pid": 999 if self.pid_change else value["pid"]})
        if self.missing != "result.json":
            record(log / "result.json", value)
        write_new(log / "stdout", self.stdout)
        write_new(log / "stderr", err)
        if self.missing != "unknown.json":
            record(log / "unknown.json", {"state": "OTHER" if self.unknown_change else "UNKNOWN"})
        if self.exception is not None:
            raise self.exception
        return b""

    def run_case(self, pins=None):
        with (
            patch.object(guard, "command", self.command),
            patch.object(
                guard, "compiler_pin", side_effect=pins or [copy.deepcopy(PIN), copy.deepcopy(PIN)]
            ),
        ):
            return guard.expected_refusal(
                ["/usr/bin/gcc", "-fsyntax-only", "probe.c"],
                self.root,
                self.root / "command",
                self.case,
                self.header,
            )

    def test_expected_nonzero_preserves_unknown(self):
        result = self.run_case()
        raw = (self.root / "command/unknown.json").read_bytes()
        self.assertEqual(json.loads(raw), {"state": "UNKNOWN"})
        self.assertEqual(result["common_unknown_retained_sha256"], sha(raw))
        self.assertFalse(result["compiler_command_succeeded"])
        self.assertEqual(self.calls[0][3], {"seconds": 20, "cap": 16384})

    def test_cancellation_propagates(self):
        self.exception = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_case()

    def test_exception_must_be_exact(self):
        self.exception = ValueError("tool_changed")
        with self.assertRaisesRegex(ValueError, "negative_exception"):
            self.run_case()

    def test_normal_return_is_never_expected_failure(self):
        self.exception = None
        with self.assertRaisesRegex(ValueError, "negative_unexpected_success"):
            self.run_case()

    def test_zero_signal_boolean_returncodes_refuse(self):
        for rc in (0, -9, True, None, 256):
            with self.subTest(rc=rc):
                value = facts()
                value["returncode"] = rc
                with self.assertRaisesRegex(ValueError, "negative_exit"):
                    guard.lifecycle(value, b"", b"")

    def test_incomplete_h1_never_heals(self):
        cases = {
            "spawn_attempted": False,
            "owned_child_reaped": False,
            "drains_complete": False,
            "killed_owned_child": True,
            "exception_type": "OSError",
            "cleanup_exception_type": "TimeoutExpired",
            "pid": True,
        }
        for name, value in cases.items():
            with self.subTest(field=name):
                row = facts()
                row[name] = value
                with self.assertRaisesRegex(ValueError, "negative_h1"):
                    guard.lifecycle(row, b"", b"")

    def test_timeout_and_explicit_unknown_refuse(self):
        row = facts()
        row["reason"] = "timeout"
        with self.assertRaisesRegex(ValueError, "negative_exit"):
            guard.lifecycle(row, b"", b"")
        row = facts()
        row["unknown"] = True
        with self.assertRaisesRegex(ValueError, "negative_facts_type"):
            guard.lifecycle(row, b"", b"")

    def test_stream_counts_are_actual(self):
        with self.assertRaisesRegex(ValueError, "negative_stream_facts"):
            guard.lifecycle(facts(), b"extra", b"")

    def test_missing_receipt_refuses(self):
        self.missing = "result.json"
        with self.assertRaises(OSError):
            self.run_case()

    def test_missing_unknown_refuses(self):
        self.missing = "unknown.json"
        with self.assertRaises(OSError):
            self.run_case()

    def test_compiler_changed_refuses(self):
        changed = copy.deepcopy(PIN)
        changed["identity"] = [1, 3, 3]
        with self.assertRaisesRegex(ValueError, "negative_compiler_changed"):
            self.run_case([copy.deepcopy(PIN), changed])

    def test_intent_not_our_tool_refuses(self):
        self.intent_change = True
        with self.assertRaisesRegex(ValueError, "negative_intent"):
            self.run_case()

    def test_foreign_pid_refuses(self):
        self.pid_change = True
        with self.assertRaisesRegex(ValueError, "negative_pid"):
            self.run_case()

    def test_unknown_journal_not_reclassified(self):
        self.unknown_change = True
        with self.assertRaisesRegex(ValueError, "negative_unknown_journal"):
            self.run_case()

    def test_unrelated_compile_error_refuses(self):
        self.rows[0]["message"] = "fatal error: expat.h: No such file or directory"
        with self.assertRaisesRegex(ValueError, "negative_guard_missing"):
            self.run_case()

    def test_guard_plus_other_error_refuses(self):
        other = copy.deepcopy(self.rows[0])
        other["message"] = "syntax error"
        self.rows.append(other)
        with self.assertRaisesRegex(ValueError, "negative_other_diagnostic"):
            self.run_case()

    def test_foreign_header_or_line_refuses(self):
        for key, value in (("file", "SDK/expat.h"), ("line", 99)):
            row = diagnostic("c99", self.header)
            row["locations"][0]["caret"][key] = value
            with (
                self.subTest(field=key),
                self.assertRaisesRegex(ValueError, "negative_diagnostic_header"),
            ):
                guard.diagnostics(json.dumps([row]).encode(), "c99", self.header)

    def test_xmlchar_secondary_is_finite(self):
        rows = [diagnostic("xmlchar", self.header), diagnostic("xmlchar", self.header, True)]
        self.assertEqual(guard.diagnostics(json.dumps(rows).encode(), "xmlchar", self.header), 2)
        with self.assertRaisesRegex(ValueError, "negative_guard_missing"):
            guard.diagnostics(json.dumps(rows[1:]).encode(), "xmlchar", self.header)
        rows.append(rows[1])
        with self.assertRaisesRegex(ValueError, "negative_diagnostics_count"):
            guard.diagnostics(json.dumps(rows).encode(), "xmlchar", self.header)

    def test_malformed_json_and_duplicate_refuse(self):
        for raw in (b"not JSON", b'{"a":1,"a":2}', b"NaN", b"[] trailing"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                guard.json_value(raw)

    def test_stdout_not_diagnostics_refuses(self):
        self.stdout = b"unexpected"
        with self.assertRaisesRegex(ValueError, "negative_stdout"):
            self.run_case()

    def test_probe_orchestration_and_private_header(self):
        source, output = self.root / "source", self.root / "output"
        tests = source / "srcw/tests"
        tests.mkdir(parents=True)
        (source / "srcw/lib").mkdir()
        (output / "work").mkdir(parents=True)
        write_new(tests / guard.HEADER, b"approved header")
        write_new(tests / "test_character_support_selftest.c", b"approved selftest")
        bundle = {
            guard.HEADER: sha(b"approved header"),
            "test_character_support_selftest.c": sha(b"approved selftest"),
        }
        sequence = []

        def expected(args, cwd, log, case, header):
            sequence.append(case)
            self.assertEqual(header.read_bytes(), b"approved header")
            self.assertEqual((header.parent / "probe.c").read_bytes(), guard.PROBE)
            self.assertEqual(args[0], "/usr/bin/g++" if case == "cxx" else "/usr/bin/gcc")
            self.assertIn("-fsyntax-only", args)
            self.assertIn("-fdiagnostics-format=json", args)
            self.assertIn("-I" + str(source / "srcw/lib"), args)
            self.assertNotIn("-o", args)
            if case == "xmlchar":
                self.assertEqual((header.parent / "expat.h").read_bytes(), guard.FAKE)
            else:
                self.assertFalse((header.parent / "expat.h").exists())
            return {"case": case, "expected_guard": True}

        with (
            patch.dict(guard.BUNDLE, bundle),
            patch.object(
                guard, "positive_prerequisite", side_effect=lambda _: sequence.append("positive")
            ),
            patch.object(guard, "expected_refusal", expected),
        ):
            guard.check_negative_guards(source, output)
        self.assertEqual(sequence, ["positive", "c99", "cxx", "xmlchar"])
        self.assertEqual(list((source / "srcw/lib").iterdir()), [])
        receipt = json.loads((output / "NEGATIVE-GUARDS.json").read_bytes())
        self.assertFalse(receipt["common_commands_admitted"])
        self.assertFalse(receipt["operational_GO"])
        self.assertFalse(receipt["CVE_closed"])
        self.assertNotIn("stderr", receipt)

    def test_positive_prerequisite_blocks_negatives(self):
        source, output = self.root / "source", self.root / "output"
        (source / "srcw/tests").mkdir(parents=True)
        write_new(source / "srcw/tests" / guard.HEADER, b"header")
        write_new(source / "srcw/tests/test_character_support_selftest.c", b"selftest")
        with (
            patch.dict(
                guard.BUNDLE,
                {
                    guard.HEADER: sha(b"header"),
                    "test_character_support_selftest.c": sha(b"selftest"),
                },
            ),
            patch.object(
                guard, "positive_prerequisite", side_effect=ValueError("positive_not_complete")
            ),
            patch.object(guard, "command") as command,
        ):
            with self.assertRaisesRegex(ValueError, "positive_not_complete"):
                guard.check_negative_guards(source, output)
        command.assert_not_called()
        self.assertFalse((output / "NEGATIVE-GUARDS.json").exists())
        output.mkdir()
        for name in ("helper-compile", "helper-run"):
            log = output / name
            log.mkdir()
            out = (
                b""
                if name == "helper-compile"
                else json.dumps(
                    {
                        "schema": "pamolive.expat-ushort-helper/1",
                        "passed": True,
                        "helper_uses_heap": False,
                    }
                ).encode()
            )
            row = facts()
            row.update(returncode=0, reason=None, stdout_bytes=len(out))
            record(log / "result.json", row)
            record(log / "pid.json", {"pid": row["pid"]})
            write_new(log / "stdout", out)
            write_new(log / "stderr", b"")
        guard.positive_prerequisite(output)
        record(output / "helper-run/unknown.json", {"state": "UNKNOWN"})
        with self.assertRaisesRegex(ValueError, "negative_positive_unknown"):
            guard.positive_prerequisite(output)
