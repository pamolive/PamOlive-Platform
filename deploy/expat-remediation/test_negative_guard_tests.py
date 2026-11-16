"""Fake processes only; exercise the actual refusal consumer and closed argv."""

import ast
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

    def run_case(self, pins=None, *, evidence=None):
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
                evidence=evidence,
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

        def expected(args, cwd, log, case, header, *, evidence):
            sequence.append(case)
            self.assertEqual(evidence, output / "negative-guard-evidence" / case)
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

    def public_case(self, case="c99"):
        parent = self.root / "negative-guard-evidence"
        parent.mkdir()
        return parent / case

    def test_public_evidence_is_exact_six_buffers_and_hashes(self):
        evidence = self.public_case()
        original = self.command

        def extra_files(*args, **kwargs):
            try:
                return original(*args, **kwargs)
            finally:
                log = args[2]
                write_new(log / "foreign.so", b"synthetic DATA, never execute")
                (log / "gpg-home").mkdir()
                write_new(log / "gpg-home/private", b"not exported")

        self.command = extra_files
        result = self.run_case(evidence=evidence)
        self.assertEqual(set(result["evidence"]["files"]), set(guard.EVIDENCE_FILES))
        self.assertEqual({path.name for path in evidence.iterdir()}, set(guard.EVIDENCE_FILES))
        self.assertEqual(result["evidence"]["path"], "negative-guard-evidence/c99")
        for name, row in result["evidence"]["files"].items():
            body = (evidence / name).read_bytes()
            self.assertEqual(body, (self.root / "command" / name).read_bytes())
            self.assertEqual(row, {"bytes": len(body), "sha256": sha(body)})
        self.assertEqual(json.loads((evidence / "unknown.json").read_bytes()), {"state": "UNKNOWN"})
        self.assertFalse(result["compiler_command_succeeded"])

    def test_single_capture_survives_origin_mutation_without_hash_reread(self):
        evidence = self.public_case()
        reads, captured = [], {}
        original_read, original_diagnostics = guard.read, guard.diagnostics

        def capture(path, cap):
            reads.append(Path(path).name)
            body = original_read(path, cap)
            captured[Path(path).name] = body
            return body

        def change_origin(body, case, header):
            for name in guard.EVIDENCE_FILES:
                (self.root / "command" / name).write_bytes(b"late synthetic mutation")
            return original_diagnostics(body, case, header)

        with (
            patch.object(guard, "read", capture),
            patch.object(guard, "diagnostics", change_origin),
        ):
            result = self.run_case(evidence=evidence)
        self.assertEqual(reads, list(guard.EVIDENCE_FILES))
        for name, body in captured.items():
            self.assertEqual((evidence / name).read_bytes(), body)
            self.assertEqual(result["evidence"]["files"][name]["sha256"], sha(body))
        self.assertEqual(result["common_unknown_retained_sha256"], sha(captured["unknown.json"]))

    def test_captured_pid_mutation_refuses_without_export(self):
        evidence = self.public_case()
        original_read = guard.read

        def altered(path, cap):
            if Path(path).name == "pid.json":
                return b'{"pid":999}'
            return original_read(path, cap)

        with patch.object(guard, "read", altered):
            with self.assertRaisesRegex(ValueError, "negative_pid"):
                self.run_case(evidence=evidence)
        self.assertFalse(evidence.exists())

    def test_preexisting_public_case_refuses_before_command(self):
        evidence = self.public_case()
        evidence.mkdir()
        write_new(evidence / "sentinel", b"keep")
        with self.assertRaisesRegex(ValueError, "negative_evidence_exists"):
            self.run_case(evidence=evidence)
        self.assertEqual(self.calls, [])
        self.assertEqual((evidence / "sentinel").read_bytes(), b"keep")

    def test_late_export_file_collision_propagates_without_overwrite(self):
        evidence = self.public_case()
        original_write = guard.write_new

        def collision(path, body, mode=0o600):
            if path.parent == evidence and path.name == "result.json":
                original_write(path, b"concurrent synthetic file")
            return original_write(path, body, mode)

        with patch.object(guard, "write_new", collision):
            with self.assertRaises(FileExistsError):
                self.run_case(evidence=evidence)
        self.assertEqual((evidence / "result.json").read_bytes(), b"concurrent synthetic file")
        self.assertEqual(
            json.loads((self.root / "command/unknown.json").read_bytes()), {"state": "UNKNOWN"}
        )

    def test_other_two_cases_publish_same_closed_evidence_contract(self):
        for case in ("cxx", "xmlchar"):
            fixture = NegativeGuards()
            fixture.setUp()
            self.addCleanup(fixture.doCleanups)
            fixture.case = case
            fixture.rows = [diagnostic(case, fixture.header)]
            if case == "xmlchar":
                fixture.rows.append(diagnostic(case, fixture.header, True))
            evidence = fixture.public_case(case)
            with self.subTest(case=case):
                result = fixture.run_case(evidence=evidence)
                self.assertEqual(result["case"], case)
                self.assertEqual(result["evidence"]["path"], "negative-guard-evidence/" + case)
                self.assertEqual(set(result["evidence"]["files"]), set(guard.EVIDENCE_FILES))
                self.assertEqual(result["diagnostic_count"], 2 if case == "xmlchar" else 1)
                self.assertEqual(
                    json.loads((evidence / "unknown.json").read_bytes()), {"state": "UNKNOWN"}
                )

    def test_invalid_export_path_or_unknown_case_refuses_before_command(self):
        evidence = self.public_case("other")
        with self.assertRaisesRegex(ValueError, "negative_evidence_path"):
            self.run_case(evidence=evidence)
        self.case = "other"
        with self.assertRaisesRegex(ValueError, "negative_case"):
            self.run_case()
        self.assertEqual(self.calls, [])

    def test_invalid_unknown_never_exports_a_positive_receipt(self):
        evidence = self.public_case()
        self.unknown_change = True
        with self.assertRaisesRegex(ValueError, "negative_unknown_journal"):
            self.run_case(evidence=evidence)
        self.assertFalse(evidence.exists())

    def test_verbose_only_in_same_bounded_stdlib_command(self):
        tree = ast.parse((Path(__file__).parent / "qualify_linux.py").read_text(encoding="utf-8"))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "command"
            and node.args
            and isinstance(node.args[0], ast.List)
            and any(
                isinstance(item, ast.Constant) and item.value == "test_pyexpat"
                for item in node.args[0].elts
            )
        ]
        self.assertEqual(len(calls), 1)
        expected = (
            ast.parse(
                'command(["/usr/local/bin/python3.12", "-I", "-B", "-S", str(launcher), '
                '"--timeout", "60", "--verbose", "test_pyexpat", "test_xml_etree", '
                '"test_xml_etree_c"], output, output / "cpython-tests", '
                'seconds=240, cap=4 * 1024**2)'
            )
            .body[0]
            .value
        )
        self.assertEqual(ast.dump(calls[0]), ast.dump(expected))
