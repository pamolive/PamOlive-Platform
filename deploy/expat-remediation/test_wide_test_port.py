"""Pure boundary tests for the test-only port; no compiler or XML parser."""

import tarfile
import unittest
from pathlib import Path
from unittest import mock

import source_audit
import test_models
import wide_test_port as wide


class WideTestPortTests(unittest.TestCase):
    def buffers(self):
        return {name: (Path(wide.HERE) / name).read_bytes() for name in wide.BUNDLE}

    def source(self):
        with tarfile.open(test_models.MATERIALS / "expat_2.10.0.orig.tar.gz") as archive:
            pins = wide.validate_capture(self.buffers())
            buffers = {
                name: archive.extractfile("libexpat-R_2_10_0/expat/" + name).read()
                for name in pins["files"]
            }
            original = {
                name: archive.extractfile("libexpat-R_2_10_0/" + name).read()
                for name in source_audit.FILE_PINS
            }
            made = source_audit.transform(original, source_audit.capture_patches())
            buffers["tests/misc_tests.c"] = made["expat/tests/misc_tests.c"]
            return buffers

    def test_exact_closed_bundle_and_original_35_sources_are_accepted(self):
        pins = wide.validate_capture(self.buffers())
        self.assertEqual(pins["START_TEST_count"], 445)
        self.assertEqual(len(pins["changed"]), 7)
        wide.validate_tree(self.source(), pins["files"], "before")

    def test_corrupt_patch_header_selftest_or_manifest_refuses(self):
        for name in wide.BUNDLE:
            data = self.buffers()
            data[name] += b"changed"
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "wide_bundle_pin"):
                wide.validate_capture(data)

    def test_missing_and_extra_bundle_source_cannot_autoapprove(self):
        data = self.buffers()
        data.pop(next(iter(data)))
        with self.assertRaisesRegex(ValueError, "wide_bundle_closure"):
            wide.validate_capture(data)
        data = self.buffers() | {"foreign": b"public but not approved"}
        with self.assertRaisesRegex(ValueError, "wide_bundle_closure"):
            wide.validate_capture(data)

    def test_changed_case_or_oom_code_refuses_before_patch_command(self):
        pins = wide.validate_capture(self.buffers())
        for name in ("tests/basic_tests.c", "tests/alloc_tests.c", "tests/nsalloc_tests.c"):
            source = self.source()
            source[name] += b"\n/* changed assertion/case/allocator */\n"
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "wide_tree_pin"):
                wide.validate_tree(source, pins["files"], "before")
        with self.assertRaisesRegex(ValueError, "wide_tree_closure"):
            wide.validate_tree({}, pins["files"], "before")

    def test_actual_multi_file_patch_has_exact_context_and_post_hashes(self):
        """Apply unified-diff DATA strictly, without invoking GNU patch on this PC."""
        pins = wide.validate_capture(self.buffers())
        source = self.source()
        text = self.buffers()["expat-ushort-tests.patch"].splitlines(keepends=True)
        index = 0
        while index < len(text):
            self.assertTrue(text[index].startswith(b"--- a/tests/"))
            name = text[index].split(b"a/", 1)[1].strip().decode()
            self.assertEqual(text[index + 1], ("+++ b/" + name + "\n").encode())
            old = source[name].splitlines(keepends=True)
            made, position = [], 0
            index += 2
            while index < len(text) and text[index].startswith(b"@@"):
                row = text[index].decode().split()
                begin, old_count = map(int, row[1][1:].split(","))
                _, new_count = map(int, row[2][1:].split(","))
                made += old[position : begin - 1]
                position = begin - 1
                index += 1
                consumed = produced = 0
                while index < len(text) and text[index][:1] in (b" ", b"+", b"-"):
                    if text[index].startswith((b"--- a/", b"+++ b/")):
                        break
                    kind, content = text[index][:1], text[index][1:]
                    if kind in (b" ", b"-"):
                        self.assertEqual(old[position], content)
                        position += 1
                        consumed += 1
                    if kind in (b" ", b"+"):
                        made.append(content)
                        produced += 1
                    index += 1
                self.assertEqual((consumed, produced), (old_count, new_count))
            made += old[position:]
            source[name] = b"".join(made)
        wide.validate_tree(source, pins["files"], "after")

    def test_suite_summary_needs_real_nonzero_twelve_way_complete_pass(self):
        trs = b":test-result: PASS\n:global-test-result: PASS\n"
        valid = wide.test_summary(b"public log\n100%: Checks: 24, Failed: 0\n", trs)
        self.assertEqual(valid["checks"], 24)
        for log in (
            b"100%: Checks: 0, Failed: 0\n",
            b"100%: Checks: 23, Failed: 0\n",
            b"99%: Checks: 24, Failed: 1\n",
            b"100%: Checks: 24, Failed: 0\n" * 2,
            b"PASS: runtests\n",
            b"100%: Checks: 24, Failed: 1\n",
        ):
            with self.subTest(log=log), self.assertRaises(ValueError):
                wide.test_summary(log, trs)

    def test_failed_skipped_unknown_or_duplicate_trs_never_passes(self):
        log = b"100%: Checks: 24, Failed: 0\n"
        for trs in (
            b"",
            b":test-result: SKIP\n:global-test-result: PASS\n",
            b":test-result: PASS\n:global-test-result: ERROR\n",
            b":test-result: PASS\n:global-test-result: UNKNOWN\n",
            b":test-result: PASS\n:global-test-result: PASS\n:test-result: PASS\n",
        ):
            with self.subTest(trs=trs), self.assertRaises(ValueError):
                wide.test_summary(log, trs)

    def test_wide_and_narrow_counts_must_match(self):
        def data(path, _cap):
            if path.name.endswith(".trs"):
                return b":test-result: PASS\n:global-test-result: PASS\n"
            number = b"24" if "buildw" in path.parts else b"12"
            return b"100%: Checks: " + number + b", Failed: 0\n"

        with (
            mock.patch.object(wide, "read", side_effect=data),
            self.assertRaisesRegex(ValueError, "wide_narrow_counts_differ"),
        ):
            wide.suite_counts(Path("/synthetic"))

    def test_helper_failure_keeps_h1_exception_and_publishes_only_closed_stage(self):
        error = ValueError("child_failed_or_unknown")
        for failure in (None, ValueError("diagnostic unavailable")):
            with (
                mock.patch.object(wide, "command", side_effect=error),
                self.assertRaises(ValueError) as caught,
            ):
                publish = mock.Mock(side_effect=failure)
                wide.check_helpers(Path("/source"), Path("/output"), publish)
            self.assertIs(caught.exception, error)
            publish.assert_called_once_with(
                Path("/output/helper-compile"), stage="wide-helper-compile"
            )

    def test_helpers_use_explicit_c11_real_header_and_bounded_child(self):
        with mock.patch.object(wide, "command", return_value=b"") as command:
            wide.check_helpers(Path("/source"), Path("/output"), mock.Mock())
        self.assertEqual(len(command.call_args_list), 2)
        args = command.call_args_list[0].args[0]
        self.assertIn("-std=c11", args)
        self.assertIn("-DXML_UNICODE", args)
        self.assertNotIn("-DXML_UNICODE_WCHAR_T", args)
        self.assertNotIn("-fshort-wchar", args)
        self.assertEqual(command.call_args_list[1].kwargs, {"seconds": 5, "cap": 65536})
