"""Release DATA and actual Python control flow; no configure/compiler is run."""

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import check_sanitizer as s
import test_models

PIN = "5466a341f9c692ef7a958a6881311be597f8e1ce345984cf78414f54793dea4c"


def capture():
    raw = (test_models.MATERIALS / "expat-2.10.0.tar.gz").read_bytes()
    if hashlib.sha256(raw).hexdigest() != PIN:
        raise ValueError("test_release_pin")
    return raw


class SanitizerRelease(unittest.TestCase):
    def test_authenticated_generated_release_supports_disabled_maintainer_mode(self):
        with tarfile.open(fileobj=io.BytesIO(capture()), mode="r:gz") as archive:

            def body(name):
                return archive.extractfile("expat-2.10.0/" + name).read().decode()

            self.assertIn("AM_MAINTAINER_MODE([enable])", body("configure.ac"))
            configure = body("configure")
            self.assertIn("--disable-maintainer-mode", configure)
            self.assertIn(
                "enableval=$enable_maintainer_mode; USE_MAINTAINER_MODE=$enableval", configure
            )
            self.assertIn("MAINTAINER_MODE_TRUE='#'", configure)
            for name in ("Makefile.in", "lib/Makefile.in", "tests/Makefile.in"):
                generated = body(name)
                for target in (
                    "$(srcdir)/Makefile.in:",
                    "$(top_srcdir)/configure:",
                    "$(ACLOCAL_M4):",
                ):
                    line = next(line for line in generated.splitlines() if line.startswith(target))
                    self.assertIn("@MAINTAINER_MODE_TRUE@", line)
                    # Exact generated substitution comments dependencies, not make/check targets.
                    expanded = line.replace("@MAINTAINER_MODE_TRUE@", "#")
                    self.assertEqual(expanded.split(":", 1)[1].split("#", 1)[0].strip(), "")
            self.assertRegex(body("tests/Makefile.in"), r"(?m)^check-TESTS:")

    def test_release_dates_and_extraction_order_explain_regeneration(self):
        with tarfile.open(fileobj=io.BytesIO(capture()), mode="r:gz") as archive:
            members = archive.getmembers()
            rows = {row.name.removeprefix("expat-2.10.0/"): row for row in members}
            sequence = {
                row.name.removeprefix("expat-2.10.0/"): index for index, row in enumerate(members)
            }
            self.assertLess(rows["configure.ac"].mtime, rows["aclocal.m4"].mtime)
            self.assertLessEqual(rows["aclocal.m4"].mtime, rows["configure"].mtime)
            self.assertLessEqual(rows["configure"].mtime, rows["Makefile.in"].mtime)
            # acinclude.m4 is an aclocal prerequisite, older in release DATA
            # but written later by the extractor.
            self.assertLess(rows["acinclude.m4"].mtime, rows["aclocal.m4"].mtime)
            self.assertGreater(sequence["acinclude.m4"], sequence["aclocal.m4"])

    def test_actual_main_keeps_instrumentation_full_check_and_closed_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            def step(args, source, log, **options):
                calls.append((args, options))
                actual = (source / "lib/xmlparse.c").read_bytes()
                self.assertEqual(actual.count(b'"counter_type"'), 2)
                self.assertIn(b"if (attIndex > INT_MAX)", actual)

            with (
                patch.object(s, "authenticate") as auth,
                patch.object(s, "material", return_value=capture()),
                patch.object(s, "build_step", side_effect=step),
                patch.object(s, "advisory_parser", return_value={}),
                patch.object(s, "advisory_cli", return_value={}),
            ):
                s.main(root / "materials", root / "output")
            auth.assert_called_once()
            self.assertEqual(
                [row[1]["stage"] for row in calls],
                ["ubsan-configure", "ubsan-build", "ubsan-build", "ubsan-check"],
            )
            self.assertEqual(
                calls[0][0][1:],
                ["--disable-shared", "--enable-static", "--disable-maintainer-mode"],
            )
            self.assertEqual(calls[1][0], ["/usr/bin/make", "-j1"])
            self.assertEqual(calls[3][0], ["/usr/bin/make", "-j1", "check"])
            for _, options in calls:
                self.assertIn("-fsanitize=undefined", options["env"]["CFLAGS"])
                self.assertIn("-fno-sanitize-recover=all", options["env"]["CFLAGS"])
                self.assertEqual(
                    options["env"]["UBSAN_OPTIONS"], "halt_on_error=1:print_stacktrace=0"
                )
            receipt = json.loads((root / "output/SANITIZER.json").read_bytes())
            self.assertTrue(receipt["UBSan"])
            self.assertFalse(receipt["fixed4_admitted"])

    def test_configure_failure_stops_before_make_and_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = ValueError("unsupported_or_failed_configure")
            with (
                patch.object(s, "authenticate"),
                patch.object(s, "material", return_value=capture()),
                patch.object(s, "build_step", side_effect=original) as step,
            ):
                with self.assertRaises(ValueError) as caught:
                    s.main(root / "materials", root / "output")
            self.assertIs(caught.exception, original)
            self.assertEqual(step.call_count, 1)
            self.assertFalse((root / "output/SANITIZER.json").exists())


class LocalBackportTests(unittest.TestCase):
    def original(self):
        import source_audit as audit

        raw = capture()
        return {
            name: audit.member(raw, "expat-2.10.0/" + name.removeprefix("expat/"))
            for name in audit.FILE_PINS
        }

    def test_two_exact_patches_and_all_prepost_images_for_both_source_models(self):
        import source_audit as audit

        made = audit.transform(self.original(), audit.capture_patches())
        self.assertEqual(set(made), set(audit.FILE_PINS))
        self.assertEqual(len(audit.PATCHES), 2)
        for name, body in made.items():
            self.assertEqual(hashlib.sha256(body).hexdigest(), audit.FILE_PINS[name]["post_sha256"])
        for debian in (True, False):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name, body in self.original().items():
                    path = root / (name if debian else name.removeprefix("expat/"))
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
                value = audit.apply_backports(root, root / "proof.json", debian=debian)
                self.assertEqual(value, audit.proof())
                self.assertFalse(value["upstream_signature_covers_local_changes"])
                for name, body in made.items():
                    path = root / (name if debian else name.removeprefix("expat/"))
                    self.assertEqual(path.read_bytes(), body)

    def test_mutation_missing_duplicate_and_already_applied_source_refuse(self):
        import source_audit as audit

        originals, patches = self.original(), audit.capture_patches()
        for name in patches:
            bad = dict(patches)
            bad[name] += patches[name]
            with self.assertRaisesRegex(ValueError, "backport_patch_pin"):
                audit.transform(originals, bad)
        for name in originals:
            bad = dict(originals)
            bad[name] += b"\n/* mutation */\n"
            with self.assertRaisesRegex(ValueError, "backport_preimage"):
                audit.transform(bad, patches)
        with self.assertRaisesRegex(ValueError, "backport_source_closure"):
            audit.transform({}, patches)
        with self.assertRaisesRegex(ValueError, "backport_patch_closure"):
            audit.transform(originals, patches | {"foreign": b""})
        with self.assertRaisesRegex(ValueError, "backport_preimage"):
            audit.transform(audit.transform(originals, patches), patches)

    def test_all_capture_checks_precede_writes_and_mutation_refuses(self):
        import source_audit as audit

        originals = self.original()
        calls = 0
        patches = audit.capture_patches()

        def captured(path, cap):
            nonlocal calls
            calls += 1
            name = "expat/" + path.as_posix().split("root/", 1)[1]
            return originals[name] + (b"changed" if calls > 4 else b"")

        with (
            patch.object(audit, "read", side_effect=captured),
            patch.object(audit, "capture_patches", return_value=patches),
            patch.object(Path, "write_bytes") as wrote,
            self.assertRaisesRegex(ValueError, "backport_source_changed"),
        ):
            audit.apply_backports(Path("/root"), Path("/receipt"), debian=False)
        wrote.assert_not_called()

    def test_authentication_failure_precedes_tar_parsing_and_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = ValueError("authentication_refused")
            with (
                patch.object(s, "authenticate", side_effect=original),
                patch.object(s, "material") as material,
                patch.object(s, "apply_backports") as backport,
                self.assertRaises(ValueError) as caught,
            ):
                s.main(root / "inputs", root / "output")
            self.assertIs(caught.exception, original)
            material.assert_not_called()
            backport.assert_not_called()

    def test_native_parser_argv_keeps_budgets_flags_and_before_mode_closed(self):
        for before in (True, False):
            calls = []
            with patch.object(s, "command", side_effect=lambda *a, **kw: calls.append((a, kw))):
                value = s.advisory_parser(
                    Path("/source"), Path("/output"), {"CC": "fixed"}, before=before
                )
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][1]["seconds"], 60)
            self.assertEqual(calls[1][1]["seconds"], 5)
            self.assertEqual(calls[1][1]["cap"], 16384)
            self.assertIn("-fsanitize=undefined", calls[0][0][0])
            self.assertIn(str(Path("/source/lib/.libs/libexpat.a")), calls[0][0][0])
            self.assertEqual(calls[1][0][0][1:], ["--advisory-124317-before"] if before else [])
            self.assertFalse(value["actual_unsafe_read_performed"])

    def cli_case(self, before=False, mutate=None):
        # Fake child only. No symlink or executable is created on this PC.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "source", root / "output"
            source.mkdir()
            output.mkdir()

            def command(args, cwd, log, **options):
                self.assertEqual(options["seconds"], 5)
                self.assertEqual(options["cap"], 16384)
                log.mkdir()
                facts = {
                    "spawn_attempted": True,
                    "pid": 12,
                    "returncode": 0 if before else 3,
                    "reason": None if before else "nonzero_exit",
                    "exception_type": None,
                    "killed_owned_child": False,
                    "owned_child_reaped": True,
                    "drains_complete": True,
                    "cleanup_exception_type": None,
                    "stdout_bytes": 0,
                    "stderr_bytes": 0,
                }
                if mutate:
                    mutate(facts)
                values = {
                    "result.json": facts,
                    "pid.json": {"pid": 12},
                    "intent.json": {
                        "argv": args,
                        "tool_sha256": hashlib.sha256(b"ELF").hexdigest(),
                    },
                    "unknown.json": {"state": "UNKNOWN"},
                }
                for name, value in values.items():
                    (log / name).write_bytes(json.dumps(value).encode())
                (log / "stdout").write_bytes(b"")
                (log / "stderr").write_bytes(b"")
                if before:
                    (source / "advisory-128241-before/victim").write_bytes(b"overwritten")
                    return b""
                raise ValueError("child_failed_or_unknown")

            actual_read = s.read

            def read(path, cap):
                return b"ELF" if path.name == "xmlwf" else actual_read(path, cap)

            with (
                patch.object(s, "command", side_effect=command),
                patch.object(s, "read", side_effect=read),
                patch.object(Path, "symlink_to"),
                patch.object(Path, "is_symlink", lambda path: path.name == "case.xml"),
            ):
                return s.advisory_cli(source, output, {}, before=before)

    def test_cli_expected_refusal_keeps_unknown_and_synthetic_victim(self):
        after, before = self.cli_case(), self.cli_case(before=True)
        self.assertEqual(after["returncode"], 3)
        self.assertTrue(after["expected_nonzero_unknown_retained"])
        self.assertTrue(after["victim_unchanged"])
        self.assertFalse(before["victim_unchanged"])

    def test_cli_timeout_nonreap_wrongrc_and_unbound_bytes_never_pass(self):
        for key, value in (
            ("reason", "timeout"),
            ("owned_child_reaped", False),
            ("drains_complete", False),
            ("returncode", 2),
            ("stderr_bytes", 1),
            ("killed_owned_child", True),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.cli_case(mutate=lambda facts: facts.update({key: value}))
