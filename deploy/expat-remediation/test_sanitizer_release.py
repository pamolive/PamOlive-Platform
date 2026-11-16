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
            ):
                s.main(root / "materials", root / "output")
            auth.assert_called_once()
            self.assertEqual(
                [row[1]["stage"] for row in calls],
                ["ubsan-configure", "ubsan-build", "ubsan-check"],
            )
            self.assertEqual(
                calls[0][0][1:],
                ["--disable-shared", "--enable-static", "--disable-maintainer-mode"],
            )
            self.assertEqual(calls[1][0], ["/usr/bin/make", "-j1"])
            self.assertEqual(calls[2][0], ["/usr/bin/make", "-j1", "check"])
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
