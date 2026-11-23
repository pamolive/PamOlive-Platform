"""Synthetic reports test the C invocation and measurement boundaries locally."""

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from qualification.python_native_provenance import compiler_probe as probe


class CompilerProbeTests(TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.cwd = self.root / "build"
        self.cwd.mkdir()
        self.trace = self.root / "trace"
        self.trace.mkdir()
        self.sdk = self.root / "sdk"
        self.sdk.mkdir()
        self.write(self.cwd, "main.c", b"int main(void) { return 0; }\n")
        self.write(self.cwd, "main.o", b"synthetic C object")
        self.write(self.sdk, "stdlib.h", b"synthetic system header")
        self.write(self.sdk, "libpq.so", b"synthetic system library")

    def write(self, directory, filename, data):
        path = directory / filename
        path.write_bytes(data)
        return path

    def test_compiler_shape_rejects_alternate_translation_units_and_tool_flags(self):
        base = ["-Wsign-compare", "-g", "-fPIC", "-DNDEBUG", "-c", "main.c", "-o", "new.o"]
        self.assertEqual(
            probe.parse_invocation(base, self.cwd),
            (
                "compile",
                [self.cwd / "main.c"],
                self.cwd / "new.o",
            ),
        )
        for flags in (["-x", "c++"], ["-fplugin=extension.so"], ["@flags"], ["-MF", "new.d"]):
            with self.subTest(flags=flags), self.assertRaises(probe.ProbeError):
                probe.parse_invocation([*flags, *base], self.cwd)
        for changed in (base[:-1] + ["../outside.o"], base[:-1] + ["main.o"]):
            with self.subTest(changed=changed), self.assertRaises(probe.ProbeError):
                probe.parse_invocation(changed, self.cwd)

    def test_link_only_accepts_expected_extension_and_libraries(self):
        base = ["-shared", "main.o", "-L../sdk", "-lpq", "-o", "pq.cpython-312-x86_64-linux-gnu.so"]
        self.assertEqual(
            probe.parse_invocation(base, self.cwd, library_roots=(self.sdk,))[0], "link"
        )
        for flags in (["-lstdc++"], ["-Wl,@link"], ["-Wl,-T,layout"], ["main.o"]):
            with self.subTest(flags=flags), self.assertRaises(probe.ProbeError):
                probe.parse_invocation([*flags, *base], self.cwd, library_roots=(self.sdk,))
        with self.assertRaisesRegex(probe.ProbeError, "link_shape"):
            probe.parse_invocation([*base[:-1], "other.so"], self.cwd, library_roots=(self.sdk,))

    def test_dependencies_include_system_headers_and_bind_primary_source(self):
        body = b"pamolive-provenance: main.c \\\n ../sdk/stdlib.h\n"
        actual = probe.read_dependencies(
            body, self.cwd, self.cwd / "main.c", include_roots=(self.sdk,)
        )
        self.assertEqual(actual, [probe.measured(self.sdk / "stdlib.h")])
        with self.assertRaisesRegex(probe.ProbeError, "dependency_source"):
            probe.read_dependencies(
                b"pamolive-provenance: ../sdk/stdlib.h main.c\n",
                self.cwd,
                self.cwd / "main.c",
                include_roots=(self.sdk,),
            )

    def test_ld_map_preserves_order_and_refuses_unlisted_objects_and_static_libraries(self):
        args = (self.cwd, [self.cwd / "main.o"])
        loads = b"LOAD main.o\n LOAD ../sdk/libpq.so\nLOAD ../sdk/libpq.so\n"
        records = probe.read_load_entries(loads, *args, library_roots=(self.sdk,))
        self.assertEqual(
            [row["path"] for row in records],
            [
                str(self.cwd / "main.o"),
                str(self.sdk / "libpq.so"),
                str(self.sdk / "libpq.so"),
            ],
        )
        self.write(self.cwd, "extra.o", b"synthetic")
        self.write(self.sdk, "libextra.a", b"synthetic")
        for added in (b"LOAD extra.o\n", b"LOAD ../sdk/libextra.a\n"):
            with self.subTest(added=added), self.assertRaises(probe.ProbeError):
                probe.read_load_entries(loads + added, *args, library_roots=(self.sdk,))
        with self.assertRaisesRegex(probe.ProbeError, "link_objects_missing"):
            probe.read_load_entries(b"LOAD ../sdk/libpq.so\n", *args, library_roots=(self.sdk,))

    def test_record_publishes_measured_inputs_and_dependency_bytes_after_success(self):
        self.write(self.cwd, "local.h", b"synthetic project header")
        arguments = ["-c", "main.c", "-o", "new.o"]
        dependency = b"pamolive-provenance: main.c local.h\n"
        observed_tool = {"path": "/usr/bin/fake-gcc", "version": "14.2.0", "machine": probe.TRIPLE}

        def run(argv, *, cwd, env, timeout, check):
            self.assertEqual(argv[0], probe.GCC)
            self.assertEqual(argv[1:5], arguments)
            self.assertEqual(cwd, self.cwd)
            self.assertEqual(argv[-2:], ["-MT", "pamolive-provenance"])
            self.assertIn("-MD", argv)
            Path(argv[argv.index("-MF") + 1]).write_bytes(dependency)
            self.write(cwd, "new.o", b"compiled synthetic object")
            return subprocess.CompletedProcess(argv, 0)

        with (
            patch.object(probe, "gcc_tool", return_value=observed_tool),
            patch.object(
                probe.subprocess,
                "run",
                side_effect=run,
            ),
        ):
            probe.record(arguments, self.cwd, self.trace, {})
        (receipt,) = self.trace.glob("compile-*.json")
        report = json.loads(receipt.read_bytes())
        self.assertEqual(report["kind"], "compile")
        self.assertEqual(report["tool"], observed_tool)
        self.assertEqual(report["source"], probe.measured(self.cwd / "main.c"))
        self.assertEqual(report["output"], probe.measured(self.cwd / "new.o"))
        self.assertEqual(report["dependency_sha256"], hashlib.sha256(dependency).hexdigest())
        self.assertEqual(receipt.with_suffix(".d").read_bytes(), dependency)
        self.assertEqual(report["headers"], [probe.measured(self.cwd / "local.h")])

    def test_failed_compiler_produces_no_success_report(self):
        with (
            patch.object(probe, "gcc_tool", return_value={}),
            patch.object(
                probe.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(1, ["gcc"]),
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            probe.record(["-c", "main.c", "-o", "new.o"], self.cwd, self.trace, {})
        self.assertEqual(list(self.trace.iterdir()), [])

    def test_environment_overrides_are_refused(self):
        value = probe.gcc_environment({"PATH": "/foreign/bin"})
        self.assertEqual(value["PATH"], "/usr/bin:/bin")
        for key in ("LD_PRELOAD", "COMPILER_PATH", "C_INCLUDE_PATH"):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(probe.ProbeError, "compiler_environment"),
            ):
                probe.gcc_environment({key: "/foreign"})
