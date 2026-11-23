"""Synthetic consistency tests for lab compiler and wheel evidence."""

import hashlib
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from unittest import TestCase

from qualification.python_native_provenance import compiler_probe
from qualification.python_native_provenance import validate_observations as observer


def file_record(path, *, tag="observed"):
    return {"path": str(path), "size": 256, "sha256": hashlib.sha256(tag.encode()).hexdigest()}


class PythonNativeProvenanceTests(TestCase):
    def setUp(self):
        samples = {
            "cc1": "/usr/lib/gcc/x86_64-linux-gnu/14/cc1",
            "as": "/usr/bin/x86_64-linux-gnu-as",
            "collect2": "/usr/lib/gcc/x86_64-linux-gnu/14/collect2",
            "ld": "/usr/bin/x86_64-linux-gnu-ld",
        }
        tool = {"machine": "x86_64-linux-gnu",
                "subprograms": {key: file_record(path) for key, path in samples.items()}}
        package_records, records = {}, []
        for package, extensions in observer.SDIST_OUTPUTS.items():
            root = PurePosixPath("/tmp/pip-build") / package
            wheel = {"extensions": {}, "source_files": {}, "wheel_sha256": "a" * 64}
            package_records[package] = wheel
            for extension, sources in extensions.items():
                install_path = extension + ".cpython-312-x86_64-linux-gnu.so"
                if package == "psycopg-c":
                    install_path = "psycopg_c/" + install_path
                output = file_record(root / "build" / install_path, tag=install_path)
                wheel["extensions"][install_path] = {key: output[key] for key in ("size", "sha256")}
                objects = []
                for source_name in sorted(sources):
                    source = file_record(root / source_name, tag=source_name)
                    obj = root / "build" / PurePosixPath(source_name).with_suffix(".o")
                    object_record = file_record(obj, tag=source_name + ".object")
                    records.append({"kind": "compile", "cwd": str(root), "tool": tool,
                                    "source": source, "output": object_record, "headers": [
                                        file_record("/usr/local/include/python3.12/Python.h"),
                                        file_record("/usr/include/stdlib.h"),
                                    ]})
                    objects.append(object_record)
                    wheel["source_files"][source_name] = source["sha256"]
                records.append({"kind": "link", "cwd": str(root), "tool": tool, "output": output,
                                "objects": objects, "load": [
                                    *objects, file_record("/usr/lib/gcc/libgcc.a"),
                                ]})
        self.calls = records
        self.derived = package_records

    def test_matches_the_twelve_c_sources_and_three_wheel_elf_outputs(self):
        result = observer.match_calls(self.calls, self.derived)
        self.assertEqual(len(result), 3)
        self.assertEqual(sum(map(lambda row: len(row["sources"]), result.values())), 12)

    def test_rejects_link_output_when_wheel_elf_is_different(self):
        output = next(row["output"] for row in self.calls if row["kind"] == "link")
        output["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "compiler_link_wheel_digest"):
            observer.match_calls(self.calls, self.derived)

    def test_rejects_load_with_an_unaccounted_static_library(self):
        link = next(row for row in self.calls if row["kind"] == "link")
        link["load"].append(file_record("/usr/lib/extra.a"))
        with self.assertRaisesRegex(ValueError, "compiler_unreviewed_static_input"):
            observer.match_calls(self.calls, self.derived)

    def test_rejects_a_wheel_object_with_unmatched_source_bytes(self):
        compiled = next(row for row in self.calls if row["kind"] == "compile")
        compiled["source"]["sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "compiler_object_source_digest"):
            observer.match_calls(self.calls, self.derived)

    def test_rejects_inconsistent_object_identity_in_the_link_map(self):
        link = next(row for row in self.calls if row["kind"] == "link")
        link["load"][0] = {**link["load"][0], "sha256": "d" * 64}
        with self.assertRaisesRegex(ValueError, "compiler_link_object_digest"):
            observer.match_calls(self.calls, self.derived)

    def test_observes_normal_command_arguments_and_dependency_paths(self):
        with TemporaryDirectory() as directory:
            cwd = Path(directory).resolve()
            (cwd / "include").mkdir()
            (cwd / "source.c").write_bytes(b'#include "fixture.h"\nint fixture(void) {return 0;}\n')
            (cwd / "include" / "fixture.h").write_bytes(b"int fixture(void);\n")
            kind, inputs, output = compiler_probe.parse_invocation(
                ["-g", "-O2", "-fPIC", "-Iinclude", "-c", "source.c", "-o", "source.o"], cwd
            )
            self.assertEqual(
                (kind, inputs, output), ("compile", [cwd / "source.c"], cwd / "source.o")
            )
            deps = compiler_probe.read_dependencies(
                b"pamolive-provenance: source.c include/fixture.h\n", cwd, inputs[0],
            )
            self.assertEqual(deps[0]["path"], str(cwd / "include" / "fixture.h"))
            output.write_bytes(b"synthetic compiled object")
            link = "pq.cpython-312-x86_64-linux-gnu.so"
            args = ["-shared", "source.o", "-lpq", "-o", link]
            self.assertEqual(
                compiler_probe.parse_invocation(args, cwd), ("link", [output], cwd / link)
            )
