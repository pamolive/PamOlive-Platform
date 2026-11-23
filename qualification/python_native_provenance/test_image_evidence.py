"""Synthetic consistency tests for compiler, wheel and image evidence."""

import hashlib
import json
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from deploy import python_materials as materials
from qualification.python_native_provenance import compiler_probe, verify_image
from qualification.python_native_provenance import validate_observations as observer


def file_record(path, *, tag="observed"):
    return {"path": str(path), "size": 256, "sha256": hashlib.sha256(tag.encode()).hexdigest()}


def synthetic_linkage(data):
    package = "python-ldap" if data.startswith(b"_ldap.") else "psycopg-c"
    return {"status": "observed", "needed": sorted(observer.LIBRARIES[package])}


class PythonNativeProvenanceTests(TestCase):
    def setUp(self):
        samples = {
            "cc1": "/usr/lib/gcc/x86_64-linux-gnu/14/cc1",
            "as": "/usr/bin/x86_64-linux-gnu-as",
            "collect2": "/usr/lib/gcc/x86_64-linux-gnu/14/collect2",
            "ld": "/usr/bin/x86_64-linux-gnu-ld",
        }
        tool = {**file_record("/usr/bin/x86_64-linux-gnu-gcc-14"), "version": "14.2.0",
                "machine": "x86_64-linux-gnu",
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

    def test_rejects_different_tool_identity_in_one_compiler_call(self):
        self.calls[-1]["tool"] = {**self.calls[-1]["tool"], "sha256": "e" * 64}
        with self.assertRaisesRegex(ValueError, "compiler_toolchain_inconsistent"):
            observer.match_calls(self.calls, self.derived)

    def make_product_evidence(self):
        raw = Path(__file__).resolve().parents[2] / "deploy/python-materials.linux-amd64.json"
        manifest, input_sha = materials.load_manifest(raw)
        inputs = {row["name"]: row for row in manifest["materials"] if row["kind"] == "sdist"}
        records = []
        captured = {verify_image.INPUTS: raw.read_bytes()}
        elf_entries = {}
        for name, wheel in self.derived.items():
            source = inputs[name]
            wheel.update(name=name, version=source["version"], source_filename=source["filename"],
                         source_sha256=source["sha256"], source_files=source["source_files"])
        for row in self.calls:
            root = PurePosixPath(row["cwd"])
            package = root.name
            if row["kind"] == "compile":
                path = PurePosixPath(row["source"]["path"]).relative_to(root).as_posix()
                row["source"]["sha256"] = inputs[package]["source_files"][path]
                field = "dependency_sha256"
            else:
                output = PurePosixPath(row["output"]["path"]).relative_to(root / "build").as_posix()
                data = output.encode("ascii")
                row["output"].update(size=len(data), sha256=materials.sha(data))
                self.derived[package]["extensions"][output] = {
                    key: row["output"][key] for key in ("size", "sha256")
                }
                absolute = verify_image.SITE_PACKAGES + output
                captured[absolute] = data
                elf_entries[absolute] = {"type": "elf", "class": 64, "machine": 62}
                field = "map_sha256"
            detail = "synthetic compiler sidecar\n"
            row.update(schema=observer.SCHEMA, **{field: materials.sha(detail.encode("ascii"))})
            records.append({"record": row, "detail": detail})
        derived = json.dumps({
            "schema": "pamolive.python-derived-wheels.v1", "target": materials.TARGET,
            "input_manifest_sha256": input_sha, "build_verified": False,
            "attestation_verified": False, "materials": list(self.derived.values()),
        }).encode()
        observations = json.dumps(records).encode()
        captured.update({
            verify_image.DERIVED: derived, verify_image.OBSERVATIONS: observations,
            verify_image.BUILD: json.dumps({
                "schema": observer.BUILD_SCHEMA, "compiler_calls": len(records),
                "extensions": observer.match_calls(self.calls, self.derived),
                "derived_manifest_sha256": materials.sha(derived),
                "observations_sha256": materials.sha(observations),
                "sdk_versions": [package + "=1.0" for package in observer.SDK_PACKAGES],
                "product_image_measured": False, "policy_disposition": None,
            }).encode(),
        })
        attrs = {path: {"mode": 0o444 if path in verify_image.RECEIPTS else 0o644,
                        "uid": 0, "gid": 0, "has_capability": False}
                 for path in captured}
        facts = SimpleNamespace(captured=captured, attributes=attrs, entries=elf_entries)
        metadata = {"revision": "a" * 40, "image_id": "sha256:" + "b" * 64,
                    "archive_sha256": "c" * 64}
        return facts, metadata, manifest, input_sha

    def test_image_receipt_binds_git_config_archive_and_the_three_installed_extensions(self):
        evidence = self.make_product_evidence()
        with patch.object(
            observer.native_inventory, "observe_elf_needed", side_effect=synthetic_linkage,
        ):
            report = verify_image.inspect_facts(*evidence)
        self.assertEqual(report["revision"], evidence[1]["revision"])
        self.assertEqual(report["image_config_id"], evidence[1]["image_id"])
        self.assertEqual(report["archive_sha256"], evidence[1]["archive_sha256"])
        self.assertEqual(report["compiler_calls"], 15)
        self.assertEqual(set(report["extensions"]),
                         {path.removeprefix(verify_image.SITE_PACKAGES)
                          for path in verify_image.EXTENSIONS})
        self.assertTrue(report["product_image_measured"])
        self.assertIsNone(report["policy_disposition"])

    def test_image_rejects_wrong_install_bytes_even_with_the_original_build_receipt(self):
        evidence = self.make_product_evidence()
        evidence[0].captured[min(verify_image.EXTENSIONS)] = b"changed extension"
        with (
            patch.object(observer.native_inventory, "observe_elf_needed",
                         side_effect=synthetic_linkage),
            self.assertRaisesRegex(ValueError, "compiler_installed_extension"),
        ):
            verify_image.inspect_facts(*evidence)

    def test_image_rejects_changed_build_details_and_writable_evidence(self):
        evidence = self.make_product_evidence()
        facts = evidence[0]
        original = facts.captured[verify_image.OBSERVATIONS]
        facts.captured[verify_image.OBSERVATIONS] = original.replace(b"sidecar", b"changed")
        with self.assertRaisesRegex(ValueError, "compiler_detail_digest"):
            verify_image.inspect_facts(*evidence)
        facts.captured[verify_image.OBSERVATIONS] = original
        facts.attributes[verify_image.DERIVED]["mode"] = 0o664
        with self.assertRaisesRegex(ValueError, "compiler_image_file_attributes"):
            verify_image.inspect_facts(*evidence)

    def test_image_rejects_a_rehashed_derived_receipt_with_a_different_source_inventory(self):
        evidence = self.make_product_evidence()
        changed = json.loads(evidence[0].captured[verify_image.DERIVED])
        changed["materials"][0]["source_sha256"] = "0" * 64
        changed = json.dumps(changed).encode()
        receipt = json.loads(evidence[0].captured[verify_image.BUILD])
        receipt["derived_manifest_sha256"] = materials.sha(changed)
        evidence[0].captured[verify_image.DERIVED] = changed
        evidence[0].captured[verify_image.BUILD] = json.dumps(receipt).encode()
        with self.assertRaisesRegex(ValueError, "compiler_derived_materials"):
            verify_image.inspect_facts(*evidence)

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
