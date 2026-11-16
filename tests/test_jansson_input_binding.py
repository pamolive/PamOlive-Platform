"""Adversarial real TAR/FD DATA tests. No ELF/native/network execution."""

import hashlib
import json
import os
import sys
from pathlib import Path
from unittest import TestCase, mock

from deploy import jansson_image_absence as migration
from deploy import qualify_image_scan as gate
from tests.test_jansson_image_absence import JanssonAbsenceTests
from tests.test_native_inventory import elf


class JanssonBindingTests(TestCase):
    def fixture(self):
        fixture = JanssonAbsenceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def archives(self):
        fixture = self.fixture()
        fixture.check()
        good = fixture.archive.read_bytes()
        fixture.make(
            [
                ("usr/lib/libsynthetic.so", elf()),
                ("var/lib/dpkg/status", fixture.status),
                ("usr/lib/renamed.so", elf() + b"cJSON_Compare"),
            ]
        )
        bad = fixture.archive.read_bytes()
        fixture.archive.write_bytes(good)
        return fixture, good, bad

    def test_real_NSS_archive_counterexample_is_refused(self):
        fixture, _, bad = self.archives()
        real = gate.archive_facts

        def swap(*args, **kwargs):
            self.assertIsNotNone(kwargs["archive_stream"])
            result = real(*args, **kwargs)
            fixture.archive.write_bytes(bad)
            return result

        with (
            mock.patch.object(gate, "archive_facts", side_effect=swap),
            self.assertRaisesRegex(gate.ScanPolicyError, "input_changed"),
        ):
            migration.examine(fixture.archive, fixture.sbom)
        with self.assertRaisesRegex(gate.ScanPolicyError, "cjson_elf_symbol"):
            migration.examine(fixture.archive, fixture.sbom)

    def test_same_size_replacement_needs_same_bytes_even_if_metadata_is_weak(self):
        fixture, good, bad = self.archives()
        self.assertEqual(len(good), len(bad))
        real = gate.archive_facts

        def swap(*args, **kwargs):
            result = real(*args, **kwargs)
            fixture.archive.write_bytes(bad)
            return result

        with (
            mock.patch.object(gate, "archive_facts", side_effect=swap),
            mock.patch.object(migration, "_identity", return_value=("weak-metadata-model",)),
            self.assertRaisesRegex(gate.ScanPolicyError, "input_changed"),
        ):
            migration.examine(fixture.archive, fixture.sbom)

    def test_open_race_refuses_before_analysis_and_closes_the_actual_FD(self):
        fixture, _, _ = self.archives()
        opened = []
        real_open = os.open

        def capture(*args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        with (
            mock.patch.object(migration.os, "open", side_effect=capture),
            mock.patch.object(
                migration, "_identity", side_effect=[("actual-fd",), ("changed-path",)]
            ),
            mock.patch.object(gate, "archive_facts") as analyze,
            self.assertRaisesRegex(gate.ScanPolicyError, "input_changed"),
        ):
            migration.examine(fixture.archive, fixture.sbom)
        analyze.assert_not_called()
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_input_size_is_refused_before_open(self):
        fixture, _, _ = self.archives()
        with (
            mock.patch.object(migration.os, "open") as opened,
            self.assertRaisesRegex(gate.ScanPolicyError, "input_regular_or_budget"),
        ):
            with migration._regular_input(fixture.archive, 3):
                self.fail("unreachable")
        opened.assert_not_called()

    def test_final_path_identity_is_checked_before_positive_result(self):
        fixture, _, _ = self.archives()
        real_identity = migration._identity
        seen = 0

        def changed_only_at_final_path(info):
            nonlocal seen
            seen += 1
            result = real_identity(info)
            # Open fstat/lstat and final fstat are genuine. Model a new pathname
            # inode at the final lstat; no platform-specific rename privilege.
            return result + ("new-path-inode",) if seen == 5 else result

        with (
            mock.patch.object(migration, "_identity", side_effect=changed_only_at_final_path),
            self.assertRaisesRegex(gate.ScanPolicyError, "input_changed"),
        ):
            migration.examine(fixture.archive, fixture.sbom)

    def test_SBOM_replacement_immediately_after_real_parse_refuses_empty_output(self):
        fixture = self.fixture()
        fixture.check()
        path = fixture.archive.parent / "os-sbom.json"
        output = fixture.archive.parent / "result.json"
        raw = json.dumps(fixture.sbom).encode()
        path.write_bytes(raw)
        bad = dict(
            fixture.sbom,
            components=fixture.sbom["components"] + [{"name": "libcjson1", "version": "1.7.18"}],
        )
        real = gate.json_bytes

        def swap(body, *args, **kwargs):
            result = real(body, *args, **kwargs)
            if body == raw:
                path.write_bytes(json.dumps(bad).encode())
            return result

        argv = [
            "migration",
            "--archive",
            str(fixture.archive),
            "--os-sbom",
            str(path),
            "--output",
            str(output),
        ]
        with (
            mock.patch.object(gate, "json_bytes", side_effect=swap),
            mock.patch.object(sys, "argv", argv),
            self.assertRaisesRegex(gate.ScanPolicyError, "input_changed"),
        ):
            migration.main()
        self.assertEqual(output.read_bytes(), b"")

    def test_success_hashes_exact_parsed_SBOM_and_FD_archive_without_path_rehash(self):
        fixture, good, _ = self.archives()
        path = fixture.archive.parent / "os-sbom.json"
        output = fixture.archive.parent / "result.json"
        raw = json.dumps(fixture.sbom, indent=1).encode() + b"\n"
        path.write_bytes(raw)
        argv = [
            "migration",
            "--archive",
            str(fixture.archive),
            "--os-sbom",
            str(path),
            "--output",
            str(output),
        ]
        with (
            mock.patch.object(gate, "hash_file", side_effect=AssertionError("late path hash")),
            mock.patch.object(gate, "read_json", side_effect=AssertionError("unbound parse")),
            mock.patch.object(sys, "argv", argv),
        ):
            migration.main()
        result = json.loads(output.read_bytes())
        self.assertTrue(result["physical_checks_passed"])
        self.assertEqual(result["archive_sha256"], hashlib.sha256(good).hexdigest())
        self.assertEqual(result["os_sbom_sha256"], hashlib.sha256(raw).hexdigest())

    def test_reference_has_native_depth64_positive_and4096_negative_controls(self):
        source = (Path(__file__).resolve().parent / "fixtures/json_backend_reference.c").read_text()
        self.assertIn("const int depth64_ok = old != NULL && now != NULL;", source)
        self.assertIn("if (!depth64_ok) return 1;", source)
        self.assertIn("return depth4096_rejected ? 0 : 1;", source)
        # These are source-oracle wiring checks. Native parser behavior remains PENDING.
        regression = (
            Path(__file__).resolve().parent / "fixtures/winpr_jansson_regression.c"
        ).read_text()
        self.assertIn("memset(deep, '[', 4096)", regression)
        self.assertIn("CHECK(!WINPR_JSON_Parse(deep))", regression)
