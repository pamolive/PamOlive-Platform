"""Driver gate adverse checks: no database, ELF execution, Django or network."""

import io
import json
import os
import subprocess
import tempfile
from contextlib import redirect_stdout
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from deploy import check_database_driver as gate
from tests.test_native_inventory import elf


class DatabaseDriverTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pamolive-driver-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_exact_core_c_versions_and_public_libpq_versions(self):
        gate.validate_versions("3.2.10", "3.2.10", "c", 170012, 170012)

    def test_same_later_patch_within_qualified_major_is_accepted(self):
        gate.validate_versions("3.2.10", "3.2.10", "c", 170013, 170013)

    def test_old_or_mismatched_distribution_versions_refused(self):
        for core, extension in (("3.2.9", "3.2.9"), ("3.2.10", "3.2.9"), ("3.3.0", "3.3.0")):
            with self.subTest(core=core, extension=extension), self.assertRaises(gate.DriverError):
                gate.validate_versions(core, extension, "c", 170012, 170012)

    def test_binary_python_or_missing_implementation_refused(self):
        for impl in ("binary", "python", None):
            with (
                self.subTest(impl=impl),
                self.assertRaisesRegex(gate.DriverError, "driver_fallback"),
            ):
                gate.validate_versions("3.2.10", "3.2.10", impl, 170012, 170012)

    def test_libpq_wrong_types_in_either_public_version_refused(self):
        for invalid in (True, False, None, "170012", 170012.0):
            for runtime, build in ((invalid, 170012), (170012, invalid)):
                with (
                    self.subTest(runtime=runtime, build=build),
                    self.assertRaisesRegex(gate.DriverError, "libpq_version"),
                ):
                    gate.validate_versions("3.2.10", "3.2.10", "c", runtime, build)

    def test_libpq_1711_or_older_runtime_or_sdk_refused(self):
        for runtime, build in (
            (170011, 170011),
            (170011, 170012),
            (170012, 170011),
            (170000, 170000),
        ):
            with (
                self.subTest(runtime=runtime, build=build),
                self.assertRaisesRegex(gate.DriverError, "libpq_version"),
            ):
                gate.validate_versions("3.2.10", "3.2.10", "c", runtime, build)

    def test_libpq_sdk_runtime_patch_mismatch_refused(self):
        for runtime, build in ((170013, 170012), (170012, 170013)):
            with (
                self.subTest(runtime=runtime, build=build),
                self.assertRaisesRegex(gate.DriverError, "libpq_build_runtime_mismatch"),
            ):
                gate.validate_versions("3.2.10", "3.2.10", "c", runtime, build)

    def test_libpq_other_or_mixed_majors_need_separate_qualification(self):
        for runtime, build in (
            (160016, 160016),
            (180000, 180000),
            (180007, 180007),
            (190000, 190000),
            (180007, 170012),
            (170012, 180007),
        ):
            with (
                self.subTest(runtime=runtime, build=build),
                self.assertRaisesRegex(gate.DriverError, "libpq_major_unqualified"),
            ):
                gate.validate_versions("3.2.10", "3.2.10", "c", runtime, build)

    def test_clean_physical_package_directory(self):
        (self.root / "psycopg").mkdir()
        (self.root / "psycopg_c").mkdir()
        gate.reject_binary_packages([self.root])

    def test_stale_binary_directory_metadata_or_vendored_libs_refused(self):
        for name in (
            "psycopg_binary",
            "psycopg_binary.libs",
            "psycopg-binary-3.2.10.dist-info",
            "psycopg_c.libs",
        ):
            with self.subTest(name=name):
                path = self.root / name
                path.mkdir()
                with self.assertRaisesRegex(gate.DriverError, "vendored_driver_present"):
                    gate.reject_binary_packages([self.root])
                path.rmdir()

    def test_exact_two_extensions_required(self):
        distribution = SimpleNamespace(
            files=[
                "psycopg_c/pq.cpython-312-x86_64-linux-gnu.so",
                "psycopg_c/_psycopg.cpython-312-x86_64-linux-gnu.so",
            ],
            locate_file=lambda item: self.root / item,
        )
        self.assertEqual(len(gate.extension_paths(distribution)), 2)

    def test_metadata_missing_extra_extension_or_traversal_refused(self):
        for files in (
            None,
            [],
            ["../evil.so"],
            ["/tmp/evil.so"],
            ["psycopg_c.libs/libpq.so"],
            ["psycopg_c/a.so", "psycopg_c/pq.so", "psycopg_c/_psycopg.so"],
        ):
            with self.subTest(files=files), self.assertRaises(gate.DriverError):
                gate.extension_paths(
                    SimpleNamespace(files=files, locate_file=lambda item: self.root / item)
                )

    def test_resolved_libpq_must_equal_single_loaded_path_and_hash(self):
        library = self.root / "libpq.so.5"
        library.write_bytes(b"synthetic-library-content")
        text = f"1000-2000 r-xp 000000 00:00 1 {library}\n2000-3000 r--p 000000 00:00 1 {library}\n"
        self.assertEqual(gate.loaded_libpq(text, library), gate.digest(library))

    def test_proc_maps_read_is_bounded_independently_of_zero_stat_size(self):
        stream = io.BytesIO(b"x" * (gate.MAX_MAPS + 2))
        path = SimpleNamespace(open=lambda mode: stream)
        with patch.object(stream, "read", wraps=stream.read) as limited:
            with self.assertRaisesRegex(gate.DriverError, "maps_budget"):
                gate.read_maps(path)
            limited.assert_called_once_with(gate.MAX_MAPS + 1)
        small = self.root / "maps"
        small.write_bytes(b"synthetic maps\n")
        self.assertEqual(gate.read_maps(small), "synthetic maps\n")

    def test_cryptography_version_uses_public_default_backend_api(self):
        backend = SimpleNamespace(openssl_version_text=lambda: "OpenSSL synthetic-version")
        with patch("cryptography.hazmat.backends.default_backend", return_value=backend) as public:
            self.assertEqual(gate.cryptography_openssl_version(), "OpenSSL synthetic-version")
        public.assert_called_once_with()

    def test_old_vendored_or_deleted_loaded_libpq_refused(self):
        expected = self.root / "libpq.so.5"
        other = self.root / "libpq-old.so.5"
        expected.write_bytes(b"expected")
        other.write_bytes(b"old")
        for text in (
            "",
            f"1000-2000 r-xp 0 0 1 {other}",
            f"1000-2000 r-xp 0 0 1 {expected} (deleted)",
            f"1000-2000 r-xp 0 0 1 {expected}\n1000-2000 r-xp 0 0 1 {other}",
        ):
            with self.subTest(text=text), self.assertRaises(gate.DriverError):
                gate.loaded_libpq(text, expected)

    def test_non_system_and_symlink_escape_refused_after_resolution(self):
        library = self.root / "libpq.so.5"
        library.write_bytes(b"outside")
        prefix = self.root / "system"
        prefix.mkdir()
        with self.assertRaisesRegex(gate.DriverError, "dependency_outside_system"):
            gate.trusted_file(library, prefix=prefix)
        # Simulate an already-resolved symlink outside the approved directory,
        # without needing Windows developer-mode symlink privileges.
        alias = SimpleNamespace(resolve=lambda **kwargs: library.resolve())
        with self.assertRaisesRegex(gate.DriverError, "dependency_outside_system"):
            gate.trusted_file(alias, prefix=prefix)

    def test_dpkg_ownership_and_installed_version_required(self):
        results = [
            SimpleNamespace(
                returncode=0,
                stdout="libpq5:amd64: /usr/lib/x86_64-linux-gnu/libpq.so.5.17\n",
                stderr="",
            ),
            SimpleNamespace(returncode=0, stdout="libpq5:amd64\t17.6-1\tii ", stderr=""),
        ]
        with patch.object(gate.subprocess, "run", side_effect=results) as run:
            result = gate.dpkg_owner(PurePosixPath("/usr/lib/x86_64-linux-gnu/libpq.so.5.17"))
        self.assertEqual(result, dict(package="libpq5:amd64", version="17.6-1"))
        self.assertEqual(run.call_args_list[0].kwargs["timeout"], 5)
        self.assertNotIn("DATABASE_URL", run.call_args_list[0].kwargs["env"])

    def test_unowned_ambiguous_wrong_or_uninstalled_dpkg_records_refused(self):
        for output in (
            "",
            "pkg: /different\n",
            "pkg: /usr/lib/libpq.so\nother: /usr/lib/libpq.so\n",
        ):
            with (
                patch.object(
                    gate.subprocess,
                    "run",
                    return_value=SimpleNamespace(returncode=0, stdout=output, stderr=""),
                ),
                self.assertRaises(gate.DriverError),
            ):
                gate.dpkg_owner(Path("/usr/lib/libpq.so"))
        results = [
            SimpleNamespace(returncode=0, stdout="libpq5: /usr/lib/libpq.so", stderr=""),
            SimpleNamespace(returncode=0, stdout="libpq5\t17.6\trc", stderr=""),
        ]
        with (
            patch.object(gate.subprocess, "run", side_effect=results),
            self.assertRaises(gate.DriverError),
        ):
            gate.dpkg_owner(Path("/usr/lib/libpq.so"))

    def test_existing_output_prevents_all_probes_and_preserves_bytes(self):
        output = self.root / "report.json"
        output.write_bytes(b"prior-proof")
        with patch.object(gate, "collect") as collect, redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(["--output", str(output)]), 1)
        collect.assert_not_called()
        self.assertEqual(output.read_bytes(), b"prior-proof")

    def test_failed_probe_never_emits_raw_exception_or_credentials(self):
        output = self.root / "failed.json"
        stdout = io.StringIO()
        with (
            patch.object(gate, "collect", side_effect=OSError("synthetic-private-string")),
            redirect_stdout(stdout),
        ):
            self.assertEqual(gate.main(["--output", str(output)]), 1)
        self.assertNotIn("synthetic-private-string", stdout.getvalue())
        self.assertEqual(output.read_bytes(), b"")

    def test_report_created_exclusively_with_private_mode(self):
        real_open = os.open
        output = self.root / "report.json"
        with (
            patch.object(gate.os, "open", wraps=real_open) as opened,
            patch.object(gate, "collect", return_value={"schema": gate.SCHEMA, "verified": True}),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(gate.main(["--output", str(output)]), 0)
        self.assertEqual(opened.call_args.args[2], 0o600)
        self.assertTrue(opened.call_args.args[1] & os.O_EXCL)
        self.assertTrue(json.loads(output.read_text())["verified"])

    def test_timeout_and_native_failures_are_fail_closed(self):
        for error in (
            subprocess.TimeoutExpired("synthetic", 5),
            gate.InventoryError("native-detail"),
        ):
            output = self.root / (type(error).__name__ + ".json")
            with patch.object(gate, "collect", side_effect=error), redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(["--output", str(output)]), 1)

    def test_environment_and_platform_checked_before_import(self):
        with (
            patch.object(gate.sys, "platform", "win32"),
            self.assertRaisesRegex(gate.DriverError, "linux_runtime_required"),
        ):
            gate.collect()

    def test_extension_symlink_rejected_before_read_or_probe(self):
        path = SimpleNamespace(is_symlink=lambda: True)
        with self.assertRaisesRegex(gate.DriverError, "driver_extension_symlink"):
            gate.validate_extension(path, self.root)

    def test_native_search_path_is_rejected_even_if_previously_approved_for_guacd(self):
        path = self.root / "pq.so"
        path.write_bytes(elf())
        # File ownership is checked independently; this test exercises the actual
        # ELF parser on synthetic bytes; neither ldd nor the ELF is executed.
        with (
            patch.object(gate, "trusted_file", return_value=path),
            self.assertRaisesRegex(gate.DriverError, "driver_search_path"),
        ):
            gate.validate_extension(path, self.root)

    def test_non_elf_extension_cannot_pass_even_with_metadata(self):
        path = self.root / "pq.so"
        path.write_bytes(b"not-an-ELF")
        with (
            patch.object(gate, "trusted_file", return_value=path),
            self.assertRaises(gate.InventoryError),
        ):
            gate.validate_extension(path, self.root)

    def test_untrusted_owner_or_writable_component_refused(self):
        path = self.root / "pq.so"
        path.write_bytes(b"synthetic")
        for uid, mode in ((42, 0o100644), (0, 0o100666)):
            with (
                self.subTest(uid=uid, mode=mode),
                patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=uid, st_mode=mode)),
                self.assertRaisesRegex(gate.DriverError, "untrusted_file_permissions"),
            ):
                gate.trusted_file(path, prefix=self.root)

    def test_binary_and_preloaded_environment_rejected_before_import(self):
        with (
            patch.object(gate.sys, "platform", "linux"),
            patch.dict(os.environ, {"PSYCOPG_IMPL": "binary"}),
            self.assertRaisesRegex(gate.DriverError, "driver_environment"),
        ):
            gate.collect()
        with (
            patch.object(gate.sys, "platform", "linux"),
            patch.dict(os.environ, {"PSYCOPG_IMPL": "c", "LD_PRELOAD": "untrusted"}),
            self.assertRaisesRegex(gate.DriverError, "loader_environment"),
        ):
            gate.collect()
