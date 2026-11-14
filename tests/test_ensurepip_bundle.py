"""Synthetic, offline ensurepip overlay tests; no bundled code is executed."""

import ast
import io
import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from deploy import ensurepip_bundle as overlay

ROOT = Path(__file__).resolve().parents[1]


class EnsurepipBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / overlay.MODULE
        (self.directory / "_bundled").mkdir(parents=True)
        self.sysconfig_path = self.root / overlay.SYSCONFIG_PATH
        self.sysconfig_path.write_bytes(b"build_time_vars = {'WHEEL_PKG_DIR': ''}\n")
        self.source = (
            b'import sysconfig\n_PIP_VERSION = "25.0.1"\n'
            b"_WHEEL_PKG_DIR = sysconfig.get_config_var('WHEEL_PKG_DIR')\n"
            b"def version(): return _PIP_VERSION\n"
        )
        self.patched = self.source.replace(overlay.BEFORE, overlay.AFTER)
        (self.directory / "__init__.py").write_bytes(self.source)
        for name in ("__main__.py", "_uninstall.py"):
            (self.directory / name).write_bytes(b"raise AssertionError('never execute')\n")
        self.old = self.directory / "_bundled" / overlay.OLD_NAME
        self.old.write_bytes(b"synthetic old wheel")
        self.metadata = b"Metadata-Version: 2.4\nName: pip\nVersion: 26.3\n"
        self.wheel = self.root / overlay.NEW_NAME
        self.make_wheel()
        self.pins = mock.patch.multiple(
            overlay,
            SOURCE_SIZE=len(self.source),
            SOURCE_SHA256=overlay.sha(self.source),
            PATCHED_SIZE=len(self.patched),
            PATCHED_SHA256=overlay.sha(self.patched),
            OLD_SIZE=self.old.stat().st_size,
            OLD_SHA256=overlay.sha(self.old.read_bytes()),
            NEW_SIZE=self.wheel.stat().st_size,
            NEW_SHA256=overlay.sha(self.wheel.read_bytes()),
            METADATA_SHA256=overlay.sha(self.metadata),
            SYSCONFIG_SHA256=overlay.sha(self.sysconfig_path.read_bytes()),
            API_SHA256={
                name: overlay.sha((self.directory / name).read_bytes())
                for name in overlay.API_SHA256
            },
        )
        self.pins.start()
        self.addCleanup(self.pins.stop)

    def make_wheel(self, *, metadata=None, tag="py3-none-any", extra=None, duplicate=False):
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("pip/__init__.py", "raise AssertionError('never execute')")
            archive.writestr(
                "pip-26.3.dist-info/METADATA", self.metadata if metadata is None else metadata
            )
            archive.writestr(
                "pip-26.3.dist-info/WHEEL",
                "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: " + tag + "\n",
            )
            if extra:
                archive.writestr(extra, b"unexpected")
            if duplicate:
                with self.assertWarns(UserWarning):
                    archive.writestr("pip-26.3.dist-info/METADATA", self.metadata)

    def apply(self, *, wheel_pkg_dir="", wheel=None):
        return overlay.replace_bundle(self.root, wheel or self.wheel, wheel_pkg_dir=wheel_pkg_dir)

    def assert_unchanged(self):
        self.assertEqual((self.directory / "__init__.py").read_bytes(), self.source)
        self.assertEqual(self.old.read_bytes(), b"synthetic old wheel")
        self.assertFalse((self.old.parent / overlay.NEW_NAME).exists())

    def test_exact_overlay_preserves_api_files_and_only_removes_verified_old_wheel(self):
        siblings = {
            name: (self.directory / name).read_bytes() for name in ("__main__.py", "_uninstall.py")
        }
        report = self.apply()
        self.assertEqual((self.directory / "__init__.py").read_bytes(), self.patched)
        self.assertEqual({p.name for p in self.old.parent.iterdir()}, {overlay.NEW_NAME})
        self.assertEqual((self.old.parent / overlay.NEW_NAME).read_bytes(), self.wheel.read_bytes())
        for name, data in siblings.items():
            self.assertEqual((self.directory / name).read_bytes(), data)
        self.assertFalse(list(self.directory.rglob("*.pyc")))
        self.assertIs(report["build_verified"], False)
        self.assertIs(report["attestation_verified"], False)
        self.assertEqual(report["wheel_pkg_dir"], "")
        self.assertEqual(report["added_wheel"]["filename"], overlay.NEW_NAME)
        self.assertNotEqual(report["removed_wheel"]["filename"], report["added_wheel"]["filename"])
        before, after = ast.parse(self.source), ast.parse(self.patched)
        before.body[1].value = ast.Constant(value="26.3")
        self.assertEqual(ast.dump(before), ast.dump(after))
        with self.assertRaises(overlay.BundleError):
            self.apply()  # No implicit acceptance of an already modified base.

    def test_target_wheel_directory_must_be_exact_empty_string(self):
        for value in (None, False, 0, [], {}, "/tmp/wheels", "/usr/share/python-wheels"):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(overlay.BundleError, "external_wheel_directory"),
            ):
                self.apply(wheel_pkg_dir=value)
            self.assert_unchanged()

    def test_target_sysconfig_bytes_are_checked_without_execution(self):
        self.sysconfig_path.write_bytes(b"raise AssertionError('never execute')\n")
        with self.assertRaisesRegex(overlay.BundleError, "sysconfig_source_pin"):
            self.apply()
        self.assert_unchanged()

    def test_unknown_or_bytecode_files_refused_before_writes(self):
        for directory, name in (
            (self.directory, "__pycache__"),
            (self.old.parent, "__pycache__"),
            (self.old.parent, "extra.whl"),
            (self.directory, "extra.py"),
        ):
            path = directory / name
            path.write_bytes(b"unexpected")
            with self.subTest(name=name), self.assertRaises(overlay.BundleError):
                self.apply()
            self.assert_unchanged()
            path.unlink()

    def test_source_old_new_and_post_hashes_are_strict(self):
        for constant in (
            "SOURCE_SHA256",
            "OLD_SHA256",
            "NEW_SHA256",
            "PATCHED_SHA256",
            "METADATA_SHA256",
        ):
            with (
                self.subTest(pin=constant),
                mock.patch.object(overlay, constant, "0" * 64),
                self.assertRaises(overlay.BundleError),
            ):
                self.apply()
            self.assert_unchanged()
        for constant in ("SOURCE_SIZE", "OLD_SIZE", "NEW_SIZE", "PATCHED_SIZE"):
            with (
                self.subTest(pin=constant),
                mock.patch.object(overlay, constant, 1),
                self.assertRaises(overlay.BundleError),
            ):
                self.apply()
            self.assert_unchanged()

    def test_missing_duplicate_or_changed_patch_literal_refused(self):
        for source in (
            self.source.replace(overlay.BEFORE, b'_PIP_VERSION = "99"'),
            self.source + overlay.BEFORE,
        ):
            (self.directory / "__init__.py").write_bytes(source)
            with (
                mock.patch.multiple(
                    overlay, SOURCE_SIZE=len(source), SOURCE_SHA256=overlay.sha(source)
                ),
                self.assertRaisesRegex(overlay.BundleError, "source_patch_count"),
            ):
                self.apply()
            self.assertTrue(self.old.exists())
            self.assertFalse((self.old.parent / overlay.NEW_NAME).exists())

    def test_wrong_filename_and_new_content_under_old_name_refused(self):
        renamed = self.root / overlay.OLD_NAME
        renamed.write_bytes(self.wheel.read_bytes())
        with self.assertRaisesRegex(overlay.BundleError, "new_wheel_name"):
            self.apply(wheel=renamed)
        self.assert_unchanged()
        self.old.write_bytes(self.wheel.read_bytes())
        with self.assertRaises(overlay.BundleError):
            self.apply()
        self.assertEqual((self.directory / "__init__.py").read_bytes(), self.source)

    def test_hardlink_alias_refused(self):
        alias = self.root / "alias"
        for path in (self.old, self.wheel, self.directory / "__init__.py"):
            os.link(path, alias)
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(overlay.BundleError, "file_alias_or_type"),
            ):
                self.apply()
            self.assert_unchanged()
            alias.unlink()

    def test_symlink_alias_refused_real_or_synthetic_lstat(self):
        target = self.root / "old-real"
        self.old.rename(target)
        try:
            self.old.symlink_to(target)
        except OSError:
            target.rename(self.old)
            original = Path.lstat

            def synthetic_lstat(path):
                return SimpleNamespace(st_mode=stat.S_IFLNK) if path == self.old else original(path)

            with (
                mock.patch.object(Path, "lstat", synthetic_lstat),
                self.assertRaisesRegex(overlay.BundleError, "file_alias_or_type"),
            ):
                self.apply()
            self.assert_unchanged()
            return
        with self.assertRaisesRegex(overlay.BundleError, "file_alias_or_type"):
            self.apply()
        self.assertEqual((self.directory / "__init__.py").read_bytes(), self.source)
        self.assertEqual(target.read_bytes(), b"synthetic old wheel")

    def test_other_ensurepip_entrypoints_are_pinned_before_writes(self):
        for name in overlay.API_SHA256:
            path = self.directory / name
            original = path.read_bytes()
            path.write_bytes(b"unexpected executable code")
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(overlay.BundleError, "api_source_pin"),
            ):
                self.apply()
            self.assert_unchanged()
            path.write_bytes(original)

    def test_wheel_metadata_tags_duplicate_and_paths_refused(self):
        cases = (
            {"metadata": self.metadata.replace(b"26.3", b"25.0.1")},
            {"metadata": self.metadata.replace(b"Name: pip", b"Name: other")},
            {"tag": "cp312-cp312-win_amd64"},
            {"duplicate": True},
            {"extra": "../outside"},
            {"extra": "inject.pth"},
            {"extra": "inject.pyc"},
        )
        for case in cases:
            with self.subTest(case=case):
                self.make_wheel(**case)
                metadata = case.get("metadata", self.metadata)
                with (
                    mock.patch.multiple(
                        overlay,
                        NEW_SIZE=self.wheel.stat().st_size,
                        NEW_SHA256=overlay.sha(self.wheel.read_bytes()),
                        METADATA_SHA256=overlay.sha(metadata),
                    ),
                    self.assertRaises(overlay.BundleError),
                ):
                    self.apply()
                self.assert_unchanged()

    def test_competing_old_file_change_aborts_without_deleting_it(self):
        original = overlay.write_new

        def substitute_old(path, data):
            original(path, data)
            self.old.write_bytes(b"changed after input verification")

        with (
            mock.patch.object(overlay, "write_new", side_effect=substitute_old),
            self.assertRaises(overlay.BundleError),
        ):
            self.apply()
        self.assertEqual(self.old.read_bytes(), b"changed after input verification")
        self.assertEqual((self.directory / "__init__.py").read_bytes(), self.source)
        self.assertFalse(list(self.directory.glob(".pamolive-ensurepip-*")))


class EnsurepipReviewedPinsTests(unittest.TestCase):
    def test_upstream_and_bootstrap_pins_are_independent_constants(self):
        self.assertEqual(
            overlay.SYSCONFIG_SHA256,
            "ff048f75a99504e073c8a9b7e9da146763fcde6960d2291c19ca2b72cde9eb69",
        )
        self.assertEqual(
            overlay.API_SHA256,
            {
                "__main__.py": "ee735f518d0fc4dfec81f7aa3da1e052372ed4202c0da4eddd2587840beaecd7",
                "_uninstall.py": "3a6e95d01c45e2e47c05df3c81073b895c97c1eb0e5b90ab175d6d9263fc81f2",
            },
        )
        self.assertEqual(overlay.SOURCE_SIZE, 9445)
        self.assertEqual(
            overlay.SOURCE_SHA256,
            "90f6c76cd9ef7ed6daa198bb9ef771139683487f1b061211be7aa511831b2028",
        )
        self.assertEqual(overlay.PATCHED_SIZE, 9443)
        self.assertEqual(
            overlay.PATCHED_SHA256,
            "5946b1d405e3650a310f4a85b1a48bdf4182f03397e069ff34f9fd7a1422217a",
        )
        self.assertEqual(
            overlay.OLD_SHA256, "c46efd13b6aa8279f33f2864459c8ce587ea6a1a59ee20de055868d8f7688f7f"
        )
        manifest = json.loads((ROOT / "deploy/python-materials.linux-amd64.json").read_text())
        pip = next(r for r in manifest["materials"] if r["name"] == "pip")
        self.assertEqual(
            (pip["filename"], pip["size"], pip["sha256"]),
            (overlay.NEW_NAME, overlay.NEW_SIZE, overlay.NEW_SHA256),
        )
        self.assertIn(
            "pip==26.3 --hash=sha256:" + overlay.NEW_SHA256,
            (ROOT / "requirements-bootstrap.lock").read_text(),
        )

    def test_docker_change_is_runtime_only_and_offline_before_pip_install(self):
        docker = (ROOT / "Dockerfile").read_text()
        before, runtime = docker.split("FROM krb5-runtime AS runtime", 1)
        self.assertNotIn("ensurepip_bundle", before)
        self.assertIn("FROM " + overlay.BASE_REFERENCE + " AS krb5-builder", before)
        runtime = runtime.split("COPY manage.py", 1)[0]
        self.assertIn("RUN --network=none python -B /tmp/ensurepip_bundle.py", runtime)
        self.assertLess(
            runtime.index("python -B /tmp/ensurepip_bundle.py"),
            runtime.index("python -m pip install"),
        )

    def test_cli_refuses_non_target_without_touching_files(self):
        with (
            mock.patch.object(overlay.sys, "platform", "win32"),
            mock.patch.object(overlay, "replace_bundle") as replace,
            mock.patch("sys.stderr", new_callable=io.StringIO) as errors,
        ):
            self.assertEqual(overlay.main(["--wheel", "unused"]), 1)
        replace.assert_not_called()
        self.assertEqual(errors.getvalue(), "ensurepip-bundle: interpreter_profile\n")


if __name__ == "__main__":
    unittest.main()
