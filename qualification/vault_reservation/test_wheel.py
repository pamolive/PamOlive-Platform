"""Adversarial wheel DATA checks, including tampering with a fresh valid RECORD."""

import base64
import copy
import csv
import hashlib
import importlib.util
import io
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "reservation_wheel_checker", Path(__file__).with_name("check_wheel.py")
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

ROOT = Path(__file__).resolve().parents[2]


def record(files):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    for name, raw in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        writer.writerow((name, "sha256=" + digest, str(len(raw))))
    writer.writerow((checker.DIST + "/RECORD", "", ""))
    return stream.getvalue().encode()


def packed(files, *, resign=True, duplicate=None, symlink=None):
    files = copy.deepcopy(files)
    if resign:
        files.pop(checker.DIST + "/RECORD", None)
        files[checker.DIST + "/RECORD"] = record(files)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in files.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFLNK | 0o777) << 16 if name == symlink else 0o100644 << 16
            archive.writestr(info, raw)
        if duplicate:
            archive.writestr(duplicate, files[duplicate])
    return stream.getvalue()


class WheelDataTests(unittest.TestCase):
    def setUp(self):
        self.files = checker.source_files(ROOT)
        self.files[checker.DIST + "/METADATA"] = (
            "Metadata-Version: 2.4\nName: pamolive-vault-reservation-runtime\n"
            "Version: 0.1.0a1\nRequires-Python: >=3.12\n"
            "License-Expression: AGPL-3.0-or-later\nLicense-File: LICENSE\n"
            "Dynamic: license-file\n"
            + "Summary: "
            + checker.SUMMARY
            + "\nDescription-Content-Type: text/markdown\n"
            + "".join("Requires-Dist: " + value + "\n" for value in sorted(checker.DEPENDENCIES))
            + "\n"
            + (ROOT / "components/vault/runtime/README.md").read_text(encoding="utf-8")
        ).encode()
        self.files[checker.DIST + "/WHEEL"] = (
            b"Wheel-Version: 1.0\nGenerator: setuptools (84.2.1)\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        )
        self.files[checker.DIST + "/top_level.txt"] = b"pamolive_vault_runtime\n"

    def refused(self, files, **kwargs):
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            checker.validate(packed(files, **kwargs), ROOT)

    def test_closed_positive_fixture_is_data_only(self):
        result = checker.validate(packed(self.files), ROOT)
        self.assertEqual(result["files"], 14)
        self.assertFalse(result["wheel_executed_or_installed"])
        self.assertFalse(result["secret_release_authority"])

    def test_extra_module_or_private_file_rejected_even_with_new_RECORD(self):
        for name in ("pamolive_vault_runtime/extra.py", "credentials.json", "tests/history/r1.py"):
            with self.subTest(name=name):
                self.refused({**self.files, name: b"synthetic unapproved addition"})

    def test_changed_source_schema_or_notice_rejected_with_new_RECORD(self):
        for name in (
            "pamolive_vault_runtime/ledger.py",
            checker.SQL,
            checker.DIST + "/licenses/LICENSE",
        ):
            with self.subTest(name=name):
                self.refused({**self.files, name: self.files[name] + b"\nchanged\n"})

    def test_recomputed_RECORD_cannot_authorize_new_or_duplicate_dependency(self):
        name = checker.DIST + "/METADATA"
        for added in (b"Requires-Dist: Django==6.0\n", b"Requires-Dist: uvicorn==0.54.0\n"):
            value = self.files[name].replace(b"\n\n", b"\n" + added + b"\n", 1)
            self.refused({**self.files, name: value})

    def test_duplicate_identity_header_and_extras_refuse(self):
        name = checker.DIST + "/METADATA"
        for added in (b"Name: other\n", b"Provides-Extra: unsafe\n", b"Dynamic: Version\n"):
            self.refused({**self.files, name: added + self.files[name]})

    def test_platform_tag_or_purelib_change_refuses(self):
        name = checker.DIST + "/WHEEL"
        for before, after in ((b"true", b"false"), (b"py3-none-any", b"cp312-cp312-win_amd64")):
            self.refused({**self.files, name: self.files[name].replace(before, after)})

    def test_corrupt_RECORD_hash_or_size_refuses(self):
        files = dict(self.files)
        files[checker.DIST + "/RECORD"] = record(files)
        for value in (b"sha256=bad", b"md5=bad"):
            changed = dict(files)
            changed[checker.DIST + "/RECORD"] = files[checker.DIST + "/RECORD"].replace(
                b"sha256=", value, 1
            )
            self.refused(changed, resign=False)
        changed = dict(files)
        changed["pamolive_vault_runtime/ledger.py"] += b"\n"
        self.refused(changed, resign=False)

    def test_duplicate_archive_member_refuses(self):
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            self.refused(self.files, duplicate="pamolive_vault_runtime/slot.py")

    def test_symlink_and_unsafe_path_refuse(self):
        self.refused(self.files, symlink="pamolive_vault_runtime/slot.py")
        self.refused({**self.files, "../outside.py": b"not extracted"})

    def test_missing_member_invalid_zip_and_oversize_refuse(self):
        files = dict(self.files)
        files.pop(checker.SQL)
        self.refused(files)
        for raw in (b"not a zip", b"x" * (checker.MAX_WHEEL + 1)):
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                checker.validate(raw, ROOT)

    def test_untracked_description_or_metadata_header_refuses(self):
        name = checker.DIST + "/METADATA"
        self.refused({**self.files, name: self.files[name] + b"unapproved opaque text"})
        self.refused({**self.files, name: b"Unknown-Field: unapproved\n" + self.files[name]})

    def test_archive_preamble_trailing_data_or_comment_refuses(self):
        valid = packed(self.files)
        for raw in (b"unapproved" + valid, valid + b"unapproved"):
            with self.assertRaises(ValueError):
                checker.validate(raw, ROOT)
        stream = io.BytesIO(valid)
        with zipfile.ZipFile(stream, "a") as archive:
            archive.comment = b"unapproved"
        with self.assertRaises(ValueError):
            checker.validate(stream.getvalue(), ROOT)

    def test_mail_envelopes_and_WHEEL_payload_refuse_with_fresh_RECORD(self):
        for name in (checker.DIST + "/METADATA", checker.DIST + "/WHEEL"):
            self.refused({**self.files, name: b"From opaque-envelope\n" + self.files[name]})
        name = checker.DIST + "/WHEEL"
        self.refused({**self.files, name: self.files[name] + b"\nopaque payload"})

    def test_header_parse_defects_refuse_with_fresh_RECORD(self):
        for name in (checker.DIST + "/METADATA", checker.DIST + "/WHEEL"):
            self.refused({**self.files, name: b"\tbroken-first-continuation\n" + self.files[name]})

    def test_regular_read_is_bounded_and_never_uses_Path_read_bytes(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            path = Path(temporary) / "synthetic"
            path.write_bytes(b"small")
            original = checker.os.fdopen
            requests = []

            class ObservedReader:
                def __init__(self, *args, **kwargs):
                    self.stream = original(*args, **kwargs)

                def __enter__(self):
                    return self

                def read(self, amount):
                    requests.append(amount)
                    return self.stream.read(amount)

                def __exit__(self, *_args):
                    self.stream.close()

            with (
                patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")),
                patch.object(checker.os, "fdopen", ObservedReader),
            ):
                self.assertEqual(checker.read_regular(path, 8), b"small")
            self.assertEqual(requests, [9])

    def test_regular_read_refuses_changed_FD_identity_and_hardlink(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            path = Path(temporary) / "synthetic"
            path.write_bytes(b"small")
            before = path.stat()
            values = {
                name: getattr(before, name)
                for name in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            }
            changed = SimpleNamespace(**{**values, "st_ino": before.st_ino + 1})
            with patch.object(checker.os, "fstat", side_effect=[before, changed]):
                with self.assertRaises(ValueError):
                    checker.read_regular(path, 8)
            alias = Path(temporary) / "alias"
            checker.os.link(path, alias)
            with self.assertRaises(ValueError):
                checker.read_regular(path, 8)

    def test_ctime_is_checked_per_API_without_equating_Windows_representations(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            path = Path(temporary) / "synthetic"
            path.write_bytes(b"small")
            before = path.stat()
            values = {
                name: getattr(before, name)
                for name in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            }
            opened = SimpleNamespace(**{**values, "st_ctime_ns": before.st_ctime_ns + 7})
            with patch.object(checker.os, "fstat", side_effect=[opened, opened]):
                self.assertEqual(checker.read_regular(path, 8), b"small")
            changed = SimpleNamespace(**{**values, "st_ctime_ns": before.st_ctime_ns + 8})
            with patch.object(checker.os, "fstat", side_effect=[opened, changed]):
                with self.assertRaises(ValueError):
                    checker.read_regular(path, 8)
            original = Path.lstat
            seen = []

            def substituted_time(item):
                if item == path:
                    seen.append(True)
                    return before if len(seen) == 1 else changed
                return original(item)

            with patch.object(Path, "lstat", substituted_time):
                with self.assertRaises(ValueError):
                    checker.read_regular(path, 8)


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(WheelDataTests)
    )
    raise SystemExit(not result.wasSuccessful() or bool(result.skipped))
