"""Synthetic capture races; no shared library, native program or network used."""

import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from deploy import jansson_oracle_identity as identity


def metadata(**changes):
    values = {
        "st_dev": 1,
        "st_ino": 2,
        "st_mode": stat.S_IFREG | 0o644,
        "st_uid": 0,
        "st_gid": 0,
        "st_nlink": 1,
        "st_size": 4,
        "st_mtime_ns": 100,
        "st_ctime_ns": 200,
        "st_atime_ns": 300,
    }
    values.update(changes)
    return SimpleNamespace(**values)


class OracleCaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "public-oracle"
        self.path.write_bytes(b"DATA")

    def capture(self, path_states, fd_states, maximum=8):
        with (
            mock.patch.object(Path, "lstat", side_effect=path_states),
            mock.patch.object(os, "fstat", side_effect=fd_states),
        ):
            return identity.captured(self.path, maximum)

    def test_legitimate_access_time_change_is_accepted(self):
        digest = self.capture(
            [metadata(), metadata(st_atime_ns=999)],
            [metadata(st_atime_ns=400), metadata(st_atime_ns=1000)],
        )
        self.assertEqual(digest, hashlib.sha256(b"DATA").hexdigest())

    def test_path_replacement_is_rejected(self):
        with self.assertRaises(ValueError):
            self.capture([metadata(), metadata(st_ino=3)], [metadata(), metadata()])

    def test_same_path_different_open_file_is_rejected(self):
        with self.assertRaises(ValueError):
            self.capture([metadata()], [metadata(st_ino=3)])

    def test_stable_path_cannot_hide_changed_file_descriptor(self):
        with self.assertRaises(ValueError):
            self.capture([metadata(), metadata()], [metadata(), metadata(st_ino=3)])

    def test_metadata_changes_are_rejected_on_both_apis(self):
        for field, value in (
            ("st_dev", 7),
            ("st_ino", 7),
            ("st_mode", stat.S_IFREG | 0o666),
            ("st_uid", 7),
            ("st_gid", 7),
            ("st_nlink", 2),
            ("st_size", 5),
            ("st_mtime_ns", 999),
            ("st_ctime_ns", 999),
        ):
            for changed_api in ("path", "fd"):
                with self.subTest(field=field, api=changed_api), self.assertRaises(ValueError):
                    changed = metadata(**{field: value})
                    self.capture(
                        [metadata(), changed if changed_api == "path" else metadata()],
                        [metadata(), changed if changed_api == "fd" else metadata()],
                    )

    def test_ctime_is_compared_within_each_api(self):
        self.assertEqual(
            self.capture(
                [metadata(), metadata()],
                [metadata(st_ctime_ns=400), metadata(st_ctime_ns=400)],
            ),
            hashlib.sha256(b"DATA").hexdigest(),
        )

    def test_untrusted_permissions_and_non_regular_inputs_are_rejected(self):
        for changes in (
            {"st_uid": 1000},
            {"st_mode": stat.S_IFREG | 0o664},
            {"st_mode": stat.S_IFREG | 0o646},
            {"st_mode": stat.S_IFIFO | 0o644},
            {"st_mode": stat.S_IFLNK | 0o777},
            {"st_size": 0},
            {"st_size": 9},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.capture([metadata(**changes)], [])

    def test_short_or_excess_bytes_are_rejected(self):
        for raw in (b"DAT", b"DATAX"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.path.write_bytes(raw)
                self.capture([metadata(), metadata()], [metadata(), metadata()])

    def test_existing_descriptor_is_closed_after_mismatch(self):
        real_open = os.open
        descriptors = []

        def tracked_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            descriptors.append(fd)
            return fd

        with mock.patch.object(os, "open", side_effect=tracked_open):
            with self.assertRaises(ValueError):
                self.capture([metadata()], [metadata(st_ino=3)])
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])


if __name__ == "__main__":
    unittest.main()
