"""Pure POSIX metadata/FD boundary probes with no real file open/read/chmod."""

import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pamolive_vault_runtime import slot
from pamolive_vault_runtime.bounded import Refusal


def info(mode, *, uid=0, links=1, size=3, ino=10):
    return SimpleNamespace(
        st_dev=1,
        st_ino=ino,
        st_mode=mode,
        st_uid=uid,
        st_gid=0,
        st_nlink=links,
        st_size=size,
        st_mtime_ns=1,
        st_ctime_ns=1,
    )


class ReadOnlySlotTests(unittest.TestCase):
    def setUp(self):
        self.path = (
            Path("C:/reviewed/slot.json") if slot.os.name == "nt" else Path("/reviewed/slot.json")
        )
        self.parent = info(stat.S_IFDIR | 0o755, size=0, ino=1)
        self.regular = info(stat.S_IFREG | 0o400)

    def read(self, *, file=None, parent=None, fd=None, chunks=None, final_file=None):
        regular = file or self.regular
        directory = parent or self.parent
        calls = [0]

        def lstat(path):
            if path == self.path:
                calls[0] += 1
                return final_file if final_file is not None and calls[0] > 1 else regular
            return directory

        with (
            patch.object(slot.os, "name", "posix"),
            patch.object(Path, "lstat", lstat),
            patch.object(slot.os, "O_NOFOLLOW", 0x20000, create=True),
            patch.object(slot.os, "O_CLOEXEC", 0x80000, create=True),
            patch.object(slot.os, "open", return_value=19) as opened,
            patch.object(slot.os, "fstat", return_value=fd or regular),
            patch.object(slot.os, "read", side_effect=chunks or [b"abc", b""]) as read,
            patch.object(slot.os, "close") as closed,
        ):
            try:
                result = slot._read_ro(self.path, 0)
            finally:
                self.opened, self.reads, self.closes = (
                    opened.call_count,
                    read.call_count,
                    closed.call_count,
                )
        return result

    def test_same_fd_bytes_then_snapshot_parents(self):
        raw, identity = self.read()
        self.assertEqual(raw, b"abc")
        self.assertEqual(identity[0], slot._identity(self.regular))
        self.assertEqual((self.opened, self.reads, self.closes), (1, 2, 1))

    def test_parent_alias_wrong_owner_and_writable_parent_refused_before_open(self):
        for value in (
            info(stat.S_IFLNK | 0o777),
            info(stat.S_IFDIR | 0o775),
            info(stat.S_IFDIR | 0o755, uid=1),
        ):
            with self.subTest(mode=value.st_mode), self.assertRaises(Refusal):
                self.read(parent=value)
            self.assertEqual((self.opened, self.reads, self.closes), (0, 0, 0))

    def test_file_link_hardlink_write_owner_type_size_refused_before_open(self):
        for value in (
            info(stat.S_IFLNK | 0o400),
            info(stat.S_IFREG | 0o400, links=2),
            info(stat.S_IFREG | 0o600),
            info(stat.S_IFREG | 0o400, uid=1),
            info(stat.S_IFIFO | 0o400),
            info(stat.S_IFREG | 0o400, size=slot.MAX_SLOT + 1),
        ):
            with self.subTest(value=value), self.assertRaises(Refusal):
                self.read(file=value)
            self.assertEqual((self.opened, self.reads, self.closes), (0, 0, 0))

    def test_fd_replacement_and_late_path_alias_refuse_and_close(self):
        for kwargs in (
            {"fd": info(stat.S_IFREG | 0o400, ino=99)},
            {"final_file": info(stat.S_IFLNK | 0o777)},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(Refusal):
                self.read(**kwargs)
            self.assertEqual((self.opened, self.closes), (1, 1))

    def test_growth_or_short_read_refused_with_bounded_read_and_close(self):
        for chunks in ([b"ab", b""], [b"abcd", b""]):
            with self.subTest(chunks=chunks), self.assertRaises(Refusal):
                self.read(chunks=chunks)
            self.assertEqual(self.closes, 1)
