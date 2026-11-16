"""Fake-IO release-path guards; no host filesystem, native code or child runs."""

import io
import stat
import unittest
from types import SimpleNamespace
from unittest import mock

import bounded_io
import build_debian
import common


class ReachedAuthentication(Exception):
    pass


class ReleasePathTests(unittest.TestCase):
    def filesystem(self, content, mode):
        trace = []
        row = SimpleNamespace(
            st_mode=mode,
            st_nlink=1,
            st_size=len(content),
            st_dev=10,
            st_ino=20,
            st_file_attributes=0,
        )

        class Stream(io.BytesIO):
            def fileno(self):
                return 123

        class File:
            def __init__(self, path):
                self.path = str(path)

            def lstat(self):
                trace.append(("lstat", self.path))
                return row

            def is_symlink(self):
                return stat.S_ISLNK(row.st_mode)

            def open(self, operation):
                trace.append(("open", self.path))
                self_outer.assertEqual(operation, "rb")
                return Stream(content)

        def fstat(fd):
            self.assertEqual(fd, 123)
            trace.append(("fstat", fd))
            return row

        self_outer = self
        return File, SimpleNamespace(fstat=fstat), trace

    def test_old_facade_symlink_is_refused_before_open(self):
        File, fake_os, trace = self.filesystem(b"VERSION_CODENAME=trixie\n", stat.S_IFLNK | 0o777)
        with (
            mock.patch.object(common, "Path", lambda p: p),
            mock.patch.object(bounded_io, "Path", File),
            mock.patch.object(bounded_io, "os", fake_os),
        ):
            with self.assertRaisesRegex(ValueError, "regular file type/size budget"):
                common.read("/etc/os-release", 32768)
        self.assertEqual(trace, [("lstat", "/etc/os-release")])

    def test_vendor_path_regular_trixie_guard_precedes_authentication(self):
        for content, mode, allowed in (
            (b"NAME=Debian\nVERSION_CODENAME=trixie\n", stat.S_IFREG | 0o644, True),
            (b"NAME=Debian\nVERSION_CODENAME=bookworm\n", stat.S_IFREG | 0o644, False),
            (b"VERSION_CODENAME=trixie\n", stat.S_IFLNK | 0o777, False),
            (b"VERSION_CODENAME=trixie\n", stat.S_IFDIR | 0o755, False),
        ):
            with self.subTest(mode=mode, content=content):
                File, fake_os, trace = self.filesystem(content, mode)

                class Work:
                    def __init__(self, value):
                        self.value = str(value)

                    def resolve(self):
                        return self

                    def __truediv__(self, name):
                        return Work(self.value + "/" + name)

                    def mkdir(self, **kwargs):
                        trace.append(("mkdir", self.value))

                def authentication(materials, work):
                    trace.append(("authenticate", work.value))
                    raise ReachedAuthentication()

                with (
                    mock.patch.object(build_debian, "Path", Work),
                    mock.patch.object(common, "Path", lambda p: p),
                    mock.patch.object(bounded_io, "Path", File),
                    mock.patch.object(bounded_io, "os", fake_os),
                    mock.patch.object(build_debian, "authenticate", authentication),
                    mock.patch.object(build_debian, "command") as command,
                ):
                    expected = ReachedAuthentication if allowed else ValueError
                    with self.assertRaises(expected):
                        build_debian.main("/materials", "/new-output")
                    command.assert_not_called()
                paths = [value for operation, value in trace if operation in {"lstat", "open"}]
                self.assertTrue(paths)
                self.assertEqual(set(paths), {"/usr/lib/os-release"})
                if allowed:
                    self.assertEqual(
                        trace[-2:],
                        [
                            ("mkdir", "/new-output"),
                            ("authenticate", "/new-output/authentication"),
                        ],
                    )
                else:
                    self.assertFalse(any(op in {"mkdir", "authenticate"} for op, value in trace))
                    if not stat.S_ISREG(mode):
                        self.assertEqual(trace, [("lstat", "/usr/lib/os-release")])


if __name__ == "__main__":
    unittest.main()
