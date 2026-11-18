"""Pure actor for nonblocking leaf type checks and owned descriptor closure."""

import io
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import future_linux as f

NONBLOCK, NOFOLLOW, DIRECTORY = 0x800, 0x20000, 0x10000


def fifo_regression(self):
    """Replace only the independently confirmed FIFO acceptance reproduction."""
    for case in (
        "fifo",
        "regular",
        "fstat_error",
        "read_error",
        "symlink",
        "parent_error",
    ):
        with self.subTest(case=case):
            calls, closed, reads, typed = [], [], [], []

            def opened(name, flags, **kwargs):
                calls.append((str(name), flags, kwargs))
                if str(name) == "file.c":
                    # This is the previous blocking-open reproduction, without a real FIFO.
                    if not flags & NONBLOCK:
                        raise AssertionError("SYNTHETIC_FIFO_OPEN_WOULD_BLOCK")
                    self.assertTrue(flags & NOFOLLOW)
                    self.assertFalse(flags & DIRECTORY)
                    self.assertEqual(kwargs, {"dir_fd": 103})
                    if case == "symlink":
                        raise OSError("SYNTHETIC_NOFOLLOW_LINK_REFUSAL")
                else:
                    self.assertTrue(flags & DIRECTORY)
                    self.assertTrue(flags & NOFOLLOW)
                    if str(name) == "a" and case == "parent_error":
                        raise OSError("SYNTHETIC_DIRECTORY_REFUSAL")
                return 100 + len(calls)

            def metadata(fd):
                typed.append(fd)
                self.assertEqual(fd, 104)
                if case == "fstat_error":
                    raise OSError("SYNTHETIC_FSTAT_REFUSAL")
                mode = stat.S_IFIFO if case == "fifo" else stat.S_IFREG
                return SimpleNamespace(st_mode=mode | 0o644, st_nlink=1, st_size=2)

            class Stream(io.BytesIO):
                def read(self, cap):
                    reads.append(cap)
                    if case == "read_error":
                        raise OSError("SYNTHETIC_READ_REFUSAL")
                    return super().read(cap)

            def fdopen(fd, mode, *, closefd):
                self.assertNotEqual(case, "fifo", "a nonregular descriptor reached the reader")
                self.assertEqual(typed, [104], "read must follow the descriptor type check")
                self.assertEqual((fd, mode, closefd), (104, "rb", False))
                return Stream(b"x\n")

            with (
                patch.object(f.os, "O_NONBLOCK", NONBLOCK, create=True),
                patch.object(f.os, "O_NOFOLLOW", NOFOLLOW, create=True),
                patch.object(f.os, "O_DIRECTORY", DIRECTORY, create=True),
                patch.object(f.os, "open", side_effect=opened),
                patch.object(f.os, "fstat", side_effect=metadata),
                patch.object(f.os, "fdopen", side_effect=fdopen),
                patch.object(f.os, "close", side_effect=lambda fd: closed.append(fd)),
            ):
                if case == "regular":
                    self.assertEqual(f.source_text(Path("SOURCE"), "a/b/file.c"), b"x\n")
                elif case == "fifo":
                    with self.assertRaisesRegex(ValueError, "patch_target_regular"):
                        f.source_text(Path("SOURCE"), "a/b/file.c")
                else:
                    with self.assertRaisesRegex(OSError, "SYNTHETIC"):
                        f.source_text(Path("SOURCE"), "a/b/file.c")
            if case == "parent_error":
                self.assertEqual(closed, [101])
                self.assertEqual((typed, reads), ([], []))
            elif case == "symlink":
                self.assertEqual(closed, [102, 103, 101])
                self.assertEqual((typed, reads), ([], []))
            else:
                self.assertEqual(closed, [102, 104, 103, 101])
                self.assertEqual(typed, [104])
                self.assertEqual(
                    reads,
                    [2 * 1024**2 + 1] if case in ("regular", "read_error") else [],
                )
            self.assertEqual(len(closed), len(set(closed)), "every owned FD closed exactly once")


class ConvertedFIFO(unittest.TestCase):
    test_07_source_FIFO_leaf_open_can_block_before_regular_check = fifo_regression
