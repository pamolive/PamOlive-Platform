"""Closed runtime adaptations; host tools, filesystems and processes are doubles."""

import json
import stat
import unittest
from pathlib import PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

import collector as c
import containerd_public as p
from test_containerd_public import ParentTests as ParentFixture
from test_containerd_public import fs, plugins, result, tool


class ToolCompatibilityTests(unittest.TestCase):
    def test_regular_cargo_sudo_measured_without_resolving_alternatives(self):
        target = "/usr/lib/cargo/bin/sudo"
        before = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=stat.S_IFREG | 0o4755,
            st_uid=0,
            st_gid=0,
            st_size=3,
            st_mtime_ns=1,
            st_nlink=1,
        )
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        opened, closed, blocks = [], [], iter((b"abc", b""))
        fake = SimpleNamespace(
            O_RDONLY=0,
            O_NOFOLLOW=1,
            O_CLOEXEC=2,
            O_NONBLOCK=4,
            open=lambda path, flags: opened.append(str(path)) or 7,
            fstat=lambda fd: before,
            read=lambda fd, size: next(blocks),
            close=closed.append,
        )
        with (
            patch.object(p, "Path", PurePosixPath),
            patch.object(p, "os", fake),
            patch.object(p, "tool_stat", lambda path: before if str(path) == target else directory),
        ):
            row = p.tool_record(target)
            self.assertEqual(row["path"], target)
            self.assertEqual(row["mode"], 0o4755)
            self.assertEqual(row["sha256"], c.sha(b"abc"))
            with self.assertRaises(p.ToolRefusal) as caught:
                p.tool_record("/usr/bin/sudo")
            self.assertEqual(caught.exception.code, "PATH")
        self.assertEqual(opened, [target])
        self.assertEqual(closed, [7])

    def test_tool_predicates_closed_and_unsafe_files_never_opened(self):
        target = "/usr/lib/cargo/bin/sudo"
        fields = dict(
            st_dev=1,
            st_ino=2,
            st_mode=stat.S_IFREG | 0o4755,
            st_uid=0,
            st_gid=0,
            st_size=3,
            st_mtime_ns=1,
            st_nlink=1,
        )
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        for changed, code in [
            ({"st_mode": stat.S_IFLNK | 0o777}, "NOT_REGULAR"),
            ({"st_nlink": 2}, "LINK_COUNT"),
            ({"st_uid": 1000}, "OWNER"),
            ({"st_mode": stat.S_IFREG | 0o4777}, "WRITABLE"),
            ({"st_size": 0}, "SIZE"),
        ]:
            row = SimpleNamespace(**dict(fields, **changed))
            with (
                patch.object(p, "Path", PurePosixPath),
                patch.object(
                    p, "tool_stat", lambda path: row if str(path) == target else directory
                ),
                patch.object(p.os, "open", side_effect=AssertionError("unsafe open")),
            ):
                with self.assertRaises(p.ToolRefusal) as caught:
                    p.tool_record(target)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(str(caught.exception), "PUBLIC_TOOL_REFUSED")

        def missing():
            raise FileNotFoundError("SYNTHETIC_PRIVATE")

        with self.assertRaises(p.ToolRefusal) as caught:
            p.tool_stat(SimpleNamespace(lstat=missing))
        self.assertEqual(caught.exception.code, "MISSING")
        self.assertNotIn("SYNTHETIC_PRIVATE", str(caught.exception))

    def test_exact_reviewed_242_cli_reaches_plugins_but_not_243_or_suffix(self):
        for version, expected in (
            ("v2.4.2", "COMPLETE"),
            ("2.4.2", "COMPLETE"),
            ("v2.4.3", "CLI_UNREVIEWED"),
            ("v2.4.2-vendor", "CLI_UNREVIEWED"),
        ):
            calls = []

            def run(argv, **options):
                calls.append((argv, options))
                raw = ("ctr github.com/containerd/containerd/v2 " + version + "\n").encode()
                return result(raw if len(calls) == 1 else plugins())

            packet = p.inspect_roots("/run/containerd/containerd.sock", run, tool, fs)
            self.assertEqual(packet["status"], expected)
            self.assertEqual(len(calls), 2 if expected == "COMPLETE" else 1)
            if expected == "COMPLETE":
                self.assertEqual(p.validate_packet(packet), packet)
                self.assertEqual(
                    calls[1][1]["env"]["CONTAINERD_SUPPRESS_DEPRECATION_WARNINGS"], "true"
                )
            else:
                self.assertIsNone(packet["exports"])


class ParentDiagnosticTests(unittest.TestCase):
    setUp = ParentFixture.setUp

    def test_parent_identifies_tool_stage_without_error_text_or_root_invocation(self):
        cp = c.public_module()

        def measure(path):
            if path == "/usr/bin/env":
                raise cp.ToolRefusal("NOT_REGULAR")
            return tool(path)

        with patch.object(c, "public_module", return_value=cp):
            c.collect_prerequisites(
                self.work,
                self.report,
                lambda *a, **k: self.fail("root invoked"),
                self.raw,
                measure=measure,
            )
        row = self.report["containerd_prerequisites"]
        self.assertEqual(row["status"], "PRECONDITION_REFUSED")
        self.assertEqual(row["failure"], {"stage": "env_tool_before", "code": "NOT_REGULAR"})
        self.assertEqual(set(row["tools"]), {"sudo"})
        self.assertFalse((self.work / "root-read-intent.json").exists())
        stored = json.loads((self.work / "root-read-result.json").read_bytes())
        self.assertEqual(stored["failure"], row["failure"])
        self.assertNotIn("PUBLIC_TOOL_REFUSED", json.dumps(row))
