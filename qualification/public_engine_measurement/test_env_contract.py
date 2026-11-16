"""Pure env-role hardlink and ROOT packet v2 contracts; no real tools or Linux FD."""

import copy
import stat
import unittest
from pathlib import PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

import collector as c
import containerd_public as p
from test_containerd_public import ParentTests as ParentFixture
from test_containerd_public import good_packet, result, tool


class EnvToolTests(unittest.TestCase):
    def measure(self, target, *, fields=None, parent=None, first_fd=None, last_fd=None, final=None):
        facts = {
            "st_dev": 1,
            "st_ino": 2,
            "st_mode": stat.S_IFREG | 0o755,
            "st_uid": 0,
            "st_gid": 0,
            "st_size": 3,
            "st_mtime_ns": 1,
            "st_nlink": 2,
        } | (fields or {})
        before = SimpleNamespace(**facts)
        directory = SimpleNamespace(
            **({"st_mode": stat.S_IFDIR | 0o755, "st_uid": 0} | (parent or {}))
        )
        blocks = iter((b"abc", b""))
        self.opened, self.closed, leaf_calls = [], [], []
        fds = iter(
            (
                SimpleNamespace(**(facts | (first_fd or {}))),
                SimpleNamespace(**(facts | (last_fd or {}))),
            )
        )

        def lstat(path):
            if str(path) != target:
                return directory
            leaf_calls.append(True)
            return before if len(leaf_calls) == 1 else SimpleNamespace(**(facts | (final or {})))

        fake = SimpleNamespace(
            O_RDONLY=0,
            O_NOFOLLOW=1,
            O_CLOEXEC=2,
            O_NONBLOCK=4,
            open=lambda path, flags: self.opened.append((str(path), flags)) or 7,
            fstat=lambda fd: next(fds),
            read=lambda fd, size: next(blocks),
            close=self.closed.append,
        )
        with (
            patch.object(p, "Path", PurePosixPath),
            patch.object(p, "os", fake),
            patch.object(p, "tool_stat", lstat),
        ):
            return p.tool_record(target)

    def test_only_fixed_env_role_accepts_positive_stable_multiple_links(self):
        for count in (1, 2, 114):
            with self.subTest(count=count):
                row = self.measure(p.ENV_TOOL, fields={"st_nlink": count})
                self.assertEqual(set(row), p.TOOL_KEYS)
                self.assertEqual(len(row), 8)
                self.assertEqual(row["nlink"], count)
                self.assertEqual(row["sha256"], c.sha(b"abc"))
                self.assertEqual(self.opened, [(p.ENV_TOOL, 7)])
                self.assertEqual(self.closed, [7])

    def test_other_tools_keep_one_link_and_unlisted_env_aliases_never_open(self):
        for target in ("/usr/bin/ctr", "/usr/lib/cargo/bin/sudo", "/usr/bin/python3.14"):
            with self.subTest(target=target), self.assertRaises(p.ToolRefusal) as caught:
                self.measure(target)
            self.assertEqual(caught.exception.code, "LINK_COUNT")
            self.assertEqual(self.opened, [])
        for target in ("/usr/bin/env", "/usr/bin/coreutils", "/usr/lib/cargo/bin/coreutils"):
            with self.subTest(target=target), self.assertRaises(p.ToolRefusal) as caught:
                self.measure(target)
            self.assertEqual(caught.exception.code, "PATH")
            self.assertEqual(self.opened, [])

    def test_env_zero_negative_bool_and_noninteger_link_counts_refuse(self):
        for count in (0, -1, True, False, "2", 2.0):
            with self.subTest(count=count), self.assertRaises(p.ToolRefusal) as caught:
                self.measure(p.ENV_TOOL, fields={"st_nlink": count})
            self.assertEqual(caught.exception.code, "LINK_COUNT")
            self.assertEqual(self.opened, [])

    def test_env_type_owner_writable_and_size_guards_are_preserved(self):
        for fields, code in (
            ({"st_mode": stat.S_IFLNK | 0o777}, "NOT_REGULAR"),
            ({"st_mode": stat.S_IFCHR | 0o600}, "NOT_REGULAR"),
            ({"st_uid": 1000}, "OWNER"),
            ({"st_mode": stat.S_IFREG | 0o775}, "WRITABLE"),
            ({"st_mode": stat.S_IFREG | 0o757}, "WRITABLE"),
            ({"st_size": 0}, "SIZE"),
            ({"st_size": 128 * 1024**2 + 1}, "SIZE"),
        ):
            with self.subTest(fields=fields), self.assertRaises(p.ToolRefusal) as caught:
                self.measure(p.ENV_TOOL, fields=fields)
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(self.opened, [])

    def test_env_all_parents_reject_symlink_nonroot_and_writable(self):
        for fields in (
            {"st_mode": stat.S_IFLNK | 0o777},
            {"st_uid": 1000},
            {"st_mode": stat.S_IFDIR | 0o775},
            {"st_mode": stat.S_IFDIR | 0o757},
        ):
            with self.subTest(fields=fields), self.assertRaises(p.ToolRefusal) as caught:
                self.measure(p.ENV_TOOL, parent=fields)
            self.assertEqual(caught.exception.code, "PARENT_UNSAFE")
            self.assertEqual(self.opened, [])

    def test_nlink_and_all_other_identity_fields_bound_to_fd_and_final_path(self):
        for position in ("first_fd", "last_fd", "final"):
            for field, value in (
                ("st_nlink", 3),
                ("st_dev", 2),
                ("st_ino", 3),
                ("st_uid", 1000),
                ("st_gid", 1000),
                ("st_mode", stat.S_IFREG | 0o700),
                ("st_size", 4),
                ("st_mtime_ns", 2),
            ):
                with (
                    self.subTest(position=position, field=field),
                    self.assertRaises(p.ToolRefusal) as caught,
                ):
                    self.measure(p.ENV_TOOL, **{position: {field: value}})
                self.assertEqual(caught.exception.code, "IDENTITY_CHANGED")
                self.assertEqual(self.closed, [7])

    def test_root_packet_v2_requires_exact_eight_fields_and_ctr_one_link(self):
        packet, _ = good_packet()
        self.assertEqual(packet["schema"], "public-containerd-roots/2")
        self.assertEqual(len(packet["tool"]), 8)
        self.assertEqual(p.validate_packet(packet), packet)
        for value in (True, False, 0, -1, 2, "1", 1.0):
            broken = copy.deepcopy(packet)
            broken["tool"]["nlink"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                p.validate_packet(broken)
        broken = copy.deepcopy(packet)
        del broken["tool"]["nlink"]
        with self.assertRaises(ValueError):
            p.validate_packet(broken)
        for status in ("COMPLETE", "UNKNOWN"):
            broken = copy.deepcopy(packet)
            broken.update(schema="public-containerd-roots/1", status=status)
            with self.assertRaises(ValueError):
                p.validate_packet(broken)
            with self.assertRaises(ValueError):
                p.refusal_diagnostic(broken)

    def test_ctr_nlink_change_never_heals_with_valid_cli_stdout(self):
        measured = []

        def measure(path):
            measured.append(path)
            return tool(path) | {"nlink": 1 if len(measured) == 1 else 2}

        calls = []
        packet = p.inspect_roots(
            "/run/containerd/containerd.sock",
            lambda *args, **kwargs: calls.append(args)
            or result(b"ctr github.com/containerd/containerd/v2 v2.4.2\n"),
            measure,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(packet["status"], "UNKNOWN")
        self.assertFalse(packet["tool_unchanged"])
        self.assertIsNone(packet["exports"])


class ParentEnvTests(unittest.TestCase):
    setUp = ParentFixture.setUp
    run_root = ParentFixture.run_root

    def test_parent_env_nlink_is_retained_and_changed_count_keeps_unknown(self):
        seen = []

        def measure(path):
            seen.append(path)
            count = 1
            if path == p.ENV_TOOL:
                count = 2 if len(seen) <= 3 else 3
            return tool(path) | {"nlink": count}

        self.run_root(after=measure)
        row = self.report["containerd_prerequisites"]
        self.assertEqual(row["tools"]["env"]["nlink"], 2)
        self.assertEqual(row["status"], "UNKNOWN")
        self.assertFalse(row["tools_unchanged"])
        self.assertIsNone(row["data"])
        self.assertEqual(row["failure"], {"stage": "reader_tools_after", "code": "TOOL_CHANGED"})
        self.assertTrue((self.work / "root-read-intent.json").exists())
        self.assertEqual(c.finalize(self.work, self.report, self.legacy.tool), 42)

    def test_parent_v1_child_packet_is_not_current_admission(self):
        packet, _ = good_packet()
        packet["schema"] = "public-containerd-roots/1"
        self.run_root(reply=result(c.json.dumps(packet).encode()))
        row = self.report["containerd_prerequisites"]
        self.assertEqual(row["status"], "UNKNOWN")
        self.assertEqual(row["failure"], {"stage": "root_packet", "code": "READ_REFUSED"})
        self.assertIsNone(row["data"])
