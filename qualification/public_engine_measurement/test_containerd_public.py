"""Adversarial pure tests. No executable, socket, real Linux FD or daemon."""

import copy
import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import collector as c
import containerd_public as p
from test_collector import CollectorTests, Result, version


def plugins():
    return b"\n".join(
        (
            "Type:    "
            + kind
            + "\nID:      "
            + row[0]
            + "\nExports:\n         "
            + row[1]
            + "  /var/lib/containerd/"
            + row[2]
            + "\n"
        ).encode()
        for kind, row in p.TYPES.items()
    )


def tool(path):
    return {
        "path": path,
        "bytes": 1234,
        "sha256": "a" * 64,
        "file_type": "regular",
        "uid": 0,
        "gid": 0,
        "mode": 0o755,
        "nlink": 1,
    }


def fs(path):
    return {
        "path": path,
        "kind": "file" if path.endswith("/meta.db") else "directory",
        "device": 7 if "/containerd/" in path else 8,
        "inode": 123,
        "uid": 0,
        "gid": 0,
        "mode": 0o700,
        "size": 4096,
        "fsid": 33,
        "block_size": 4096,
        "blocks": 500,
        "available_blocks": 400,
        "available_bytes": 400 * 4096,
    }


def result(raw, **changes):
    row = Result(**changes)
    row.stdout = raw
    return row


def good_packet():
    calls = []

    def run(argv, **options):
        calls.append((argv, options))
        return result(
            b"ctr github.com/containerd/containerd/v2 v2.2.3\n" if len(calls) == 1 else plugins()
        )

    packet = p.inspect_roots("/run/containerd/containerd.sock", run, tool, fs)
    return packet, calls


class PublicTests(unittest.TestCase):
    def test_corrupt_support_source_pin_refuses_before_import(self):
        with patch.object(c, "PUBLIC_SHA", "0" * 64), self.assertRaises(ValueError):
            c.public_module()

    def test_components_and_endpoint_projection_closed_no_raw_or_hash(self):
        for bad in (
            [],
            [{"version": "v2.2.3", "revision": "A" * 40}],
            [{"version": "v2.2.3", "revision": "a" * 40}] * 2,
            [{"version": "SYNTHETIC_PRIVATE", "revision": "a" * 40}],
        ):
            projected = c.project("version", dict(version(), containerd=bad))
            self.assertEqual(projected["containerd"], {"redacted": True})
            self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(projected))
        for endpoint in (
            {"Address": "/private/SYNTHETIC_PRIVATE", "Namespaces": {}},
            {
                "Address": "/run/containerd/containerd.sock",
                "Namespaces": {"Containers": "other", "Plugins": "plugins.moby"},
            },
        ):
            projected = c.project(
                "info",
                {
                    "driver": "overlayfs",
                    "driver_status": None,
                    "root": "/var/lib/docker",
                    "containerd": endpoint,
                },
            )
            self.assertEqual(projected["containerd"], {"redacted": True})
            self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(projected))

    def test_two_readonly_ctr_calls_closed_env_filters_and_version(self):
        packet, calls = good_packet()
        self.assertEqual(p.validate_packet(packet), packet)
        self.assertEqual(calls[0][0], ["/usr/bin/ctr", "--version"])
        self.assertEqual(
            calls[1][0][-3:],
            ["type==" + name + ",id==" + row[0] for name, row in p.TYPES.items()],
        )
        self.assertNotIn("version", calls[1][0])
        self.assertEqual(
            packet["cli_identity"],
            {"package": "github.com/containerd/containerd/v2", "version": "v2.2.3"},
        )
        for argv, options in calls:
            self.assertEqual(options["env"], p.ENV)
            self.assertEqual(options["env"]["CONTAINERD_SUPPRESS_DEPRECATION_WARNINGS"], "true")
            self.assertNotIn("info", argv)
        self.assertEqual(len(packet["filesystems"]), 4)
        self.assertNotIn("total_available", packet)

    def test_cli_mismatch_or_unknown_version_never_reaches_plugins(self):
        for raw in (
            b"ctr github.com/containerd/containerd/v2 v2.1.5\n",
            b"secret-version\n",
            b"ctr github.com/containerd/containerd/v2 v2.2.3\ntrailing",
        ):
            calls = []
            packet = p.inspect_roots(
                "/run/containerd/containerd.sock",
                lambda *a, **k: calls.append(a) or result(raw),
                tool,
                fs,
            )
            self.assertEqual(len(calls), 1)
            self.assertEqual(packet["status"], "CLI_UNREVIEWED")
            self.assertNotIn("secret-version", json.dumps(packet))
            self.assertIsNone(packet["exports"])

    def test_unknown_version_lifecycle_stops_even_with_valid_stdout(self):
        for facts in (
            {"owned_child_reaped": False},
            {"drains_complete": False},
            {"exception_type": "RuntimeError"},
            {"pid": None},
        ):
            calls = []
            packet = p.inspect_roots(
                "/run/containerd/containerd.sock",
                lambda *a, **k: calls.append(a)
                or result(b"ctr github.com/containerd/containerd/v2 v2.2.3\n", **facts),
                tool,
                fs,
            )
            self.assertEqual(packet["status"], "UNKNOWN")
            self.assertEqual(len(calls), 1)

    def test_malformed_duplicate_error_and_unrelated_plugins_refuse(self):
        variants = [
            plugins() + plugins(),
            plugins().replace(b"ID:      content", b"ID:      wrong"),
            plugins().replace(b"Type:    io.containerd.content.v1", b"Type:    private.plugin"),
            plugins() + b"Error:\n    Message: SYNTHETIC_PRIVATE\n",
            plugins().replace(b"Exports:", b"Exports:\n         root /bad", 1),
            plugins().replace(
                b"/var/lib/containerd/io.containerd.content.v1.content",
                b"/private/SYNTHETIC_PRIVATE",
            ),
            b"x" * 32769,
            b"Type:\xff",
        ]
        for raw in variants:
            with (
                self.subTest(raw=raw[:40]),
                self.assertRaises((ValueError, UnicodeError)),
            ):
                p.plugin_exports(raw)

    def test_other_exports_dropped_not_hashed_or_published(self):
        raw = plugins().replace(b"Exports:\n", b"Exports:\n         other SYNTHETIC_PRIVATE\n", 1)
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(p.plugin_exports(raw)))
        self.assertEqual(p.plugin_exports(raw), p.plugin_exports(plugins()))

    def test_unexpected_endpoint_never_runs_and_path_never_stats(self):
        calls = []
        with self.assertRaises(ValueError):
            p.inspect_roots("/private/socket", lambda *a, **k: calls.append(a), tool, fs)
        self.assertEqual(calls, [])
        raw = plugins().replace(
            b"/var/lib/containerd/io.containerd.content.v1.content",
            b"/private/SYNTHETIC_PRIVATE",
        )
        seen = []
        calls = []

        def run(*args, **kwargs):
            calls.append(args)
            return result(
                b"ctr github.com/containerd/containerd/v2 v2.2.3\n" if len(calls) == 1 else raw
            )

        packet = p.inspect_roots(
            "/run/containerd/containerd.sock", run, tool, lambda path: seen.append(path)
        )
        self.assertEqual(seen, [])
        self.assertEqual(packet["status"], "DATA_REFUSED")
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(packet))

    def test_permission_refused_distinct_from_unknown_and_no_raw_error(self):
        def denied(_path):
            raise PermissionError("SYNTHETIC_PRIVATE")

        packet = p.inspect_roots(
            "/run/containerd/containerd.sock", lambda *a, **k: None, denied, fs
        )
        self.assertEqual(packet["status"], "PERMISSION_REFUSED")
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(packet))

    def test_refusal_diagnostic_keeps_cli_measurement_not_other_fields(self):
        packet, _ = good_packet()
        packet.update(
            status="CLI_UNREVIEWED",
            cli_identity={"package": "github.com/containerd/containerd/v2", "version": "v2.1.5"},
            private="SYNTHETIC_PRIVATE",
        )
        packet.update(ctr_process=None, exports=None, filesystems=None)
        projected = p.refusal_diagnostic(packet)
        self.assertEqual(projected["ctr_tool"], tool("/usr/bin/ctr"))
        self.assertEqual(
            projected["cli_identity"],
            {"package": "github.com/containerd/containerd/v2", "version": "v2.1.5"},
        )
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(projected))
        self.assertNotIn("exports", projected)

    def test_tool_changes_never_complete(self):
        count = 0

        def changing(path):
            nonlocal count
            count += 1
            return dict(tool(path), sha256=("b" if count > 1 else "a") * 64)

        packet = p.inspect_roots(
            "/run/containerd/containerd.sock",
            lambda *a, **k: result(b"ctr github.com/containerd/containerd/v2 v2.2.3\n"),
            changing,
            fs,
        )
        self.assertEqual(packet["status"], "UNKNOWN")
        self.assertFalse(packet["tool_unchanged"])

    def test_nested_plugins_unknown_is_not_healed_by_valid_bytes(self):
        calls = []

        def run(*_args, **_options):
            calls.append(1)
            return (
                result(b"ctr github.com/containerd/containerd/v2 v2.2.3\n")
                if len(calls) == 1
                else result(plugins(), owned_child_reaped=False, drains_complete=False)
            )

        packet = p.inspect_roots("/run/containerd/containerd.sock", run, tool, fs)
        self.assertEqual(packet["status"], "UNKNOWN")
        self.assertIsNone(packet["exports"])
        self.assertFalse(packet["ctr_process"]["owned_child_reaped"])

    def test_internal_deadline_is_set_and_unknown_output_is_typed(self):
        timings, output = [], io.BytesIO()
        fake_signal = SimpleNamespace(
            SIGALRM=1,
            ITIMER_REAL=2,
            signal=lambda *_a: None,
            setitimer=lambda *a: timings.append(a),
        )
        fake_os = SimpleNamespace(
            name="posix",
            getuid=lambda: 0,
            environ={key: p.ENV[key] for key in ("PATH", "HOME", "LANG", "LC_ALL")},
        )
        with (
            patch.object(p, "signal", fake_signal),
            patch.object(p, "os", fake_os),
            patch.object(p.sys, "executable", "/usr/bin/python3.14"),
            patch.object(p.sys, "argv", ["-c", "/run/containerd/containerd.sock"]),
            patch.object(p.sys, "stdout", SimpleNamespace(buffer=output)),
            patch.object(p, "inspect_roots", side_effect=TimeoutError("PRIVATE")),
            patch.dict(p.__dict__, {"run_capped": lambda *a: None}),
        ):
            code = p.root_main()
        self.assertEqual(code, 42)
        self.assertEqual(timings, [(2, 25), (2, 0)])
        self.assertEqual(
            json.loads(output.getvalue()),
            {"schema": "public-containerd-roots/3", "status": "UNKNOWN"},
        )
        self.assertNotIn(b"PRIVATE", output.getvalue())

    def test_closed_packet_rejects_fact_types_unknown_path_and_fabricated_capacity(
        self,
    ):
        packet, _ = good_packet()
        changes = [
            lambda x: x.update(authority=True),
            lambda x: x["ctr_process"].update(pid=True),
            lambda x: x["ctr_process"].update(owned_child_reaped=False),
            lambda x: x["filesystems"]["docker_root"].update(available_bytes=99),
            lambda x: x["exports"].update({"io.containerd.content.v1": "/private"}),
            lambda x: x["tool"].update(extra="PRIVATE"),
            lambda x: x["filesystems"]["docker_root"].update(blocks=True),
        ]
        for change in changes:
            value = copy.deepcopy(packet)
            change(value)
            with self.assertRaises((ValueError, TypeError)):
                p.validate_packet(value)

    def test_capacity_fd_chain_file_itself_and_cleanup(self):
        fake = FakeOS()
        path = "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"
        value = p.capacity(path, system=fake)
        self.assertEqual(value["kind"], "file")
        self.assertEqual(fake.vfs_fd, fake.opened[-1][0])
        self.assertEqual(fake.closed, list(reversed([fd for fd, *_ in fake.opened])))
        self.assertTrue(
            all(options.get("follow_symlinks") is False for options in fake.stat_options)
        )

    def test_capacity_symlink_or_device_refused_before_open(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFCHR | 0o600):
            fake = FakeOS(bad=mode)
            with self.assertRaises(ValueError):
                p.capacity(
                    "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db",
                    system=fake,
                )
            self.assertNotIn("meta.db", [path for _fd, path, _flags in fake.opened])
            self.assertEqual(len(fake.closed), len(fake.opened))

    def test_capacity_path_or_inode_swap_never_claims_complete(self):
        fake = FakeOS(swap=True)
        with self.assertRaises(ValueError):
            p.capacity("/var/lib/docker", system=fake)
        self.assertEqual(len(fake.closed), len(fake.opened))
        fake = FakeOS()
        with self.assertRaises(ValueError):
            p.capacity("/private/SYNTHETIC", system=fake)
        self.assertEqual(fake.opened, [])


class FakeOS:
    O_RDONLY, O_NOFOLLOW, O_CLOEXEC, O_NONBLOCK, O_DIRECTORY = 0, 1, 2, 4, 8

    def __init__(self, bad=None, swap=False):
        self.opened, self.closed, self.stat_options = [], [], []
        self.bad, self.swap, self.vfs_fd = bad, swap, None

    def row(self, name):
        mode = (self.bad or stat.S_IFREG | 0o600) if name == "meta.db" else stat.S_IFDIR | 0o700
        return SimpleNamespace(
            st_dev=7,
            st_ino=123,
            st_mode=mode,
            st_uid=0,
            st_gid=0,
            st_size=4096,
            st_nlink=1,
        )

    def stat(self, name, **options):
        self.stat_options.append(options)
        return self.row(name)

    def open(self, path, flags, **_options):
        fd = 100 + len(self.opened)
        self.opened.append((fd, path, flags))
        return fd

    def fstat(self, fd):
        row = self.row(next(path for number, path, _ in self.opened if number == fd))
        if self.swap:
            row.st_ino = 456
        return row

    def fstatvfs(self, fd):
        self.vfs_fd = fd
        return SimpleNamespace(f_frsize=4096, f_blocks=500, f_bavail=400, f_fsid=33)

    def close(self, fd):
        self.closed.append(fd)


class ParentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=c.HERE, prefix="parent-pure-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.legacy = CollectorTests()
        self.legacy.tool = tool("/usr/bin/docker")
        self.calls = []
        self.report = c.collect(self.work / "work", self.legacy.good(self.calls), self.legacy.tool)
        self.work = self.work / "work"
        self.raw = (c.HERE / "bounded_io.py").read_bytes()

    def run_root(self, reply=None, fail=None, after=None):
        packet, _ = good_packet()

        def runner(argv, **options):
            self.assertTrue((self.work / "root-read-intent.json").exists())
            self.assertFalse((self.work / "root-read-result.json").exists())
            self.assertEqual(
                argv[:5],
                ["/usr/lib/cargo/bin/sudo", "-n", "--", "/usr/lib/cargo/bin/coreutils/env", "-i"],
            )
            self.assertEqual(set(options["env"]), {"PATH", "HOME", "LANG", "LC_ALL"})
            self.assertEqual(argv[-1], "/run/containerd/containerd.sock")
            self.assertNotIn("SYNTHETIC_PRIVATE", argv)
            self.assertIn("/usr/bin/python3.14", argv)
            self.assertEqual(options["stdout_cap"], 16384)
            options["on_spawn"](321)
            if fail:
                raise RuntimeError("SYNTHETIC_PRIVATE")
            return result(json.dumps(packet).encode()) if reply is None else reply

        c.collect_prerequisites(
            self.work,
            self.report,
            runner,
            self.raw,
            measure=after or tool,
            python="/usr/bin/python3.14",
        )

    def test_parent_one_sudo_closed_code_env_intent_pid_actual_h1_and_data(self):
        self.run_root()
        self.assertEqual(self.report["containerd_prerequisites"]["status"], "COMPLETE")
        self.assertEqual(json.loads((self.work / "root-read-pid.json").read_bytes())["pid"], 321)
        self.assertEqual(c.finalize(self.work, self.report, self.legacy.tool), 0)
        written = json.loads((self.work / "public-report.json").read_bytes())
        self.assertTrue(written["all_prerequisites_received"])
        self.assertFalse(written["profile_accepted"])
        self.assertEqual(len(self.calls), 4)

    def test_parent_unknown_h1_never_admits_valid_child_packet(self):
        packet, _ = good_packet()
        self.run_root(reply=result(json.dumps(packet).encode(), owned_child_reaped=False))
        self.assertEqual(self.report["containerd_prerequisites"]["status"], "UNKNOWN")
        self.assertIsNone(self.report["containerd_prerequisites"]["data"])
        self.assertEqual(c.finalize(self.work, self.report, self.legacy.tool), 42)

    def test_parent_exception_keeps_pending_and_durable_unknown(self):
        with self.assertRaises(RuntimeError):
            self.run_root(fail=True)
        self.assertEqual(
            json.loads((self.work / "root-read-result.json").read_bytes())["state"],
            "UNKNOWN",
        )
        self.assertTrue((self.work / "root-read-intent.json").exists())

    def test_parent_incomplete_docker_never_attempts_root(self):
        self.report["all_clients_reaped_drained"] = False
        c.collect_prerequisites(
            self.work,
            self.report,
            lambda *a, **k: self.fail("unexpected sudo"),
            self.raw,
            measure=tool,
            python="/usr/bin/python3.14",
        )
        self.assertFalse((self.work / "root-read-intent.json").exists())

    def test_redacted_endpoint_does_not_reach_sudo(self):
        self.report["queries"]["info"]["data"]["containerd"] = {"redacted": True}
        c.collect_prerequisites(
            self.work,
            self.report,
            lambda *a, **k: self.fail("unexpected sudo"),
            self.raw,
            measure=tool,
            python="/usr/bin/python3.14",
        )
        self.assertEqual(self.report["containerd_prerequisites"]["status"], "PRECONDITION_REFUSED")

    def test_parent_permission_refusal_no_raw_stderr(self):
        self.run_root(
            reply=result(b"", code=1, error=b"sudo: a password is required SYNTHETIC_PRIVATE")
        )
        row = self.report["containerd_prerequisites"]
        self.assertEqual(row["status"], "PERMISSION_REFUSED")
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(row))

    def test_parent_changed_sudo_blocks_despite_complete_child(self):
        count = 0

        def changing(path):
            nonlocal count
            count += 1
            return dict(tool(path), sha256=("b" if count > 3 else "a") * 64)

        self.run_root(after=changing)
        self.assertEqual(self.report["containerd_prerequisites"]["status"], "UNKNOWN")
        self.assertIsNone(self.report["containerd_prerequisites"]["data"])


if __name__ == "__main__":
    unittest.main()
