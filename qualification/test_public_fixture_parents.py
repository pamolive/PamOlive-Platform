"""Four in-memory adversarial cases; no target filesystem or Linux call on Windows."""

import copy
import errno
import importlib.util
import json
import stat
import unittest
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location(
    "public_fixture_parents_subject", Path(__file__).with_name("public_fixture_parents.py")
)
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)


class Clock:
    def __init__(self):
        self.value = 10.0

    def __call__(self):
        self.value += 0.001
        return self.value


class MemoryOS:
    O_PATH, O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC = 0x200000, 0x10000, 0x20000, 0x80000
    O_WRONLY, O_CREAT, O_EXCL = 1, 0x40, 0x80

    def __init__(
        self, *, alias=None, swap=None, denied=None, writable=None, expire=None, clock=None
    ):
        paths = [
            "/",
            "/usr",
            "/usr/bin",
            "/usr/bin/dpkg-query",
            "/opt",
            "/opt/google",
            "/opt/google/chrome",
            "/opt/google/chrome/chrome",
            "/run",
            "/run/ci-temp",
        ]
        self.rows = {}
        for ino, path in enumerate(paths, 1):
            directory = path not in subject.ROLE_PATHS.values()
            self.rows[path] = SimpleNamespace(
                st_dev=1,
                st_ino=ino,
                st_mode=(stat.S_IFDIR | 0o755) if directory else stat.S_IFREG | 0o755,
                st_uid=0,
                st_gid=0,
                st_nlink=2 if directory else 1,
                st_mtime_ns=1,
                st_ctime_ns=1,
            )
        self.rows["/run/ci-temp"].st_uid = 1001
        self.rows["/run/ci-temp"].st_mode = stat.S_IFDIR | 0o700
        if alias:
            self.rows[alias].st_mode = stat.S_IFLNK | 0o777
        if writable:
            self.rows[writable].st_mode |= 0o022
        self.alias, self.swap, self.denied = alias, swap, denied
        self.expire, self.clock = expire, clock
        self.fds, self.closed, self.calls, self.files = {}, [], [], {}
        self.next = 10

    def getuid(self):
        return 1001

    def geteuid(self):
        return 1001

    def path(self, name, parent):
        return str(
            PurePosixPath(name)
            if name.startswith("/")
            else PurePosixPath(self.fds[parent][0]) / name
        )

    def stat(self, name, *, dir_fd=None, follow_symlinks=True):
        assert follow_symlinks is False
        path = self.path(name, dir_fd)
        self.calls.append(("stat", path))
        if path == self.denied:
            raise PermissionError(errno.EACCES, "PRIVATE_ERROR_MUST_NOT_LEAK")
        if path not in self.rows:
            raise FileNotFoundError(errno.ENOENT, "PRIVATE_MISSING")
        return copy.copy(self.rows[path])

    def open(self, name, flags, *, dir_fd=None, mode=0o777):
        path = self.path(name, dir_fd)
        self.calls.append(("open", path, flags))
        assert flags & self.O_NOFOLLOW and flags & self.O_CLOEXEC
        if flags & self.O_CREAT:
            assert flags & self.O_EXCL and mode == 0o600
            if path in self.rows:
                raise FileExistsError(errno.EEXIST, "PRIVATE_COLLISION")
            self.rows[path] = SimpleNamespace(
                st_dev=1,
                st_ino=999,
                st_mode=stat.S_IFREG | mode,
                st_uid=1001,
                st_gid=1001,
                st_nlink=1,
                st_mtime_ns=1,
                st_ctime_ns=1,
            )
        else:
            assert flags & self.O_PATH
        self.next += 1
        observed = copy.copy(self.rows[path])
        if path == self.swap:
            observed.st_ino += 1000
        self.fds[self.next] = (path, observed)
        if path == self.expire:
            self.clock.value = 99.0
        return self.next

    def fstat(self, fd):
        self.calls.append(("fstat", fd))
        return copy.copy(self.fds[fd][1])

    def close(self, fd):
        assert fd in self.fds
        self.closed.append(fd)
        del self.fds[fd]

    def write(self, fd, raw):
        self.files[self.fds[fd][0]] = raw
        return len(raw)

    def fsync(self, fd):
        assert fd in self.fds


def environment():
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "pamolive/PamOlive-Platform",
        "GITHUB_REPOSITORY_ID": "1449671447",
        "GITHUB_REPOSITORY_OWNER_ID": "305596298",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ID": "44113660586",
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_TEMP": "/run/ci-temp",
        "ImageOS": "ubuntu24",
        "ImageVersion": "20261116.1",
    }


def collect(ops, env=None, clock=None):
    return subject.collect(
        environment() if env is None else env,
        subject.ACK,
        ops=ops,
        platform="linux",
        clock=clock or Clock(),
        wall=lambda: 1794900000,
    )


class PublicFixtureParentTests(unittest.TestCase):
    def test_alias_stops_before_descendants_no_follow_no_leaked_FD(self):
        ops = MemoryOS(alias="/opt/google")
        packet, _ = collect(ops)
        chrome = packet["roles"]["CHROME_TARGET"]
        self.assertEqual(chrome["nodes"][-1]["status"], "ALIAS")
        self.assertTrue(chrome["nodes"][-1]["metadata"]["alias"])
        self.assertFalse(packet["observation_complete"])
        self.assertFalse(
            any(
                c[0] in {"stat", "open"} and c[1].startswith("/opt/google/chrome")
                for c in ops.calls
            )
        )
        self.assertEqual(ops.fds, {})
        with self.assertRaisesRegex(ValueError, "FIXED_ROLE_PATH_REQUIRED"):
            subject.walk("/PRIVATE", ops, Clock(), 40)

    def test_swapped_FD_and_budget_after_open_refuse_before_descendants_and_close(self):
        ops = MemoryOS(swap="/opt/google")
        packet, _ = collect(ops)
        chrome = packet["roles"]["CHROME_TARGET"]
        self.assertEqual(chrome["nodes"][-1]["status"], "RACE")
        self.assertTrue(chrome["nodes"][-1]["race"])
        self.assertFalse(chrome["observation_complete"])
        self.assertEqual(ops.fds, {})
        self.assertFalse(
            any(c[0] == "stat" and c[1].startswith("/opt/google/chrome") for c in ops.calls)
        )
        clock = Clock()
        ops = MemoryOS(expire="/usr", clock=clock)
        with self.assertRaisesRegex(ValueError, "METADATA_BUDGET"):
            collect(ops, clock=clock)
        self.assertEqual(ops.fds, {})

    def test_permission_unknown_invalid_labels_and_context_never_dump_private_error(self):
        ops = MemoryOS(denied="/opt/google")
        env = environment() | {"ImageVersion": "PRIVATE\nRAW", "ImageOS": "x" * 65}
        packet, _ = collect(ops, env)
        self.assertEqual(
            packet["roles"]["CHROME_TARGET"]["nodes"][-1]["status"], "PERMISSION_DENIED"
        )
        self.assertFalse(packet["observation_complete"])
        self.assertIsNone(packet["roles"]["CHROME_TARGET"]["parent_guard_compatible"])
        self.assertIsNone(packet["supplier_labels"]["ImageVersion"]["value"])
        self.assertNotIn("PRIVATE", json.dumps(packet))
        self.assertEqual(ops.fds, {})
        for key, value in (
            ("GITHUB_REPOSITORY_ID", "1"),
            ("RUNNER_ENVIRONMENT", "self-hosted"),
            ("GITHUB_SHA", "PRIVATE"),
            ("GITHUB_RUN_ID", "0"),
        ):
            ops = MemoryOS()
            with self.assertRaises(ValueError):
                collect(ops, environment() | {key: value})
            self.assertEqual(ops.calls, [])
        ops = MemoryOS()
        ops.getuid = lambda: 0
        ops.geteuid = lambda: 0
        with self.assertRaisesRegex(ValueError, "DISPOSABLE_GH_NONROOT_REQUIRED"):
            collect(ops)
        self.assertEqual(ops.calls, [])

    def test_complete_writable_observation_is_not_compatible_and_output_exclusive_bounded(self):
        ops, clock = MemoryOS(writable="/usr"), Clock()
        packet, deadline = collect(ops, clock=clock)
        self.assertTrue(packet["observation_complete"])
        self.assertFalse(packet["roles"]["DPKG_QUERY"]["parent_guard_compatible"])
        self.assertTrue(packet["roles"]["DPKG_QUERY"]["nodes"][1]["metadata"]["group_writable"])
        self.assertFalse(packet["full_tool_guard_verified"])
        self.assertFalse(packet["authority"])
        self.assertFalse(packet["profile_accepted"])
        self.assertFalse(packet["provider_attested"])
        self.assertFalse(packet["historical_dfb_cause_proved"])
        self.assertFalse(packet["automatic_action_allowed"])
        self.assertFalse(packet["operational_GO"])
        path = "/run/ci-temp/" + subject.OUTPUT_NAME
        subject.write_public(packet, path, environment(), deadline, ops=ops, clock=clock)
        raw = ops.files[path]
        self.assertLessEqual(len(raw), 16384)
        self.assertEqual(json.loads(raw), packet)
        with self.assertRaises(FileExistsError):
            subject.write_public(packet, path, environment(), deadline, ops=ops, clock=clock)
        self.assertEqual(ops.files[path], raw)
        self.assertEqual(ops.fds, {})
        with self.assertRaisesRegex(ValueError, "PUBLIC_OUTPUT_PATH"):
            subject.write_public(
                packet, "/arbitrary/out.json", environment(), deadline, ops=ops, clock=clock
            )
        clock.value = deadline
        with self.assertRaisesRegex(ValueError, "METADATA_BUDGET"):
            subject.write_public(packet, path, environment(), deadline, ops=MemoryOS(), clock=clock)
