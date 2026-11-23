"""Probe staging tests with a synthetic TAR and an in-memory POSIX workspace."""

import io
import stat
import tarfile
import time
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

from qualification.p1g_headless import chrome_bundle as bundle
from qualification.p1g_headless import chrome_probe_stage as stage
from qualification.p1g_headless.test_chrome_bundle import PKG, MemoryOS, payload, profile

WORKSPACE = "/tmp/private"
DESTINATION = WORKSPACE + "/browser"
HELPER = (bundle.PREFIX + "/chrome-sandbox", b"SYNTHETIC_HELPER", 0o4755, tarfile.REGTYPE)


class RunnerOS(MemoryOS):
    uid = 1000

    def __init__(self):
        super().__init__()
        self.make(WORKSPACE, stat.S_IFDIR | 0o700)

    def getuid(self):
        return self.uid

    geteuid = getuid

    def make(self, name, mode, raw=b""):
        node = super().make(name, mode, raw)
        node["uid"] = node["gid"] = self.uid
        return node

    def open(self, path, flags, mode=0, *, dir_fd=None):
        node = self.nodes.get(self.name(path, dir_fd))
        if node and stat.S_ISLNK(node["mode"]):
            raise OSError("SYNTHETIC_NOFOLLOW")
        return super().open(path, flags, mode, dir_fd=dir_fd)

    def row(self, node):
        info = super().row(node)
        info.st_nlink = node.get("nlink", info.st_nlink)
        return info

    @contextmanager
    def scandir(self, fd):
        yield (SimpleNamespace(name=name) for name in self.listdir(fd))


class ProbeStageTests(unittest.TestCase):
    def setUp(self):
        self.until = time.monotonic() + 10
        self.stream = payload(extra=(HELPER,))
        tree = bundle.inventory(self.stream, PKG, until=self.until)
        helper = next(row for row in tree["entries"] if row["name"] == stage.HELPER)
        raw, digest = profile(tree, roles={stage.HELPER: {
            "role": "setuid-sandbox-helper", "sha256": helper["sha256"], "mode": 0o4755,
        }})
        self.names = bundle.admit(tree, raw, digest)
        self.ops = RunnerOS()
        patcher = patch.object(stage, "os", self.ops)
        patcher.start()
        self.addCleanup(patcher.stop)

    def materialize(self, stream=None):
        return stage.materialize(self.stream if stream is None else stream,
                                 self.names, DESTINATION, until=self.until)

    def verify(self):
        return stage.verify_tree(self.names, DESTINATION, until=self.until)

    def test_copies_exact_tree_without_helper_or_outside_files(self):
        self.assertIsNone(self.materialize())
        self.assertEqual(self.ops.fds, {})
        self.assertIsNone(self.verify())
        expected = {"": 0o700, "/chrome": 0o500,
                    "/locales": 0o700, "/locales/en-US.pak": 0o400}
        staged = {name.removeprefix(DESTINATION): node for name, node in self.ops.nodes.items()
                  if name == DESTINATION or name.startswith(DESTINATION + "/")}
        self.assertEqual({name: stat.S_IMODE(node["mode"]) for name, node in staged.items()},
                         expected)
        self.assertEqual({node["uid"] for node in staged.values()}, {1000})
        self.assertEqual(staged["/locales/en-US.pak"]["data"], b"SYNTHETIC_RESOURCE")
        self.assertEqual(self.ops.fds, {})

    def test_rejects_extra_missing_duplicate_and_changed_metadata_before_creation(self):
        resource = bundle.PREFIX + "/locales/en-US.pak"

        def change_metadata(member):
            if member.name == resource:
                member.uid = 999

        def change_directory(member):
            if member.name == bundle.PREFIX + "/locales":
                member.mode = 0o700

        extra = (bundle.PREFIX + "/extra", b"data", 0o644, tarfile.REGTYPE)
        duplicate = (resource, b"data", 0o644, tarfile.REGTYPE)
        for stream, error in (
            (payload(), "probe_stage_members"),
            (payload(extra=(HELPER, extra)), "probe_stage_metadata"),
            (payload(extra=(HELPER, duplicate)), "bundle_tar_collision"),
            (payload(extra=(HELPER,), change=change_metadata), "probe_stage_metadata"),
            (payload(extra=(HELPER,), change=change_directory), "probe_stage_metadata"),
        ):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                self.materialize(stream)
            self.assertNotIn(DESTINATION, self.ops.nodes)
            self.assertEqual(self.ops.fds, {})

    def test_rejects_payload_drift_in_both_copied_and_omitted_members(self):
        tampered_helper = self.stream.getvalue().replace(b"SYNTHETIC_HELPER", b"SYNTHETIC_H3LPER")
        with self.assertRaisesRegex(ValueError, "probe_stage_payload"):
            self.materialize(io.BytesIO(tampered_helper))
        self.assertNotIn(DESTINATION, self.ops.nodes)
        tampered_chrome = self.stream.getvalue().replace(b"NOT_EXECUTABLE", b"NOT_3XECUTABLE")
        with self.assertRaisesRegex(ValueError, "probe_stage_payload"):
            self.materialize(io.BytesIO(tampered_chrome))
        self.assertEqual(stat.S_IMODE(self.ops.nodes[DESTINATION + "/chrome"]["mode"]), 0o600)
        self.assertEqual(self.ops.fds, {})

    def test_rejects_existing_destination_nonprivate_parent_and_root(self):
        self.ops.make(DESTINATION, stat.S_IFLNK | 0o777)
        with self.assertRaises(FileExistsError):
            self.materialize()
        self.assertEqual(self.ops.fds, {})
        del self.ops.nodes[DESTINATION]
        self.ops.nodes[WORKSPACE]["mode"] = stat.S_IFDIR | 0o755
        with self.assertRaisesRegex(ValueError, "probe_stage_private_directory"):
            self.materialize()
        self.ops.uid = 0
        with self.assertRaisesRegex(ValueError, "probe_stage_nonroot"):
            self.materialize()
        self.assertNotIn(DESTINATION, self.ops.nodes)

    def test_tree_recheck_refuses_links_unknowns_and_content_mode_owner_changes(self):
        self.materialize()
        leaf = DESTINATION + "/chrome"
        node = self.ops.nodes[leaf]
        for change in (
            {"data": b"x" * len(node["data"])},
            {"mode": stat.S_IFREG | 0o4700},
            {"mode": stat.S_IFLNK | 0o777},
            {"uid": 0},
            {"nlink": 2},
        ):
            with (
                self.subTest(change=change),
                patch.dict(node, change),
                self.assertRaisesRegex(ValueError, "probe_stage_"),
            ):
                self.verify()
            self.assertEqual(self.ops.fds, {})
        self.ops.make(DESTINATION + "/chrome-sandbox", stat.S_IFREG | 0o400)
        with self.assertRaisesRegex(ValueError, "probe_stage_fileset"):
            self.verify()
        del self.ops.nodes[DESTINATION + "/chrome-sandbox"]
        del self.ops.nodes[leaf]
        with self.assertRaisesRegex(ValueError, "probe_stage_fileset"):
            self.verify()
        self.assertEqual(self.ops.fds, {})

    def test_deadline_and_short_write_refuse_without_executable_clone(self):
        with self.assertRaisesRegex(ValueError, "bundle_deadline"):
            stage.materialize(self.stream, self.names, DESTINATION, until=time.monotonic() - 1)
        self.assertNotIn(DESTINATION, self.ops.nodes)
        self.ops.short_write = True
        with self.assertRaisesRegex(ValueError, "probe_stage_short_write"):
            self.materialize()
        self.assertEqual(stat.S_IMODE(self.ops.nodes[DESTINATION + "/chrome"]["mode"]), 0o600)
        self.assertEqual(self.ops.fds, {})

    def test_tree_recheck_refuses_directory_drift_during_scan(self):
        self.materialize()
        read = self.ops.read

        def changing_read(fd, count):
            self.ops.nodes[DESTINATION]["version"] += 1
            return read(fd, count)

        with (
            patch.object(self.ops, "read", side_effect=changing_read),
            self.assertRaisesRegex(ValueError, "probe_stage_fileset"),
        ):
            self.verify()
        self.assertEqual(self.ops.fds, {})
