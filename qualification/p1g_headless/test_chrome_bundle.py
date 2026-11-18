"""Synthetic in-memory TARs and OS doubles only; never a DEB or native program."""

import copy
import io
import json
import posixpath
import stat
import tarfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from qualification.p1g_headless import chrome_bundle as b
from qualification.p1g_headless import lab_support as support

ENV = {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
PKG = "a" * 64
BINDINGS = {
    "revision": "b" * 40,
    "pins_manifest_sha256": "c" * 64,
    "context_receipt_sha256": "d" * 64,
    "package_version": "157.0.8103.78-1",
    "signature": {"synthetic": True},
    "key_scope": {"synthetic": True},
    "root_interpreter": {"synthetic": True},
}


def payload(*, extra=(), change=None):
    rows = [
        (b.PREFIX, b"", 0o755, tarfile.DIRTYPE),
        (b.PREFIX + "/chrome", b"\x7fELF_SYNTHETIC_NOT_EXECUTABLE", 0o755, tarfile.REGTYPE),
        (b.PREFIX + "/locales", b"", 0o755, tarfile.DIRTYPE),
        (b.PREFIX + "/locales/en-US.pak", b"SYNTHETIC_RESOURCE", 0o644, tarfile.REGTYPE),
        ("usr/share/doc/SYNTHETIC", b"OUTSIDE_BUNDLE", 0o644, tarfile.REGTYPE),
    ]
    rows.extend(extra)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        for name, raw, mode, kind in rows:
            member = tarfile.TarInfo(name)
            member.uid = member.gid = 0
            member.mode, member.type = mode, kind
            member.size = len(raw) if kind == tarfile.REGTYPE else 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = raw.decode()
            if change:
                change(member)
            archive.addfile(member, io.BytesIO(raw) if member.isfile() else None)
    stream.seek(0)
    return stream


def profile(tree, *, roles=None, commissioned=True):
    raw = b.canonical(
        {
            "schema": b.PROFILE_SCHEMA,
            "commissioned": commissioned,
            "package_sha256": PKG,
            "tree_sha256": tree["tree_sha256"],
            "privileged_roles": roles or {},
        }
    )
    return raw, b.digest(raw)


class MemoryOS:
    O_RDONLY, O_WRONLY, O_CREAT, O_EXCL = 0, 1, 64, 128
    O_NOFOLLOW, O_CLOEXEC, O_DIRECTORY, O_NONBLOCK = 131072, 524288, 65536, 2048

    def __init__(self):
        self.nodes, self.fds, self.events, self.counter = {}, {}, [], 0
        self.short_write = False
        self.fail_fsync = False
        self.fail_close = False
        self.truncate = None
        for name in ("/", "/usr", "/usr/lib"):
            self.make(name, stat.S_IFDIR | 0o755)

    def getuid(self):
        return 0

    getgid = geteuid = getegid = getuid

    def name(self, path, parent=None):
        name = str(path).replace("\\", "/")
        return posixpath.normpath(
            name if name.startswith("/") else posixpath.join(self.fds[parent]["path"], name)
        )

    def make(self, name, mode, raw=b""):
        self.counter += 1
        self.nodes[name] = {
            "ino": self.counter,
            "mode": mode,
            "uid": 0,
            "gid": 0,
            "data": bytes(raw),
            "version": 1,
        }
        return self.nodes[name]

    def row(self, node):
        return SimpleNamespace(
            st_dev=1,
            st_ino=node["ino"],
            st_mode=node["mode"],
            st_uid=node["uid"],
            st_gid=node["gid"],
            st_nlink=2 if stat.S_ISDIR(node["mode"]) else 1,
            st_size=len(node["data"]),
            st_mtime_ns=node["version"],
            st_ctime_ns=node["version"],
        )

    def stat(self, path, *, dir_fd=None, follow_symlinks=False):
        assert follow_symlinks is False
        return self.row(self.nodes[self.name(path, dir_fd)])

    def mkdir(self, path, mode, *, dir_fd):
        name = self.name(path, dir_fd)
        if name in self.nodes:
            raise FileExistsError("SYNTHETIC_PRIVATE")
        self.make(name, stat.S_IFDIR | mode)
        self.events.append(("mkdir", name, mode))

    def open(self, path, flags, mode=0, *, dir_fd=None):
        assert flags & self.O_NOFOLLOW and flags & self.O_CLOEXEC
        name = self.name(path, dir_fd)
        if flags & self.O_CREAT:
            assert flags & self.O_EXCL
            if name in self.nodes:
                raise FileExistsError("SYNTHETIC_PRIVATE")
            self.make(name, stat.S_IFREG | mode)
        node = self.nodes[name]
        if flags & self.O_DIRECTORY:
            assert stat.S_ISDIR(node["mode"])
        assert not stat.S_ISLNK(node["mode"])
        fd = max([2, *self.fds]) + 1
        self.fds[fd] = {"node": node, "path": name, "cursor": 0}
        self.events.append(("open", name, flags))
        return fd

    def fstat(self, fd):
        return self.row(self.fds[fd]["node"])

    def fchmod(self, fd, mode):
        node = self.fds[fd]["node"]
        node["mode"] = stat.S_IFMT(node["mode"]) | mode
        node["version"] += 1
        self.events.append(("chmod", self.fds[fd]["path"], mode))

    def write(self, fd, raw):
        node = self.fds[fd]["node"]
        n = len(raw) - 1 if self.short_write else len(raw)
        node["data"] += raw[:n]
        node["version"] += 1
        self.events.append(("write", self.fds[fd]["path"], n))
        return n

    def fsync(self, fd):
        self.events.append(("fsync", self.fds[fd]["path"]))
        if self.fail_fsync:
            raise OSError("SYNTHETIC_PRIVATE")

    def close(self, fd):
        name = self.fds[fd]["path"]
        del self.fds[fd]
        self.events.append(("close", name))
        if self.fail_close:
            raise OSError("SYNTHETIC_PRIVATE")

    def read(self, fd, count):
        assert 0 < count <= 65536
        item = self.fds[fd]
        if self.truncate == item["path"]:
            return b""
        raw = item["node"]["data"][item["cursor"] : item["cursor"] + count]
        item["cursor"] += len(raw)
        return raw

    def listdir(self, fd):
        prefix = self.fds[fd]["path"].rstrip("/") + "/"
        return [
            name[len(prefix) :]
            for name in self.nodes
            if name.startswith(prefix) and "/" not in name[len(prefix) :]
        ]


class BundleTests(unittest.TestCase):
    def prepared(self, **kwargs):
        stream = payload(**kwargs)
        tree = b.inventory(stream, PKG, until=10, clock=lambda: 0)
        raw, sha = profile(tree)
        return stream, tree, raw, sha

    def staged(self, **kwargs):
        stream, tree, raw, sha = self.prepared(**kwargs)
        ops = MemoryOS()
        result = b.stage(stream, tree, raw, sha, ENV, BINDINGS, until=10, clock=lambda: 0, ops=ops)
        return ops, result, tree, raw, sha

    def verify(self, ops, raw, sha, **kwargs):
        return b.verify(
            ENV,
            {
                k: BINDINGS[k]
                for k in (
                    "revision",
                    "pins_manifest_sha256",
                    "context_receipt_sha256",
                    "package_version",
                )
            },
            raw,
            sha,
            until=10,
            clock=lambda: 0,
            ops=ops,
            runtime_check=lambda facts: b.need(
                type(facts) is dict and facts == BINDINGS["root_interpreter"], "bundle_test_runtime"
            ),
            **kwargs,
        )

    def test_01_inventory_all_resources_is_DATA_without_staging_or_external_calls(self):
        _, tree, raw, sha = self.prepared()
        self.assertEqual(
            [r["name"] for r in tree["entries"]], [".", "chrome", "locales", "locales/en-US.pak"]
        )
        self.assertFalse(tree["admitted"])
        self.assertFalse(tree["operational_GO"])
        self.assertNotIn("OUTSIDE_BUNDLE", json.dumps(tree))
        self.assertEqual(
            set(b.admit(tree, raw, sha)), {".", "chrome", "locales", "locales/en-US.pak"}
        )

    def test_02_profile_is_external_pinned_and_uncommissioned_never_stages(self):
        stream, tree, raw, sha = self.prepared()
        raw, sha = profile(tree, commissioned=False)
        for data, pin in ((raw, sha), (raw, "0" * 64)):
            ops = MemoryOS()
            with self.assertRaises(ValueError):
                b.stage(stream, tree, data, pin, ENV, BINDINGS, until=10, clock=lambda: 0, ops=ops)
            self.assertEqual(ops.events, [])

    def test_03_complete_tree_stages_exclusively_then_revalidates_every_resource(self):
        ops, result, tree, raw, sha = self.staged()
        self.assertEqual(result["schema"], b.SCHEMA)
        self.assertEqual(result["state"], "STAGED_AUTHENTICATED_TEST_BUNDLE")
        self.assertFalse(result["browser_executed"])
        self.assertFalse(result["operational_GO"])
        binary, pin = self.verify(ops, raw, sha)
        self.assertEqual(binary, b.root_path(ENV) / "chrome")
        self.assertEqual(
            pin["sha256"], next(r["sha256"] for r in tree["entries"] if r["name"] == "chrome")
        )
        self.assertEqual(ops.fds, {})
        root = b.root_path(ENV).as_posix()
        published = [i for i, event in enumerate(ops.events) if event == ("chmod", root, 0o755)]
        self.assertEqual(len(published), 1)
        writes = [i for i, event in enumerate(ops.events) if event[0] == "write"]
        self.assertLess(max(writes), published[0])
        self.assertFalse(
            any(
                event[0] == "chmod" and event[1] in {"/", "/usr", "/usr/lib"}
                for event in ops.events
            )
        )

    def test_04_existing_prefix_is_not_adopted_or_chmodded(self):
        stream, tree, raw, sha = self.prepared()
        ops = MemoryOS()
        ops.make(b.root_path(ENV).as_posix(), stat.S_IFDIR | 0o777)
        with self.assertRaises(FileExistsError):
            b.stage(stream, tree, raw, sha, ENV, BINDINGS, until=10, clock=lambda: 0, ops=ops)
        self.assertFalse(any(e[0] == "chmod" for e in ops.events))
        self.assertEqual(ops.fds, {})

    def test_05_traversal_absolute_alias_duplicate_and_sparse_inputs_refuse(self):
        for name in (
            "../escape",
            "/escape",
            "opt/google/chrome/../escape",
            "opt//google/chrome/a",
            "opt/google/chrome/./a",
            "opt/google/chrome/a\\b",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                b.inventory(
                    payload(extra=((name, b"DATA", 0o644, tarfile.REGTYPE),)),
                    PKG,
                    until=10,
                    clock=lambda: 0,
                )
        with self.assertRaises(ValueError):
            b.inventory(
                payload(extra=((b.PREFIX + "/chrome", b"COPY", 0o755, tarfile.REGTYPE),)),
                PKG,
                until=10,
                clock=lambda: 0,
            )

    def test_06_links_are_observed_but_never_implicitly_admitted(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            _, tree, raw, sha = self.prepared(extra=((b.PREFIX + "/link", b"chrome", 0o777, kind),))
            self.assertIn("link", [r["name"] for r in tree["entries"]])
            with self.assertRaisesRegex(ValueError, "bundle_unsupported_entry"):
                b.admit(tree, raw, sha)

    def test_07_privileged_helper_requires_exact_source_profile_role_and_bytes(self):
        stream, tree, _, _ = self.prepared(
            extra=(
                (
                    b.PREFIX + "/chrome-sandbox",
                    b"\x7fELF_SYNTHETIC_HELPER",
                    0o4755,
                    tarfile.REGTYPE,
                ),
            )
        )
        raw, sha = profile(tree)
        with self.assertRaisesRegex(ValueError, "bundle_privileged_roles"):
            b.admit(tree, raw, sha)
        role = next(r for r in tree["entries"] if r["name"] == "chrome-sandbox")
        raw, sha = profile(
            tree,
            roles={
                "chrome-sandbox": {
                    "role": "setuid-sandbox-helper",
                    "sha256": role["sha256"],
                    "mode": 0o4755,
                }
            },
        )
        ops = MemoryOS()
        b.stage(stream, tree, raw, sha, ENV, BINDINGS, until=10, clock=lambda: 0, ops=ops)
        self.verify(ops, raw, sha)
        self.assertEqual(
            stat.S_IMODE(ops.nodes[b.root_path(ENV).as_posix() + "/chrome-sandbox"]["mode"]), 0o4755
        )

    def test_08_other_suid_sgid_writable_owners_and_missing_parents_refuse(self):
        for field, value in (
            ("mode", 0o4755),
            ("mode", 0o2755),
            ("mode", 0o777),
            ("uid", 1001),
            ("gid", 1001),
        ):
            _, tree, _, _ = self.prepared()
            next(r for r in tree["entries"] if r["name"] == "locales/en-US.pak")[field] = value
            tree["tree_sha256"] = b.digest(b.canonical(tree["entries"]))
            raw, sha = profile(tree)
            with self.assertRaises(ValueError):
                b.admit(tree, raw, sha)
        _, tree, _, _ = self.prepared()
        tree["entries"] = [r for r in tree["entries"] if r["name"] != "locales"]
        tree["tree_sha256"] = b.digest(b.canonical(tree["entries"]))
        raw, sha = profile(tree)
        with self.assertRaisesRegex(ValueError, "bundle_parent_entry"):
            b.admit(tree, raw, sha)

    def test_09_tree_or_package_digest_changes_do_not_inherit_admission(self):
        _, tree, raw, sha = self.prepared()
        for changed in (
            {"package_sha256": "f" * 64},
            {"tree_sha256": "f" * 64},
            {"admitted": True},
            {"operational_GO": True},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                b.admit(dict(tree, **changed), raw, sha)

    def test_10_sidecar_change_is_rejected_even_when_main_ELF_is_unchanged(self):
        ops, _, _, raw, sha = self.staged()
        name = b.root_path(ENV).as_posix() + "/locales/en-US.pak"
        ops.nodes[name]["data"] = b"SYNTHETIC_CHANGED"
        with self.assertRaises(ValueError):
            self.verify(ops, raw, sha)
        self.assertEqual(ops.fds, {})

    def test_11_unexpected_resource_and_directory_alias_are_rejected(self):
        for option in ("extra", "alias", "writable"):
            ops, _, _, raw, sha = self.staged()
            root = b.root_path(ENV).as_posix()
            if option == "extra":
                ops.make(root + "/EXTRA", stat.S_IFREG | 0o644, b"DATA")
            elif option == "alias":
                ops.nodes[root + "/locales"]["mode"] = stat.S_IFLNK | 0o777
            else:
                ops.nodes[root + "/locales"]["mode"] = stat.S_IFDIR | 0o777
            with self.assertRaises((ValueError, AssertionError)):
                self.verify(ops, raw, sha)
            self.assertEqual(ops.fds, {})

    def test_12_short_write_or_fsync_failure_never_publishes_prefix(self):
        for flag in ("short_write", "fail_fsync"):
            stream, tree, raw, sha = self.prepared()
            ops = MemoryOS()
            setattr(ops, flag, True)
            with self.assertRaises((ValueError, OSError)):
                b.stage(stream, tree, raw, sha, ENV, BINDINGS, until=10, clock=lambda: 0, ops=ops)
            self.assertEqual(stat.S_IMODE(ops.nodes[b.root_path(ENV).as_posix()]["mode"]), 0o700)
            self.assertEqual(ops.fds, {})

    def test_13_truncated_read_and_fd_or_named_replacement_refuse(self):
        ops, _, _, raw, sha = self.staged()
        ops.truncate = b.root_path(ENV).as_posix() + "/chrome"
        with self.assertRaises(ValueError):
            self.verify(ops, raw, sha)
        self.assertEqual(ops.fds, {})
        ops, _, _, raw, sha = self.staged()
        original = ops.open

        def replaced(path, flags, mode=0, *, dir_fd=None):
            fd = original(path, flags, mode, dir_fd=dir_fd)
            if str(path) == "chrome":
                name = ops.fds[fd]["path"]
                previous = ops.nodes[name]
                ops.make(name, previous["mode"], previous["data"])
            return fd

        ops.open = replaced
        with self.assertRaises(ValueError):
            self.verify(ops, raw, sha)
        self.assertEqual(ops.fds, {})

    def test_14_receipt_wrong_run_revision_profile_or_state_is_not_authority(self):
        for change in (
            {"revision": "f" * 40},
            {"run": "999"},
            {"state": "INSTALLED_AUTHENTICATED_PACKAGE_ONLY"},
            {"profile_sha256": "f" * 64},
            {"browser_executed": True},
        ):
            ops, _, _, raw, sha = self.staged()
            name = b.root_path(ENV).as_posix() + "/.bundle-receipt.json"
            value = json.loads(ops.nodes[name]["data"])
            value.update(change)
            ops.nodes[name]["data"] = b.canonical(value)
            with self.assertRaises(ValueError):
                self.verify(ops, raw, sha)
            self.assertEqual(ops.fds, {})

    def test_15_no_arbitrary_prefix_from_user_or_receipt_and_no_unknown_mode_fallback(self):
        for key in ENV:
            with self.assertRaises(ValueError):
                b.root_path(dict(ENV, **{key: "../escape"}))
        with self.assertRaisesRegex(ValueError, "chrome_mode"):
            support.chrome_target(Path("SYNTHETIC"), mode="test-bundle-v3-or-legacy")
        with patch.object(support, "tool_pin", return_value={"fixture": True}) as pin:
            path, value = support.chrome_target(Path("SYNTHETIC"), mode="legacy-installed-v2")
            self.assertEqual(path, Path("/opt/google/chrome/chrome"))
            self.assertEqual(value, {"fixture": True})
            pin.assert_called_once_with(path)

    def test_16_expired_budget_refuses_before_prefix_creation_or_revalidation(self):
        stream, tree, raw, sha = self.prepared()
        ops = MemoryOS()
        with self.assertRaisesRegex(ValueError, "bundle_deadline"):
            b.stage(stream, tree, raw, sha, ENV, BINDINGS, until=10, clock=lambda: 10, ops=ops)
        self.assertEqual(ops.events, [])
        with self.assertRaisesRegex(ValueError, "bundle_deadline"):
            b.inventory(stream, PKG, until=10, clock=lambda: 10)

    def test_17_real_default_profile_is_source_pinned_and_not_commissioned(self):
        raw = (Path(__file__).parent / b.PROFILE_NAME).read_bytes()
        self.assertEqual(b.digest(raw), b.PROFILE_SHA)
        self.assertIs(json.loads(raw)["commissioned"], False)
        _, tree, _, _ = self.prepared()
        with self.assertRaisesRegex(ValueError, "bundle_profile_uncommissioned"):
            b.admit(tree, raw, b.PROFILE_SHA)

    def test_18_duplicate_nonfinite_JSON_and_tree_extra_fields_refuse(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError):
                b.json_bytes(raw)
        _, tree, raw, sha = self.prepared()
        with self.assertRaises(ValueError):
            b.admit(dict(tree, authority=True), raw, sha)

    def test_19_no_unadmitted_SUID_from_inventory_boolean_or_role_label(self):
        _, tree, _, _ = self.prepared(
            extra=((b.PREFIX + "/chrome-sandbox", b"\x7fELF_SYNTHETIC", 0o4755, tarfile.REGTYPE),)
        )
        for roles in (
            {"chrome-sandbox": True},
            {
                "chrome-sandbox": {
                    "role": "setuid-sandbox-helper",
                    "sha256": "f" * 64,
                    "mode": 0o4755,
                }
            },
            {"other": {}},
        ):
            raw, sha = profile(tree, roles=roles)
            with self.assertRaises(ValueError):
                b.admit(tree, raw, sha)

    def test_20_payload_changes_between_inventory_and_stage_are_fatal_private(self):
        _, tree, raw, sha = self.prepared()
        changed = payload(
            change=lambda member: setattr(member, "mode", 0o777)
            if member.name.endswith("/chrome")
            else None
        )
        ops = MemoryOS()
        with self.assertRaises(ValueError):
            b.stage(changed, tree, raw, sha, ENV, BINDINGS, until=10, clock=lambda: 0, ops=ops)
        self.assertEqual(stat.S_IMODE(ops.nodes[b.root_path(ENV).as_posix()]["mode"]), 0o700)
        self.assertEqual(ops.fds, {})

    def composed(self, *, reject=False):
        from qualification.p1g_headless import test_chrome_bootstrap as old

        boot = old.boot
        native_main = boot.main
        events = []

        def wrapped(argv):
            existing = boot.load

            def load(name, *args):
                if name != "p1g_authenticated_bundle":
                    return existing(name, *args)

                def inventory(*args, **kwargs):
                    events.append("inventory")
                    return {"synthetic": True}

                def admit(*args):
                    events.append("admit")
                    if reject:
                        raise ValueError("bundle_profile_uncommissioned")
                    return {}

                return SimpleNamespace(
                    inventory=inventory,
                    admit=admit,
                    PROFILE_SHA="f" * 64,
                    canonical=lambda value: json.dumps(value).encode(),
                )

            def stage(*args):
                events.append("stage")
                return {"schema": b.SCHEMA, "state": "STAGED_AUTHENTICATED_TEST_BUNDLE"}

            with (
                patch.object(boot, "load", side_effect=load),
                patch.object(boot, "stage_bundle_root", side_effect=stage),
            ):
                return native_main([*argv, "--test-bundle"])

        with patch.object(boot, "main", side_effect=wrapped):
            rc, original_events, writes = old.RootAptCacheTests().controller()
        return rc, events, original_events, writes

    def test_21_actual_root_controller_authenticates_then_admits_v3_no_legacy_install(self):
        rc, events, outer, writes = self.composed()
        self.assertEqual(rc, 0)
        self.assertEqual(events, ["inventory", "admit", "stage"])
        self.assertLess(outer.index("auth"), outer.index("--field"))
        self.assertLess(outer.index("--field"), outer.index("--fsys-tarfile"))
        apt = [row for row in outer if isinstance(row, tuple)]
        self.assertEqual(len(apt), 1)
        self.assertIn("--simulate", apt[0])
        self.assertNotIn("query", outer)
        self.assertNotIn("/runner/p1g-headless-123-1-chrome/installed.json", writes)
        self.assertIn("/runner/p1g-headless-123-1-chrome/test-bundle.json", writes)

    def test_22_actual_root_controller_uncommissioned_profile_stops_before_stage_or_APT(self):
        rc, events, outer, writes = self.composed(reject=True)
        self.assertEqual(rc, 42)
        self.assertEqual(events, ["inventory", "admit"])
        self.assertFalse(any(isinstance(row, tuple) for row in outer))
        self.assertNotIn("/runner/p1g-headless-123-1-chrome/installed.json", writes)
        self.assertNotIn("/runner/p1g-headless-123-1-chrome/test-bundle.json", writes)
        self.assertEqual(
            json.loads(writes["/runner/p1g-headless-123-1-chrome/root-UNKNOWN.json"])["phase"],
            "test_bundle_admission",
        )

    def test_23_same_v3_resolver_is_used_before_and_after_browser_without_sandbox_relaxation(self):
        import ast

        here = Path(__file__).parent
        browser = (here / "browser_case.py").read_text(encoding="utf8")
        worker = (here / "run_lab.py").read_text(encoding="utf8")
        tree = ast.parse(browser)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "chrome_target"
        ]
        self.assertEqual(len(calls), 2)
        self.assertIn("support.chrome_target(REPO)", worker)
        self.assertIn("chromium_sandbox=True", browser)
        self.assertNotIn("--no-sandbox", browser)
        self.assertNotIn("chmod", browser)

    def test_24_source_profile_is_not_runtime_observed_data_or_an_env_override(self):
        helper = (Path(__file__).parent / "chrome_bundle.py").read_text(encoding="utf8")
        support_source = (Path(__file__).parent / "lab_support.py").read_text(encoding="utf8")
        self.assertNotIn('os.environ.get("PROFILE_SHA"', helper)
        self.assertIn("== bundle.PROFILE_SHA", support_source)
        self.assertIn("bundle_profile_context", support_source)
        self.assertIn("support.source_binding", (Path(__file__).parent / "run_lab.py").read_text())

    def resolver(self, change=None):
        import hashlib
        import sys

        change = change or {}
        raw_profile = b.canonical({"synthetic_source_profile": True})
        profile_sha = b.digest(raw_profile)
        source = f'''from pathlib import Path
PROFILE_SHA = "{profile_sha}"
def verify(env, expected, raw, pin, **kwargs):
 assert expected['revision'] == 'b'*40
 assert expected['pins_manifest_sha256'] == EXPECTED_MANIFEST
 assert expected['context_receipt_sha256'] == EXPECTED_CONTEXT
 assert expected['package_version'] == '157.0.8103.78-1'
 assert pin == PROFILE_SHA
 kwargs['runtime_check']({{"synthetic_runtime":True}})
 target=Path('/usr/lib/pamolive-p1g-chrome-123-1/chrome')
 pin={{'sha256':'e'*64,'bytes':20,'uid':0,'mode':493}}
 return target,pin
'''.encode()
        names = {
            "helper": "qualification/p1g_headless/chrome_bundle.py",
            "profile": "qualification/p1g_headless/chrome-bundle-profile.json",
            "manifest": "qualification/p1g_headless/chrome-bootstrap-pins.json",
            "validator": "qualification/p1g_headless/chrome_bootstrap.py",
        }
        validator_source = b"""def root_interpreter_pin(support):
 return 'SYNTHETIC_INDEPENDENT_ROLE'
def check_root_interpreter(facts,role,**kwargs):
 if facts != {'synthetic_runtime':True} or role != 'SYNTHETIC_INDEPENDENT_ROLE':
  raise ValueError('SYNTHETIC_BAD_RUNTIME')
"""
        # The expected digests are installed by a test-only module dictionary
        # initializer; candidate helper verification still hashes its exact bytes.
        pins = {
            "source_files": {
                names["helper"]: b.digest(source),
                names["profile"]: profile_sha,
                names["validator"]: b.digest(validator_source),
            },
            "package": {"Version": "157.0.8103.78-1"},
        }
        manifest = b.canonical(pins)
        context = b.canonical(
            {
                "files": {
                    names["helper"]: b.digest(source),
                    names["profile"]: profile_sha,
                    names["manifest"]: b.digest(manifest),
                    names["validator"]: b.digest(validator_source),
                }
            }
        )
        mapping = {
            "p1g-source.json": context,
            names["helper"]: source,
            names["profile"]: raw_profile,
            names["manifest"]: manifest,
            names["validator"]: validator_source,
        }
        if "helper" in change:
            mapping[names["helper"]] = change["helper"]
        if "profile" in change:
            mapping[names["profile"]] = change["profile"]
        if "manifest" in change:
            mapping[names["manifest"]] = change["manifest"]
        if "validator" in change:
            mapping[names["validator"]] = change["validator"]
        events = []

        def read(path, cap):
            name = path.as_posix()
            key = (
                "p1g-source.json"
                if name.endswith("/p1g-source.json")
                else name.removeprefix("/SOURCE/")
            )
            value = mapping[key]
            self.assertLessEqual(len(value), cap)
            events.append(("read", key))
            return value

        original_factory = support.importlib.util.module_from_spec

        def make(spec):
            module = original_factory(spec)
            module.EXPECTED_MANIFEST = hashlib.sha256(manifest).hexdigest()
            module.EXPECTED_CONTEXT = hashlib.sha256(context).hexdigest()
            return module

        env = dict(ENV, GITHUB_SHA="b" * 40, RUNNER_TEMP="/TEMP", P1G_CHROME_MODE="test-bundle-v3")
        with (
            patch.dict(support.os.environ, env, clear=True),
            patch.object(support, "guard", side_effect=lambda env: events.append(("guard",))),
            patch.object(
                support, "source_binding", side_effect=lambda *a: events.append(("source_binding",))
            ),
            patch.object(support, "bounded", return_value=SimpleNamespace(read_regular=read)),
            patch.object(
                support,
                "tool_pin",
                return_value={"sha256": "e" * 64, "bytes": 20, "uid": 0, "mode": 493},
            ),
            patch.object(support.importlib.util, "module_from_spec", side_effect=make),
        ):
            error = value = None
            try:
                value = support.chrome_target(Path("/SOURCE"))
            except ValueError as caught:
                error = caught.args[0]
        sys.modules.pop("p1g_reviewed_bundle", None)
        sys.modules.pop("p1g_reviewed_root_validator", None)
        return value, error, events

    def test_25_actual_resolver_validates_source_helper_profile_context_before_verifier(self):
        value, error, events = self.resolver()
        self.assertIsNone(error)
        self.assertEqual(value[0], Path("/usr/lib/pamolive-p1g-chrome-123-1/chrome"))
        self.assertEqual(events[:2], [("guard",), ("source_binding",)])

    def test_26_changed_helper_profile_or_manifest_refuse_without_canonical_fallback(self):
        for change, expected in (
            (
                {"helper": b"raise AssertionError('UNADMITTED_CODE_EXECUTED')"},
                "bundle_helper_context",
            ),
            ({"profile": b"UNADMITTED_PROFILE"}, "bundle_profile_context"),
            ({"manifest": b"UNADMITTED_MANIFEST"}, "bundle_manifest_context"),
        ):
            with self.subTest(change=change):
                value, error, _ = self.resolver(change)
                self.assertIsNone(value)
                self.assertEqual(error, expected)

    def test_27_expiry_during_parent_observation_prevents_even_prefix_creation(self):
        stream, tree, raw, sha = self.prepared()
        ops = MemoryOS()
        now = [0]
        original = ops.stat

        def slow(path, **kwargs):
            value = original(path, **kwargs)
            if ops.name(path, kwargs.get("dir_fd")) == "/usr/lib":
                now[0] = 10
            return value

        ops.stat = slow
        with self.assertRaisesRegex(ValueError, "bundle_deadline"):
            b.stage(stream, tree, raw, sha, ENV, BINDINGS, until=10, clock=lambda: now[0], ops=ops)
        self.assertNotIn(b.root_path(ENV).as_posix(), ops.nodes)
        self.assertFalse(any(event[0] == "mkdir" for event in ops.events))
        self.assertEqual(ops.fds, {})

    def test_28_expiry_at_final_directory_sync_does_not_publish_prefix(self):
        stream, tree, raw, sha = self.prepared()
        ops = MemoryOS()
        now = [0]
        original = ops.fsync

        def slow(fd):
            original(fd)
            if ops.fds[fd]["path"] == b.root_path(ENV).as_posix():
                now[0] = 10

        ops.fsync = slow
        with self.assertRaisesRegex(ValueError, "bundle_deadline"):
            b.stage(stream, tree, raw, sha, ENV, BINDINGS, until=10, clock=lambda: now[0], ops=ops)
        self.assertEqual(stat.S_IMODE(ops.nodes[b.root_path(ENV).as_posix()]["mode"]), 0o700)
        self.assertEqual(ops.fds, {})

    def test_29_nonfinite_or_boolean_deadline_is_never_an_unbounded_lease(self):
        for until in (float("inf"), float("nan"), True):
            with self.subTest(until=until), self.assertRaisesRegex(ValueError, "bundle_deadline"):
                b.inventory(payload(), PKG, until=until, clock=lambda: 0)


class TarBudgetR12Tests(unittest.TestCase):
    class Probe(io.BytesIO):
        def __init__(self, raw):
            super().__init__(raw)
            self.requests = []
            self.seeks = []

        def read(self, count=-1):
            self.requests.append(count)
            if count < 0 or count > 65536:
                raise AssertionError("SYNTHETIC_LARGE_ALLOCATION_BLOCKED")
            return super().read(count)

        def seek(self, offset, whence=0):
            self.seeks.append((offset, whence))
            return super().seek(offset, whence)

    def extension(self, kind, declared=0):
        member = tarfile.TarInfo("SYNTHETIC_METADATA")
        member.type, member.size = kind, declared
        return member.tobuf(format=tarfile.USTAR_FORMAT)

    def test_30_PAX_GNU_global_sparse_rejected_before_internal_parser_or_large_read(self):
        from qualification.p1g_headless import chrome_bootstrap as boot

        prepared = BundleTests().prepared()
        for kind in (
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
            tarfile.GNUTYPE_SPARSE,
        ):
            for site in ("inventory", "legacy", "stage"):
                probe = self.Probe(self.extension(kind, b.MAX_FILE + 512))
                ops = MemoryOS()
                with (
                    self.subTest(kind=kind, site=site),
                    patch.object(tarfile, "open", side_effect=AssertionError("NO_STDLIB_PARSE")),
                    self.assertRaisesRegex(ValueError, "bundle_tar_extensions_refused"),
                ):
                    if site == "inventory":
                        b.inventory(probe, PKG, until=10, clock=lambda: 0)
                    elif site == "legacy":
                        boot.payload_target(probe)
                    else:
                        _, tree, raw, sha = prepared
                        b.stage(
                            probe, tree, raw, sha, ENV, BINDINGS, until=10, clock=lambda: 0, ops=ops
                        )
                self.assertEqual(probe.requests, [512])
                self.assertFalse(any(event[0] == "mkdir" for event in ops.events))
                self.assertEqual(ops.fds, {})

    def test_31_chained_empty_extensions_cannot_hide_outside_member_budget(self):
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
            probe = self.Probe(self.extension(kind) * 30 + payload().getvalue())
            with patch.object(b, "MAX_FILES", 5), self.assertRaisesRegex(ValueError, "extensions"):
                b.inventory(probe, PKG, until=10, clock=lambda: 0)
            self.assertEqual(probe.requests, [512])

    def test_32_physical_headers_counted_before_frombuf_not_only_logical_members(self):
        probe = self.Probe(payload().getvalue())
        original = tarfile.TarInfo.frombuf
        with (
            patch.object(b, "MAX_TAR_HEADERS", 3),
            patch.object(tarfile.TarInfo, "frombuf", wraps=original) as parsed,
            self.assertRaisesRegex(ValueError, "bundle_tar_header_budget"),
        ):
            b.inventory(probe, PKG, until=10, clock=lambda: 0)
        self.assertEqual(parsed.call_count, 3)
        self.assertLessEqual(max(probe.requests), b.MAX_TAR_READ)
        with patch.object(b, "MAX_TAR_HEADERS", 5):
            self.assertEqual(
                len(
                    b.inventory(self.Probe(payload().getvalue()), PKG, until=10, clock=lambda: 0)[
                        "entries"
                    ]
                ),
                4,
            )

    def test_33_reader_rejects_unbounded_or_oversized_requests_without_raw_IO(self):
        probe = self.Probe(payload().getvalue())
        reader = b.TarReader(probe, 10, lambda: 0)
        for count in (-1, b.MAX_TAR_READ + 1, b.MAX_FILE + 512, True):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "read_budget"):
                reader.read(count)
        self.assertEqual(probe.requests, [])
        self.assertEqual(len(reader.read(b.MAX_TAR_READ)), len(payload().getvalue()))
        self.assertEqual(probe.requests, [b.MAX_TAR_READ])

    def test_34_real_header_budget_IO_before_and_after_deadline(self):
        now = [0]

        class LateRead(self.Probe):
            def read(self, count=-1):
                raw = super().read(count)
                now[0] = 10
                return raw

        probe = LateRead(payload().getvalue())
        with self.assertRaisesRegex(ValueError, "bundle_deadline"):
            b.inventory(probe, PKG, until=10, clock=lambda: now[0])
        self.assertEqual(probe.requests, [512])
        probe = self.Probe(payload().getvalue())
        with self.assertRaisesRegex(ValueError, "bundle_deadline"):
            b.inventory(probe, PKG, until=10, clock=lambda: 10)
        self.assertEqual(probe.seeks, [])

    def test_35_truncation_checksum_nonzero_padding_and_concatenation_refuse(self):
        clean = payload().getvalue()
        corrupt_checksum = bytearray(clean)
        corrupt_checksum[0] ^= 1
        corrupt_padding = bytearray(clean)
        # First member is directory, second is the 28-byte synthetic ELF.
        target = tarfile.TarInfo.frombuf(clean[512:1024], "utf8", "strict")
        corrupt_padding[1024 + target.size] = 1
        cases = (
            clean[:500],
            clean[:1024],
            bytes(corrupt_checksum),
            bytes(corrupt_padding),
            clean + b"NOT_ZERO".ljust(512, b"\0"),
            clean + clean,
        )
        for raw in cases:
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                b.inventory(self.Probe(raw), PKG, until=10, clock=lambda: 0)

    def test_36_ordinary_ustar_prefixes_supported_without_extensions(self):
        name = b.PREFIX + "/" + "a" * 80 + "/" + "b" * 70
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
            for full, kind in (
                (b.PREFIX, tarfile.DIRTYPE),
                (b.PREFIX + "/" + "a" * 80, tarfile.DIRTYPE),
                (name, tarfile.REGTYPE),
            ):
                member = tarfile.TarInfo(full)
                member.type, member.mode = kind, 0o755 if kind == tarfile.DIRTYPE else 0o644
                member.size = 0 if kind == tarfile.DIRTYPE else 4
                archive.addfile(member, io.BytesIO(b"DATA") if member.isfile() else None)
        tree = b.inventory(self.Probe(stream.getvalue()), PKG, until=10, clock=lambda: 0)
        self.assertIn(name[len(b.PREFIX) + 1 :], [row["name"] for row in tree["entries"]])

    def test_37_header_mutation_after_preflight_cannot_reintroduce_extensions(self):
        probe = self.Probe(payload().getvalue())
        reader = b.TarReader(probe, 10, lambda: 0)
        b.preflight_tar(reader)
        probe.seek(0)
        probe.write(self.extension(tarfile.XHDTYPE, b.MAX_FILE + 512))
        reader.seek(0)
        with self.assertRaisesRegex(ValueError, "bundle_tar_header_changed"):
            tarfile.open(fileobj=reader, mode="r:")
        self.assertLessEqual(max(probe.requests), b.MAX_TAR_READ)

    def test_38_physical_size_or_seek_never_becomes_an_implicit_allocation(self):
        class Huge(self.Probe):
            def seek(self, offset, whence=0):
                if whence == 2:
                    return b.MAX_TAR_BYTES + 512
                return super().seek(offset, whence)

        probe = Huge(b"")
        with self.assertRaisesRegex(ValueError, "physical_budget"):
            b.TarReader(probe, 10, lambda: 0)
        self.assertEqual(probe.requests, [])
        probe = self.Probe(payload().getvalue())
        reader = b.TarReader(probe, 10, lambda: 0)
        before = len(probe.seeks)
        for target in (-1, reader.size + 1):
            with self.assertRaisesRegex(ValueError, "bundle_tar_seek"):
                reader.seek(target)
        self.assertEqual(len(probe.seeks), before)


class RuntimeR12Tests(unittest.TestCase):
    def frontend(self, change=..., *, changed_role=None):
        from qualification.p1g_headless import test_chrome_bootstrap as old

        owner = old.RootInterpreterTests()
        owner.setUp()
        facts = owner.runtime()
        if change is not ...:
            if type(change) is dict:
                facts.update(copy.deepcopy(change))
            else:
                facts = change
        roles = iter([owner.role(), changed_role or owner.role(), owner.role()])
        events = []

        def pin(support):
            events.append("independent_pin")
            return next(roles)

        def run(argv, **kwargs):
            self.assertIn("--test-bundle", argv)
            self.assertIn("--root-install", argv)
            self.assertEqual(kwargs, {"seconds": 480, "sudo": True})
            events.append("normal_H1")

        def verify(*args, **kwargs):
            self.assertNotIn("root_interpreter", args[1])
            events.append("protected_receipt")
            kwargs["runtime_check"](facts)
            events.append("runtime_checked")

        bindings = {
            "revision": owner.bindings["revision"],
            "context_receipt_sha256": owner.bindings["context_sha"],
            "pins_manifest_sha256": owner.bindings["pins_sha"],
            "package_version": "157.0.8103.78-1",
            "signature": {},
            "key_scope": {},
            "root_interpreter": None,
        }
        with (
            patch.object(old.boot, "root_interpreter_pin", side_effect=pin),
            patch.object(old.boot.time, "monotonic", return_value=100),
        ):
            old.boot.root_bundle_supervisor(
                SimpleNamespace(run=run, until=1000),
                owner.support,
                SimpleNamespace(verify=verify, PROFILE_SHA="e" * 64),
                b"SOURCE_PROFILE",
                bindings,
                owner.bindings["pins_sha"],
                owner.bindings["source_sha"],
            )
        return events

    def test_39_frontend_requires_real_historical_runtime_check_and_three_role_observations(self):
        self.assertEqual(
            self.frontend(),
            [
                "independent_pin",
                "normal_H1",
                "independent_pin",
                "protected_receipt",
                "runtime_checked",
                "independent_pin",
            ],
        )

    def test_40_bool_missing_shape_flags_UID_and_replayed_runtime_are_refused(self):
        cases = [
            None,
            True,
            False,
            "SYNTHETIC",
            {"flags": {}},
            {"real_uid": False},
            {"effective_uid": 1001},
            {"revision": "f" * 40},
            {"context_receipt_sha256": "f" * 64},
            {"pins_manifest_sha256": "f" * 64},
            {"bootstrap_source_sha256": "f" * 64},
            {"running_identity": [1, 2]},
            {"flags": {"isolated": 1, "no_site": 1}},
            {"stdlib_loader_hermeticity_verified": True},
        ]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.frontend(change)

    def test_41_role_change_after_normal_child_never_reaches_acceptance(self):
        from qualification.p1g_headless import test_chrome_bootstrap as old

        owner = old.RootInterpreterTests()
        owner.setUp()
        role = owner.role()
        role["identity"][1] += 1
        with self.assertRaisesRegex(ValueError, "root_interpreter_changed"):
            self.frontend(changed_role=role)

    def test_42_nonroot_resource_verifier_cannot_omit_the_runtime_checker(self):
        ops, _, _, raw, sha = BundleTests().staged()
        expected = {
            k: BINDINGS[k]
            for k in (
                "revision",
                "pins_manifest_sha256",
                "context_receipt_sha256",
                "package_version",
            )
        }
        with self.assertRaisesRegex(ValueError, "bundle_root_runtime_checker"):
            b.verify(ENV, expected, raw, sha, until=10, clock=lambda: 0, ops=ops)
        self.assertEqual(ops.fds, {})
        receipt = ops.nodes[b.root_path(ENV).as_posix() + "/.bundle-receipt.json"]
        value = json.loads(receipt["data"])
        value["root_interpreter"] = True
        receipt["data"] = b.canonical(value)
        with self.assertRaisesRegex(ValueError, "bundle_test_runtime"):
            BundleTests().verify(ops, raw, sha)
        self.assertEqual(ops.fds, {})

    def test_43_validator_source_change_is_refused_before_untrusted_compile(self):
        value, error, _ = BundleTests().resolver(
            {"validator": b"raise AssertionError('UNADMITTED_VALIDATOR')"}
        )
        self.assertIsNone(value)
        self.assertEqual(error, "bundle_runtime_validator_context")
