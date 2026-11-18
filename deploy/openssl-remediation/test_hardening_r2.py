"""Synthetic clocks/HTTP/process actors and plain UTF-8 patches only."""

import difflib
import io
import json
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import acquisition_io as a
import acquisition_owner as owner
import future_linux as f
import source_data as d

common = f._common


def make_plan(extra=False):
    tree, rows, patches = {}, [], {}
    for i, cve in enumerate(sorted(d.CVES)):
        name, path = f"data{i}.txt", f"patch{i}.patch"
        tree[name] = b"before\n"
        raw = diff(name, b"before\n", b"after\n")
        if extra:
            tree[f"extra{i}.txt"] = b"before\n"
            raw += diff(f"extra{i}.txt", b"before\n", b"UNDECLARED\n")
        patches[path] = raw
        rows.append(
            {
                "cve": cve,
                "action": "APPLY_EXACT_AUTHENTICATED_DEBIAN_SOURCE",
                "before": {name: d.sha(b"before\n")},
                "after": {name: d.sha(b"after\n")},
                "proposed_patch": path,
                "proposed_patch_sha256": d.sha(raw),
            }
        )
    return (
        tree,
        {"schema": "pamolive.openssl-static-source-replay.v1", "rows": rows},
        patches,
    )


def diff(name, before, after):
    return "".join(
        difflib.unified_diff(
            before.decode().splitlines(True),
            after.decode().splitlines(True),
            fromfile="a/" + name,
            tofile="b/" + name,
        )
    ).encode()


class Actor:
    def __init__(self, *, chunks=None, step=0, setup=0, write=0, flush=0, close=0):
        self.clock, self.events, self.timeouts = [0.0], [], []
        self.chunks = list(chunks if chunks is not None else [b"x", b""])
        self.step, self.setup, self.write_delay, self.flush_delay, self.close_delay = (
            step,
            setup,
            write,
            flush,
            close,
        )
        self.status = 200
        self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=self))
        self.sink = self.Sink(self)

    class Sink(io.BytesIO):
        def __init__(self, actor):
            super().__init__()
            self.actor = actor

        def write(self, raw):
            self.actor.clock[0] += self.actor.write_delay
            self.actor.events.append("write")
            return super().write(raw)

        def flush(self):
            self.actor.clock[0] += self.actor.flush_delay
            self.actor.events.append("flush")

        def close(self):
            self.actor.clock[0] += self.actor.close_delay
            self.actor.events.append("sink_close")

    def open(self, request, timeout):
        self.events.append("open")
        self.timeouts.append(timeout)
        self.clock[0] += self.setup
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.events.append("response_close")

    def settimeout(self, value):
        self.timeouts.append(value)

    def read1(self, count):
        self.events.append(("read1", count))
        self.clock[0] += self.step
        return self.chunks.pop(0)

    def call(self, deadline=30, maximum=4, expected=None):
        with (
            patch.object(a.time, "monotonic", side_effect=lambda: self.clock[0]),
            patch.object(a.urllib.request, "build_opener", return_value=self),
            patch.object(a.Path, "open", return_value=self.sink),
        ):
            return a.acquire_blob(
                a.BASE_URL + "SYNTHETIC",
                Path("SYNTHETIC"),
                maximum,
                expected,
                deadline=deadline,
            )


class ConvertedIndependentFindings(unittest.TestCase):
    def test_download_slow_drip_no_longer_accepted_at_145(self):
        actor = Actor(chunks=[b"x"] * 4 + [b""], step=29)
        with self.assertRaisesRegex(ValueError, "ACQUISITION_UNKNOWN_DEADLINE"):
            actor.call()
        self.assertEqual(actor.clock[0], 58)
        self.assertEqual(actor.sink.getvalue(), b"x")
        self.assertEqual(actor.timeouts, [30, 30, 30, 1])
        self.assertEqual(actor.events.count("write"), 1)

    def test_extra_patch_targets_now_refuse_before_any_transformation(self):
        tree, plan, patches = make_plan(extra=True)
        original = dict(tree)
        with patch.object(
            d, "apply_bound", side_effect=AssertionError("application_before_inventory")
        ):
            with self.assertRaisesRegex(ValueError, "patch_target_inventory_not_exhaustive"):
                d.patch_source_buffers(tree, plan, patches)
        self.assertEqual(tree, original)


class AcquisitionTests(unittest.TestCase):
    def test_policy_v2_requires_explicit_runtime_and_preserves_eight_tool_roles(self):
        role = {
            "path": "/usr/local/bin/python3.12",
            "sha256": "a" * 64,
            "metadata": {name: 1 for name in owner.META},
            "user_uid": 1000,
            "source_files": {name: "b" * 64 for name in owner.SOURCES.values()},
        }
        tools = [
            "gpgv",
            "dpkg-source",
            "dpkg-buildpackage",
            "dpkg-deb",
            "dpkg-checkbuilddeps",
            "dch",
            "dpkg-query",
            "quilt",
        ]
        policy = {
            "schema": "pamolive.openssl-source-trust-policy.v2",
            "suite": "trixie-security",
            "keyring_sha256": "a" * 64,
            "dependency_lock_sha256": "b" * 64,
            "signer_to_primary": {"A" * 40: "B" * 40},
            "allowed_primaries": ["B" * 40],
            "tools": {"/usr/bin/" + tool: "c" * 64 for tool in tools},
            "acquisition_runtime": role,
        }
        raw = json.dumps(policy).encode()
        self.assertEqual(d.check_policy(raw, d.sha(raw)), policy)
        for key, value in [
            ("schema", "pamolive.openssl-source-trust-policy.v1"),
            ("acquisition_runtime", True),
            ("tools", {}),
        ]:
            changed = deepcopy(policy)
            changed[key] = value
            raw = json.dumps(changed).encode()
            with self.subTest(key=key), self.assertRaises(ValueError):
                d.check_policy(raw, d.sha(raw))

    def test_captured_loader_hashes_before_compile_and_never_reads_source_files(self):
        import contextlib
        import sys

        code = "def acquisition_worker(p):\n assert p['deadline']==175\n"
        payload = {
            "root": "SYNTHETIC",
            "deadline": 175,
            "modules": {"future_linux": "future_linux.py"},
            "sources": {"future_linux.py": code},
            "trust": {
                "acquisition_runtime": {"source_files": {"future_linux.py": d.sha(code.encode())}}
            },
        }
        old_module = sys.modules["future_linux"]
        old_finders = list(sys.meta_path)
        try:
            sys.modules.pop("future_linux")
            stream = io.StringIO()
            with (
                patch.object(sys, "argv", ["loader", json.dumps(payload)]),
                contextlib.redirect_stdout(stream),
                patch.object(Path, "read_bytes", side_effect=AssertionError("loader_disk_reread")),
            ):
                exec(
                    compile(owner.LOADER, "captured-synthetic-loader", "exec"),
                    {"__name__": "__main__"},
                )
            self.assertEqual(stream.getvalue(), '{"state":"COMPLETE"}\n')
            payload["sources"]["future_linux.py"] += 'raise AssertionError("unapproved_compile")\n'
            with (
                patch.object(sys, "argv", ["loader", json.dumps(payload)]),
                self.assertRaises(SystemExit) as raised,
            ):
                exec(
                    compile(owner.LOADER, "captured-synthetic-loader", "exec"),
                    {"__name__": "__main__"},
                )
            self.assertEqual(raised.exception.code, 75)
        finally:
            sys.modules["future_linux"] = old_module
            sys.meta_path[:] = old_finders

    def test_valid_body_and_exact_hash(self):
        actor = Actor(chunks=[b"xy", b""])
        self.assertEqual(actor.call(expected=(2, d.sha(b"xy")))["bytes"], 2)

    def test_before_open_no_operations(self):
        actor = Actor()
        with self.assertRaisesRegex(ValueError, "DEADLINE"):
            actor.call(deadline=0)
        self.assertEqual(actor.events, [])

    def test_dns_TLS_or_headers_stall_no_file_created(self):
        actor = Actor(setup=31)
        with self.assertRaisesRegex(ValueError, "DEADLINE"):
            actor.call()
        self.assertNotIn("write", actor.events)
        self.assertFalse(any(isinstance(e, tuple) for e in actor.events))

    def test_socket_timeouts_follow_actual_remaining(self):
        actor = Actor(chunks=[b"x", b"y", b""], step=4, setup=3)
        self.assertEqual(actor.call(deadline=20)["bytes"], 2)
        self.assertEqual(actor.timeouts, [20, 17, 17, 13, 9])

    def test_eof_after_deadline_never_confirms_complete(self):
        actor = Actor(chunks=[b"x", b""], step=16)
        with self.assertRaisesRegex(ValueError, "DEADLINE"):
            actor.call()
        self.assertEqual(actor.clock[0], 32)

    def test_write_flush_and_context_close_deadlines(self):
        for kw in ({"write": 31}, {"flush": 31}, {"close": 31}):
            with self.subTest(kw=kw):
                actor = Actor(**kw)
                with self.assertRaisesRegex(ValueError, "DEADLINE"):
                    actor.call()

    def test_hash_and_cap_and_read_contract_refuse(self):
        for chunks, maximum, expected in [
            ([b"abc", b""], 2, None),
            ([b"x", b""], 4, (1, "f" * 64)),
            ([b""], 4, None),
            ([bytearray(b"x")], 4, None),
        ]:
            with self.subTest(chunks=chunks), self.assertRaises(ValueError):
                Actor(chunks=chunks).call(maximum=maximum, expected=expected)

    def test_redirect_and_origin_refuse(self):
        with self.assertRaisesRegex(ValueError, "REDIRECT"):
            a.NoRedirect().redirect_request(None)
        for url in (
            "http://security.debian.org/debian-security/x",
            a.BASE_URL + "x#fragment",
            "https://u@security.debian.org/debian-security/x",
            "https://security.debian.org:443/debian-security/x",
        ):
            with (
                self.subTest(url=url),
                self.assertRaisesRegex(ValueError, "source_origin"),
            ):
                a.acquire_blob(url, Path("SYNTHETIC"), 4, deadline=a.time.monotonic() + 30)

    def test_shared_sequence_deadline_refuses_before_next_stage(self):
        clock, events = [0], []

        def blob(*args, deadline, **kwargs):
            events.append(("body", deadline))
            clock[0] += 10

        def verified(*args, deadline, **kwargs):
            events.append(("signature", deadline))
            clock[0] += 10
            return (1, "a" * 64), {}

        with (
            patch.object(f, "linux"),
            patch.object(a.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(f.Path, "mkdir"),
            patch.object(f, "read", return_value=b"x"),
            patch.object(f, "write_new"),
            patch.object(f, "acquire_blob", side_effect=blob),
            patch.object(f, "verified_release", side_effect=verified),
            patch.object(f, "release_index", side_effect=AssertionError("post_deadline_stage")),
        ):
            with self.assertRaisesRegex(ValueError, "DEADLINE"):
                f.acquire_sequence(
                    Path("SYNTHETIC"),
                    Path("SYNTHETIC"),
                    {"keyring_sha256": d.sha(b"x")},
                    deadline=30,
                )
        self.assertEqual(events, [("body", 30), ("signature", 30), ("body", 30)])

    def test_owner_absolute_horizon_and_cleanup_reservation(self):
        clock, calls, records = [0], [], []
        role = {"path": "/usr/bin/python3.12", "source_files": {"synthetic": "x"}}
        trust = {"acquisition_runtime": role}

        def command(*args, **kwargs):
            calls.append((args, kwargs))
            return b'{"state":"COMPLETE"}\n'

        with (
            patch.object(owner, "runtime_contract", return_value=role),
            patch.object(owner, "runtime_role"),
            patch.object(owner, "snapshot", return_value={"synthetic": "x"}),
            patch.object(owner.Path, "mkdir"),
            patch.object(a.time, "monotonic", side_effect=lambda: clock[0]),
        ):
            self.assertEqual(
                owner.supervise(
                    Path("SYNTHETIC"),
                    Path("M"),
                    Path("W"),
                    trust,
                    None,
                    command,
                    lambda p, v: records.append(v),
                    deadline=180,
                ),
                Path("W/sequence/complete-source"),
            )
        kwargs = calls[0][1]
        self.assertEqual((kwargs["seconds"], kwargs["deadline"], kwargs["cap"]), (175, 180, 4096))
        payload = json.loads(calls[0][0][0][-1])
        self.assertEqual(payload["deadline"], 175)
        self.assertEqual(calls[0][0][0][1:4], ["-I", "-B", "-S"])
        self.assertEqual(records[-1]["state"], "COMPLETE")

    def test_owner_late_RC0_invalid_control_or_cleanup_unknown_never_succeed(self):
        for kind in ("late", "bad_result", "cleanup_unknown"):
            clock = [0]
            records = []

            def command(*args, **kwargs):
                if kind == "cleanup_unknown":
                    raise ValueError("child_failed_or_unknown")
                if kind == "late":
                    clock[0] = 176
                return b'{"state":"COMPLETE"}\n' if kind == "late" else b'{"state":true}\n'

            role = {"path": "/usr/bin/python3.12", "source_files": {}}
            with (
                self.subTest(kind=kind),
                patch.object(owner, "runtime_contract", return_value=role),
                patch.object(owner, "runtime_role"),
                patch.object(owner, "snapshot", return_value={}),
                patch.object(owner.Path, "mkdir"),
                patch.object(a.time, "monotonic", side_effect=lambda: clock[0]),
            ):
                with self.assertRaises(ValueError):
                    owner.supervise(
                        Path("S"),
                        Path("M"),
                        Path("W"),
                        {"acquisition_runtime": role},
                        None,
                        command,
                        lambda p, v: records.append(v),
                        deadline=180,
                    )
                self.assertEqual(records[-1], {"state": "UNKNOWN", "resources_released": False})

    def test_runtime_role_never_alias_or_root_or_boolean_or_partial_sources(self):
        role = {
            "path": "/usr/bin/python3.12",
            "sha256": "a" * 64,
            "metadata": {n: 1 for n in owner.META},
            "user_uid": 1000,
            "source_files": {name: "b" * 64 for name in owner.SOURCES.values()},
        }
        self.assertEqual(owner.runtime_contract(role), role)
        for key, value in [
            ("path", "/usr/bin/python3"),
            ("path", "python3.12"),
            ("user_uid", 0),
            ("user_uid", True),
            ("sha256", True),
            ("source_files", {}),
            ("metadata", {}),
        ]:
            bad = deepcopy(role)
            bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                owner.runtime_contract(bad)

    def test_runtime_source_changed_before_spawn(self):
        role = {"source_files": {name: "f" * 64 for name in owner.SOURCES.values()}}
        with self.assertRaisesRegex(ValueError, "acquisition_source_changed"):
            owner.snapshot(
                Path("SYNTHETIC"),
                role,
                lambda *args: b"changed",
                a.time.monotonic() + 30,
            )

    def test_real_runtime_checker_requires_exact_ELF_parents_bytes_identity_and_flags(
        self,
    ):
        import stat

        metadata = {
            "dev": 1,
            "ino": 2,
            "mode": stat.S_IFREG | 0o755,
            "uid": 0,
            "gid": 0,
            "nlink": 1,
            "size": 8,
        }
        role = {
            "path": "/usr/bin/python3.12",
            "sha256": d.sha(b"\x7fELFdata"),
            "metadata": metadata,
            "user_uid": 1000,
            "source_files": {name: "a" * 64 for name in owner.SOURCES.values()},
        }
        faults = {"parent": False, "metadata": False}

        class P:
            def __init__(self, name):
                self.name = name

            @property
            def parents(self):
                return [P("/usr/bin"), P("/usr"), P("/")]

            def __eq__(self, other):
                return isinstance(other, P) and self.name == other.name

            def lstat(self):
                if self.name == role["path"]:
                    row = {**metadata, "ino": 3} if faults["metadata"] else metadata
                else:
                    row = {
                        "mode": stat.S_IFDIR | (0o777 if faults["parent"] else 0o755),
                        "uid": 0,
                    }
                return SimpleNamespace(**{"st_" + key: value for key, value in row.items()})

        with (
            patch.object(owner, "Path", side_effect=P),
            patch.object(owner.os, "getuid", return_value=1000, create=True),
            patch.object(owner.os, "geteuid", return_value=1000, create=True),
            patch.object(owner.os, "readlink", return_value=role["path"]),
            patch.object(owner, "sys_flags", return_value=True),
        ):
            self.assertEqual(
                owner.runtime_role(role, lambda *args: b"\x7fELFdata", a.time.monotonic() + 30),
                metadata,
            )
            for fault in faults:
                faults[fault] = True
                with self.subTest(fault=fault), self.assertRaises(ValueError):
                    owner.runtime_role(role, lambda *args: b"\x7fELFdata", a.time.monotonic() + 30)
                faults[fault] = False
            with self.assertRaisesRegex(ValueError, "runtime_bytes"):
                owner.runtime_role(role, lambda *args: b"notELF", a.time.monotonic() + 30)
            with (
                patch.object(owner.os, "readlink", return_value="/wrong"),
                self.assertRaisesRegex(ValueError, "running_runtime"),
            ):
                owner.runtime_role(role, lambda *args: b"\x7fELFdata", a.time.monotonic() + 30)
            with (
                patch.object(owner, "sys_flags", return_value=False),
                self.assertRaisesRegex(ValueError, "running_runtime"),
            ):
                owner.runtime_role(role, lambda *args: b"\x7fELFdata", a.time.monotonic() + 30)

    def test_nested_signature_commands_remain_in_owner_session(self):
        with (
            patch.object(f, "linux"),
            patch.object(f, "read", return_value=b"tool"),
            patch.object(f.Path, "resolve", return_value=Path("/usr/bin/gpgv")),
            patch.object(f, "command", return_value=b"") as command,
        ):
            f.run(
                ["/usr/bin/gpgv"],
                Path("S"),
                Path("L"),
                {"tools": {"/usr/bin/gpgv": d.sha(b"tool")}},
                deadline=a.time.monotonic() + 20,
            )
            self.assertIs(command.call_args.kwargs["owned_session"], False)
            self.assertLessEqual(command.call_args.kwargs["seconds"], 20)

    def test_common_H172_unknown_reap_or_drain_uses_absolute_deadline(self):
        fake = SimpleNamespace()
        fake.is_absolute = lambda: True
        fake.stat = lambda: SimpleNamespace(st_mode=0o100755, st_uid=0)
        fake.resolve = lambda **kw: fake
        fake.mkdir = lambda **kw: None
        fake.__truediv__ = lambda value: fake

        class P:
            def is_absolute(self):
                return True

            def stat(self):
                return SimpleNamespace(st_mode=0o100755, st_uid=0)

            def resolve(self, **kwargs):
                return self

            def mkdir(self, **kwargs):
                pass

            def __truediv__(self, other):
                return self

            def __str__(self):
                return "SYNTHETIC"

        for reaped, drained in ((False, True), (True, False)):
            result = common.bounded_io.Result(
                returncode=0, owned_child_reaped=reaped, drains_complete=drained
            )
            records = []
            with (
                self.subTest(reaped=reaped, drained=drained),
                patch.object(common.os, "name", "posix"),
                patch.object(common, "Path", side_effect=lambda *args: P()),
                patch.object(common, "read", return_value=b"x"),
                patch.object(common, "record", side_effect=lambda p, v: records.append(v)),
                patch.object(common, "write_new"),
                patch.object(common.bounded_io, "run_capped", return_value=result) as run,
            ):
                with self.assertRaisesRegex(ValueError, "child_failed_or_unknown"):
                    common.command(["/SYNTHETIC"], P(), P(), seconds=17, deadline=100)
                self.assertEqual(
                    (
                        run.call_args.kwargs["timeout"],
                        run.call_args.kwargs["work_timeout"],
                        run.call_args.kwargs["deadline"],
                    ),
                    (22, 17, 100),
                )
                self.assertIn({"state": "UNKNOWN"}, records)


class PatchTests(unittest.TestCase):
    def test_existing_three_reference_patches_fit_closed_format_without_Debian_authority(
        self,
    ):
        from patch_contracts import bound_patch

        root = Path(__file__).parent
        replay = json.loads((root / "static-source-replay.json").read_bytes())
        rows = [
            r for r in replay["rows"] if r["action"] == "APPLY_TEXT_ONLY_UPSTREAM_TAG_REFERENCE"
        ]
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(
                {r["name"] for r in bound_patch(row, (root / row["proposed_patch"]).read_bytes())},
                set(row["before"]),
            )

    def reject(self, raw, message=None):
        tree, plan, patches = make_plan()
        name = plan["rows"][0]["proposed_patch"]
        patches[name] = raw
        plan["rows"][0]["proposed_patch_sha256"] = d.sha(raw)
        with self.assertRaisesRegex(ValueError, message or "patch|archive"):
            d.patch_source_buffers(tree, plan, patches)

    def test_valid_existing_file_plain_diff_and_all_hashes(self):
        tree, plan, patches = make_plan()
        self.assertEqual(set(d.patch_source_buffers(tree, plan, patches).values()), {b"after\n"})

    def test_extra_missing_and_duplicate_targets(self):
        raw = diff("data0.txt", b"before\n", b"after\n")
        for candidate in (
            raw + diff("extra.txt", b"x\n", b"y\n"),
            diff("other.txt", b"x\n", b"y\n"),
            raw + raw,
        ):
            with self.subTest(candidate=candidate):
                self.reject(candidate)

    def test_unsafe_normalized_alias_paths(self):
        for name in (
            "../outside",
            "/absolute",
            "x/../y",
            "x/./y",
            "x//y",
            "x\\y",
            "C:/x",
            "x\ttimestamp",
            "x space",
            "./x",
        ):
            with self.subTest(name=name):
                self.reject(diff(name, b"before\n", b"after\n"))

    def test_create_delete_rename_mode_binary_and_symlink_forms(self):
        raw = diff("data0.txt", b"before\n", b"after\n")
        attacks = [
            raw.replace(b"--- a/data0.txt", b"--- /dev/null"),
            raw.replace(b"+++ b/data0.txt", b"+++ /dev/null"),
            raw.replace(b"+++ b/data0.txt", b"+++ b/renamed"),
            b"new file mode 120000\n" + raw,
            b"deleted file mode 100644\n" + raw,
            b"rename from x\nrename to y\n" + raw,
            b"GIT binary patch\nliteral 5\nabc\n",
            b"diff --git a/data0.txt b/data0.txt\nold mode 100644\nnew mode 120000\n" + raw,
        ]
        for candidate in attacks:
            with self.subTest(candidate=candidate):
                self.reject(candidate)

    def test_trailing_hidden_file_headers_and_malformed_hunks(self):
        raw = diff("data0.txt", b"before\n", b"after\n")
        for candidate in (
            raw + b"+++ b/hidden\n",
            raw + b"\n",
            raw.replace(b"@@ -1 +1 @@", b"@@ -1,2 +1 @@"),
            raw.replace(b"@@ -1 +1 @@", b"@@ -0,0 +1 @@"),
            raw.replace(b"@@ -1 +1 @@", b"@@ -9999999999999 +1 @@"),
            raw[:-1],
            raw + b"\0",
            raw.replace(b"\n", b"\r\n"),
        ):
            with self.subTest(candidate=candidate):
                self.reject(candidate)

    def test_nonunique_context_and_postimage_mismatch_refuse(self):
        tree, plan, patches = make_plan()
        name = next(iter(plan["rows"][0]["before"]))
        tree[name] = b"before\nbefore\n"
        plan["rows"][0]["before"][name] = d.sha(tree[name])
        with self.assertRaisesRegex(ValueError, "patch_context_not_unique"):
            d.patch_source_buffers(tree, plan, patches)
        tree, plan, patches = make_plan()
        plan["rows"][0]["after"]["data0.txt"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "debian_source_postimage"):
            d.patch_source_buffers(tree, plan, patches)

    def test_all_four_patches_preflight_before_first_application(self):
        tree, plan, patches = make_plan()
        row = plan["rows"][-1]
        raw = patches[row["proposed_patch"]] + diff("hidden", b"a\n", b"b\n")
        patches[row["proposed_patch"]] = raw
        row["proposed_patch_sha256"] = d.sha(raw)
        with patch.object(d, "apply_bound", side_effect=AssertionError("early_application")):
            with self.assertRaisesRegex(ValueError, "inventory_not_exhaustive"):
                d.patch_source_buffers(tree, plan, patches)

    def test_linux_patch_extra_target_refuses_before_source_read_write_or_command(self):
        tree, plan, patches = make_plan(extra=True)

        def read(path, cap):
            return patches[path.name]

        with (
            patch.object(f, "offline"),
            patch.object(f, "read", side_effect=read),
            patch.object(
                f,
                "source_text",
                side_effect=AssertionError("source_read_before_inventory"),
            ),
            patch.object(f, "write_new", side_effect=AssertionError("write_before_inventory")),
            patch.object(f, "run", side_effect=AssertionError("quilt_before_inventory")),
        ):
            with self.assertRaisesRegex(ValueError, "inventory_not_exhaustive"):
                f.patch_tree(Path("S"), plan, Path("W"), {})

    def test_linux_all_pre_postimages_simulated_before_first_quilt(self):
        tree, plan, patches = make_plan()
        plan["rows"][-1]["after"]["data3.txt"] = "f" * 64
        with (
            patch.object(f, "offline"),
            patch.object(f, "read", side_effect=lambda p, c: patches[p.name]),
            patch.object(f, "source_text", side_effect=lambda p, n: tree[n]),
            patch.object(
                f,
                "write_new",
                side_effect=AssertionError("write_before_all_postimages"),
            ),
            patch.object(f, "run", side_effect=AssertionError("quilt_before_all_postimages")),
        ):
            with self.assertRaisesRegex(ValueError, "debian_source_postimage"):
                f.patch_tree(Path("S"), plan, Path("W"), {})

    def test_pinned_plan_extra_target_refuses_before_build_or_extraction(self):
        tree, plan, patches = make_plan(extra=True)
        raw = json.dumps(plan).encode()

        def read(path, cap):
            return raw if path.name == "exact-debian-patch-plan.json" else patches[path.name]

        with (
            patch.object(f, "read", side_effect=read),
            patch.object(f, "run", side_effect=AssertionError("command_before_inventory")),
        ):
            with self.assertRaisesRegex(ValueError, "inventory_not_exhaustive"):
                f.checked_plan({"exact_debian_patch_plan_sha256": d.sha(raw)})

    def test_linux_positive_quilt_only_after_exact_full_simulation(self):
        tree, plan, patches = make_plan()
        current = dict(tree)
        events = []
        index = [0]

        def run(args, *rest, **kwargs):
            events.append(args)
            if args[1] == "push":
                row = plan["rows"][index[0]]
                current.update(d.apply_bound(current, row, patches[row["proposed_patch"]]))
                index[0] += 1
            return b""

        with (
            patch.object(f, "offline"),
            patch.object(f, "read", side_effect=lambda p, c: patches[p.name]),
            patch.object(f, "source_text", side_effect=lambda p, n: current[n]),
            patch.object(f, "write_new"),
            patch.object(f, "run", side_effect=run),
        ):
            f.patch_tree(Path("S"), plan, Path("W"), {})
        self.assertEqual(len(events), 8)
        self.assertEqual(set(current.values()), {b"after\n"})

    def test_source_target_FD_anchoring_link_and_parent_refusal(self):
        import stat

        calls = []

        def opened(name, flags, **kwargs):
            calls.append((name, flags, kwargs))
            return 100 + len(calls)

        row = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_nlink=1, st_size=2)
        with (
            patch.object(f.os, "O_NOFOLLOW", 0x10000, create=True),
            patch.object(f.os, "O_DIRECTORY", 0x20000, create=True),
            patch.object(f.os, "open", side_effect=opened),
            patch.object(f.os, "close"),
            patch.object(f.os, "fstat", return_value=row),
            patch.object(f.os, "fdopen", side_effect=lambda *args, **kwargs: io.BytesIO(b"x\n")),
        ):
            self.assertEqual(f.source_text(Path("S"), "sub/file.c"), b"x\n")
            self.assertTrue(all(flags & 0x10000 for _, flags, _ in calls))
            self.assertEqual(calls[1][2], {"dir_fd": 101})
            self.assertEqual(calls[2][2], {"dir_fd": 102})
            row.st_nlink = 2
            with self.assertRaisesRegex(ValueError, "patch_target_regular"):
                f.source_text(Path("S"), "file.c")
            with patch.object(f.os, "open", side_effect=OSError("synthetic_NOFOLLOW_symlink")):
                with self.assertRaises(OSError):
                    f.source_text(Path("S"), "linked/file.c")
