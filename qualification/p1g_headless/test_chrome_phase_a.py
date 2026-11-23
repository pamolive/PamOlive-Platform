"""Private Phase A lifecycle, synthetic memory TAR and OS actors only."""

import copy
import io
import json
import stat
import tarfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from qualification.p1g_headless import chrome_bootstrap as bootstrap
from qualification.p1g_headless import chrome_bundle as b
from qualification.p1g_headless import chrome_phase_a as a
from qualification.p1g_headless import test_chrome_bundle as fixture


class MemoryOS(fixture.MemoryOS):
    def __init__(self):
        super().__init__()
        self.fail_unlink = False
        self.fail_rmdir = False

    def stat(self, path, *, dir_fd=None, follow_symlinks=False):
        name = self.name(path, dir_fd)
        if name not in self.nodes:
            raise FileNotFoundError("SYNTHETIC_ABSENT")
        return super().stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def unlink(self, path, *, dir_fd):
        name = self.name(path, dir_fd)
        self.events.append(("unlink", name))
        if self.fail_unlink:
            raise OSError("SYNTHETIC_UNLINK")
        if stat.S_ISDIR(self.nodes[name]["mode"]):
            raise IsADirectoryError("SYNTHETIC_DIRECTORY")
        del self.nodes[name]

    def rmdir(self, path, *, dir_fd):
        name = self.name(path, dir_fd)
        self.events.append(("rmdir", name))
        if self.fail_rmdir:
            raise OSError("SYNTHETIC_RMDIR")
        if not stat.S_ISDIR(self.nodes[name]["mode"]):
            raise NotADirectoryError("SYNTHETIC_NONDIR")
        if any(value.startswith(name.rstrip("/") + "/") for value in self.nodes):
            raise OSError("SYNTHETIC_NOTEMPTY")
        del self.nodes[name]


def prepared(*, admitted=True, sandbox=True):
    extra = (
        ((b.PREFIX + "/chrome-sandbox", b"\x7fELF_SYNTHETIC_HELPER", 0o4755, tarfile.REGTYPE),)
        if sandbox else ()
    )
    stream = fixture.payload(extra=extra)
    tree = b.inventory(stream, fixture.PKG, until=100, clock=lambda: 0)
    roles = {}
    if sandbox:
        row = next(row for row in tree["entries"] if row["name"] == "chrome-sandbox")
        roles = {"chrome-sandbox": {
            "role": "setuid-sandbox-helper", "sha256": row["sha256"], "mode": 0o4755,
        }}
    raw = b.canonical({"schema": a.PROFILE_SCHEMA, "purpose": a.PURPOSE, "admitted": admitted,
                       "package_sha256": fixture.PKG, "tree_sha256": tree["tree_sha256"],
                       "privileged_roles": roles})
    return stream, tree, raw, b.digest(raw)


class PrivatePhaseATests(unittest.TestCase):
    def run_cycle(
        self, ops=None, prepared_args=None, *, clock=lambda: 0, until=100, env=None, bindings=None
    ):
        ops = MemoryOS() if ops is None else ops
        stream, tree, raw, pin = prepared_args or prepared()
        result = a.run(b, stream, tree, raw, pin, fixture.ENV if env is None else env,
                       fixture.BINDINGS if bindings is None else bindings,
                       until=until, clock=clock, ops=ops)
        return ops, result

    def test_01_complete_cycle_private_distinct_revokes_helper_and_removes_only_owned_tree(self):
        ops, result = self.run_cycle()
        self.assertEqual(result["schema"], a.RESULT_SCHEMA)
        self.assertEqual(result["purpose"], a.PURPOSE)
        self.assertNotEqual(result["schema"], b.SCHEMA)
        for field in (
            "UI_eligible", "v3_receipt_emitted", "browser_executed", "operational_GO",
            "all_OS_descendants_released",
        ):
            self.assertIs(result[field], False)
        self.assertIs(result["prefix_absent_verified"], True)
        self.assertEqual(set(ops.nodes), {"/", "/usr", "/usr/lib"})
        self.assertEqual(ops.fds, {})
        root = b.root_path(fixture.ENV).as_posix()
        self.assertFalse(any(event == ("chmod", root, 0o755) for event in ops.events))
        revoked = ops.events.index(("chmod", root + "/chrome-sandbox", 0o600))
        removed = ops.events.index(("unlink", root + "/chrome-sandbox"))
        self.assertLess(revoked, removed)
        for event in ops.events:
            if event[0] in {"chmod", "unlink", "rmdir"}:
                self.assertTrue(event[1] == root or event[1].startswith(root + "/"))

    def test_02_unadmitted_profile_and_same_UID_never_create_or_delete_anything(self):
        for which in ("profile", "uid"):
            ops = MemoryOS()
            args = prepared(admitted=which != "profile")
            if which == "uid":
                ops.getuid = ops.geteuid = lambda: 1001
            with self.assertRaises(ValueError):
                self.run_cycle(ops, args)
            self.assertEqual(ops.events, [])
            self.assertEqual(ops.fds, {})

    def test_03_existing_prefix_collision_is_never_adopted_deleted_or_repaired(self):
        ops = MemoryOS()
        root = b.root_path(fixture.ENV).as_posix()
        ops.make(root, stat.S_IFDIR | 0o700)
        with self.assertRaisesRegex(ValueError, "phase_a_cycle_unknown"):
            self.run_cycle(ops)
        self.assertIn(root, ops.nodes)
        self.assertFalse(any(event[0] in {"chmod", "unlink", "rmdir"} for event in ops.events))
        self.assertEqual(ops.fds, {})

    def test_04_short_write_refuses_work_but_cleans_the_owned_partial_file(self):
        ops = MemoryOS()
        ops.short_write = True
        with self.assertRaisesRegex(ValueError, "phase_a_cycle_unknown"):
            self.run_cycle(ops)
        self.assertEqual(set(ops.nodes), {"/", "/usr", "/usr/lib"})
        self.assertEqual(ops.fds, {})

    def test_05_unlink_or_rmdir_error_never_returns_complete_and_prefix_remains_private(self):
        for flag in ("fail_unlink", "fail_rmdir"):
            ops = MemoryOS()
            setattr(ops, flag, True)
            with (
                self.subTest(flag=flag),
                self.assertRaisesRegex(ValueError, "phase_a_cycle_unknown"),
            ):
                self.run_cycle(ops)
            self.assertEqual(
                stat.S_IMODE(ops.nodes[b.root_path(fixture.ENV).as_posix()]["mode"]), 0o700
            )
            self.assertEqual(ops.fds, {})

    def test_06_unexpected_entry_alias_hardlink_owner_or_identity_refuses_before_deletion(self):
        for fault in ("extra", "alias", "hardlink", "owner", "identity"):
            ops = MemoryOS()
            original = a.PrivateCycle._scan
            injected = [False]
            def scan(cycle, fd, prefix, observed):
                if not injected[0]:
                    injected[0] = True
                    root = b.root_path(fixture.ENV).as_posix()
                    leaf = ops.nodes[root + "/chrome"]
                    if fault == "extra":
                        ops.make(root + "/EXTRA", stat.S_IFREG | 0o600, b"DATA")
                    elif fault == "alias":
                        leaf["mode"] = stat.S_IFLNK | 0o777
                    elif fault == "owner":
                        leaf["uid"] = 1001
                    elif fault == "identity":
                        leaf["ino"] += 1000
                    else:
                        old_row = ops.row
                        def row(node):
                            result = old_row(node)
                            if node is leaf:
                                result.st_nlink = 2
                            return result
                        ops.row = row
                return original(cycle, fd, prefix, observed)
            with (
                self.subTest(fault=fault), patch.object(a.PrivateCycle, "_scan", scan),
                self.assertRaisesRegex(ValueError, "phase_a_cycle_unknown"),
            ):
                self.run_cycle(ops)
            self.assertFalse(any(event[0] == "unlink" for event in ops.events))
            self.assertEqual(ops.fds, {})

    def test_07_absolute_cleanup_reserve_not_reset_after_work_or_deletion(self):
        now = [0]
        ops = MemoryOS()
        original = ops.write
        def late(fd, raw):
            value = original(fd, raw)
            now[0] = 81
            return value
        ops.write = late
        with self.assertRaisesRegex(ValueError, "phase_a_cycle_unknown"):
            self.run_cycle(ops, clock=lambda: now[0])
        self.assertEqual(set(ops.nodes), {"/", "/usr", "/usr/lib"})
        self.assertEqual(ops.fds, {})
        now[0] = 0
        ops = MemoryOS()
        original_unlink = ops.unlink
        def expire(path, **kwargs):
            original_unlink(path, **kwargs)
            now[0] = 101
        ops.unlink = expire
        with self.assertRaisesRegex(ValueError, "phase_a_cycle_unknown"):
            self.run_cycle(ops, clock=lambda: now[0])
        self.assertIn(b.root_path(fixture.ENV).as_posix(), ops.nodes)
        self.assertEqual(ops.fds, {})

    def test_08_phase_A_private_receipt_is_rejected_by_unchanged_v3_consumer(self):
        ops = MemoryOS()
        original = a.PrivateCycle.cleanup
        observed = []
        def check(cycle, parent, root, name):
            with self.assertRaises(ValueError):
                b.verify(fixture.ENV, fixture.BINDINGS, cycle.profile_raw, cycle.profile_sha,
                         until=100, ops=ops, clock=lambda: 0)
            receipt = json.loads(ops.nodes[
                b.root_path(fixture.ENV).as_posix() + "/.bundle-receipt.json"
            ]["data"])
            self.assertEqual(receipt["schema"], a.STAGED_SCHEMA)
            observed.append(True)
            return original(cycle, parent, root, name)
        with patch.object(a.PrivateCycle, "cleanup", check):
            self.run_cycle(ops)
        self.assertEqual(observed, [True])

    def test_09_wrong_run_or_context_cannot_be_substituted_after_ownership(self):
        args = prepared()
        _, tree, raw, pin = args
        ops = MemoryOS()
        cycle = a.PrivateCycle(
            b, tree, raw, pin, fixture.ENV, fixture.BINDINGS, 100, ops, lambda: 0
        )
        for env, bindings in ((dict(fixture.ENV, GITHUB_RUN_ID="999"), fixture.BINDINGS),
                              (fixture.ENV, dict(fixture.BINDINGS, context_receipt_sha256="f"*64))):
            with self.assertRaisesRegex(ValueError, "phase_a_cycle_binding"):
                cycle.validate(env, bindings)
        self.assertEqual(ops.events, [])

    def test_10_Root_admitted_stage_profile_is_pinned_operational_v1_remains_false(self):
        here = Path(__file__).parent
        raw = (here / a.PROFILE_NAME).read_bytes()
        self.assertEqual(b.digest(raw), a.PROFILE_SHA)
        self.assertIs(json.loads(raw)["admitted"], True)
        self.assertEqual(json.loads(raw)["purpose"], a.PURPOSE)
        self.assertIs(json.loads((here / b.PROFILE_NAME).read_bytes())["commissioned"], False)

    def test_11_close_or_fsync_uncertainty_attempts_all_acquired_FDs_and_never_succeeds(self):
        for fault in ("fail_close", "fail_fsync"):
            ops = MemoryOS()
            setattr(ops, fault, True)
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(ValueError, "phase_a_cycle_unknown"),
            ):
                self.run_cycle(ops)
            self.assertEqual(ops.fds, {})
            opened = sum(event[0] == "open" for event in ops.events)
            closed = sum(event[0] == "close" for event in ops.events)
            self.assertEqual(opened, closed)

    def test_12_reserve_is_available_to_cleanup_and_is_not_a_new_work_deadline(self):
        ops = MemoryOS()
        now = [0]
        original = ops.unlink
        def reserved(path, **kwargs):
            original(path, **kwargs)
            now[0] = 90
        ops.unlink = reserved
        _, result = self.run_cycle(ops, clock=lambda: now[0])
        self.assertIs(result["prefix_absent_verified"], True)
        self.assertEqual(ops.fds, {})

    def test_13_prefix_replacement_and_directory_drift_cannot_select_other_objects(self):
        for fault in ("prefix", "directory_mode", "directory_identity", "directory_alias"):
            ops = MemoryOS()
            original = a.PrivateCycle._scan
            injected = [False]
            def scan(cycle, fd, prefix, observed):
                if not injected[0]:
                    injected[0] = True
                    root = b.root_path(fixture.ENV).as_posix()
                    if fault == "prefix":
                        ops.make(root, stat.S_IFDIR | 0o700)
                    elif fault == "directory_mode":
                        ops.nodes[root + "/locales"]["mode"] = stat.S_IFDIR | 0o777
                    elif fault == "directory_identity":
                        ops.nodes[root + "/locales"]["ino"] += 1000
                    else:
                        ops.nodes[root + "/locales"]["mode"] = stat.S_IFLNK | 0o777
                return original(cycle, fd, prefix, observed)
            with (
                self.subTest(fault=fault), patch.object(a.PrivateCycle, "_scan", scan),
                self.assertRaises(ValueError),
            ):
                self.run_cycle(ops)
            self.assertFalse(any(event[0] == "unlink" for event in ops.events))
            self.assertEqual(ops.fds, {})

    def test_14_cleanup_rechecks_each_file_after_scan_before_unlink(self):
        ops = MemoryOS()
        original = a.PrivateCycle._parent
        mutated = [False]
        def parent(cycle, root, name):
            if not mutated[0]:
                mutated[0] = True
                ops.nodes[b.root_path(fixture.ENV).as_posix() + "/" + name]["version"] += 100
            yield from original(cycle, root, name)
        with (
            patch.object(a.PrivateCycle, "_parent", parent),
            self.assertRaisesRegex(ValueError, "phase_a_cycle_unknown"),
        ):
            self.run_cycle(ops)
        self.assertFalse(any(event[0] == "unlink" for event in ops.events))
        self.assertEqual(ops.fds, {})

    def test_15_post_stat_expiry_prevents_the_next_mutation(self):
        ops = MemoryOS()
        now = [0]
        original = a.PrivateCycle._parent
        def parent(cycle, root, name):
            for fd in original(cycle, root, name):
                now[0] = 101
                yield fd
        with (
            patch.object(a.PrivateCycle, "_parent", parent),
            self.assertRaisesRegex(ValueError, "phase_a_cycle_unknown"),
        ):
            self.run_cycle(ops, clock=lambda: now[0])
        self.assertFalse(any(event[0] == "unlink" for event in ops.events))
        self.assertEqual(ops.fds, {})

    def test_16_typed_result_is_closed_bound_and_never_authorizes_UI(self):
        args = prepared()
        _, tree, _, pin = args
        _, result = self.run_cycle(prepared_args=args)
        self.assertEqual(
            a.result_contract(b, b.canonical(result), tree, pin, fixture.ENV, fixture.BINDINGS),
            result,
        )
        faults = {"schema": b.SCHEMA, "purpose": "UI", "UI_eligible": True,
                  "v3_receipt_emitted": True, "operational_GO": True,
                  "run": "999", "attempt": "2", "prefix": "/usr/lib/OTHER",
                  "profile_sha256": "0" * 64, "package_sha256": "0" * 64,
                  "manifest_sha256": "0" * 64, "context_receipt_sha256": "0" * 64,
                  "deleted_files": True, "deleted_directories": -1, "UNKNOWN": True,
                  "root_identity": [1, 2, stat.S_IFDIR | 0o755, 0, 0]}
        for key, value in faults.items():
            bad = copy.deepcopy(result)
            bad[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                a.result_contract(b, b.canonical(bad), tree, pin, fixture.ENV, fixture.BINDINGS)
        for raw in (b"{", b"{}", b"null", b" " * 32769):
            with self.assertRaises(ValueError):
                a.result_contract(b, raw, tree, pin, fixture.ENV, fixture.BINDINGS)

    def test_17_private_receipt_schema_blocks_v3_even_if_a_Root_actor_changes_mode(self):
        ops = MemoryOS()
        original = a.PrivateCycle.cleanup
        def check(cycle, parent, root, name):
            root_path = b.root_path(fixture.ENV).as_posix()
            ops.nodes[root_path]["mode"] = stat.S_IFDIR | 0o755
            # An independently valid operational test profile cannot convert a Phase A receipt.
            raw, pin = fixture.profile(
                cycle.tree, roles=json.loads(cycle.profile_raw)["privileged_roles"]
            )
            with self.assertRaisesRegex(ValueError, "bundle_receipt"):
                b.verify(
                    fixture.ENV, fixture.BINDINGS, raw, pin, until=100, ops=ops, clock=lambda: 0
                )
            ops.nodes[root_path]["mode"] = stat.S_IFDIR | 0o700
            return original(cycle, parent, root, name)
        with patch.object(a.PrivateCycle, "cleanup", check):
            self.run_cycle(ops)

    def test_18_absence_is_independent_fixed_run_target_and_closes_parent_chain(self):
        ops = MemoryOS()
        a.assert_absent(b, fixture.ENV, until=100, clock=lambda: 0, ops=ops)
        self.assertEqual(ops.fds, {})
        root = b.root_path(fixture.ENV).as_posix()
        for mode in (stat.S_IFDIR | 0o700, stat.S_IFLNK | 0o777, stat.S_IFREG | 0o600):
            ops.make(root, mode)
            with self.assertRaisesRegex(ValueError, "phase_a_prefix_still_present"):
                a.assert_absent(b, fixture.ENV, until=100, clock=lambda: 0, ops=ops)
            self.assertEqual(ops.fds, {})
        self.assertFalse(any(
            event[0] in {"mkdir", "chmod", "unlink", "rmdir"} for event in ops.events
        ))

    def test_19_profile_patch_tree_roles_and_reserved_names_are_not_inferred(self):
        _, tree, raw, _ = prepared()
        for fault in ("pin", "package", "tree", "role", "reserved", "schema", "purpose"):
            candidate, profile = copy.deepcopy(tree), json.loads(raw)
            if fault == "package":
                profile["package_sha256"] = "f" * 64
            elif fault == "tree":
                profile["tree_sha256"] = "f" * 64
            elif fault == "role":
                profile["privileged_roles"]["chrome-sandbox"]["sha256"] = "f" * 64
            elif fault == "reserved":
                candidate["entries"].append({
                    "name": ".bundle-receipt.json", "type": "regular", "mode": 0o644,
                                              "bytes": 1, "sha256": "e" * 64, "uid": 0, "gid": 0})
                candidate["tree_sha256"] = b.digest(b.canonical(candidate["entries"]))
                profile["tree_sha256"] = candidate["tree_sha256"]
            elif fault == "schema":
                profile["schema"] = b.PROFILE_SCHEMA
            elif fault == "purpose":
                profile["purpose"] = "UI"
            changed = b.canonical(profile)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                a.admit(b, candidate, changed, "0" * 64 if fault == "pin" else b.digest(changed))

    def test_20_non_UI_supervisor_requires_historical_runtime_and_independent_absence(self):
        args = prepared()
        _, tree, _, pin = args
        _, result = self.run_cycle(prepared_args=args)
        class Commands:
            until = 100
            def run(self, argv, **kwargs):
                self.argv, self.kwargs = argv, kwargs
                return b.canonical(result)
        commands = Commands()
        role = {"independent": "SYNTHETIC_ROOT_ROLE"}
        with (
            patch.dict(bootstrap.os.environ, fixture.ENV), patch.object(a, "PROFILE_SHA", pin),
            patch.object(bootstrap, "root_interpreter_pin", return_value=role) as observe,
            patch.object(bootstrap, "check_root_interpreter") as historical,
            patch.object(a, "assert_absent") as absence,
            patch.object(bootstrap.time, "monotonic", return_value=0),
        ):
            actual = bootstrap.private_stage_supervisor(commands, object(), b, a, tree,
                                                        fixture.BINDINGS, "c" * 64, "e" * 64)
        self.assertEqual(actual, result)
        self.assertEqual(observe.call_count, 3)
        historical.assert_called_once_with(
            result["root_interpreter"], role, context_sha="d" * 64,
            pins_sha="c" * 64, source_sha="e" * 64, revision="b" * 40,
        )
        absence.assert_called_once()
        self.assertIn("--stage-cleanup-only", commands.argv)
        self.assertNotIn("--test-bundle", commands.argv)
        self.assertEqual(commands.kwargs, {"seconds": 480, "cap": 32768, "sudo": True})
        for refusing in ("check_root_interpreter", "absence", "role"):
            with (
                self.subTest(refusing=refusing), patch.dict(bootstrap.os.environ, fixture.ENV),
                patch.object(a, "PROFILE_SHA", pin),
                patch.object(bootstrap.time, "monotonic", return_value=0),
                patch.object(bootstrap, "root_interpreter_pin",
                             side_effect=([role, {}] if refusing == "role" else None),
                             return_value=role),
                patch.object(bootstrap, "check_root_interpreter", side_effect=(
                    ValueError("UNKNOWN") if refusing == "check_root_interpreter" else None
                )),
                patch.object(a, "assert_absent", side_effect=(
                    ValueError("UNKNOWN") if refusing == "absence" else None
                )),
                self.assertRaises(ValueError),
            ):
                bootstrap.private_stage_supervisor(commands, object(), b, a, tree,
                                                   fixture.BINDINGS, "c" * 64, "e" * 64)

    def composed(self, *, admitted):
        from qualification.p1g_headless import test_chrome_bootstrap as old

        native_main = bootstrap.main
        events = []
        if admitted:
            here = Path(__file__).parent
            tree = b.json_bytes((here / "chrome-stage-inventory-158.DATA.json").read_bytes())
            raw, pin = (here / a.PROFILE_NAME).read_bytes(), a.PROFILE_SHA
        else:
            # Explicit negative policy actor; the actual source policy is now admitted.
            _, tree, raw, pin = prepared(admitted=False)
        def wrapped(argv):
            existing_load, existing_context = bootstrap.load, bootstrap.context
            def context(*args):
                pins, captured = existing_context(*args)
                captured = dict(captured)
                captured["qualification/p1g_headless/" + a.PROFILE_NAME] = raw
                return pins, captured
            def load(name, *args):
                if name == "p1g_authenticated_bundle":
                    def inventory(*args, **kwargs):
                        events.append("inventory")
                        return tree
                    return SimpleNamespace(inventory=inventory, canonical=b.canonical)
                if name == "p1g_private_phase_a":
                    def admit(bundle, actual_tree, actual_raw, pin):
                        events.append("private_admit")
                        return a.admit(b, actual_tree, actual_raw, pin)
                    return SimpleNamespace(
                        admit=admit, PROFILE_SHA=pin
                    )
                return existing_load(name, *args)
            def stage(*args):
                events.append("private_stage_cleanup")
                return {"schema": a.RESULT_SCHEMA, "UI_eligible": False, "operational_GO": False}
            with patch.object(bootstrap, "context", side_effect=context), \
                 patch.object(bootstrap, "load", side_effect=load), \
                 patch.object(bootstrap, "private_stage_root", side_effect=stage), \
                 patch("sys.stdout", new=io.StringIO()):
                return native_main([*argv, "--stage-cleanup-only"])
        with patch.object(bootstrap, "main", side_effect=wrapped):
            rc, outer, writes = old.RootAptCacheTests().controller()
        return rc, events, outer, writes

    def test_21_actual_controller_unadmitted_actor_refuses_before_dependencies_or_Root_stage(self):
        rc, events, outer, writes = self.composed(admitted=False)
        self.assertEqual(rc, 42)
        self.assertEqual(events, ["inventory", "private_admit"])
        self.assertFalse(any(isinstance(event, tuple) for event in outer))
        packet = json.loads(writes["/runner/p1g-headless-123-1-chrome/root-UNKNOWN.json"])
        self.assertEqual(packet["phase"], "private_stage_admission")
        self.assertEqual(packet["code"], "phase_a_profile_unadmitted")
        self.assertIn("/runner/p1g-headless-123-1-chrome/root/bundle-inventory.json", writes)
        for name in ("installed.json", "test-bundle.json", "root-private-stage.json"):
            self.assertNotIn("/runner/p1g-headless-123-1-chrome/" + name, writes)

    def test_22_actual_controller_admitted_actor_cannot_reach_legacy_install_or_v3_stage(self):
        rc, events, outer, writes = self.composed(admitted=True)
        self.assertEqual(rc, 0)
        self.assertEqual(events, ["inventory", "private_admit", "private_stage_cleanup"])
        apt = [event for event in outer if isinstance(event, tuple)]
        self.assertEqual(len(apt), 1)
        self.assertIn("--simulate", apt[0])
        self.assertNotIn("--assume-yes", apt[0])
        self.assertNotIn("query", outer)
        inventory = writes[
            "/runner/p1g-headless-123-1-chrome/root/bundle-inventory.json"
        ]
        self.assertEqual(
            b.digest(inventory),
            "328dc76543cb40c0d9fd50e6f3870c8f8f90f8f61428b32acb33e024920759af",
        )
        self.assertEqual(len(b.json_bytes(inventory)["entries"]), 261)
        self.assertIn("/runner/p1g-headless-123-1-chrome/root-private-stage.json", writes)
        self.assertNotIn("/runner/p1g-headless-123-1-chrome/test-bundle.json", writes)
        self.assertNotIn("/runner/p1g-headless-123-1-chrome/installed.json", writes)

    def test_23_Root_private_stage_revalidates_same_cache_and_runtime_after_cleanup(self):
        payload = SimpleNamespace(open=lambda mode: io.BytesIO(b"SYNTHETIC_NOT_READ"))
        commands = SimpleNamespace(until=100)
        runtime = {"synthetic": True}
        for fault in (None, "cache", "runtime", "deadline"):
            events = []
            def cache(*args):
                events.append("cache")
                if fault == "cache" and len(events) > 1:
                    raise ValueError("UNKNOWN")
            def run(*args, **kwargs):
                events.append("cycle")
                self.assertEqual(kwargs["until"], 90)
                return {"schema": a.RESULT_SCHEMA}
            with (
                self.subTest(fault=fault),
                patch.object(bootstrap, "root_cache_check", side_effect=cache),
                patch.object(a, "run", side_effect=run),
                patch.object(bootstrap, "root_interpreter_runtime",
                             return_value={} if fault == "runtime" else runtime),
                patch.object(bootstrap.time, "monotonic",
                             return_value=101 if fault == "deadline" else 0),
            ):
                def call():
                    return bootstrap.private_stage_root(
                        commands, object(), b, a, {}, b"", fixture.BINDINGS,
                        object(), object(), {"package": {}}, payload, "e" * 64, runtime,
                    )
                if fault:
                    with self.assertRaises(ValueError):
                        call()
                else:
                    self.assertEqual(call(), {"schema": a.RESULT_SCHEMA})
                self.assertEqual(events, ["cache", "cycle", "cache"])

    def test_24_creation_failure_before_ledger_is_unknown_and_never_adopts_an_object(self):
        for fault in ("root_open", "file_fstat", "directory_open"):
            ops = MemoryOS()
            original_open, original_stat = ops.open, ops.fstat
            root = b.root_path(fixture.ENV).as_posix()
            def opened(path, flags, mode=0, *, dir_fd=None):
                name = ops.name(path, dir_fd)
                if (fault == "root_open" and name == root) or (
                    fault == "directory_open" and name == root + "/locales"
                ):
                    raise OSError("SYNTHETIC_OPEN")
                return original_open(path, flags, mode, dir_fd=dir_fd)
            def row(fd):
                if fault == "file_fstat" and ops.fds[fd]["path"] == root + "/chrome":
                    raise OSError("SYNTHETIC_FSTAT")
                return original_stat(fd)
            ops.open, ops.fstat = opened, row
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(ValueError, "phase_a_cycle_unknown"),
            ):
                self.run_cycle(ops)
            self.assertEqual(ops.fds, {})
            self.assertFalse(any(event[0] == "unlink" for event in ops.events))
            self.assertEqual(stat.S_IMODE(ops.nodes[root]["mode"]), 0o700)

    def test_25_admitted_source_profile_accepts_exact_261_public_DATA_records_only(self):
        here = Path(__file__).parent
        raw = (here / "chrome-stage-inventory.DATA.json").read_bytes()
        self.assertEqual(
            b.digest(raw),
            "c132e7c97c82f326019632044c35e916336f482a9dae6d8765b7997ab3eea738",
        )
        tree = b.json_bytes(raw)
        self.assertEqual(b.canonical(tree), raw)
        self.assertIs(tree["admitted"], False)
        self.assertIs(tree["operational_GO"], False)
        self.assertEqual(
            tree["package_sha256"],
            "4d740636b5c96f687798602c5aad6a5a270f44dd02e48db0638ae77aa4867b1b",
        )
        self.assertEqual(
            tree["tree_sha256"],
            "bde1999adb166df18728a4de24ceef9799e5d23442c43ce8d1e37eb1d97a3e6c",
        )
        self.assertEqual(b.digest(b.canonical(tree["entries"])), tree["tree_sha256"])
        profile_raw = (here / "chrome-stage-only-profile.json").read_bytes()
        historical_pin = "14f1f02f2f987c7a07f62079f534fa0c48282b4efba0f04d595d8976625a0841"
        names = a.admit(b, tree, profile_raw, historical_pin)
        with self.assertRaisesRegex(ValueError, "phase_a_profile_pin"):
            a.admit(b, tree, profile_raw, a.PROFILE_SHA)
        self.assertEqual(len(names), 261)
        self.assertEqual(sum(row["type"] == "regular" for row in names.values()), 253)
        self.assertEqual(sum(row["type"] == "directory" for row in names.values()), 8)
        self.assertEqual(sum(row["bytes"] for row in names.values()), 472983443)
        self.assertTrue(all(row["uid"] == row["gid"] == 0 for row in names.values()))
        self.assertTrue(all(not row["mode"] & 0o2022 for row in names.values()))
        self.assertEqual([name for name, row in names.items() if row["mode"] & 0o4000],
                         ["chrome-sandbox"])
        self.assertEqual(names["chrome-sandbox"]["bytes"], 15248)
        self.assertEqual(names["chrome-sandbox"]["mode"], 0o4755)
        self.assertEqual(names["chrome-sandbox"]["sha256"],
                         "8f93aa6b8dbf07073b2baedf2ae7b169515922bc097043de9dca27f6c7905704")
        for fault in ("admitted", "GO", "content", "package", "tree"):
            changed = copy.deepcopy(tree)
            if fault == "admitted":
                changed["admitted"] = True
            elif fault == "GO":
                changed["operational_GO"] = True
            elif fault == "content":
                changed["entries"][1]["mode"] = 0o777
            elif fault == "package":
                changed["package_sha256"] = "f" * 64
            else:
                changed["tree_sha256"] = "f" * 64
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                a.admit(b, changed, profile_raw, historical_pin)

    def test_25b_chrome158_has_its_own_profile_and_cannot_admit_the_157_tree(self):
        here = Path(__file__).parent
        profile_raw = (here / a.PROFILE_NAME).read_bytes()
        profile = b.json_bytes(profile_raw)
        self.assertEqual(b.digest(profile_raw), a.PROFILE_SHA)
        pins = b.json_bytes((here / "chrome-bootstrap-pins.json").read_bytes())
        self.assertEqual(profile["package_sha256"], pins["package"]["SHA256"])
        self.assertEqual(profile["purpose"], a.PURPOSE)
        self.assertEqual(set(profile["privileged_roles"]), {"chrome-sandbox"})
        active_raw = (here / "chrome-stage-inventory-158.DATA.json").read_bytes()
        names = a.admit(b, b.json_bytes(active_raw), profile_raw, a.PROFILE_SHA)
        self.assertEqual(len(names), 261)
        self.assertEqual(sum(row["bytes"] for row in names.values()), 480561176)
        self.assertEqual(names["chrome-sandbox"]["bytes"], 15296)
        self.assertEqual(names["chrome-sandbox"]["mode"], 0o4755)
        tree = b.json_bytes((here / "chrome-stage-inventory.DATA.json").read_bytes())
        with self.assertRaises(ValueError):
            a.admit(b, tree, profile_raw, a.PROFILE_SHA)
        self.assertFalse(b.json_bytes((here / b.PROFILE_NAME).read_bytes())["commissioned"])

    def test_26_real_DATA_never_admits_a_false_or_unpinned_profile_or_operational_v3(self):
        here = Path(__file__).parent
        tree = b.json_bytes((here / "chrome-stage-inventory.DATA.json").read_bytes())
        profile_raw = (here / "chrome-stage-only-profile.json").read_bytes()
        negative = b.json_bytes(profile_raw)
        negative["admitted"] = False
        negative_raw = b.canonical(negative)
        ops = MemoryOS()
        with self.assertRaisesRegex(ValueError, "phase_a_profile_unadmitted"):
            a.PrivateCycle(b, tree, negative_raw, b.digest(negative_raw),
                           fixture.ENV, fixture.BINDINGS, 100, ops, lambda: 0)
        with self.assertRaisesRegex(ValueError, "phase_a_profile_pin"):
            a.admit(b, tree, profile_raw, "f" * 64)
        with self.assertRaisesRegex(ValueError, "bundle_profile_uncommissioned"):
            b.admit(tree, (here / b.PROFILE_NAME).read_bytes(), b.PROFILE_SHA)
        self.assertEqual(ops.events, [])
        self.assertEqual(ops.fds, {})

    def test_26b_stage_branch_refuses_legacy_install_and_browser_modes_before_setup(self):
        branch = "agent/p1g-chrome158-private-stage"
        for ref, head in (("refs/heads/" + branch, ""), ("refs/pull/1/merge", branch)):
            for mode in ([], ["--test-bundle"], ["--root-install"]):
                with (
                    self.subTest(ref=ref, head=head, mode=mode),
                    patch.dict(bootstrap.os.environ, GITHUB_REF=ref, GITHUB_HEAD_REF=head),
                    self.assertRaisesRegex(ValueError, "phase_a_stage_only_mode"),
                ):
                    bootstrap.main(["--pins-sha", "f" * 64,
                                    "--native-scope-preflight-required", *mode])

    def test_27_private_cycle_success_cannot_make_the_workflow_pass_without_UI(self):
        workflow = (Path(__file__).parents[2] / ".github/workflows/ci.yml").read_bytes()
        workflow = workflow.replace(b"\r\n", b"\n")
        hold = (
            b"      - name: HOLD phase A - full UI qualification awaits separate Phase B review\n"
            b"        shell: bash\n"
            b"        run: exit 42\n"
        )
        ui_name = b"      - name: Exercise the synthetic P1-G JavaScript increment\n"
        retain_name = b"      - name: Retain only typed synthetic public evidence\n"

        def require_gate(raw):
            job = raw.split(b"\n  p1g-headless:\n", 1)[1].split(
                b"\n  readonly-source-contracts:\n", 1
            )[0]
            self.assertNotIn(b"continue-on-error:", job)
            self.assertEqual(job.count(hold), 1)
            position = job.index(hold)
            self.assertLess(job.index(b" --stage-cleanup-only\n"), position)
            self.assertEqual(position + len(hold), job.index(ui_name))
            ui = job[job.index(ui_name) : job.index(retain_name)]
            self.assertEqual(
                b.digest(ui),
                "fc47c7c1fc8cf671944139efd3f15d1d107cdc538cf22f9b01fa26c6ea2bab42",
            )

        require_gate(workflow)
        ui = workflow[workflow.index(ui_name) : workflow.index(retain_name)]
        mutations = {
            "UI_removed": workflow.replace(ui, b"", 1),
            "hold_removed": workflow.replace(hold, b"", 1),
            "hold_conditional": workflow.replace(
                hold, hold.replace(b"        shell:", b"        if: false\n        shell:"), 1
            ),
            "hold_ignored": workflow.replace(
                hold,
                hold.replace(b"        shell:", b"        continue-on-error: true\n        shell:"),
                1,
            ),
            "hold_success": workflow.replace(hold, hold.replace(b"exit 42", b"exit 0"), 1),
        }
        for reason, changed in mutations.items():
            with self.subTest(reason=reason), self.assertRaises((AssertionError, ValueError)):
                require_gate(changed)
