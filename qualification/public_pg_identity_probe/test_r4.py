"""Targeted R4 ownership, START and public diagnostic adversaries; fake IO only."""

import copy
import json
import unittest
from pathlib import Path

import owner as o
import probe as p
from test_probe import CID, LEGACY, LINUX, PROFILE, RUN, ProbeTests, Result, row


def acknowledged():
    state = ProbeTests().state()
    state["IO"] = [{"operation": "create", **Result().facts()}]
    state["IO_total"] = 1
    state["create_ack"] = {
        "cid": CID,
        "run": RUN,
        "manifest": p.MANIFEST,
        "user": "0:0",
        "io_index": 0,
    }
    state["legacy_reservation"] = {
        "name": RUN + "-stage0",
        "run": RUN,
        "user": "0:0",
        "image_config": p.MANIFEST,
        "cid": CID,
        "attempted": True,
        "outcome": "confirmed",
    }
    state.update(metadata_verified=True, owner_cleaning=True)
    return state


class R4Tests(unittest.TestCase):
    def test_ack_identity_and_h1_are_all_required(self):
        state = acknowledged()
        p.require_create_ack(state, CID)
        for key, value in [
            ("cid", "d" * 64),
            ("manifest", p.CONFIG),
            ("run", "foreign"),
            ("user", "999:999"),
            ("io_index", True),
            ("io_index", 1),
        ]:
            bad = copy.deepcopy(state)
            bad["create_ack"][key] = value
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.require_create_ack(bad, CID)
        for key, value in [
            ("operation", "inspect"),
            ("spawn_attempted", False),
            ("returncode", True),
            ("returncode", 1),
            ("owned_child_reaped", False),
            ("drains_complete", False),
            ("killed_owned_child", True),
            ("exception_type", "TimeoutError"),
            ("cleanup_exception_type", "Error"),
        ]:
            bad = copy.deepcopy(state)
            bad["IO"][0][key] = value
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.require_create_ack(bad, CID)

    def test_foreign_identity_never_qualifies_cleanup(self):
        for where, key, value in [
            (None, "Id", "d" * 64),
            (None, "Name", "/foreign"),
            (None, "Image", p.CONFIG),
            ("Config", "User", "999:999"),
            ("Config", "Labels", {p.LABEL: "foreign"}),
            ("Config", "Labels", {p.LABEL: RUN, "foreign": "yes"}),
        ]:
            candidate = row()
            target = candidate if where is None else candidate[where]
            target[key] = value
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.inspect_owned(candidate, acknowledged(), CID)

    def test_cleanup_state_strict_and_unstarted_running_refuses_stop(self):
        for key, value in [
            ("Running", 0),
            ("OOMKilled", 0),
            ("ExitCode", False),
            ("ExitCode", 256),
            ("Running", True),
        ]:
            candidate = row()
            candidate["State"][key] = value
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.inspect_owned(candidate, acknowledged(), CID)

    def test_bad_sandbox_never_passes_start_but_can_identify_owned_cid(self):
        for key, value in [
            ("Mounts", None),
            ("Init", None),
            ("Privileged", True),
            ("NetworkMode", "host"),
            ("Binds", ["SYNTHETIC_PRIVATE:/private"]),
            ("Memory", 0),
        ]:
            candidate = row()
            candidate["HostConfig"][key] = value
            self.assertEqual(p.inspect_owned(candidate, acknowledged(), CID)["Id"], CID)
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.inspect_profile(candidate, RUN, PROFILE)

    def test_start_gate_requires_full_profile_cid_and_ack(self):
        state = acknowledged()
        state.update(owner_cleaning=False, started=True)
        with self.assertRaises(ValueError):
            o.command_allowed(p, state, ["start", "--attach", CID])
        state["start_profile_cid"] = CID
        o.command_allowed(p, state, ["start", "--attach", CID])
        state["start_profile_cid"] = "d" * 64
        with self.assertRaises(ValueError):
            o.command_allowed(p, state, ["start", "--attach", CID])
        state["start_profile_cid"] = CID
        del state["create_ack"]
        with self.assertRaises(ValueError):
            o.command_allowed(p, state, ["start", "--attach", CID])

    def test_cleanup_gate_requires_ack_even_with_confirmed_legacy_record(self):
        state = acknowledged()
        del state["create_ack"]
        for args in [["rm", CID], ["stop", "--time", "5", CID]]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                o.command_allowed(p, state, args)

    def test_diagnostics_no_unknown_env_labels_paths_or_passwd(self):
        candidate = row()
        sentinel = "SYNTHETIC_UNEXPECTED_PRIVATE_MARKER"
        candidate["Config"]["Env"] = ["SECRET=" + sentinel]
        candidate["Config"]["Labels"][sentinel] = sentinel
        for key in ["Image", "User", "WorkingDir"]:
            candidate["Config"][key] = sentinel
        candidate["Config"]["Entrypoint"] = [sentinel]
        candidate["HostConfig"]["Binds"] = [sentinel]
        candidate["HostConfig"]["Tmpfs"][sentinel] = sentinel
        candidate["HostConfig"]["LogConfig"]["Config"]["max-size"] = sentinel
        candidate["Mounts"] = [{"Source": sentinel}]
        candidate["Path"] = sentinel
        result = p.inspect_projection(candidate, RUN, PROFILE, "START_PROFILE")
        raw = json.dumps(result)
        self.assertNotIn(sentinel, raw)
        self.assertFalse(result["Env"]["matches_expected"])
        self.assertLessEqual(len(raw), 16384)

    def test_diagnostics_preserve_absent_null_empty_and_numeric_types(self):
        candidate = row()
        candidate["HostConfig"]["Mounts"] = None
        projection = p.inspect_projection(candidate, RUN, PROFILE, "START_PROFILE")
        self.assertIsNone(projection["HostConfig_Mounts"]["value"])
        self.assertEqual(projection["Mounts"]["value"], [])
        del candidate["HostConfig"]["Init"]
        candidate["HostConfig"]["Memory"] = 0
        projection = p.inspect_projection(candidate, RUN, PROFILE, "START_PROFILE")
        self.assertEqual(projection["HostConfig"]["Init"], {"present": False})
        self.assertEqual(projection["HostConfig"]["Memory"]["value"], 0)
        self.assertFalse(projection["HostConfig"]["Memory"]["matches_expected"])

    def test_ack_is_durable_before_first_inspect(self):
        state = ProbeTests().state()
        saved = []

        def save():
            saved.append(copy.deepcopy(state))

        def runner(argv, **_options):
            op = argv[5]
            if op == "container":
                return Result()
            if op == "create":
                return Result((CID + "\n").encode())
            self.assertEqual(op, "inspect")
            self.assertEqual(saved[-1]["create_ack"]["cid"], CID)
            self.assertIsNone(saved[-1]["legacy_reservation"]["cid"])
            return Result(json.dumps([row()]).encode())

        client = p.make_client(
            LEGACY,
            LINUX,
            None,
            Path("/fresh"),
            state,
            save,
            PROFILE,
            runner=runner,
            clock=lambda: 1,
        )
        self.assertEqual(p.reserve_owned(client, LEGACY, state, save), CID)
        self.assertEqual(state["legacy_reservation"]["cid"], CID)

    def test_foreign_inspect_keeps_unknown_across_actual_wrappers(self):
        state = acknowledged()
        state["legacy_reservation"]["outcome"] = "unknown"
        state["legacy_reservation"]["cid"] = None
        calls = []

        def runner(argv, **_options):
            op = argv[5]
            calls.append(op)
            if op == "container":
                return Result((CID + "\n").encode())
            self.assertEqual(op, "inspect")
            candidate = row()
            candidate["Config"]["Labels"] = {p.LABEL: "foreign"}
            return Result(json.dumps([candidate]).encode())

        client = p.make_client(
            LEGACY,
            LINUX,
            None,
            Path("/fresh"),
            state,
            lambda: None,
            PROFILE,
            runner=runner,
            clock=lambda: 1,
        )
        client.cleaning = True
        for _ in range(2):
            self.assertFalse(p.reconcile_owned(client, LEGACY, state, lambda: None)["released"])
            self.assertEqual(state["legacy_reservation"]["outcome"], "unknown")
        self.assertFalse(set(calls) & {"rm", "stop", "start"})
