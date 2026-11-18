"""True reserve/reconcile/inspect/H1 paths under a fake daemon/IO boundary."""

import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import host_seam
import schema
import workload_host
from support import ROOT, load, sha
from test_seam import ENTRY, Result, profile

P2, LEGACY = load("controller.py"), load("legacy_controller.py")


class HostTests(unittest.TestCase):
    def scenario(self, *, appear=True):
        work, row, env = profile()
        state = {
            "run": "pamolive-p2-installed-" + "a" * 32,
            "image_config": "sha256:" + "b" * 64,
            "user": "1000:1000",
            "IO": [],
            "IO_total": 0,
            "IO_uncertain": False,
        }
        row.update(
            Id="c" * 64,
            Name="/" + state["run"] + "-stage0",
            Image=state["image_config"],
            Run=state["run"],
            User=state["user"],
        )
        daemon = {"exists": False}
        calls = []

        def invoke(command, **limits):
            args = command[1:]
            calls.append(args)
            result = Result()
            result.stdout = result.stderr = b""
            if args[:2] == ["container", "ls"]:
                self.assertEqual(
                    args[args.index("--filter") + 1], "name=^/" + state["run"] + "-stage0$"
                )
                self.assertFalse(any("label=" in value for value in args))
                result.stdout = (row["Id"] + "\n").encode() if daemon["exists"] else b""
            elif args[0] == "create":
                self.assertEqual(args[4], P2.LABEL + "=" + state["run"])
                self.assertNotIn(LEGACY.LABEL + "=" + state["run"], args)
                daemon["exists"] = appear
                result.returncode, result.reason = 1, "timeout"
            elif args[0] == "inspect":
                template = args[-1]
                self.assertIn('"' + P2.LABEL + '"', template)
                self.assertNotIn('"' + LEGACY.LABEL + '"', template)
                result.stdout = json.dumps(row).encode()
            elif args[0] == "rm":
                self.assertEqual(args[1:], [row["Id"]])
                daemon["exists"] = False
            else:
                self.fail("unexpected fake command")
            return result

        parent = P2.docker_class(LEGACY, SimpleNamespace(run_capped=invoke))
        with patch.object(host_seam, "client_class", return_value=parent):
            cls = workload_host.client_class(ENTRY, sha(ENTRY))
        client = object.__new__(cls)
        client.work, client.prefix, client.env, client.state = work, ["FAKE_CLI"], {}, state
        client.entry_raw, client.expected_environment = ENTRY, env
        client.cleaning, client.work_deadline, client.cleanup_deadline = False, 200, 260
        return client, state, calls

    def test_lost_create_reconciles_same_owned_P2_label_and_exact_name_then_removes(self):
        client, state, calls = self.scenario()
        with patch.object(P2.time, "monotonic", return_value=100), patch.object(P2, "persist_io"):
            with self.assertRaises(P2.Refusal):
                LEGACY.reserve_create(client, state, lambda: None, ["--pull", "never"])
            self.assertEqual(state["create"]["outcome"], "unknown")
            result = LEGACY.reconcile(client, state, lambda: None)
        self.assertTrue(result["released"])
        self.assertEqual(state["create"]["outcome"], "removed")
        self.assertEqual(LEGACY.LABEL, "pamolive.b0pre.run")
        self.assertEqual(sum(args[0] == "rm" for args in calls), 1)

    def test_lost_create_absence_stays_unknown_and_zero_or_two_oldmarkers_refuse(self):
        client, state, calls = self.scenario(appear=False)
        with patch.object(P2.time, "monotonic", return_value=100), patch.object(P2, "persist_io"):
            with self.assertRaises(P2.Refusal):
                LEGACY.reserve_create(client, state, lambda: None, ["--pull", "never"])
            self.assertFalse(LEGACY.reconcile(client, state, lambda: None)["released"])
            before = len(calls)
            for args in (
                ("create", "--name", "n", "--label", "WRONG", "image"),
                (
                    "create",
                    "--name",
                    "n",
                    "--label",
                    LEGACY.LABEL + "=" + state["run"],
                    "--label",
                    LEGACY.LABEL + "=" + state["run"],
                    "image",
                ),
            ):
                with self.assertRaises(ValueError):
                    client.command(*args)
            self.assertEqual(len(calls), before)
        self.assertFalse(any(args[0] == "rm" for args in calls))

    def test_cleanup_attempted_despite_journal_failure_global_release_unknown(self):
        work, _, _ = profile()
        bindings = dict.fromkeys(
            ("expected_source", "expected_input", "expected_sql", "expected_materials"), "a" * 64
        )
        state = {
            "type": host_seam.STATE,
            "phase": host_seam.PHASE,
            "pull": "ready",
            "started": False,
            "IO": [],
            "IO_total": 0,
            "IO_uncertain": False,
            "bindings": bindings,
            "image_config": (
                "sha256:78976a69c067520ef8be34cde307ef9f6fea6dcefa50edb57039773d241ca0db"
            ),
            "user": "1000:1000",
        }

        class Client:
            def __init__(self, *_args):
                self.cleaning = False

            def command(self, *_args, **_kwargs):
                raise ValueError("PUBLIC_SIMULATED_PS_FAILURE")

        with (
            patch.object(P2, "ci_guard"),
            patch.object(P2, "check_inputs"),
            patch.object(P2, "atomic", side_effect=OSError("PUBLIC_IO")),
            patch.object(LEGACY, "reconcile", return_value={"released": True}) as cleanup,
        ):
            result = workload_host.run_owned(
                work,
                json.loads((ROOT / "s0-pins.json").read_bytes()),
                state,
                ENTRY,
                sha(ENTRY),
                bindings=bindings,
                factory=Client,
            )
        self.assertEqual(cleanup.call_count, 1)
        self.assertTrue(result["container_released"])
        self.assertFalse(result["resources_released"])
        self.assertFalse(result["ok"])

    def test_pull_timeout_is_unknown_original_preserved_and_no_retry(self):
        work, _, _ = profile()
        pins = json.loads((ROOT / "s0-pins.json").read_bytes())
        state = {
            "type": host_seam.STATE,
            "phase": host_seam.PHASE,
            "image_config": pins["image_config"],
            "user": "1000:1000",
            "pull": "not_attempted",
            "started": False,
            "IO": [],
            "IO_total": 0,
            "IO_uncertain": False,
        }
        original = TimeoutError("PUBLIC_TIMEOUT")
        pulls = []

        class Client:
            def __init__(self, *_args):
                pass

            def command(self, *_args, **_kwargs):
                return 0, b"", b""

            def pull(self, _pins):
                pulls.append(True)
                raise original

        with (
            patch.object(P2, "ci_guard"),
            patch.object(P2, "check_inputs"),
            patch.object(P2, "atomic"),
            patch.object(LEGACY, "storage_observation"),
            patch.object(LEGACY, "memory_guard"),
        ):
            with self.assertRaises(TimeoutError) as caught:
                workload_host.pull_owned(work, pins, state, ENTRY, sha(ENTRY), factory=Client)
            self.assertIs(caught.exception, original)
            self.assertEqual(state["pull"], "unknown")
            with self.assertRaises(ValueError):
                workload_host.pull_owned(work, pins, state, ENTRY, sha(ENTRY), factory=Client)
        self.assertEqual(len(pulls), 1)

    def test_repeated_cleanup_keeps_prior_unknown_IO_and_confirmed_exit_only(self):
        work, _, _ = profile()
        pins = json.loads((ROOT / "s0-pins.json").read_bytes())
        state = {
            "type": host_seam.STATE,
            "phase": host_seam.PHASE,
            "image_config": pins["image_config"],
            "user": "1000:1000",
            "pull": "ready",
            "IO": [],
            "IO_total": 0,
            "IO_uncertain": True,
            "failure": "ORIGINAL_FAILURE",
            "create": {"outcome": "removed"},
            "cleanup": {"released": True, "exit_code": 137, "OOMKilled": False},
        }

        class Client:
            def __init__(self, *_args):
                pass

        with (
            patch.object(P2, "ci_guard"),
            patch.object(P2, "atomic"),
            patch.object(LEGACY, "reconcile", return_value={"released": True}),
        ):
            for _ in range(2):
                result = workload_host.cleanup_owned(
                    work, pins, state, ENTRY, sha(ENTRY), factory=Client
                )
                self.assertTrue(result["container_released"])
                self.assertFalse(result["resources_released"])
                self.assertEqual(result["failure"], "ORIGINAL_FAILURE")
                self.assertEqual(state["cleanup"]["exit_code"], 137)
                self.assertIs(state["cleanup"]["OOMKilled"], False)

    def test_actual_run_owned_requires_exit0_and_OOMfalse_even_when_resources_released(self):
        import wheel_transfer
        import workload_schema
        from test_phase2_orchestration import OrchestrationTests

        fixture = OrchestrationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        report = fixture.run_workload()
        bindings = fixture.bindings(report)
        packet = workload_schema.packet(report, **bindings)
        pins = json.loads((ROOT / "s0-pins.json").read_bytes())
        work, _, _ = profile()

        class Client:
            def __init__(self, *_args):
                pass

            def command(self, *args, **_kwargs):
                return (0, raw, b"") if args[0] == "start" else (0, b"", b"")

            def image(self, _pins):
                pass

            def inspect(self, _cid):
                return {"Running": False}

        for exit_code, oom, transfer, expected in (
            (0, False, False, True),
            (137, False, False, False),
            (0, True, False, False),
            (None, False, False, False),
            (False, False, False, False),
            (0, False, True, True),
            (137, False, True, False),
            (0, True, True, False),
        ):
            raw = (
                wheel_transfer.from_work(fixture.work, packet, bindings=bindings)
                if transfer
                else schema.encode(packet, schema.MAX_PACKET)
            )
            state = {
                "type": host_seam.STATE,
                "phase": host_seam.PHASE,
                "image_config": pins["image_config"],
                "user": "1000:1000",
                "pull": "ready",
                "started": False,
                "transfer_verified_wheels": transfer,
                "bindings": bindings,
                "failure": None,
                "IO": [{"operation": "pull", **Result().facts()}],
                "IO_total": 1,
                "IO_uncertain": False,
                "create": {},  # reserve_create is mocked; its owned state exists in real flow.
            }
            with (
                patch.object(P2, "ci_guard"),
                patch.object(P2, "check_inputs"),
                patch.object(P2, "atomic"),
                patch.object(LEGACY, "storage_observation"),
                patch.object(LEGACY, "memory_guard"),
                patch.object(LEGACY, "reserve_create", return_value="c" * 64),
                patch.object(LEGACY, "owns", return_value=True),
                patch.object(wheel_transfer, "keep_private") as persist,
                patch.object(
                    LEGACY,
                    "reconcile",
                    return_value={"released": True, "exit_code": exit_code, "OOMKilled": oom},
                ),
            ):
                result = workload_host.run_owned(
                    work,
                    pins,
                    state,
                    ENTRY,
                    sha(ENTRY),
                    bindings=bindings,
                    factory=Client,
                )
            self.assertTrue(result["resources_released"])
            self.assertIs(result["ok"], expected)
            if transfer and expected:
                persist.assert_called_once_with(work, raw)
            else:
                persist.assert_not_called()
