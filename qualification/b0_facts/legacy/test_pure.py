"""No main, subprocess, Docker, Node, network, package code or PG is executed."""

import copy
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("b0_stage0_controller", ROOT / "controller.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
CID = "c" * 64


class FakeDocker:
    def __init__(self, state, fault=None):
        self.state, self.fault, self.rows, self.removed = state, fault, {}, []

    def named(self, name):
        if self.fault == "inaccessible":
            raise TimeoutError
        return [cid for cid, row in self.rows.items() if row["Name"] == "/" + name]

    def inspect(self, cid):
        return self.rows[cid]

    def command(self, *arguments):
        assert arguments[0] == "create"
        assert self.state["create"]["attempted"] and self.state["create"]["outcome"] == "pending"
        if self.fault != "late-create":
            self.materialize()
        if self.fault in ("lost-response", "late-create"):
            raise TimeoutError
        return 0, CID.encode(), b""

    def materialize(self):
        reservation = self.state["create"]
        self.rows[CID] = {
            "Id": CID,
            "Name": "/" + reservation["name"],
            "Run": reservation["run"],
            "Image": reservation["image_config"],
            "User": reservation["user"],
            "Running": False,
            "ExitCode": 42,
            "OOMKilled": False,
        }

    def remove(self, cid, running):
        self.removed.append(cid)
        return self.rows.pop(cid)


class Stage0PureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="b0-stage0-pure-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = {
            "run": "pamolive-b0-pre-" + "a" * 32,
            "image_config": "sha256:" + "b" * 64,
            "user": "1001:1001",
            "pull": "ready",
            "create": None,
        }

    def source(self, pins=None):
        source = self.root / "source"
        source.mkdir()
        raw = (ROOT / "pins-stage0.json").read_bytes() if pins is None else pins
        (source / "pins-stage0.json").write_bytes(raw)
        (source / "stage0.cjs").write_bytes((ROOT / "stage0.cjs").read_bytes())
        rows = {
            name: {
                "bytes": (source / name).stat().st_size,
                "sha256": C.digest((source / name).read_bytes()),
            }
            for name in C.ASSETS
        }
        data = json.dumps(
            {"schema": "pamolive.b0-stage0-assets/2", "assets": rows, "authority": False}
        ).encode()
        (source / "assets-manifest.json").write_bytes(data)
        return source, C.digest(data)

    def test_duplicate_and_all_nonfinite_forms_are_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(C.Refusal):
                C.strict_json(raw)

    def test_oversize_refused_before_file_read_and_hardlink_refused(self):
        path = self.root / "oversize"
        path.write_bytes(b"x" * 9)
        with self.assertRaises(C.Refusal):
            C.regular_bytes(path, 8)
        linked = self.root / "linked"
        os.link(path, linked)
        with self.assertRaises(C.Refusal):
            C.regular_bytes(linked, 16)

    def test_bad_manifest_hash_precedes_json_parser(self):
        source, _ = self.source()
        (source / "assets-manifest.json").write_bytes(b"{not-json")
        with patch.object(C, "strict_json", side_effect=AssertionError("must not parse")):
            with self.assertRaisesRegex(C.Refusal, "MANIFEST_CHANGED"):
                C.verified_assets(source, "0" * 64)

    def test_pins_hash_precedes_interpretation_same_buffer(self):
        source, sha = self.source()
        (source / "pins-stage0.json").write_bytes(b"{not-json")
        with self.assertRaisesRegex(C.Refusal, "ASSET_CHANGED"):
            C.verified_assets(source, sha)

    def test_unknown_pins_and_bool_budget_are_refused(self):
        for name, value in (("extra", "unknown"), ("memory_MiB", True)):
            with self.subTest(name=name):
                temporary = self.root / name
                temporary.mkdir()
                original = self.root
                self.root = temporary
                pins = json.loads((ROOT / "pins-stage0.json").read_bytes())
                pins[name] = value
                source, sha = self.source(json.dumps(pins).encode())
                self.root = original
                with self.assertRaises(C.Refusal):
                    C.verified_assets(source, sha)

    def test_extra_source_git_is_not_exported_and_extra_spool_is_refused(self):
        source, sha = self.source()
        (source / ".git").write_text("unrelated source data")
        _, buffers = C.verified_assets(source, sha)
        work = self.root / "work"
        work.mkdir()
        target = C.spool(work, buffers)
        target.chmod(0o700)
        self.assertEqual(set(path.name for path in target.iterdir()), set(C.ASSETS))
        (target / ".git").write_text("extra")
        with self.assertRaisesRegex(C.Refusal, "SPOOL_NOT_CLOSED"):
            C.check_spool(target, buffers)

    def test_manifest_assets_are_exactly_two(self):
        source, _ = self.source()
        value = json.loads((source / "assets-manifest.json").read_bytes())
        value["assets"][".git"] = {"bytes": 1, "sha256": "0" * 64}
        raw = json.dumps(value).encode()
        (source / "assets-manifest.json").write_bytes(raw)
        with self.assertRaisesRegex(C.Refusal, "JSON_SCHEMA"):
            C.verified_assets(source, C.digest(raw))

    def test_create_lost_reply_recovers_and_removes_exact_owned_object(self):
        client, saved = FakeDocker(self.state, "lost-response"), []

        def save():
            saved.append(copy.deepcopy(self.state))

        with self.assertRaises(TimeoutError):
            C.reserve_create(client, self.state, save, [])
        self.assertIsNone(self.state["create"]["cid"])
        self.assertTrue(any(item["create"]["outcome"] == "pending" for item in saved))
        result = C.reconcile(client, self.state, save)
        self.assertTrue(result["released"])
        self.assertEqual(client.removed, [CID])

    def test_late_create_or_inaccessible_is_never_reported_released(self):
        client = FakeDocker(self.state, "late-create")
        with self.assertRaises(TimeoutError):
            C.reserve_create(client, self.state, lambda: None, [])
        self.assertFalse(C.reconcile(client, self.state, lambda: None)["released"])
        client.fault = "inaccessible"
        self.assertFalse(C.reconcile(client, self.state, lambda: None)["released"])

    def test_wrong_owner_never_removed(self):
        client = FakeDocker(self.state, "lost-response")
        with self.assertRaises(TimeoutError):
            C.reserve_create(client, self.state, lambda: None, [])
        client.rows[CID]["Run"] = "another-owner"
        self.assertFalse(C.reconcile(client, self.state, lambda: None)["released"])
        self.assertEqual(client.removed, [])

    def test_unknown_create_absence_can_be_reconciled_later(self):
        client = FakeDocker(self.state, "late-create")
        with self.assertRaises(TimeoutError):
            C.reserve_create(client, self.state, lambda: None, [])
        self.assertFalse(C.reconcile(client, self.state, lambda: None)["released"])
        client.fault = None
        # Original daemon request materializes; this is not a second create request.
        client.materialize()
        self.assertTrue(C.reconcile(client, self.state, lambda: None)["released"])

    def test_certutil_missing_preserves_unobserved_null(self):
        pins = json.loads((ROOT / "pins-stage0.json").read_bytes())
        value = {
            "code": "B0_PRE_CERTUTIL_MISSING",
            "ok": False,
            "authority": False,
            "nodeVersion": "v26.0.0",
            "browserVersion": None,
            "certutilPresent": False,
            "certutilFunctional": None,
            "nssEmpty": None,
            "browserPresent": None,
            "nonroot": True,
            "rootReadOnly": True,
            "capsZero": True,
            "noNewPrivs": True,
        }
        self.assertIsNone(C.validate_evidence(value, pins)["browserPresent"])
        value["browserPresent"] = False
        with self.assertRaisesRegex(C.Refusal, "UNOBSERVED_MISREPORTED"):
            C.validate_evidence(value, pins)

    def test_actual_docker_store_filesystem_measured_and_low_free_refused(self):
        client = SimpleNamespace(
            info=lambda: {
                "DockerRootDir": "/daemon/store",
                "Driver": "overlay2",
                "DriverStatus": [],
            }
        )
        seen, observation = [], {}

        def free(path):
            seen.append(path)
            return SimpleNamespace(free=9 * 1024**3)

        C.storage_observation(client, 8192, observation, lambda _: SimpleNamespace(st_dev=91), free)
        self.assertEqual(seen, ["/daemon/store"])
        self.assertEqual(observation["filesystems"][0]["device"], 91)
        self.assertFalse(observation["hard_disk_quota_enforced"])
        with self.assertRaisesRegex(C.Refusal, "DISK_INSUFFICIENT"):
            C.storage_observation(
                client,
                8192,
                {},
                lambda _: SimpleNamespace(st_dev=91),
                lambda _: SimpleNamespace(free=1024),
            )

    def test_containerd_unknown_root_refuses_before_acquisition(self):
        client = SimpleNamespace(
            info=lambda: {
                "DockerRootDir": "/daemon/store",
                "Driver": "overlayfs",
                "DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]],
            }
        )
        observation = {}
        with self.assertRaisesRegex(C.Refusal, "CONTAINERD_STORAGE_UNPROVEN"):
            C.storage_observation(
                client,
                8192,
                observation,
                lambda _: SimpleNamespace(st_dev=91),
                lambda _: SimpleNamespace(free=9 * 1024**3),
            )
        self.assertEqual(observation["content_store_type"], "containerd")
        self.assertIsNone(observation["containerd_measurement"])

    def test_pull_is_devnull_bounded_and_timeout_is_not_retried(self):
        client = C.LocalDocker(self.root)
        pins = json.loads((ROOT / "pins-stage0.json").read_bytes())
        with patch.object(
            C.subprocess, "run", side_effect=subprocess.TimeoutExpired("fake", 480)
        ) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                client.pull(pins)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["timeout"], 480)

    def test_unknown_pull_does_not_become_released_due_to_no_containers(self):
        state = {"pull": "unknown"}
        report = C.public_report(
            self.root,
            state,
            "B0_PRE_PULL_DAEMON_OUTCOME_UNKNOWN",
            False,
            {"status": "not_created", "released": True},
        )
        self.assertFalse(report["resources_released"])
        self.assertFalse(report["TLS_observed"])

    def test_cleanup_preserves_original_failed_phase(self):
        source, sha = self.source()
        pins, buffers = C.verified_assets(source, sha)
        work = self.root / "pamolive-b0-pre-cleanup"
        work.mkdir()
        C.spool(work, buffers)
        state = {
            **self.state,
            "image_config": pins["image_config"],
            "pins_sha256": C.digest(buffers["pins-stage0.json"]),
        }
        C.atomic(work / "state.json", state)
        C.atomic(work / "public-report.json", {"code": "B0_PRE_CERTUTIL_MISSING", "ok": False})
        with (
            patch.object(C, "SOURCE", source),
            patch.object(C, "ci_guard"),
            patch.object(C.os, "getuid", return_value=1001, create=True),
            patch.object(C.os, "getgid", return_value=1001, create=True),
            patch.object(C, "LocalDocker", return_value=FakeDocker(state)),
            patch.object(
                C.sys,
                "argv",
                ["controller", "cleanup", "--work-dir", str(work), "--manifest-sha256", sha],
            ),
            redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as exit_status,
        ):
            C.main()
        self.assertEqual(exit_status.exception.code, 42)
        report = json.loads((work / "public-report.json").read_bytes())
        self.assertEqual(report["code"], "B0_PRE_CERTUTIL_MISSING")
        self.assertFalse(report["ok"])

    def test_control_output_is_bounded_during_drain_and_client_killed(self):
        class Pipe:
            def fileno(self):
                return 5

            def close(self):
                pass

        class Process:
            stdout, stderr = Pipe(), Pipe()
            killed = False

            def poll(self):
                return 0 if self.killed else None

            def kill(self):
                self.killed = True

            def wait(self, **_):
                return 0

        class Selector:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def register(self, *_):
                pass

            def get_map(self):
                return {5: True}

            def select(self, _):
                return [(SimpleNamespace(fileobj=process.stdout, data=1), None)]

        process = Process()
        with (
            patch.object(C.subprocess, "Popen", return_value=process),
            patch.object(C.selectors, "DefaultSelector", return_value=Selector()),
            patch.object(C.os, "read", side_effect=lambda _, size: b"x" * size) as read,
            self.assertRaisesRegex(C.Refusal, "OUTPUT_BUDGET"),
        ):
            C.LocalDocker(self.root).command("pure-fake")
        self.assertTrue(process.killed)
        self.assertEqual(sum(call.args[1] for call in read.call_args_list), 65537)


if __name__ == "__main__":
    unittest.main()
