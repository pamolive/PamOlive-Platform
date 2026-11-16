"""Real owner/view/lease seams with a closed fake runner, never an Engine."""

import copy
import io
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import owner as o
import probe as p
from test_probe import (
    CID,
    HERE,
    LEGACY,
    LINUX,
    PROFILE,
    RUN,
    ProbeTests,
    Result,
    row,
    store,
    version,
)


def image():
    return {
        "Id": p.MANIFEST,
        "Descriptor": {
            "digest": p.MANIFEST,
            "size": 3628,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
        },
        "RepoDigests": ["postgres@" + p.MANIFEST],
        "Os": "linux",
        "Architecture": "amd64",
        "Config": json.loads((HERE / "data/config.json").read_bytes())["config"],
        "RootFS": {"Type": "layers", "Layers": PROFILE["rootfs_diff_ids"]},
    }


class OwnerTests(unittest.TestCase):
    def test_actual_wrappers_lost_create_and_two_reconciles_keep_canonical_unknown(self):
        state = ProbeTests().state()
        saved = []

        def save():
            saved.append(copy.deepcopy(state))

        def runner(argv, **_options):
            if "create" in argv:
                self.assertEqual(saved[-1]["legacy_reservation"]["outcome"], "pending")
                self.assertEqual(saved[-1]["IO"][-1]["reason"], "pending")
                raise TimeoutError("SYNTHETIC lost response")
            return Result()

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
        with self.assertRaises(TimeoutError):
            p.reserve_owned(client, LEGACY, state, save)
        client.cleaning = True
        for _ in range(2):
            self.assertFalse(p.reconcile_owned(client, LEGACY, state, save)["released"])
            self.assertEqual(state["legacy_reservation"]["outcome"], "unknown")
            self.assertIsNone(state["legacy_reservation"]["cid"])
            self.assertTrue(state["IO_uncertain"])
            self.assertEqual(state["image_config"], p.CONFIG)
            self.assertEqual(state["image_manifest"], p.MANIFEST)
            self.assertEqual(state["legacy_reservation"]["image_config"], p.MANIFEST)
        self.assertEqual(saved[-1]["legacy_reservation"]["outcome"], "unknown")

    def test_legacy_config_alias_and_mutated_record_are_refused(self):
        state = ProbeTests().state()
        state["legacy_reservation"] = {"image_config": p.CONFIG}
        with self.assertRaisesRegex(p.Refusal, "LEGACY_MANIFEST_BINDING"):
            p.legacy_reservation_view(state)
        state = ProbeTests().state()
        state["image_manifest"] = p.CONFIG
        with self.assertRaises(p.Refusal):
            p.legacy_reservation_view(state)

    def test_public_bytes_tamper_and_classic_image_id_refuse(self):
        buffers = {
            name: (HERE / name).read_bytes()
            for name in (
                "data/amd64-manifest.json",
                "data/config.json",
                "data/profile.json",
            )
        }
        p.verify_public_binding(buffers)
        for name in ("data/amd64-manifest.json", "data/config.json"):
            bad = dict(buffers, **{name: b"X" + buffers[name][1:]})
            with self.subTest(name=name), self.assertRaises(p.Refusal):
                p.verify_public_binding(bad)
        candidate = image()
        candidate["Id"] = p.CONFIG
        with self.assertRaises(p.Refusal):
            p.verify_image(candidate, PROFILE)
        candidate = row()
        candidate["Image"] = p.CONFIG
        with self.assertRaises(p.Refusal):
            p.inspect_profile(candidate, RUN, PROFILE)

    def test_compressed_layers_and_unexpected_image_config_refuse(self):
        candidate = image()
        manifest = json.loads((HERE / "data/amd64-manifest.json").read_bytes())
        candidate["RootFS"]["Layers"] = [v["digest"] for v in manifest["layers"]]
        with self.assertRaises(p.Refusal):
            p.verify_image(candidate, PROFILE)
        candidate = image()
        candidate["Config"]["StopSignal"] = "SIGTERM"
        with self.assertRaises(p.Refusal):
            p.verify_image(candidate, PROFILE)

    def test_closed_command_gate_refuses_exec_pull_foreign_mutation_or_extra_labels(self):
        state = ProbeTests().state()
        state.update(metadata_verified=True, owner_cleaning=False)
        state["legacy_reservation"] = {
            "name": RUN + "-stage0",
            "run": RUN,
            "user": "0:0",
            "image_config": p.MANIFEST,
            "cid": CID,
            "attempted": True,
            "outcome": "confirmed",
        }
        o.command_allowed(p, state, ["image", "inspect", p.IMAGE])
        for args in (
            ["exec", CID, "sh"],
            ["pull", p.IMAGE],
            ["rm", "d" * 64],
            ["rm", "--force", CID],
            ["start", "--attach", CID],
            ["create", "--name", RUN + "-stage0", "--label", "foreign=yes", *p.arguments()],
        ):
            with self.subTest(args=args[:2]), self.assertRaises(ValueError):
                o.command_allowed(p, state, args)
        state.update(owner_cleaning=True)
        o.command_allowed(p, state, ["rm", CID])

    def test_checked_runner_exact_env_caps_and_cli_pre_post(self):
        state = ProbeTests().state()
        work = Path("/fresh")
        argv = [
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
            str(work / "docker-config"),
            "version",
            "--format",
            p.VERSION_TEMPLATE,
        ]
        options = {
            "cwd": str(work),
            "env": {
                "PATH": "/usr/bin:/bin",
                "HOME": str(work / "home"),
                "LANG": "C",
                "LC_ALL": "C",
                "DOCKER_API_VERSION": "1.52",
            },
            "timeout": 15,
            "stdout_cap": 32768,
            "stderr_cap": 4096,
        }
        events = []
        bounded = types.SimpleNamespace(
            run_capped=lambda *_a, **_k: events.append("runner") or Result()
        )
        runner = o.checked_runner(p, state, work, bounded)
        with (
            patch.object(o, "verify_cli", side_effect=lambda: events.append("verified")),
            patch.object(o.time, "monotonic", return_value=1),
        ):
            runner(argv, **copy.deepcopy(options))
            self.assertEqual(events, ["verified", "runner", "verified"])
            bad = copy.deepcopy(options)
            bad["env"]["HTTP_PROXY"] = "SYNTHETIC"
            with self.assertRaises(ValueError):
                runner(argv, **bad)
        self.assertEqual(events, ["verified", "runner", "verified"])

    def test_cli_fd_owner_hash_model_without_reading_real_cli(self):
        binary = b"SYNTHETIC CLI FILE NEVER EXECUTED"
        expected = dict(o.CLI_FACTS, bytes=len(binary), sha256=o.sha(binary))
        info = types.SimpleNamespace(
            st_mode=stat.S_IFREG | 0o755,
            st_nlink=1,
            st_uid=0,
            st_gid=0,
            st_size=len(binary),
            st_dev=1,
            st_ino=2,
            st_mtime_ns=1,
            st_ctime_ns=1,
        )
        directory = types.SimpleNamespace(lstat=lambda: types.SimpleNamespace(st_mode=stat.S_IFDIR))
        node = types.SimpleNamespace(parents=[directory], lstat=lambda: copy.copy(info))
        with (
            patch.object(o, "CLI", node),
            patch.object(o, "CLI_FACTS", expected),
            patch.object(o.os, "open", return_value=7),
            patch.object(o.os, "fstat", return_value=info),
            patch.object(o.os, "close"),
            patch.object(o.os, "fdopen", return_value=io.BytesIO(binary)),
        ):
            o.verify_cli()
        for key, value in (("st_uid", 1), ("st_gid", 1), ("st_nlink", 2), ("st_ino", 3)):
            bad = copy.copy(info)
            setattr(bad, key, value)
            with (
                self.subTest(key=key),
                patch.object(o, "CLI", node),
                patch.object(o, "CLI_FACTS", expected),
                patch.object(o.os, "open", return_value=7),
                patch.object(o.os, "fstat", return_value=bad),
                patch.object(o.os, "close"),
                self.assertRaises(ValueError),
            ):
                o.verify_cli()

    def test_ci_guard_refuses_ambient_overrides_and_wrong_work(self):
        with tempfile.TemporaryDirectory(prefix="pamolive-getent-pure-") as directory:
            root = Path(directory).resolve()
            self.assertTrue(root.is_relative_to(Path(tempfile.gettempdir()).resolve()))
            env = {
                "GITHUB_ACTIONS": "true",
                "CI": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_RUN_ID": "123",
                "GITHUB_RUN_ATTEMPT": "1",
                "RUNNER_TEMP": str(root),
            }
            with (
                patch.object(o.sys, "platform", "linux"),
                patch.object(o.os, "getuid", return_value=1001, create=True),
                patch.object(o.os, "getgid", return_value=1001, create=True),
                patch.dict(os.environ, env, clear=True),
            ):
                o.ci_guard(root / "pamolive-pg-identity-123-1")
                for name in ("DOCKER_HOST", "DOCKER_API_VERSION", "HTTPS_PROXY", "PYTHONPATH"):
                    with (
                        self.subTest(name=name),
                        patch.dict(os.environ, {name: ""}),
                        self.assertRaises(ValueError),
                    ):
                        o.ci_guard(root / "pamolive-pg-identity-123-1")
                with self.assertRaises(ValueError):
                    o.ci_guard(root / "different")

    def test_real_received_lease_body_durable_and_foreign_token_retained(self):
        with tempfile.TemporaryDirectory(prefix="pamolive-getent-pure-") as directory:
            root = Path(directory).resolve()
            self.assertTrue(root.is_relative_to(Path(tempfile.gettempdir()).resolve()))
            state, saved = ProbeTests().state(), []
            lease = o.received_lease(
                (HERE / "helpers/lease_support.py").read_bytes(),
                p,
                root / "synthetic.lock",
                state,
                lambda: saved.append(copy.deepcopy(state)),
            )
            lease.acquire()
            self.assertTrue(state["lease"]["held"])
            self.assertFalse(saved[0]["lease"]["held"])
            (root / "synthetic.lock").write_bytes(b"SYNTHETIC FOREIGN TOKEN")
            self.assertFalse(lease.release(True)["released"])
            self.assertTrue(state["lease"]["held"])
            self.assertEqual((root / "synthetic.lock").read_bytes(), b"SYNTHETIC FOREIGN TOKEN")

    def test_cli_owner_full_lifecycle_and_two_real_unknown_recoveries(self):
        # Only helper Popen is replaced. Owner capture, source compilation,
        # journal, view wrappers, received Lease body and exact argv gate are real.
        asset_sha = o.sha((HERE / "assets.json").read_bytes())
        original_load = o.load
        for lost in (False, True):
            with (
                self.subTest(lost=lost),
                tempfile.TemporaryDirectory(prefix="pamolive-getent-pure-") as directory,
            ):
                root = Path(directory).resolve()
                self.assertTrue(root.is_relative_to(Path(tempfile.gettempdir()).resolve()))
                work = root / "pamolive-pg-identity-123-1"
                created, removed, calls = False, False, []

                def fake(argv, **_options):
                    nonlocal created, removed
                    args = argv[5:]
                    calls.append(args)
                    snapshot = json.loads((work / "state.json").read_bytes())
                    self.assertEqual(snapshot["image_config"], p.CONFIG)
                    self.assertEqual(snapshot["image_manifest"], p.MANIFEST)
                    self.assertEqual(snapshot["IO"][-1]["reason"], "pending")
                    run = snapshot["run"]
                    if args[0] == "version":
                        return Result(json.dumps(version()).encode())
                    if args[0] == "info":
                        return Result(json.dumps(store()).encode())
                    if args[:2] == ["image", "inspect"]:
                        return Result(json.dumps([image()]).encode())
                    if args[0] == "container":
                        return Result((CID + "\n").encode() if created and not removed else b"")
                    if args[0] == "create":
                        self.assertEqual(snapshot["legacy_reservation"]["outcome"], "pending")
                        self.assertEqual(snapshot["legacy_reservation"]["image_config"], p.MANIFEST)
                        if lost:
                            raise TimeoutError("SYNTHETIC lost create response")
                        created = True
                        return Result((CID + "\n").encode())
                    if args[0] == "inspect":
                        value = row()
                        value["Name"], value["Config"]["Labels"] = (
                            "/" + run + "-stage0",
                            {p.LABEL: run},
                        )
                        return Result(json.dumps([value]).encode())
                    if args[:2] == ["start", "--attach"]:
                        return Result(b"postgres:x:123:456:SYNTHETIC:/synthetic/home:/bin/sh\n")
                    self.assertEqual(args, ["rm", CID])
                    removed = True
                    return Result()

                def load(name, raw, filename):
                    if name == "_getent_bounded":
                        return types.SimpleNamespace(run_capped=fake)
                    return original_load(name, raw, filename)

                with (
                    patch.object(o, "ci_guard", return_value=root),
                    patch.object(o, "verify_cli"),
                    patch.object(o, "load", side_effect=load),
                    patch.object(
                        sys,
                        "argv",
                        ["owner.py", "run", "--assets-sha", asset_sha, "--work", str(work)],
                    ),
                    redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(o.main(), 42 if lost else 0)
                report = json.loads((work / "public-report.json").read_bytes())
                self.assertNotIn("SYNTHETIC:/synthetic", json.dumps(report))
                self.assertFalse(report["PGDATA_ownership_measured"])
                if not lost:
                    self.assertEqual(report["measurement"], {"uid": 123, "gid": 456})
                    self.assertTrue(report["resources_released"])
                    self.assertFalse((root / ".pamolive-public-pg-identity-ci.lock").exists())
                    continue
                self.assertIsNone(report["measurement"])
                for attempt in (1, 2):
                    with (
                        patch.object(o, "ci_guard", return_value=root),
                        patch.object(o, "verify_cli"),
                        patch.object(o, "load", side_effect=load),
                        patch.object(
                            sys,
                            "argv",
                            ["owner.py", "cleanup", "--assets-sha", asset_sha, "--work", str(work)],
                        ),
                        redirect_stdout(io.StringIO()),
                    ):
                        self.assertEqual(o.main(), 42)
                    snapshot = json.loads((work / "state.json").read_bytes())
                    self.assertTrue(snapshot["IO_uncertain"])
                    self.assertTrue(snapshot["lease"]["held"])
                    self.assertIsNone(snapshot["legacy_reservation"]["cid"])
                    self.assertEqual(snapshot["legacy_reservation"]["outcome"], "unknown")
                    cleanup = json.loads(
                        (work / f"cleanup-public-report-{attempt}.json").read_bytes()
                    )
                    self.assertFalse(cleanup["resources_released"])
                self.assertEqual(sum(args[0] == "create" for args in calls), 1)
                self.assertFalse(any(args[0] in {"start", "stop", "rm"} for args in calls))
