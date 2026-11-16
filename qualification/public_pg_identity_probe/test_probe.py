"""Pure tests only. No Engine process, lease file, network or PostgreSQL."""

import copy
import json
import types
import unittest
from pathlib import Path

import probe as p

HERE = Path(__file__).resolve().parent


def load(name, filename):
    module = types.ModuleType(name)
    module.__file__ = str(HERE / "helpers" / filename)
    exec(
        compile((HERE / "helpers" / filename).read_bytes(), module.__file__, "exec"),
        module.__dict__,
    )
    return module


LEGACY = load("w_pg_legacy", "legacy.py")
LINUX = load("w_pg_linux", "linux.py")
PROFILE = json.loads((HERE / "data/profile.json").read_bytes())
RUN = "w-pg-id-" + "b" * 32
CID = "c" * 64


def version():
    return {
        "client_version": "29.4.2",
        "client_api": "1.52",
        "client_os": "linux",
        "client_arch": "amd64",
        "server_version": "29.4.2",
        "server_api_min": "1.40",
        "server_api_max": "1.54",
        "server_os": "linux",
        "server_arch": "amd64",
    }


def store():
    return {
        "DockerRootDir": "/var/lib/docker",
        "Driver": "overlayfs",
        "DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]],
    }


def row():
    env = dict(PROFILE["declared_public_image_env"], LANG="C", LC_ALL="C")
    return {
        "Id": CID,
        "Name": "/" + RUN + "-stage0",
        "Image": p.MANIFEST,
        "Config": {
            "Image": p.IMAGE,
            "User": "0:0",
            "Entrypoint": ["/usr/bin/getent"],
            "Cmd": ["passwd", "postgres"],
            "Labels": {p.LABEL: RUN},
            "WorkingDir": "",
            "Tty": False,
            "OpenStdin": False,
            "Env": [key + "=" + value for key, value in env.items()],
        },
        "Path": "/usr/bin/getent",
        "Args": ["passwd", "postgres"],
        "HostConfig": copy.deepcopy(p.HOST),
        "Mounts": [],
        "State": {"Running": False, "OOMKilled": False, "ExitCode": 0},
    }


def facts(**changes):
    value = {
        "spawn_attempted": True,
        "pid": 123,
        "returncode": 0,
        "reason": None,
        "exception_type": None,
        "killed_owned_child": False,
        "owned_child_reaped": True,
        "drains_complete": True,
        "cleanup_exception_type": None,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }
    value.update(changes)
    return value


class Result:
    def __init__(self, raw=b"", code=0, **changes):
        self.stdout, self.stderr = raw, b""
        self.data = facts(
            stdout_bytes=len(raw),
            returncode=code,
            reason="nonzero_exit" if code else None,
            **changes,
        )
        self.__dict__.update(self.data)

    def facts(self):
        return copy.deepcopy(self.data)


class Lease:
    def __init__(self, busy=False):
        self.busy, self.calls = busy, []

    def acquire(self):
        self.calls.append("acquire")
        if self.busy:
            raise p.Refusal("BUSY")

    def release(self, safe):
        self.calls.append(("release", safe))
        return {"released": safe}


class ProbeTests(unittest.TestCase):
    def state(self):
        return {
            "run": RUN,
            "image_manifest": p.MANIFEST,
            "image_config": p.CONFIG,
            "user": "0:0",
            "IO": [],
            "IO_total": 0,
            "IO_uncertain": False,
            "started": False,
            "pull": "not_attempted",
            "work_deadline": 90,
            "cleanup_deadline": 120,
        }

    def client(self, runner, state=None):
        state = self.state() if state is None else state
        saves = []
        client = p.make_client(
            LEGACY,
            LINUX,
            None,
            Path("/fresh"),
            state,
            lambda: saves.append(copy.deepcopy(state)),
            PROFILE,
            runner=runner,
            clock=lambda: 1,
        )
        return client, state, saves

    def test_arguments_closed_public_probe(self):
        args = p.arguments()
        self.assertEqual(args[-3:], [p.IMAGE, "passwd", "postgres"])
        self.assertEqual(args[args.index("--entrypoint") + 1], "/usr/bin/getent")
        for flag, value in (
            ("--user", "0:0"),
            ("--network", "none"),
            ("--cpus", "0.10"),
            ("--memory", "64m"),
            ("--memory-swap", "64m"),
            ("--pids-limit", "16"),
        ):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertNotIn("--volume", args)
        self.assertNotIn("--mount", args)
        self.assertNotIn("--publish", args)
        self.assertEqual(args.count("--tmpfs"), 2)
        self.assertIn(p.PGDATA + ":" + p.TMPFS[p.PGDATA], args)
        self.assertTrue(all(value.startswith("ro,") for value in p.TMPFS.values()))

    def test_passwd_only_uid_gid_no_ownership(self):
        self.assertEqual(
            p.parse_passwd(b"postgres:x:123:456:PostgreSQL:/var/lib/postgresql:/bin/bash\n"),
            {"uid": 123, "gid": 456},
        )

    def test_passwd_refuses_shapes_budgets_and_noncanonical_numbers(self):
        good = b"postgres:x:123:456:G:/home:/bin/sh\n"
        for value in (
            None,
            "text",
            b"",
            b"x" * 4097,
            good + good,
            good.replace(b"\n", b"\r\n"),
            good[:-1],
            good.replace(b"postgres", b"root"),
            good.replace(b":x:", b":!:"),
            good.replace(b":123:", b":0:"),
            good.replace(b":123:", b":0123:"),
            good.replace(b":123:", b":4294967295:"),
            good.replace(b":123:", b":-1:"),
            good.replace(b":G:", b":G:extra:"),
            good.replace(b"/home", b"relative"),
            good.replace(b"G", b"\x00"),
        ):
            with self.subTest(value_type=type(value).__name__, size=len(value) if value else 0):
                with self.assertRaises(p.Refusal):
                    p.parse_passwd(value)

    def test_profile_exact_and_security_mutations(self):
        self.assertEqual(p.inspect_profile(row(), RUN, PROFILE)["User"], "0:0")
        changes = {
            "Memory": True,
            "MemorySwap": 128 * 1024**2,
            "CapAdd": ["CHOWN"],
            "NetworkMode": "host",
            "PortBindings": {"5432/tcp": []},
            "Binds": ["/host:/tmp:ro"],
            "Privileged": True,
            "ReadonlyRootfs": False,
            "SecurityOpt": [],
            "GroupAdd": ["999"],
            "IpcMode": "host",
            "PidsLimit": -1,
            "Tmpfs": {p.PGDATA: "rw,size=4m"},
        }
        for key, value in changes.items():
            candidate = row()
            candidate["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.inspect_profile(candidate, RUN, PROFILE)
        for key, value in (
            ("Mounts", [{"Type": "volume"}]),
            ("Args", ["passwd", "root"]),
            ("Path", "docker-entrypoint.sh"),
            ("Image", "sha256:" + "0" * 64),
        ):
            candidate = row()
            candidate[key] = value
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.inspect_profile(candidate, RUN, PROFILE)

    def test_profile_rejects_environment_and_foreign_ownership(self):
        for change in (
            lambda value: value["Config"]["Env"].append("PGPASSWORD=synthetic"),
            lambda value: value["Config"]["Env"].append("LANG=C"),
            lambda value: value["Config"].update(Labels={p.LABEL: "foreign"}),
            lambda value: value["Config"].update(User="999:999"),
        ):
            candidate = row()
            change(candidate)
            with self.assertRaises(p.Refusal):
                p.inspect_profile(candidate, RUN, PROFILE)

    def test_identity_tied_to_all_fourteen_diffids_and_volume(self):
        config = json.loads((HERE / "data/config.json").read_bytes())
        image = {
            "Id": p.MANIFEST,
            "Descriptor": {
                "digest": p.MANIFEST,
                "size": 3628,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
            },
            "RepoDigests": ["postgres@" + p.MANIFEST],
            "Os": "linux",
            "Architecture": "amd64",
            "RootFS": {"Type": "layers", "Layers": PROFILE["rootfs_diff_ids"]},
            "Config": config["config"],
        }
        self.assertEqual(len(image["RootFS"]["Layers"]), 14)
        p.verify_image(image, PROFILE)
        image["Config"] = dict(image["Config"], User=None)
        with self.assertRaises(p.Refusal):
            p.verify_image(image, PROFILE)
        image["Config"] = config["config"]
        image["RootFS"]["Layers"] = image["RootFS"]["Layers"][:-1]
        with self.assertRaises(p.Refusal):
            p.verify_image(image, PROFILE)
        forged = copy.deepcopy(PROFILE)
        forged["rootfs_diff_ids"] = image["RootFS"]["Layers"]
        with self.assertRaisesRegex(p.Refusal, "PINNED_PUBLIC_PROFILE"):
            p.verify_image(image, forged)

    def test_actual_reservation_create_label_pending_before_runner(self):
        calls = []
        state = self.state()

        def runner(argv, **options):
            self.assertEqual(state["IO"][-1]["reason"], "pending")
            calls.append((argv, options))
            args = argv[5:]
            self.assertEqual(options["env"]["DOCKER_API_VERSION"], "1.52")
            if args[0] == "container":
                return Result()
            if args[0] == "create":
                self.assertIn(p.LABEL + "=" + RUN, args)
                self.assertNotIn(p.LEGACY_LABEL + "=" + RUN, args)
                return Result((CID + "\n").encode())
            return Result(json.dumps([row()]).encode())

        client, _, saves = self.client(runner, state)
        cid = p.reserve_owned(client, LEGACY, state, lambda: None)
        self.assertEqual(cid, CID)
        self.assertTrue(saves)
        self.assertTrue(LINUX.io_history_released(state))
        self.assertIn("name=^/" + RUN + "-stage0$", calls[0][0])
        self.assertFalse(
            any(
                "--filter" in argv and any("label=" in value for value in argv)
                for argv, _options in calls
            )
        )

    def test_lost_create_no_cid_stays_unknown_after_two_cleanups(self):
        def runner(argv, **options):
            if "create" in argv:
                raise TimeoutError
            return Result()

        client, state, _ = self.client(runner)
        with self.assertRaises(TimeoutError):
            p.reserve_owned(client, LEGACY, state, lambda: None)
        client.cleaning = True
        for _ in range(2):
            outcome = p.reconcile_owned(client, LEGACY, state, lambda: None)
            self.assertFalse(outcome["released"])
            self.assertFalse(LINUX.io_history_released(state))

    def test_unreaped_undrained_overflow_timeout_refuse(self):
        for changes in (
            {"owned_child_reaped": False},
            {"drains_complete": False},
            {"reason": "stdout_budget"},
            {"killed_owned_child": True},
            {"exception_type": "TimeoutError"},
        ):

            def runner(_argv, **_options):
                result = Result()
                result.__dict__.update(changes)
                result.data.update(changes)
                return result

            client, state, _ = self.client(runner)
            with self.subTest(changes=changes), self.assertRaises(p.Refusal):
                client.command("ps")
            self.assertTrue(state["IO_uncertain"])

    def test_lease_busy_blocks_all_engine_access(self):
        client = types.SimpleNamespace(json=lambda *_args: self.fail("Engine attempted"))
        with self.assertRaises(p.Refusal):
            p.observe(client, LEGACY, LINUX, Lease(True), self.state(), lambda: None, PROFILE)

    def test_foreign_cleanup_never_removes_and_error_not_data(self):
        calls = []

        def runner(argv, **_options):
            calls.append(argv)
            if "container" in argv:
                return Result((CID + "\n").encode())
            candidate = row()
            candidate["Config"]["Labels"] = {p.LABEL: "foreign"}
            return Result(json.dumps([candidate]).encode())

        client, state, _ = self.client(runner)
        state["legacy_reservation"] = {
            "name": RUN + "-stage0",
            "run": RUN,
            "image_config": p.MANIFEST,
            "user": "0:0",
            "cid": CID,
            "attempted": True,
            "outcome": "confirmed",
        }
        self.assertFalse(p.reconcile_owned(client, LEGACY, state, lambda: None)["released"])
        self.assertFalse(any("rm" in argv or "stop" in argv for argv in calls))

    def test_full_fake_lifecycle_data_only_and_removes_exact_owned_id(self):
        config = json.loads((HERE / "data/config.json").read_bytes())
        image = {
            "Id": p.MANIFEST,
            "Descriptor": {
                "digest": p.MANIFEST,
                "size": 3628,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
            },
            "RepoDigests": ["postgres@" + p.MANIFEST],
            "Os": "linux",
            "Architecture": "amd64",
            "RootFS": {"Type": "layers", "Layers": PROFILE["rootfs_diff_ids"]},
            "Config": config["config"],
        }
        created, removed, calls = False, False, []
        inspect_count, oom_late, getent_code = 0, False, 0

        def runner(argv, **options):
            nonlocal created, removed, inspect_count
            args = argv[5:]
            calls.append((args, options))
            if args[:2] == ["image", "inspect"]:
                return Result(json.dumps([image]).encode())
            if args[0] == "version":
                return Result(json.dumps(version()).encode())
            if args[0] == "info":
                return Result(json.dumps(store()).encode())
            if args[0] == "container":
                return Result((CID + "\n").encode() if created and not removed else b"")
            if args[0] == "create":
                created = True
                return Result((CID + "\n").encode())
            if args[0] == "inspect":
                inspect_count += 1
                candidate = row()
                candidate["State"]["OOMKilled"] = oom_late and inspect_count >= 3
                return Result(json.dumps([candidate]).encode())
            if args[:2] == ["start", "--attach"]:
                self.assertEqual(options["stdout_cap"], 4096)
                self.assertEqual(options["stderr_cap"], 4096)
                return Result(b"postgres:x:123:456:G:/home:/bin/sh\n", code=getent_code)
            self.assertEqual(args, ["rm", CID])
            removed = True
            return Result()

        client, state, _ = self.client(runner)
        lease = Lease()
        result = p.observe(client, LEGACY, LINUX, lease, state, lambda: None, PROFILE)
        self.assertTrue(result["ok"])
        self.assertTrue(removed)
        self.assertEqual(result["measurement"], {"uid": 123, "gid": 456})
        self.assertFalse(result["commissioned"])
        self.assertFalse(result["PGDATA_ownership_measured"])
        self.assertTrue(result["independent_Root_comparison_required"])
        self.assertEqual(lease.calls, ["acquire", ("release", True)])
        self.assertFalse(
            any("--force" in args or "-v" in args or "pull" in args for args, _ in calls)
        )
        created, removed, inspect_count, oom_late = False, False, 0, True
        client, state, _ = self.client(runner)
        result = p.observe(client, LEGACY, LINUX, Lease(), state, lambda: None, PROFILE)
        self.assertFalse(result["ok"])
        self.assertIsNone(result["measurement"])
        self.assertTrue(result["resources_released"])
        self.assertEqual(result["failure"], "FINAL_OR_CLEANUP_UNCONFIRMED")
        created, removed, inspect_count, oom_late, getent_code = False, False, 0, False, 2
        client, state, _ = self.client(runner)
        result = p.observe(client, LEGACY, LINUX, Lease(), state, lambda: None, PROFILE)
        self.assertFalse(result["ok"])
        self.assertIsNone(result["measurement"])
        self.assertEqual(result["failure"], "PROBE_FAILED_OR_UNKNOWN")

    def test_nonzero_getent_is_failure_with_no_measurement(self):
        client, state, _ = self.client(lambda *_args, **_options: Result(code=2))
        lease = Lease()
        result = p.observe(client, LEGACY, LINUX, lease, state, lambda: None, PROFILE)
        self.assertFalse(result["ok"])
        self.assertIsNone(result["measurement"])
        self.assertEqual(result["failure"], "PROBE_FAILED_OR_UNKNOWN")

    def test_deadline_and_binding_refuse_before_spawn(self):
        for work, cleanup in (
            (92, 120),
            (90, 121),
            (True, 120),
            (0, 30),
            (float("inf"), float("inf")),
        ):
            state = self.state()
            state.update(work_deadline=work, cleanup_deadline=cleanup)
            with self.subTest(work=work), self.assertRaises(p.Refusal):
                self.client(lambda *_a, **_k: self.fail("spawn"), state)
        for key, value in (("run", "foreign"), ("user", "999:999"), ("image_config", "other")):
            state = self.state()
            state[key] = value
            lease = Lease()
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.observe(None, LEGACY, LINUX, lease, state, lambda: None, PROFILE)
            self.assertEqual(lease.calls, [])

    def test_version_fixed_api_and_types_before_create(self):
        self.assertEqual(p.verify_version(version()), version())
        for key, value in (
            ("client_api", "1.54"),
            ("client_version", "28.5.1"),
            ("server_version", "30.0.0"),
            ("client_os", "windows"),
            ("server_arch", "arm64"),
            ("server_api_min", "1.53"),
            ("server_api_max", "1.51"),
            ("server_api_min", True),
            ("server_api_max", "1.055"),
        ):
            candidate = dict(version(), **{key: value})
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.verify_version(candidate)
        for key, value in (("Mounts", None), ("Init", None)):
            candidate = row()
            candidate["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.inspect_profile(candidate, RUN, PROFILE)
        self.assertIn("--init=false", p.arguments())

    def test_store_containerd_exact_not_classic_alias(self):
        self.assertFalse(p.verify_store(store())["real_storage_root_received"])
        for key, value in (
            ("Driver", "overlay2"),
            ("DriverStatus", None),
            ("DriverStatus", []),
            ("DockerRootDir", "/unknown"),
        ):
            candidate = dict(store(), **{key: value})
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.verify_store(candidate)
        self.assertEqual(p.CONFIG, PROFILE["config_descriptor"]["digest"])
        self.assertNotEqual(p.CONFIG, p.MANIFEST)
