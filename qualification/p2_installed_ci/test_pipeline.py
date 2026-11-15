"""Pure controller/packet/lifecycle tests; no installed package or real daemon."""

import ast
import copy
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import controller as c
import entrypoint as e

ROOT = Path(__file__).resolve().parent


def io_fact(operation="pull", **changes):
    result = {
        "operation": operation,
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
    result.update(changes)
    return result


def success_execution():
    probes = {"probe" + str(index): 1 for index in range(6)}
    child = {"forbidden_attempts": {}, "intentional_guard_probes": probes}
    return {
        "schema": "pamolive.public-pam-verifier-installed-qualification/1",
        "state": e.SUCCESS,
        "authority": False,
        "build_verified": False,
        "attestation_verified": False,
        "source_manifest_sha256": e.PAYLOAD_SHA,
        "materials_plan_sha256": e.MATERIALS_SHA,
        "tests_expected": 30,
        "inputs_after_hashes_unchanged": True,
        "staged_inputs_hashes_unchanged": True,
        "source_test_fallback": False,
        "new_P0_run": False,
        "processes": [
            {"returncode": 0, "reason": None, "owned_child_reaped": True, "drains_complete": True}
        ],
        "tests": {
            **copy.deepcopy(child),
            "tests": {"run": 30, "failures": 0, "errors": 0, "skips": 0},
            "case_comparisons": [{"matches": True} for _ in range(20)],
        },
        "venvs": {
            name: {
                **copy.deepcopy(child),
                "venv": {"distributions": {str(index): "fixture" for index in range(count)}},
            }
            for name, count in (("build", 4), ("verifier", 11))
        },
    }


def summary():
    return {"state": e.SUCCESS, "methods": 30, "authority": False}


def profile_row(work, run, pins, entry=b"PUBLIC_SYNTHETIC_ENTRY"):
    base = {
        "Id": "a" * 64,
        "Name": "/" + run + "-stage0",
        "Run": run,
        "Image": pins["image_config"],
        "User": "1000:1000",
        "Running": False,
        "ExitCode": 0,
        "OOMKilled": False,
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(work / name),
                "Destination": "/" + name,
                "RW": False,
                "Propagation": "rprivate",
            }
            for name in ("controller", "source", "materials")
        ],
        "Profile": {
            "Memory": 512 * c.MIB,
            "MemorySwap": 512 * c.MIB,
            "NanoCpus": 1000000000,
            "PidsLimit": 128,
            "ShmSize": 16 * c.MIB,
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "IpcMode": "private",
            "PidMode": "",
            "NetworkMode": "none",
            "PortBindings": None,
            "PublishAllPorts": False,
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {
                "/work": "rw,nosuid,nodev,exec,size=256m,mode=0700,uid=1000,gid=1000",
                "/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777",
            },
        },
        "Entrypoint": ["/usr/local/bin/python3"],
        "Cmd": ["-I", "-B", "-c", entry.decode()],
        "Init": True,
        "GroupAdd": None,
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "64k", "max-file": "1"}},
        "Env": ["PUBLIC=value"],
    }
    return base


class PacketTests(unittest.TestCase):
    def test_synthetic_success_is_only_a_protocol_fixture(self):
        value = success_execution()
        e.success(value, summary())
        raw = e.encode(value)
        packet = e.packet(value, raw, summary(), "INSTALLED_PUBLIC_FIXTURES_PASS")
        self.assertTrue(packet["ok"])
        self.assertEqual(e.parse(e.encode(packet), e.PACKET_MAX), packet)

    def test_unknown_raw_log_or_secret_field_is_never_exported(self):
        for field in ("stdout", "stderr", "env", "secret", "logs", "private_key", "wheel_bytes"):
            with self.subTest(field=field), self.assertRaises(e.Refusal):
                e.encode({"public": {field: "NEVER_EXPORT"}})
        with self.assertRaises(e.Refusal):
            e.check_execution({**success_execution(), "unknown": "data"})

    def test_only_exact_parent_summary_not_arbitrary_JSON_log(self):
        self.assertEqual(e.parse_summary(e.encode(summary())), summary())
        for value in (
            {"message": "PRIVATE"},
            {**summary(), "methods": 30.0},
            {**summary(), "authority": True},
            {**summary(), "extra": "data"},
        ):
            with self.assertRaises(e.Refusal):
                e.parse_summary(e.encode(value))

    def test_stream_capture_bounds_before_retention(self):
        sink = e.Capture(4, True)
        self.assertEqual(sink.write("abcd"), 4)
        with self.assertRaises(e.Refusal):
            sink.write("x")
        self.assertEqual(sink.bytes(), b"abcd")
        discarded = e.Capture(4, False)
        discarded.write("éé")
        self.assertEqual(discarded.bytes(), b"")
        with self.assertRaises(e.Refusal):
            discarded.write("x")

    def test_serializer_exact_budget_and_shared_expansion(self):
        raw = e.encode({"a": "x"})
        self.assertEqual(e.encode({"a": "x"}, len(raw)), raw)
        with self.assertRaises(e.Refusal):
            e.encode({"a": "xx"}, len(raw))
        with self.assertRaises(e.Refusal):
            e.encode(["x" * 4096] * 1000, 65536)

    def test_JSON_prebounds_duplicate_alias_nonfinite_and_depth(self):
        for raw in (b'{"x":1,"\\u0078":2}', b'{"x":NaN}', b"[" * 25 + b"]" * 25):
            with self.assertRaises(e.Refusal):
                e.parse(raw, 1024)
        with patch.object(e.json, "loads", side_effect=AssertionError("parser reached")):
            with self.assertRaises(e.Refusal):
                e.parse(b"x" * 1025, 1024)

    def test_success_failures_skips_processes_guards_and_pins_reject(self):
        for mutate in (
            lambda v: v.update(authority=True),
            lambda v: v.update(source_manifest_sha256="0" * 64),
            lambda v: v.update(tests_expected=30.0),
            lambda v: v.update(inputs_after_hashes_unchanged=False),
            lambda v: v["tests"]["tests"].update(skips=1),
            lambda v: v["tests"]["tests"].update(run=30.0),
            lambda v: v["tests"]["case_comparisons"].pop(),
            lambda v: v["tests"]["forbidden_attempts"].update(DNS=1),
            lambda v: v["venvs"]["build"]["intentional_guard_probes"].pop("probe0"),
            lambda v: v["processes"][0].update(returncode=False),
            lambda v: v["processes"][0].update(owned_child_reaped=False),
        ):
            value = success_execution()
            mutate(value)
            with self.assertRaises(e.Refusal):
                e.success(value, summary())

    def test_qualifier_hash_precedes_compile_or_import(self):
        with patch("builtins.compile", side_effect=AssertionError("compile reached")):
            with self.assertRaisesRegex(e.Refusal, "QUALIFIER_PIN"):
                e.load_qualifier(b"NEVER_EXECUTE")

    def test_entry_main_only_exports_while_live_before_exit_AST(self):
        tree = ast.parse((ROOT / "entrypoint.py").read_bytes())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        positions = {
            ast.unparse(n.func): n.lineno for n in ast.walk(main) if isinstance(n, ast.Call)
        }
        self.assertLess(
            positions["sys.__stdout__.buffer.write"], positions["sys.__stdout__.buffer.flush"]
        )
        self.assertLess(positions["sys.__stdout__.buffer.flush"], positions["SystemExit"])
        self.assertNotIn("docker", positions)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.work = Path("/synthetic-ci/work").resolve()
        self.pins = json.loads((ROOT / "pins.json").read_bytes())
        self.row = profile_row(self.work, "unit-run", self.pins)

    def test_exact_three_mounts_tmpfs_exec_ro_caps_and_init(self):
        c.validate_profile(self.row, self.work, b"PUBLIC_SYNTHETIC_ENTRY", {"PUBLIC": "value"})
        arguments = c.create_arguments(self.work, self.pins, b"PUBLIC_SYNTHETIC_ENTRY")
        self.assertEqual(arguments.count("--mount"), 3)
        self.assertNotIn("/var/run/docker.sock", " ".join(arguments))
        self.assertNotIn("/bin/sh", arguments)
        self.assertEqual(arguments[arguments.index("--memory") + 1], "512m")
        self.assertEqual(arguments[arguments.index("--memory-swap") + 1], "512m")
        self.assertIn("/work:rw,nosuid,nodev,exec,size=256m,mode=0700,uid=1000,gid=1000", arguments)

    def test_each_resource_or_network_relaxation_refuses(self):
        for field, value in (
            ("Memory", 1024),
            ("MemorySwap", 1024),
            ("NanoCpus", 1000000000.0),
            ("ReadonlyRootfs", False),
            ("Privileged", True),
            ("CapAdd", ["SYS_ADMIN"]),
            ("NetworkMode", "host"),
            ("IpcMode", "host"),
            ("PidsLimit", True),
        ):
            row = copy.deepcopy(self.row)
            row["Profile"][field] = value
            with self.assertRaises(c.Refusal):
                c.validate_profile(row, self.work)

    def test_mounts_extra_shadow_writable_type_and_propagation_refuse(self):
        for mutate in (
            lambda r: r["Mounts"].append(copy.deepcopy(r["Mounts"][0])),
            lambda r: r["Mounts"][0].update(RW=True),
            lambda r: r["Mounts"][0].update(RW=0),
            lambda r: r["Mounts"][0].update(Source="/checkout"),
            lambda r: r["Mounts"][0].update(Propagation="rshared"),
        ):
            row = copy.deepcopy(self.row)
            mutate(row)
            with self.assertRaises(c.Refusal):
                c.validate_profile(row, self.work)

    def test_command_environment_or_logging_drift_refuses(self):
        for field, value in (
            ("Cmd", ["-c", "EVIL"]),
            ("Entrypoint", ["/bin/sh"]),
            ("Init", False),
            ("GroupAdd", ["0"]),
            ("Env", ["LD_PRELOAD=foreign"]),
            ("LogConfig", {"Type": "none"}),
        ):
            row = copy.deepcopy(self.row)
            row[field] = value
            with self.assertRaises(c.Refusal):
                c.validate_profile(row, self.work, b"PUBLIC_SYNTHETIC_ENTRY", {"PUBLIC": "value"})

    def test_status_and_mount_profile_is_data_only(self):
        status = (
            "Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\t1000\nNoNewPrivs:\t1\n"
            + "".join(
                key + ":\t0000000000000000\n"
                for key in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb")
            )
        )
        mounts = (
            "root / overlay ro 0 0\n"
            + "".join(
                "bind /" + name + " ext4 ro 0 0\n" for name in ("controller", "source", "materials")
            )
            + "tmp /work tmpfs rw,nosuid,nodev 0 0\ntmp /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"
        )
        e.profile(status, mounts)
        for broken in (
            status.replace("1000 1000 1000 1000", "0 0 0 0"),
            status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            status.replace("Groups:\t1000", "Groups:\t0"),
        ):
            with self.assertRaises(e.Refusal):
                e.profile(broken, mounts)


class LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy, cls.bounded = c.supports()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p2-ci-pure-", dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.pins = json.loads((ROOT / "pins.json").read_bytes())
        self.state = {
            "run": "unit-run",
            "image_config": self.pins["image_config"],
            "user": "1000:1000",
        }
        outer = self

        class Fake:
            row = None
            lost = False
            unavailable = False
            calls = []

            def __init__(self):
                self.row, self.lost, self.unavailable, self.calls = None, False, False, []

            def named(self, _name):
                if self.unavailable:
                    raise OSError("unavailable")
                return [] if self.row is None else [self.row["Id"]]

            def inspect(self, _cid):
                c.validate_profile(self.row, outer.work)
                return self.row

            def command(self, *arguments, **_kwargs):
                self.calls.append(arguments)
                if arguments[0] == "create":
                    if not outer.state["create"]["attempted"]:
                        raise AssertionError("intent missing")
                    if (
                        arguments[arguments.index("--label") + 1]
                        != c.LABEL + "=" + outer.state["run"]
                    ):
                        raise AssertionError("P2 label not used")
                    self.row = profile_row(outer.work, "unit-run", outer.pins)
                    if self.lost:
                        raise TimeoutError("lost response")
                    return 0, b"a" * 64, b""
                if arguments[0] == "stop":
                    self.row["Running"] = False
                if arguments[0] == "rm":
                    self.row = None
                return 0, b"", b""

            remove = outer.legacy.LocalDocker.remove

        self.client = Fake()
        self.saved = []
        self.save = lambda: self.saved.append(copy.deepcopy(self.state))

    def test_durable_create_and_cleanup_use_original_primitives(self):
        cid = self.legacy.reserve_create(self.client, self.state, self.save, [])
        self.assertEqual(cid, "a" * 64)
        self.assertTrue(self.saved[1]["create"]["attempted"])
        result = self.legacy.reconcile(self.client, self.state, self.save)
        self.assertTrue(result["released"])
        self.assertEqual(result["exit_code"], 0)

    def test_lost_CID_reconciles_only_matching_nonce_profile(self):
        self.client.lost = True
        with self.assertRaises(TimeoutError):
            self.legacy.reserve_create(self.client, self.state, self.save, [])
        self.assertEqual(self.state["create"]["outcome"], "unknown")
        self.assertTrue(self.legacy.reconcile(self.client, self.state, self.save)["released"])

    def test_lost_create_absence_stays_unknown(self):
        self.client.lost = True
        with self.assertRaises(TimeoutError):
            self.legacy.reserve_create(self.client, self.state, self.save, [])
        self.client.row = None
        self.assertFalse(self.legacy.reconcile(self.client, self.state, self.save)["released"])

    def test_foreign_nonce_or_profile_never_removed(self):
        self.legacy.reserve_create(self.client, self.state, self.save, [])
        self.client.row["Run"] = "foreign"
        self.client.calls.clear()
        self.assertFalse(self.legacy.reconcile(self.client, self.state, self.save)["released"])
        self.assertFalse(any(row[0] in ("stop", "rm") for row in self.client.calls))

    def test_unavailable_daemon_stays_unknown(self):
        self.legacy.reserve_create(self.client, self.state, self.save, [])
        self.client.unavailable = True
        self.assertFalse(self.legacy.reconcile(self.client, self.state, self.save)["released"])

    def test_legacy_supports_hashes_and_lifecycle_source_not_rewritten(self):
        for name, digest in c.SUPPORT.items():
            self.assertEqual(c.sha((ROOT / name).read_bytes()), digest)
        self.assertEqual(self.legacy.reserve_create.__module__, "p2_ci_legacy_controller")
        self.assertEqual(self.legacy.LABEL, c.LABEL)


class HostTests(unittest.TestCase):
    def test_ambient_Docker_context_auth_and_proxy_rejected(self):
        environment = {
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_TEMP": str(ROOT),
        }
        work = ROOT / "pamolive-p2-installed-1-1"
        for name in (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_AUTH_CONFIG",
            "DOCKER_CONFIG",
            "HTTP_PROXY",
        ):
            with (
                patch.dict(os.environ, {**environment, name: ""}, clear=True),
                patch.object(c.sys, "platform", "linux"),
                patch.object(c.os, "getuid", return_value=1001, create=True),
                patch.object(c.os, "getgid", return_value=1001, create=True),
            ):
                with self.assertRaisesRegex(c.Refusal, "AMBIENT"):
                    c.ci_guard(work)

    def test_no_local_or_self_hosted_run_is_accepted(self):
        with (
            patch.dict(
                os.environ,
                {"GITHUB_ACTIONS": "true", "CI": "true", "RUNNER_ENVIRONMENT": "self-hosted"},
                clear=True,
            ),
            patch.object(c.sys, "platform", "linux"),
            patch.object(c.os, "getuid", return_value=1001, create=True),
            patch.object(c.os, "getgid", return_value=1001, create=True),
        ):
            with self.assertRaises(c.Refusal):
                c.ci_guard(ROOT / "pamolive-p2-installed-1-1")

    def test_regular_reader_refuses_large_before_open(self):
        target = ROOT / "impossible-large-public-input"
        row = SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=1, st_size=1 << 40)
        directory = SimpleNamespace(st_mode=stat.S_IFDIR)

        def metadata(path):
            return row if path == target else directory

        for module in (c, e):
            with (
                patch.object(Path, "lstat", metadata),
                patch.object(Path, "open", side_effect=AssertionError("open reached")),
            ):
                with self.assertRaises(module.Refusal):
                    module.regular(target, 1024)

    def test_closed_source_rejects_cache_files_and_oversized_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "only.py").write_bytes(b"public")
            c.closed_files(root, {"only.py"})
            (root / ".ruff_cache").mkdir()
            (root / ".ruff_cache/entry").write_bytes(b"public cache")
            with self.assertRaisesRegex(c.Refusal, "CLOSED"):
                c.closed_files(root, {"only.py"})
            with self.assertRaises(c.Refusal):
                c.regular(root / "only.py", 2)

    def test_workflow_pins_before_acquisition_and_has_no_cp_or_fallback(self):
        text = (ROOT / "workflow-template.yml").read_text()
        self.assertLess(
            text.index("sha256sum --check --strict source-checksums"),
            text.index("actions/setup-python@"),
        )
        self.assertLess(
            text.index("controller.py verify"), text.index("acquire_materials.py acquire")
        )
        self.assertLess(text.index("controller.py prepare"), text.index("controller.py pull"))
        self.assertIn("if: always() && env.P2_WORK", text)
        for forbidden in (
            "docker cp",
            "docker.sock:",
            "--no-sandbox",
            "continue-on-error",
            "PYTHONPATH",
            "pip install",
        ):
            self.assertNotIn(forbidden, text)


class ExportTransportTests(unittest.TestCase):
    def setUp(self):
        self.pins = json.loads((ROOT / "pins.json").read_bytes())
        self.legacy, self.bounded = c.supports()
        self.persistence = patch.object(c, "persist_io")
        self.persistence.start()
        self.addCleanup(self.persistence.stop)

    def test_real_export_main_with_only_simulated_qualifier_and_files(self):
        value = success_execution()

        def simulated():
            print(json.dumps(summary()))

        output = io.BytesIO()

        def read(path, _maximum):
            return (
                e.encode(value) if str(path).endswith("execution.json") else b"synthetic-qualifier"
            )

        with (
            patch.object(e, "regular", side_effect=read),
            patch.object(e, "load_qualifier", return_value=SimpleNamespace(main=simulated)),
            patch.object(e, "profile"),
            patch.object(Path, "read_text", return_value="synthetic-proc"),
            patch.object(e.sys, "__stdout__", SimpleNamespace(buffer=output)),
            patch.object(e.sys, "argv", []),
        ):
            with self.assertRaises(SystemExit) as stopped:
                e.main()
        self.assertEqual(stopped.exception.code, 0)
        packet = e.parse(output.getvalue(), e.PACKET_MAX)
        self.assertTrue(c.validate_packet(packet, self.pins, e)["ok"])

    def test_masked_guard_attempt_cannot_export_success(self):
        value = success_execution()
        value["tests"]["forbidden_attempts"] = {"open.write": 1}
        output = io.BytesIO()

        def read(path, _maximum):
            return (
                e.encode(value) if str(path).endswith("execution.json") else b"synthetic-qualifier"
            )

        with (
            patch.object(e, "regular", side_effect=read),
            patch.object(
                e,
                "load_qualifier",
                return_value=SimpleNamespace(main=lambda: print(json.dumps(summary()))),
            ),
            patch.object(e, "profile"),
            patch.object(Path, "read_text", return_value="synthetic-proc"),
            patch.object(e.sys, "__stdout__", SimpleNamespace(buffer=output)),
            patch.object(e.sys, "argv", []),
        ):
            with self.assertRaises(SystemExit) as stopped:
                e.main()
        self.assertEqual(stopped.exception.code, 42)
        self.assertFalse(e.parse(output.getvalue(), e.PACKET_MAX)["ok"])

    def test_inspect_projection_changes_only_label_and_explicit_fields(self):
        client = object.__new__(c.docker_class(self.legacy, self.bounded))
        client.work = ROOT
        client.entry_raw = b"PUBLIC_SYNTHETIC_ENTRY"
        client.expected_environment = {"PUBLIC": "value"}
        observed = []

        def answer(*arguments, **_kwargs):
            observed.append(arguments)
            return 0, e.encode(profile_row(ROOT, "unit-run", self.pins)), b""

        client.command = answer
        client.inspect("a" * 64)
        projection = observed[0][-1]
        self.assertIn('"pamolive.p2.installed.run"', projection)
        self.assertNotIn('"pamolive.b0pre.run"', projection)
        for field in ("Entrypoint", "Cmd", "Env", "Init", "GroupAdd", "LogConfig"):
            self.assertIn('"' + field + '":', projection)

    def test_transport_caps_deadline_and_no_raw_logs_in_facts(self):
        client = object.__new__(c.docker_class(self.legacy, self.bounded))
        client.prefix, client.env, client.work = ["/usr/bin/docker"], {}, ROOT
        client.state, client.cleaning = {"IO": [], "IO_total": 0, "IO_uncertain": False}, False
        client.work_deadline, client.cleanup_deadline = 100.0, 160.0
        result = self.bounded.Result(
            spawn_attempted=True,
            pid=123,
            returncode=0,
            owned_child_reaped=True,
            drains_complete=True,
            stdout=b"public",
            stderr=b"",
        )
        with (
            patch.object(c.time, "monotonic", return_value=10.0),
            patch.object(self.bounded, "run_capped", return_value=result) as run,
        ):
            client.command("start", "--attach", "a" * 64, timeout=900)
            self.assertEqual(run.call_args.kwargs["timeout"], 90)
            self.assertEqual(run.call_args.kwargs["stdout_cap"], 512 * 1024)
            self.assertEqual(run.call_args.kwargs["stderr_cap"], 16384)
            client.cleaning = True
            client.command("rm", "a" * 64, timeout=900)
            self.assertEqual(run.call_args.kwargs["timeout"], 150)
            self.assertEqual(run.call_args.kwargs["stdout_cap"], 32768)
        self.assertNotIn("stdout", client.state["IO"][0])
        with (
            patch.object(c.time, "monotonic", return_value=161.0),
            patch.object(self.bounded, "run_capped", side_effect=AssertionError("late spawn")),
        ):
            with self.assertRaisesRegex(c.Refusal, "DEADLINE"):
                client.command("rm", "a" * 64)

    def test_unreaped_or_overflow_cli_never_becomes_success(self):
        client = object.__new__(c.docker_class(self.legacy, self.bounded))
        client.prefix, client.env, client.work = ["/usr/bin/docker"], {}, ROOT
        client.state, client.cleaning = {"IO": [], "IO_total": 0, "IO_uncertain": False}, False
        client.work_deadline = 100.0
        for result in (
            self.bounded.Result(returncode=0),
            self.bounded.Result(
                returncode=0, owned_child_reaped=True, drains_complete=True, reason="overflow"
            ),
        ):
            with (
                patch.object(c.time, "monotonic", return_value=1.0),
                patch.object(self.bounded, "run_capped", return_value=result),
            ):
                with self.assertRaisesRegex(c.Refusal, "UNCONFIRMED"):
                    client.command("version")

    def test_public_report_rejects_changed_packet_and_preserves_prior_failure(self):
        value = success_execution()
        packet = e.packet(value, e.encode(value), summary(), "INSTALLED_PUBLIC_FIXTURES_PASS")
        raw = c.encode(packet, e.PACKET_MAX)
        state = {
            "packet": {"sha256": c.sha(raw), "bytes": len(raw), "ok": True},
            "failure": "EARLIER_FAIL",
            "pull": "ready",
            "IO": [],
        }
        cleanup = {"released": True, "exit_code": 0, "OOMKilled": False}
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "packet-public.json").write_bytes(raw)
            result = c.report(work, state, cleanup, self.pins)
            self.assertFalse(result["ok"])
            self.assertEqual(result["failure"], "EARLIER_FAIL")
            (work / "packet-public.json").write_bytes(b"changed")
            state["failure"] = None
            result = c.report(work, state, cleanup, self.pins)
            self.assertFalse(result["ok"])
            self.assertEqual(result["failure"], "PUBLIC_PACKET_UNAVAILABLE_OR_CHANGED")

    def test_frozen_qualifier_report_fields_match_closed_export_contract_AST(self):
        # Data/AST only: never compile/import the source package or qualifier.
        source = ROOT.parent / "pam_trust_verifier/qualify_installed.py"
        if not source.exists():
            # Prototype tests only. The future repository uses the single sibling above.
            source = (
                ROOT.parent
                / "p2-r1b1-integrable-source-candidate-20261115"
                / "qualification/pam_trust_verifier/qualify_installed.py"
            )
        raw = source.read_bytes()
        self.assertEqual(c.sha(raw), e.QUALIFIER_SHA)
        tree = ast.parse(raw)
        run = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run"
        )
        fields = set()
        for node in ast.walk(run):
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id == "report"
                and isinstance(node.slice, ast.Constant)
            ):
                fields.add(node.slice.value)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "report"
                and node.func.attr == "update"
            ):
                fields.update(keyword.arg for keyword in node.keywords)
            if (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "report"
                    for target in node.targets
                )
                and isinstance(node.value, ast.Dict)
            ):
                fields.update(key.value for key in node.value.keys)
        self.assertEqual(fields, set(e.EXECUTION_KEYS))

    def test_report_budget_refuses_but_keeps_confirmed_cleanup_public(self):
        state = {
            "packet": None,
            "failure": "EARLIER_FAIL",
            "pull": "ready",
            "IO": [{"public": "x" * 4096}] * 200,
        }
        cleanup = {"released": True, "exit_code": 0, "OOMKilled": False}
        with tempfile.TemporaryDirectory() as temporary:
            result = c.report(Path(temporary), state, cleanup, self.pins)
            self.assertFalse(result["ok"])
            self.assertEqual(result["state"], "PUBLIC_REPORT_BUDGET_REFUSED")
            self.assertEqual(result["cleanup"], cleanup)
            self.assertLessEqual(
                len((Path(temporary) / "public-report.json").read_bytes()), c.MAX_PUBLIC
            )


class WholeControllerFakeTests(unittest.TestCase):
    """Real controller orchestration; only Docker, host guards and resource facts simulated."""

    def exercise(self, *, invalid_packet=False, lost_create=False, drift=False, repeat=False):
        legacy, bounded = c.supports()
        pins = json.loads((ROOT / "pins.json").read_bytes())
        entry = (ROOT / "entrypoint.py").read_bytes()
        packet = e.packet(
            success_execution(),
            e.encode(success_execution()),
            summary(),
            "INSTALLED_PUBLIC_FIXTURES_PASS",
        )
        raw = b"invalid" if invalid_packet else e.encode(packet)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            identities = {}
            for directory in ("controller", "source", "materials"):
                (work / directory).mkdir()
                (work / directory / "public.txt").write_bytes(b"public")
                identities[directory + "/public.txt"] = c.sha(b"public")
            state = {
                "type": c.TYPE,
                "phase": c.PHASE,
                "user": "1000:1000",
                "image_config": pins["image_config"],
                "assets_sha256": c.sha(b"synthetic-assets"),
                "run": "unit-whole",
                "pull": "ready",
                "started": False,
                "identities": identities,
                "packet": None,
                "failure": None,
                "IO": [io_fact()],
                "IO_total": 1,
                "IO_uncertain": False,
            }
            c.atomic(work / "state.json", state)
            clients = []

            class Fake:
                def __init__(self, _work, _pins, _state, deadline):
                    self.row, self.calls, self.cleaning = None, [], False
                    self.deadline, self.state = deadline, _state
                    clients.append(self)

                def image(self, _pins):
                    return None

                def named(self, _name):
                    return [self.row["Id"]] if self.row else []

                def inspect(self, _cid):
                    c.validate_profile(self.row, work, entry, {"PUBLIC": "value"})
                    return self.row

                def command(self, *args, **_kwargs):
                    self.calls.append(args)
                    record = c.begin_io(self.state, args[0])
                    record.clear()
                    record.update(io_fact(args[0]))
                    if args[0] == "ps":
                        return 0, b"", b""
                    if args[0] == "create":
                        self.row = profile_row(work, "unit-whole", pins, entry)
                        if drift:
                            self.row["Mounts"][0]["RW"] = True
                        if lost_create:
                            raise TimeoutError("synthetic lost CID")
                        return 0, b"a" * 64, b""
                    if args[:2] == ("start", "--attach"):
                        return 0, raw, b""
                    if args[0] == "stop":
                        self.row["Running"] = False
                    if args[0] == "rm":
                        self.row = None
                    return 0, b"", b""

                remove = legacy.LocalDocker.remove

            original = c.regular

            def reader(path, maximum, empty=False):
                if Path(path) == ROOT / "assets.json":
                    return b"synthetic-assets"
                return original(path, maximum, empty)

            with (
                patch.object(c, "ci_guard"),
                patch.object(c, "regular", side_effect=reader),
                patch.object(legacy, "storage_observation"),
                patch.object(legacy, "memory_guard"),
            ):
                result = c.execute(
                    "run", work, pins, {"entrypoint.py": entry}, legacy, bounded, factory=Fake
                )
                if repeat:
                    # Next process sees no container; prior confirmed exit evidence persists.
                    result = c.execute(
                        "cleanup",
                        work,
                        pins,
                        {"entrypoint.py": entry},
                        legacy,
                        bounded,
                        factory=Fake,
                    )
            return result, [call for client in clients for call in client.calls], clients

    def test_positive_full_fake_lifecycle_and_repeat_cleanup(self):
        value, calls, clients = self.exercise(repeat=True)
        self.assertTrue(value["ok"])
        self.assertTrue(value["resources_released"])
        self.assertEqual(sum(row[0] == "create" for row in calls), 1)
        self.assertEqual(sum(row[0] == "start" for row in calls), 1)
        self.assertEqual(sum(row[0] == "rm" for row in calls), 1)
        self.assertLessEqual(clients[-1].deadline, c.time.monotonic())

    def test_invalid_attach_packet_stays_failure_after_owned_cleanup(self):
        value, calls, _ = self.exercise(invalid_packet=True, repeat=True)
        self.assertFalse(value["ok"])
        self.assertTrue(value["resources_released"])
        self.assertTrue(any(row[0] == "rm" for row in calls))

    def test_lost_create_response_cleans_owned_but_never_claims_tests(self):
        value, calls, _ = self.exercise(lost_create=True)
        self.assertFalse(value["ok"])
        self.assertTrue(value["resources_released"])
        self.assertFalse(any(row[0] == "start" for row in calls))
        self.assertTrue(any(row[0] == "rm" for row in calls))

    def test_profile_mismatch_neither_starts_nor_removes_unconfirmed_object(self):
        value, calls, _ = self.exercise(drift=True)
        self.assertFalse(value["ok"])
        self.assertFalse(value["resources_released"])
        self.assertFalse(any(row[0] in ("start", "rm", "stop") for row in calls))


class H1HistoryTests(unittest.TestCase):
    def exercise(self, operation=None, field=None, reason=None):
        legacy, bounded = c.supports()
        pins = json.loads((ROOT / "pins.json").read_bytes())
        entry = (ROOT / "entrypoint.py").read_bytes()
        packet = e.packet(
            success_execution(),
            e.encode(success_execution()),
            summary(),
            "INSTALLED_PUBLIC_FIXTURES_PASS",
        )
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            identities = {}
            for group in ("source", "controller", "materials"):
                (work / group).mkdir()
                (work / group / "public.txt").write_bytes(b"public")
                identities[group + "/public.txt"] = c.sha(b"public")
            state = {
                "type": c.TYPE,
                "phase": c.PHASE,
                "run": "h1-unit",
                "user": "1000:1000",
                "image_config": pins["image_config"],
                "assets_sha256": c.sha(b"assets-fixture"),
                "identities": identities,
                "pull": "ready",
                "started": False,
                "packet": None,
                "failure": None,
                "IO": [io_fact()],
                "IO_total": 1,
                "IO_uncertain": False,
            }
            c.atomic(work / "state.json", state)
            client = object.__new__(c.docker_class(legacy, bounded))
            client.prefix, client.env, client.work = ["never-executed"], {}, work
            client.row = None
            calls, pending = [], []

            def factory(_work, _pins, loaded, deadline):
                client.state, client.cleaning = loaded, False
                client.work_deadline, client.cleanup_deadline = deadline, deadline + 60
                return client

            def inspect(_cid):
                c.validate_profile(client.row, work, entry, {"PUBLIC": "value"})
                return copy.deepcopy(client.row)

            client.inspect = inspect
            client.named = lambda _name: [client.row["Id"]] if client.row else []
            client.image = lambda _pins: None

            def process(command, **_kwargs):
                op = command[1]
                calls.append(op)
                durable = json.loads((work / "state.json").read_bytes())
                self.assertIsNone(durable["IO"][-1]["spawn_attempted"])
                self.assertEqual(durable["IO_total"], len(durable["IO"]))
                pending.append(copy.deepcopy(durable["IO"][-1]))
                facts = io_fact(op)
                facts.pop("operation")
                result = bounded.Result(**facts)
                if op == "create":
                    client.row = profile_row(work, "h1-unit", pins, entry)
                    result.stdout = b"a" * 64
                if op == "start":
                    result.stdout = e.encode(packet)
                if op == "rm":
                    client.row = None
                if op == operation:
                    if field:
                        setattr(result, field, False)
                    result.reason = reason or "unconfirmed_fixture"
                    if reason == "nonzero_exit":
                        result.returncode = 1
                    elif reason in ("timeout", "stdout_overflow"):
                        result.returncode, result.killed_owned_child = -9, True
                return result

            original = c.regular

            def reader(path, maximum, empty=False):
                return (
                    b"assets-fixture"
                    if Path(path) == ROOT / "assets.json"
                    else original(path, maximum, empty)
                )

            with (
                patch.object(c, "ci_guard"),
                patch.object(c, "regular", side_effect=reader),
                patch.object(legacy, "storage_observation"),
                patch.object(legacy, "memory_guard"),
                patch.object(bounded, "run_capped", side_effect=process),
            ):
                if operation == "ps":
                    with self.assertRaisesRegex(c.Refusal, "OWNED_CLI_UNCONFIRMED"):
                        c.execute(
                            "run",
                            work,
                            pins,
                            {"entrypoint.py": entry},
                            legacy,
                            bounded,
                            factory=factory,
                        )
                    value = None
                else:
                    value = c.execute(
                        "run",
                        work,
                        pins,
                        {"entrypoint.py": entry},
                        legacy,
                        bounded,
                        factory=factory,
                    )
                repeated = c.execute(
                    "cleanup",
                    work,
                    pins,
                    {"entrypoint.py": entry},
                    legacy,
                    bounded,
                    factory=factory,
                )
                again = c.execute(
                    "cleanup",
                    work,
                    pins,
                    {"entrypoint.py": entry},
                    legacy,
                    bounded,
                    factory=factory,
                )
            final = json.loads((work / "state.json").read_bytes())
            self.assertEqual(final["IO_total"], len(final["IO"]))
            return value, repeated, again, final, calls, pending

    def check_unconfirmed(self, operation, field):
        first, second, third, state, calls, pending = self.exercise(operation, field)
        self.assertTrue(pending)
        for result in (first, second, third):
            self.assertTrue(result["container_released"])
            self.assertFalse(result["clients_released"])
            self.assertFalse(result["resources_released"])
            self.assertFalse(result["ok"])
            self.assertTrue(result["IO_uncertain"])
            self.assertEqual(result["failure"], "OWNED_CLI_UNCONFIRMED")
        self.assertTrue(state["IO_uncertain"])
        self.assertEqual(
            sum(row["operation"] == operation and row[field] is False for row in state["IO"]), 1
        )
        self.assertIn("rm", calls)

    def test_runtime_create_unreaped_stays_global_unknown_after_two_cleanups(self):
        self.check_unconfirmed("create", "owned_child_reaped")

    def test_runtime_create_undrained_stays_global_unknown_after_two_cleanups(self):
        self.check_unconfirmed("create", "drains_complete")

    def test_runtime_attach_unreaped_stays_global_unknown_after_two_cleanups(self):
        self.check_unconfirmed("start", "owned_child_reaped")

    def test_runtime_attach_undrained_stays_global_unknown_after_two_cleanups(self):
        self.check_unconfirmed("start", "drains_complete")

    def test_positive_all_reaped_drained_and_repeat_cleanup(self):
        first, second, third, state, _, _ = self.exercise()
        for result in (first, second, third):
            self.assertTrue(result["ok"])
            self.assertTrue(result["resources_released"])
            self.assertTrue(result["clients_released"])
        self.assertFalse(state["IO_uncertain"])

    def test_overflow_timeout_nonzero_remain_qualification_failures_when_resources_reaped(self):
        for reason in ("stdout_overflow", "timeout", "nonzero_exit"):
            first, second, third, state, _, _ = self.exercise("start", reason=reason)
            for result in (first, second, third):
                self.assertFalse(result["ok"])
                self.assertTrue(result["resources_released"])
                self.assertEqual(result["failure"], "OWNED_CLI_UNCONFIRMED")
            self.assertFalse(state["IO_uncertain"])

    def test_prephase_ps_bad_IO_is_durable_even_before_run_try(self):
        _, second, third, state, calls, _ = self.exercise("ps", "owned_child_reaped")
        self.assertNotIn("create", calls)
        self.assertTrue(state["IO_uncertain"])
        self.assertFalse(second["resources_released"])
        self.assertFalse(third["resources_released"])

    def test_missing_malformed_or_pending_history_never_clears_uncertainty(self):
        states = [
            {},
            {"IO": [], "IO_total": 1, "IO_uncertain": False},
            {"IO": [io_fact()], "IO_total": True, "IO_uncertain": False},
            {"IO": [io_fact()], "IO_total": 1},
            {"IO": [io_fact(pid=True)], "IO_total": 1, "IO_uncertain": False},
            {"IO": [io_fact(spawn_attempted=None)], "IO_total": 1, "IO_uncertain": False},
            {
                "IO": [
                    {key: value for key, value in io_fact().items() if key != "drains_complete"}
                ],
                "IO_total": 1,
                "IO_uncertain": False,
            },
        ]
        for state in states:
            with self.subTest(state=state):
                self.assertFalse(c.io_history_released(state))
                state["IO"], state["IO_total"] = [io_fact()], 1
                self.assertFalse(c.io_history_released(state))

    def test_spawn_not_attempted_does_not_invent_owned_resource(self):
        no_process = io_fact(
            spawn_attempted=False,
            pid=None,
            returncode=None,
            owned_child_reaped=False,
            drains_complete=False,
            reason="not_attempted",
        )
        state = {"IO": [no_process], "IO_total": 1, "IO_uncertain": False}
        self.assertTrue(c.io_history_released(state))
        for change in ({"pid": 123}, {"owned_child_reaped": True}, {"stdout_bytes": 1}):
            mutated = copy.deepcopy(state)
            mutated["IO"][0].update(change)
            self.assertFalse(c.io_history_released(mutated))

    def test_closed_32_record_limit_refuses_before_another_client(self):
        state = {"IO": [io_fact()] * 32, "IO_total": 32, "IO_uncertain": False}
        self.assertTrue(c.io_history_released(state))
        with self.assertRaisesRegex(c.Refusal, "MALFORMED_OR_FULL"):
            c.begin_io(state, "inspect")
        self.assertEqual(len(state["IO"]), 32)
        self.assertTrue(state["IO_uncertain"])
        self.assertFalse(c.io_history_released(state))

    def test_valid_test_packet_does_not_mask_malformed_history(self):
        pins = json.loads((ROOT / "pins.json").read_bytes())
        value = success_execution()
        packet = e.packet(value, e.encode(value), summary(), "INSTALLED_PUBLIC_FIXTURES_PASS")
        raw = c.encode(packet, e.PACKET_MAX)
        state = {
            "packet": {"sha256": c.sha(raw), "bytes": len(raw), "ok": True},
            "failure": None,
            "pull": "ready",
            "IO": [io_fact(pid=True)],
            "IO_total": 1,
            "IO_uncertain": False,
        }
        cleanup = {"released": True, "exit_code": 0, "OOMKilled": False}
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "packet-public.json").write_bytes(raw)
            result = c.report(work, state, cleanup, pins)
        self.assertTrue(result["container_released"])
        self.assertFalse(result["resources_released"])
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
