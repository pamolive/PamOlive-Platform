"""Real composed P2 methods with fake process/daemon boundaries only."""

import copy
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import host_seam
import schema
from support import load, sha

P2 = load("controller.py")
ENTRY = b"# Vault workload capsule; no process action\n"
SOURCE = "2" * 64
INPUT = "4" * 64
SQL = "3" * 64
EXPECTED = {"pip": "26.3"}


def packet(success=True):
    child = {
        "schema": schema.CHILD,
        "state": "INSTALLED_RUNTIME_52_PASS" if success else "FAILED",
        "authority": False,
        "venv": {
            "distributions": EXPECTED,
            "origins": {
                module: "lib/python3.12/site-packages/" + module + "/__init__.py"
                for module in schema.MODULES
            },
        },
        "installed": {
            "modules": schema.MODULES.copy(),
            "files_matched": 18,
            "sql_sha256": "3" * 64,
            "site_PTH": 0,
        },
        "tests": {"run": 52, "failures": 0 if success else 1, "errors": 0, "skips": 0},
        "attempts": {},
        "probes": dict.fromkeys(schema.PROBES, 1),
        "input_sha256": "4" * 64,
        "elapsed_seconds": 1.25,
        "failure_code": "NONE" if success else "TESTS",
        "exception_type": None if success else "AssertionError",
    }
    raw = schema.encode(child)
    return {
        "schema": schema.PACKET,
        "ok": success,
        "authority": False,
        "child": child,
        "child_sha256": sha(raw),
        "child_bytes": len(raw),
        "source_sha256": SOURCE,
        "attestation_verified": False,
    }


class Result:
    def __init__(self, code=0, value=None):
        self.returncode = code
        self.stdout = schema.encode(packet() if value is None else value, schema.MAX_PACKET)
        self.stderr = b""
        self.reason = None if code == 0 else "nonzero_exit"
        self.spawn_attempted = True
        self.pid = 31337
        self.owned_child_reaped = self.drains_complete = True
        self.killed_owned_child = False
        self.exception_type = self.cleanup_exception_type = None

    def facts(self):
        return {
            "spawn_attempted": self.spawn_attempted,
            "pid": self.pid,
            "returncode": self.returncode,
            "reason": self.reason,
            "exception_type": self.exception_type,
            "killed_owned_child": self.killed_owned_child,
            "owned_child_reaped": self.owned_child_reaped,
            "drains_complete": self.drains_complete,
            "cleanup_exception_type": self.cleanup_exception_type,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": len(self.stderr),
        }


def profile():
    work = Path("/tmp/pamolive-p2-installed-123-1")
    row = {
        "Running": False,
        "OOMKilled": False,
        "ExitCode": 0,
        "Profile": {
            "Memory": 512 * 1024**2,
            "MemorySwap": 512 * 1024**2,
            "NanoCpus": 10**9,
            "PidsLimit": 128,
            "ShmSize": 16 * 1024**2,
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
        "Entrypoint": ["/usr/local/bin/python3"],
        "Cmd": ["-I", "-B", "-c", ENTRY.decode()],
        "Init": True,
        "GroupAdd": None,
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "64k", "max-file": "1"}},
        "Env": ["HOME=/tmp/p2-installed-home", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"],
    }
    env = dict(value.split("=", 1) for value in row["Env"])
    return work, row, env


class SeamTests(unittest.TestCase):
    def test_subclass_real_constructor_preserves_parent_context_and_checks_new_entry(self):
        legacy = SimpleNamespace(LocalDocker=type("LocalDocker", (), {}), strict_json=json.loads)
        client_type = host_seam.client_class(
            ENTRY, sha(ENTRY), controller=P2, legacy=legacy, bounded=object()
        )
        state = {"type": host_seam.STATE, "phase": host_seam.PHASE}
        original = P2.regular

        def files(path, maximum, empty=False):
            if path == P2.CLI:
                return b"PUBLIC_CLI_MODEL"
            return original(path, maximum, empty)

        with patch.object(P2, "regular", side_effect=files):
            client = client_type(Path("/tmp/work"), {}, state, 123.0)
        self.assertIs(client.state, state)
        self.assertEqual(client.entry_raw, ENTRY)
        self.assertEqual(client.work_deadline, 123.0)
        self.assertEqual(client.cleanup_deadline, 183.0)
        self.assertEqual(client.expected_environment["HOME"], "/tmp/p2-installed-home")
        self.assertIs(client_type.inspect, client_type.__mro__[1].inspect)
        self.assertIs(client_type.command, client_type.__mro__[1].command)
        with self.assertRaises(ValueError):
            host_seam.client_class(ENTRY, "0" * 64, controller=Mock())
        with self.assertRaises(ValueError):
            client_type(Path("/tmp/work"), {}, {"type": "OLD", "phase": host_seam.PHASE})

    def test_create_arguments_are_exact_parent_and_contain_new_entry(self):
        work, _, _ = profile()
        pins = {"image": "PINNED_PUBLIC_S0"}
        actual = host_seam.create_arguments(work, pins, ENTRY, sha(ENTRY))
        self.assertEqual(actual, P2.create_arguments(work, pins, ENTRY))
        self.assertEqual(actual[-1], ENTRY.decode())
        for pair in (
            ("--memory", "512m"),
            ("--cpus", "1"),
            ("--network", "none"),
            ("--ipc", "private"),
        ):
            self.assertEqual(actual[actual.index(pair[0]) + 1], pair[1])
        self.assertIn("--init", actual)

    def test_actual_inherited_inspect_refuses_old_command_and_profile_mutations(self):
        work, row, environment = profile()

        class Local:
            def inspect(self, cid):
                return copy.deepcopy(self.response)

        cls = host_seam.client_class(
            ENTRY,
            sha(ENTRY),
            controller=P2,
            legacy=SimpleNamespace(LocalDocker=Local),
            bounded=None,
        )
        client = object.__new__(cls)
        client.work, client.entry_raw, client.expected_environment = work, ENTRY, environment
        client.response = row
        self.assertEqual(client.inspect("owned"), row)
        for key, bad in (
            ("Memory", 513 * 1024**2),
            ("NetworkMode", "bridge"),
            ("Privileged", True),
            ("CapAdd", ["SYS_ADMIN"]),
        ):
            with self.subTest(key=key):
                client.response = copy.deepcopy(row)
                client.response["Profile"][key] = bad
                with self.assertRaises(P2.Refusal):
                    client.inspect("owned")
        for key, bad in (
            ("Cmd", ["-I", "-B", "-c", "OLD_VERIFIER_PAYLOAD"]),
            ("Init", False),
            ("Env", ["HOME=/tmp/other"]),
        ):
            with self.subTest(key=key):
                client.response = {**copy.deepcopy(row), key: bad}
                with self.assertRaises(P2.Refusal):
                    client.inspect("owned")

    def test_actual_command_journals_pending_before_fake_bounded_IO_and_latches_uncertainty(self):
        result = Result()
        state = {"IO": [], "IO_total": 0, "IO_uncertain": False}
        records = []

        def capped(command, **limits):
            self.assertEqual(state["IO"][-1]["reason"], "pending")
            self.assertIsNone(state["IO"][-1]["spawn_attempted"])
            self.assertEqual(limits["stdout_cap"], 512 * 1024)
            self.assertEqual(limits["stderr_cap"], 16384)
            return result

        cls = host_seam.client_class(
            ENTRY,
            sha(ENTRY),
            controller=P2,
            legacy=SimpleNamespace(LocalDocker=type("Local", (), {})),
            bounded=SimpleNamespace(run_capped=capped),
        )
        client = object.__new__(cls)
        client.state, client.work, client.prefix, client.env = (
            state,
            Path("/tmp/work"),
            ["fixed-cli"],
            {},
        )
        client.cleaning, client.work_deadline, client.cleanup_deadline = False, 200, 260
        with (
            patch.object(P2.time, "monotonic", return_value=100),
            patch.object(
                P2, "persist_io", side_effect=lambda *_: records.append(copy.deepcopy(state))
            ),
        ):
            self.assertEqual(client.command("start", "--attach", "owned")[0], 0)
            self.assertTrue(P2.io_history_released(state))
            result.drains_complete = False
            with self.assertRaises(P2.Refusal):
                client.command("start", "--attach", "owned")
            self.assertTrue(state["IO_uncertain"])
            result.drains_complete = True
            client.command("start", "--attach", "owned")
            self.assertFalse(P2.io_history_released(state))
        self.assertTrue(records)

    def test_attach_success_and_failed42_are_distinct_observations(self):
        self.assertTrue(host_seam.accept_attach(Result(), EXPECTED, SOURCE, INPUT, SQL)["ok"])
        failed = host_seam.accept_attach(Result(42, packet(False)), EXPECTED, SOURCE, INPUT, SQL)
        self.assertFalse(failed["ok"])
        self.assertEqual(failed["packet"]["child"]["failure_code"], "TESTS")
        for value, code in ((packet(), 42), (packet(False), 0)):
            with self.assertRaises(ValueError):
                host_seam.accept_attach(Result(code, value), EXPECTED, SOURCE, INPUT, SQL)

    def test_attach_bad_facts_or_raw_output_never_parse_as_success(self):
        for field, bad in (
            ("owned_child_reaped", False),
            ("drains_complete", False),
            ("killed_owned_child", True),
            ("exception_type", "ValueError"),
            ("pid", None),
        ):
            result = Result()
            setattr(result, field, bad)
            with self.subTest(field=field), self.assertRaises(ValueError):
                host_seam.accept_attach(result, EXPECTED, SOURCE, INPUT, SQL)
        for raw in (
            b"raw logs",
            b"x" * (schema.MAX_PACKET + 1),
            json.dumps({"schema": "pamolive.p2-installed-ci-packet/1"}).encode(),
        ):
            result = Result()
            result.stdout = raw
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                host_seam.accept_attach(result, EXPECTED, SOURCE, INPUT, SQL)

    def test_real_accept_attach_binds_child_input_SQL_and_exact_init_origin(self):
        for field in ("input_sha256", "sql_sha256", "origin"):
            with self.subTest(field=field):
                value = packet()
                if field == "input_sha256":
                    value["child"]["input_sha256"] = "5" * 64
                elif field == "sql_sha256":
                    value["child"]["installed"]["sql_sha256"] = "5" * 64
                else:
                    value["child"]["venv"]["origins"]["pamolive_vault_runtime"] = (
                        "lib/python3.12/site-packages/pamolive_vault_runtime/foreign/__init__.py"
                    )
                raw = schema.encode(value["child"])
                value["child_sha256"], value["child_bytes"] = sha(raw), len(raw)
                with self.assertRaises(ValueError):
                    host_seam.accept_attach(Result(value=value), EXPECTED, SOURCE, INPUT, SQL)
        failed = packet(False)
        failed["child"]["input_sha256"] = "6" * 64
        raw = schema.encode(failed["child"])
        failed["child_sha256"], failed["child_bytes"] = sha(raw), len(raw)
        self.assertFalse(
            host_seam.accept_attach(Result(42, failed), EXPECTED, SOURCE, INPUT, SQL)["ok"]
        )

    def test_scope_binding_mixtures_never_promote_failed_or_foreign_success(self):
        for mask in range(1, 8):
            value = packet()
            if mask & 1:
                value["child"]["input_sha256"] = "7" * 64
            if mask & 2:
                value["child"]["installed"]["sql_sha256"] = "8" * 64
            if mask & 4:
                value["child"]["venv"]["origins"]["pamolive_vault_runtime"] = (
                    "lib/python3.12/site-packages/pamolive_vault_runtime/shadow/__init__.py"
                )
            raw = schema.encode(value["child"])
            value["child_sha256"], value["child_bytes"] = sha(raw), len(raw)
            with self.subTest(mask=mask), self.assertRaises(ValueError):
                host_seam.accept_attach(Result(value=value), EXPECTED, SOURCE, INPUT, SQL)
