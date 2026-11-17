"""Read-only preflight projection tests, no tool execution."""

import ast
import json
import unittest
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

from qualification.build_origin import commands
from qualification.build_origin import preflight as p


class ReadonlyTests(unittest.TestCase):
    def test_missing_explicit_policy_refuses(self):
        for policy in (None, True, "unknown"):
            chain = {"family": "ip", "type": "filter", "hook": "forward"}
            if policy is not None:
                chain["policy"] = policy
            with self.assertRaises(ValueError):
                p.policy_projection(json.dumps({"nftables": [{"chain": chain}]}).encode(), None)

    def test_late_posthash_controller_keeps_UNKNOWN_and_never_commits_DATA(self):
        clock, observed, runs, writes = [0.0], [], [], {}

        class MP(PurePosixPath):
            def mkdir(self, **kw):
                pass

            def absolute(self):
                return self

        def write(path, raw, *args):
            writes[str(path)] = raw

        def run(argv, **kw):
            runs.append(argv)
            kw["on_spawn"](100 + len(runs))
            stdout = (
                b"ip utility, iproute2-6.1.0\n"
                if argv[0] == p.profile.PATHS["ip"]
                else b"Vendor 1.2.3\n"
            )
            return SimpleNamespace(
                ok=True,
                spawn_attempted=True,
                pid=100 + len(runs),
                returncode=0,
                killed_owned_child=False,
                exception_type=None,
                cleanup_exception_type=None,
                stdout=stdout,
                stderr=b"",
                facts=lambda: {"memory_fixture_only": True},
            )

        def observed_tool(role, *, until_ns):
            observed.append(role)
            if len(observed) == 18:
                clock[0] = 200.0
            return {"sha256": "a" * 64}

        def owner(root, env):
            return commands.Commands(root, env, runner=run, now=lambda: clock[0])

        route = (
            b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
            b"eth0\t00000000\t01020304\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        )

        def proc(path, cap, *, until_ns):
            return b"1\n" if path.endswith("ip_forward") else route

        env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY_ID": "1449671447",
            "GITHUB_REPOSITORY_OWNER_ID": "305596298",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "PAMOLIVE_DISPOSABLE_ORIGIN_JOB": "true",
        }
        with (
            patch.object(p, "Path", MP),
            patch.object(p, "Commands", owner),
            patch.object(p, "observed_tool", observed_tool),
            patch.object(p, "proc_bytes", proc),
            patch.object(p, "exclusive", write),
            patch.object(commands, "exclusive", write),
            patch.object(p.os, "getuid", return_value=1001, create=True),
            patch.object(p.os, "umask", return_value=0),
            patch.dict(p.os.environ, env, clear=True),
            patch.object(p.sys, "platform", "linux"),
            patch.object(p.sys, "executable", p.profile.PATHS["python"]),
            patch.object(p.time, "monotonic_ns", side_effect=lambda: int(clock[0] * 1e9)),
            patch.object(p.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                p.sys,
                "argv",
                [
                    "preflight.py",
                    "measure-vendor",
                    "--ack-trusted-public-vendor-TCB",
                    "--out",
                    "/synthetic/new",
                ],
            ),
        ):
            with self.assertRaises(SystemExit) as raised:
                p.main()
        self.assertEqual(raised.exception.code, 42)
        self.assertEqual(len(runs), 9)
        self.assertFalse(any(name.endswith("readonly-DATA.json") for name in writes))
        packet = json.loads(writes["/synthetic/new/public/failure.json"])
        self.assertEqual(packet["state"], "UNKNOWN")
        self.assertTrue(packet["no_more_spawns"])

    def test_proc_short_reads_require_EOF_and_deadline(self):
        with (
            patch.object(p.os, "open", return_value=4),
            patch.object(p.os, "close"),
            patch.object(p.os, "O_NOFOLLOW", 0, create=True),
            patch.object(p.os, "read", side_effect=[b"1", b"\n", b""]),
            patch.object(p.time, "monotonic_ns", return_value=0),
        ):
            self.assertEqual(
                p.proc_bytes("/proc/sys/net/ipv4/ip_forward", 16, until_ns=100), b"1\n"
            )
        with (
            patch.object(p.os, "open", return_value=4),
            patch.object(p.os, "close"),
            patch.object(p.os, "O_NOFOLLOW", 0, create=True),
            patch.object(p.os, "read", return_value=b"1\n"),
            patch.object(p.time, "monotonic_ns", side_effect=[0, 0, 101]),
        ):
            with self.assertRaisesRegex(ValueError, "preflight_deadline"):
                p.proc_bytes("/proc/sys/net/ipv4/ip_forward", 16, until_ns=100)

    def test_expired_hash_refuses_before_open_or_read(self):
        with (
            patch.object(p.time, "monotonic_ns", return_value=101),
            patch.object(p.os, "open") as opened,
        ):
            with self.assertRaisesRegex(ValueError, "preflight_deadline"):
                p.observed_tool("python", until_ns=100)
            opened.assert_not_called()

    def test_drop_is_observed_without_exporting_rule_or_address(self):
        raw = json.dumps(
            {
                "nftables": [
                    {
                        "chain": {
                            "family": "ip",
                            "table": "PRIVATE_TABLE",
                            "name": "PRIVATE_CHAIN",
                            "type": "filter",
                            "hook": "forward",
                            "policy": "drop",
                        }
                    }
                ]
            }
        ).encode()
        value = p.policy_projection(raw, b"filter\n")
        self.assertEqual(value["classification"], "DROP_POLICY_OBSERVED")
        self.assertEqual(value["drop_policies"], 1)
        self.assertTrue(value["legacy_filter_present"])
        self.assertFalse(value["legacy_policy_known"])
        self.assertNotIn("PRIVATE", json.dumps(value))

    def test_accept_and_absent_legacy_are_not_connectivity_proof(self):
        raw = (
            b'{"nftables":[{"chain":{"family":"inet","type":"filter",'
            b'"hook":"forward","policy":"accept"}}]}'
        )
        value = p.policy_projection(raw, None)
        self.assertEqual(value["classification"], "NO_DROP_POLICY_IN_NFT_SNAPSHOT")
        self.assertIsNone(value["legacy_filter_present"])
        self.assertFalse(value["legacy_names_available"])
        self.assertFalse(value["owned_veth_connectivity_proved"])
        self.assertTrue(value["rules_can_still_deny"])

    def test_unknown_policy_and_duplicate_JSON_refuse(self):
        for raw in (
            b'{"nftables":[],"nftables":[]}',
            b'{"nftables":[{"chain":{"family":"ip","type":"filter","hook":"forward","policy":"PRIVATE"}}]}',
        ):
            with self.assertRaises(ValueError):
                p.policy_projection(raw, b"")

    def test_route_projection_has_no_addresses(self):
        raw = (
            b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
            b"eth0\t00000000\t01020304\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        )
        value = p.route_projection(raw)
        self.assertEqual(value["uplink_label"], "eth0")
        self.assertNotIn("01020304", json.dumps(value))
        self.assertFalse(value["raw_addresses_exported"])
        with self.assertRaises(ValueError):
            p.route_projection(raw + raw.splitlines(keepends=True)[1])

    def test_proc_role_never_reads_arbitrary_path(self):
        with self.assertRaisesRegex(ValueError, "preflight_proc_role"):
            p.proc_bytes("/etc/shadow", 100, until_ns=10**30)

    def test_source_has_only_version_and_list_chains_command_roles(self):
        tree = ast.parse((Path(__file__).parent / "preflight.py").read_bytes())
        calls = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and ast.unparse(n.func) == "cmd.run"
        ]
        self.assertEqual(len(calls), 2)
        text = "\n".join(ast.unparse(n) for n in calls)
        for banned in ("netns", "sysctl", "install", "flush", "add", "delete", "ruleset"):
            self.assertNotIn(banned, text)
        self.assertIn("'list', 'chains'", text)
