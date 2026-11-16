"""ROOT3 finite package/version pairs, actual parent projections and no learning."""

import copy
import json
import unittest

import containerd_public as p
import test_containerd_public as fixtures


class CliIdentityTests(unittest.TestCase):
    def inspect(self, raw, **facts):
        calls, stats = [], []

        def runner(argv, **options):
            calls.append((argv, options))
            return fixtures.result(raw if len(calls) == 1 else fixtures.plugins(), **facts)

        def statter(path):
            stats.append(path)
            return fixtures.fs(path)

        value = p.inspect_roots("/run/containerd/containerd.sock", runner, fixtures.tool, statter)
        return value, calls, stats

    def parent(self, packet):
        case = fixtures.ParentTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.run_root(reply=fixtures.result(json.dumps(packet).encode()))
        return case.report["containerd_prerequisites"]

    def test_all_eight_exact_pairs_keep_package_and_version(self):
        expected = {
            (package, prefix + version)
            for package, versions in (
                ("github.com/containerd/containerd/v2", ("2.2.3", "2.4.2")),
                ("containerd", ("2.4.2",)),
                ("containerd.io", ("2.4.2",)),
            )
            for version in versions
            for prefix in ("", "v")
        }
        self.assertEqual(p.CLI_PAIRS, expected)
        for package, version in expected:
            packet, calls, stats = self.inspect(f"ctr {package} {version}\n".encode())
            self.assertEqual(packet["schema"], "public-containerd-roots/3")
            self.assertEqual(packet["status"], "COMPLETE")
            self.assertEqual(packet["cli_identity"], {"package": package, "version": version})
            self.assertNotIn("cli_version", packet)
            self.assertNotIn("version_format", packet)
            self.assertEqual(p.validate_packet(packet), packet)
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(stats), 4)

    def test_unknown_suffix_label_pair_and_nonexact_stdout_stop_before_plugins(self):
        lines = (
            b"ctr containerd v2.2.3\n",
            b"ctr containerd.io 2.2.3\n",
            b"ctr containerd v9.9.9\n",
            b"ctr containerd.io v2.4.3\n",
            b"ctr containerd v2.04.2\n",
            b"ctr containerd.io v2.4.2+unknown\n",
            b"ctr containerd v2.4.2-vendor\n",
            b"ctr CONTAINERD v2.4.2\n",
            b"ctr containerd.io.evil v2.4.2\n",
            b"ctr github.com/containerd/containerd v2.4.2\n",
            b"ctr arbitrary-private-label v2.4.2\n",
            b"ctr containerd  v2.4.2\n",
            b"ctr containerd v2.4.2\r\n",
            b"ctr containerd v2.4.2\ntrailing\n",
            b"ctr containerd v2.4.2\x00\n",
            b"ctr containerd v2.4.2",
        )
        for line in lines:
            with self.subTest(line=line):
                packet, calls, stats = self.inspect(line)
                self.assertEqual(packet["status"], "CLI_UNREVIEWED")
                self.assertEqual(len(calls), 1)
                self.assertEqual(stats, [])
                self.assertIsNone(packet["ctr_process"])
                self.assertIsNone(packet["exports"])
                with self.assertRaises(ValueError):
                    p.validate_packet(packet)

    def test_parent_preserves_each_packaging_label_as_distinct_data(self):
        identities = []
        for package in ("containerd", "containerd.io"):
            packet, _, _ = self.inspect(f"ctr {package} v2.4.2\n".encode())
            row = self.parent(packet)
            self.assertEqual(row["status"], "COMPLETE")
            self.assertEqual(row["data"]["cli_identity"], packet["cli_identity"])
            identities.append(row["data"]["cli_identity"])
            self.assertIs(row["profile_accepted"], False)
            self.assertIs(row["operational_GO"], False)
        self.assertNotEqual(identities[0], identities[1])

    def test_parent_typed_identity_rejects_unreviewed_or_malformed_fields(self):
        packet, _, _ = self.inspect(b"ctr containerd v2.4.2\n")
        for identity in (
            None,
            "v2.4.2",
            [],
            {},
            {"package": "containerd"},
            {"version": "v2.4.2"},
            {"package": [], "version": "v2.4.2"},
            {"package": "containerd", "version": 2.4},
            {"package": "containerd.io.evil", "version": "v2.4.2"},
            {"package": "containerd", "version": "v2.2.3"},
            {"package": "containerd", "version": "v9.9.9"},
            {"package": "containerd", "version": "v2.4.2+unknown"},
            {"package": "containerd", "version": "v2.4.2", "extra": False},
        ):
            bad = copy.deepcopy(packet)
            bad["cli_identity"] = identity
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                p.validate_packet(bad)
        bad = copy.deepcopy(packet)
        bad["cli_identity"] = {"package": "containerd", "version": "v2.2.3"}
        row = self.parent(bad)
        self.assertNotEqual(row["status"], "COMPLETE")
        self.assertIsNone(row["data"])

    def test_current_parent_refuses_historical_schemas_and_old_field(self):
        packet, _, _ = self.inspect(b"ctr containerd v2.4.2\n")
        for schema in ("public-containerd-roots/1", "public-containerd-roots/2"):
            bad = copy.deepcopy(packet)
            bad["schema"] = schema
            with self.assertRaises(ValueError):
                p.validate_packet(bad)
            row = self.parent(bad)
            self.assertNotEqual(row["status"], "COMPLETE")
            self.assertIsNone(row["data"])
        for old in (None, "v2.4.2"):
            bad = copy.deepcopy(packet)
            bad["cli_version"] = old
            with self.assertRaises(ValueError):
                p.validate_packet(bad)

    def test_root2_diagnostic_strict_context_cannot_learn_or_carry_old_key(self):
        packet, _, _ = self.inspect(b"ctr synthetic-private v2.4.2\n")
        self.assertIsNone(packet["cli_identity"])
        row = p.refusal_diagnostic(packet)
        self.assertEqual(row["version_format"]["package"], "other_redacted")
        self.assertNotIn("synthetic-private", json.dumps(row))
        for mutate in (
            lambda v: v.update(cli_version=None),
            lambda v: v.update(cli_identity={"package": "containerd", "version": "v2.4.2"}),
            lambda v: v.update(exports={}),
            lambda v: v.update(filesystems={}),
            lambda v: v.update(ctr_process={}),
            lambda v: v.update(authority=True),
            lambda v: v.update(profile_accepted=True),
            lambda v: v.update(operational_GO=True),
            lambda v: v.update(tool_unchanged=False),
            lambda v: v["version_process"].update(owned_child_reaped=False),
            lambda v: v["version_process"].update(returncode=42),
        ):
            bad = copy.deepcopy(packet)
            mutate(bad)
            with self.assertRaises(ValueError):
                p.refusal_diagnostic(bad)

    def test_packaging_labels_keep_tool_h1_environment_and_query_controls(self):
        for changes in (
            {"owned_child_reaped": False},
            {"drains_complete": False},
            {"code": 42},
            {"error": b"warning"},
            {"exception_type": "OSError"},
        ):
            packet, calls, stats = self.inspect(b"ctr containerd v2.4.2\n", **changes)
            self.assertNotEqual(packet["status"], "COMPLETE")
            self.assertEqual(len(calls), 1)
            self.assertEqual(stats, [])
        packet, calls, _ = self.inspect(b"ctr containerd.io 2.4.2\n")
        self.assertEqual(calls[0][0], ["/usr/bin/ctr", "--version"])
        self.assertEqual(calls[0][1]["timeout"], 3)
        self.assertEqual(calls[1][1]["timeout"], 8)
        for _, options in calls:
            self.assertEqual(options["env"], p.ENV)
        self.assertIs(packet["profile_accepted"], False)
        self.assertIs(packet["authority"], False)
        self.assertIs(packet["operational_GO"], False)

    def test_typed_diagnostic_is_not_reviewed_version_admission(self):
        packet, calls, _ = self.inspect(b"ctr containerd v9.9.9\n")
        diagnostic = p.refusal_diagnostic(packet)
        self.assertEqual(diagnostic["cli_identity"], {"package": "containerd", "version": "v9.9.9"})
        with self.assertRaises(ValueError):
            p.validate_cli_identity(diagnostic["cli_identity"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(packet["status"], "CLI_UNREVIEWED")

    def refusal_parent(self, packet, **facts):
        case = fixtures.ParentTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.run_root(reply=fixtures.result(json.dumps(packet).encode(), code=42, **facts))
        return case.report["containerd_prerequisites"]

    def test_parent_identity_requires_closed_normal_observation_context(self):
        packet, _, _ = self.inspect(b"ctr containerd v9.9.9\n")
        changes = (
            lambda v: v.update(version_process=None),
            lambda v: v["version_process"].update(spawn_attempted=False),
            lambda v: v["version_process"].update(pid=True),
            lambda v: v["version_process"].update(pid=0),
            lambda v: v["version_process"].update(pid=2**31),
            lambda v: v["version_process"].update(returncode=42),
            lambda v: v["version_process"].update(reason="timeout"),
            lambda v: v["version_process"].update(exception_type="OSError"),
            lambda v: v["version_process"].update(killed_owned_child=True),
            lambda v: v["version_process"].update(owned_child_reaped=False),
            lambda v: v["version_process"].update(drains_complete=False),
            lambda v: v["version_process"].update(cleanup_exception_type="TimeoutError"),
            lambda v: v["version_process"].update(extra=False),
            lambda v: v.update(tool=None),
            lambda v: v["tool"].update(uid=1000),
            lambda v: v["tool"].update(nlink=2),
            lambda v: v.update(tool_unchanged=False),
            lambda v: v.update(authority=True),
            lambda v: v.update(profile_accepted=True),
            lambda v: v.update(operational_GO=True),
            lambda v: v.update(ctr_process={}),
            lambda v: v.update(exports={}),
            lambda v: v.update(filesystems={}),
            lambda v: v.update(status="UNKNOWN"),
        )
        for index, mutate in enumerate(changes):
            bad = copy.deepcopy(packet)
            mutate(bad)
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    p.refusal_diagnostic(bad)
                row = self.refusal_parent(bad)
                self.assertIsNone(row["data"])
                self.assertNotIn("diagnostic", row)
                self.assertIs(row["profile_accepted"], False)
                self.assertIs(row["operational_GO"], False)

    def test_parent_identity_normal_refusal_is_data_only_and_frontend_h1_stays_required(self):
        packet, calls, stats = self.inspect(b"ctr containerd.io v9.9.9\n")
        row = self.refusal_parent(packet)
        self.assertEqual(row["status"], "CLI_UNREVIEWED")
        self.assertEqual(
            row["diagnostic"]["cli_identity"], {"package": "containerd.io", "version": "v9.9.9"}
        )
        self.assertIsNone(row["data"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(stats, [])
        with self.assertRaises(ValueError):
            p.validate_packet(packet)
        for changes in ({"owned_child_reaped": False}, {"drains_complete": False}):
            row = self.refusal_parent(packet, **changes)
            self.assertEqual(row["status"], "UNKNOWN")
            self.assertIsNone(row["data"])
            self.assertNotIn("diagnostic", row)

    def test_identity_and_format_share_prequery_guard_without_mixing_observations(self):
        packet, _, _ = self.inspect(b"ctr containerd v9.9.9\n")
        for status in ("PERMISSION_REFUSED", "QUERY_REFUSED", "DATA_REFUSED"):
            bad = copy.deepcopy(packet)
            bad.update(status=status, ctr_process=copy.deepcopy(bad["version_process"]))
            with self.subTest(status=status), self.assertRaises(ValueError):
                p.refusal_diagnostic(bad)
        formatted, _, _ = self.inspect(b"ctr SYNTHETIC_PRIVATE v2.4.2\n")
        self.assertIsNone(formatted["cli_identity"])
        self.assertIn("version_format", p.refusal_diagnostic(formatted))
        formatted["cli_identity"] = {"package": "containerd", "version": "v9.9.9"}
        with self.assertRaises(ValueError):
            p.refusal_diagnostic(formatted)
