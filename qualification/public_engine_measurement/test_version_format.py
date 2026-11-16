"""Unknown version stdout remains refused; only finite public shape is exposed."""

import copy
import json
import unittest

import containerd_public as p
from test_containerd_public import fs, plugins, result, tool


class VersionFormatTests(unittest.TestCase):
    def test_parent_format_requires_complete_inner_h1_and_stable_ctr(self):
        packet, _, _ = self.inspect(b"ctr github.com/containerd/containerd/v2 2.4.2+unknown\n")
        self.assertIn("version_format", p.refusal_diagnostic(packet))
        variants = []
        for key, bad in (
            ("spawn_attempted", False),
            ("pid", True),
            ("pid", 0),
            ("returncode", True),
            ("returncode", 42),
            ("reason", "timeout"),
            ("exception_type", "TimeoutError"),
            ("killed_owned_child", True),
            ("owned_child_reaped", False),
            ("drains_complete", False),
            ("cleanup_exception_type", "OSError"),
        ):
            value = copy.deepcopy(packet)
            value["version_process"][key] = bad
            variants.append(value)
        for mutate in (
            lambda v: v.update(authority=True),
            lambda v: v.update(profile_accepted=True),
            lambda v: v.update(operational_GO=True),
            lambda v: v.update(ctr_process={}),
            lambda v: v.update(exports={}),
            lambda v: v.update(filesystems={}),
            lambda v: v.update(tool_unchanged=False),
            lambda v: v.update(tool=None),
            lambda v: v["tool"].update(nlink=2),
            lambda v: v.update(version_process=None),
            lambda v: v["version_process"].pop("pid"),
            lambda v: v["version_process"].update(extra="SYNTHETIC_PRIVATE"),
        ):
            value = copy.deepcopy(packet)
            mutate(value)
            variants.append(value)
        for value in variants:
            with self.assertRaises(ValueError):
                p.refusal_diagnostic(value)

    def inspect(self, raw, **changes):
        calls = []
        stats = []

        def run(argv, **options):
            calls.append((argv, options))
            return result(raw if len(calls) == 1 else plugins(), **changes)

        def statter(path):
            stats.append(path)
            return fs(path)

        packet = p.inspect_roots("/run/containerd/containerd.sock", run, tool, statter)
        return packet, calls, stats

    def test_reviewed_exact_grammar_still_uses_original_admission(self):
        for version in (b"v2.2.3", b"2.2.3", b"v2.4.2", b"2.4.2"):
            packet, calls, stats = self.inspect(
                b"ctr github.com/containerd/containerd/v2 " + version + b"\n"
            )
            self.assertEqual(p.validate_packet(packet), packet)
            self.assertNotIn("version_format", packet)
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(stats), 4)

    def test_suffix_or_legacy_never_reaches_plugins_or_storage(self):
        for module, expected in (
            (b"github.com/containerd/containerd/v2", "module_v2"),
            (b"github.com/containerd/containerd", "module_legacy"),
            (b"SYNTHETIC_PRIVATE", "other_redacted"),
        ):
            for suffix, label in ((b"+unknown", "plus_unknown"), (b"-private", "other_redacted")):
                packet, calls, stats = self.inspect(b"ctr " + module + b" v2.4.2" + suffix + b"\n")
                self.assertEqual(packet["status"], "CLI_UNREVIEWED")
                self.assertIsNone(packet["cli_identity"])
                diagnostic = p.refusal_diagnostic(packet)["version_format"]
                self.assertEqual(diagnostic["numeric_triplet"], [2, 4, 2])
                self.assertEqual(diagnostic["package"], expected)
                self.assertEqual(diagnostic["suffix_kind"], label)
                self.assertEqual(len(calls), 1)
                self.assertEqual(stats, [])
                self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(diagnostic))
                self.assertNotIn("-private", json.dumps(diagnostic))
                with self.assertRaises(ValueError):
                    p.validate_packet(packet)

    def test_no_raw_text_hash_or_length_for_unrecognized_output(self):
        for raw in (
            b"SYNTHETIC_PRIVATE\n",
            b"ctr SYNTHETIC_PRIVATE v2.4.2+SYNTHETIC_PRIVATE\n",
            b"ctr github.com/containerd/containerd/v2 2.4.2\x00private\n",
            b"ctr github.com/containerd/containerd/v2 2.4.2\x1b[31m\n",
            b"ctr github.com/containerd/containerd/v2 2.4.2\xff\n",
            b"ctr github.com/containerd/containerd/v2 2.4.2\nSYNTHETIC_PRIVATE\n",
            b"ctr github.com/containerd/containerd/v2 2.4.2  SYNTHETIC_PRIVATE\n",
            b"x" * 513,
        ):
            diagnostic = p.version_format_diagnostic(raw)
            self.assertEqual(p.validate_version_format(diagnostic), diagnostic)
            public = json.dumps(diagnostic)
            self.assertNotIn("SYNTHETIC_PRIVATE", public)
            self.assertNotIn("sha256", public)
            self.assertNotIn("bytes", public)
            self.assertNotIn("length", public)
            self.assertLess(len(public), 250)

    def test_numeric_match_outside_allowlist_is_not_format_failure(self):
        packet, calls, stats = self.inspect(b"ctr github.com/containerd/containerd/v2 v9.9.9\n")
        self.assertEqual(packet["status"], "CLI_UNREVIEWED")
        self.assertEqual(
            packet["cli_identity"],
            {"package": "github.com/containerd/containerd/v2", "version": "v9.9.9"},
        )
        self.assertNotIn("version_format", packet)
        self.assertEqual(len(calls), 1)
        self.assertEqual(stats, [])

    def test_incomplete_h1_or_nonzero_never_becomes_format_evidence(self):
        for changes in (
            {"owned_child_reaped": False},
            {"drains_complete": False},
            {"code": 42},
        ):
            packet, calls, stats = self.inspect(
                b"ctr github.com/containerd/containerd/v2 2.4.2+unknown\n", **changes
            )
            self.assertNotEqual(packet["status"], "COMPLETE")
            self.assertNotIn("version_format", packet)
            self.assertEqual(len(calls), 1)
            self.assertEqual(stats, [])

    def test_parent_rejects_malformed_diagnostic_and_wrong_state(self):
        good = p.version_format_diagnostic(
            b"ctr github.com/containerd/containerd/v2 2.4.2+unknown\n"
        )
        mutations = (
            lambda v: v.update(extra="SYNTHETIC_PRIVATE"),
            lambda v: v.update(package="SYNTHETIC_PRIVATE"),
            lambda v: v.update(package=[]),
            lambda v: v.update(suffix_kind="SYNTHETIC_PRIVATE"),
            lambda v: v.update(suffix_kind=[]),
            lambda v: v.update(form=[]),
            lambda v: v.update(prefix_v=1),
            lambda v: v.update(numeric_triplet=[True, 4, 2]),
            lambda v: v.update(numeric_triplet=[100, 4, 2]),
            lambda v: v.update(numeric_triplet=[2, 4, 1000]),
            lambda v: v.update(numeric_triplet=[2, 4, 2, 1]),
        )
        for mutate in mutations:
            value = copy.deepcopy(good)
            mutate(value)
            with self.assertRaises(ValueError):
                p.validate_version_format(value)
        for state, cli in (("UNKNOWN", None), ("CLI_UNREVIEWED", "v9.9.9"), ("COMPLETE", None)):
            with self.assertRaises(ValueError):
                p.refusal_diagnostic(
                    {
                        "schema": "public-containerd-roots/3",
                        "status": state,
                        "cli_identity": None
                        if cli is None
                        else {"package": "github.com/containerd/containerd/v2", "version": cli},
                        "version_format": good,
                    }
                )

    def test_redacted_form_has_no_optional_fields(self):
        good = {"schema": "ctr-version-format-DATA/1", "form": "redacted"}
        self.assertEqual(p.validate_version_format(good), good)
        for key in ("numeric_triplet", "package", "prefix_v", "suffix_kind"):
            with self.assertRaises(ValueError):
                p.validate_version_format(good | {key: None})
