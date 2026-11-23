"""Closed-scope and ownership tests for the stock-runner preflight."""

import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from qualification.p1g_headless import chrome_canonical_preflight as preflight
from qualification.p1g_headless import chrome_sandbox_probe as probe
from qualification.p1g_headless.test_chrome_sandbox_probe import ENV

PIN = {"bytes": probe.CHROME_BYTES, "sha256": probe.CHROME_SHA, "uid": 0, "mode": 0o755}


def row(mode, *, uid=0, gid=0, size=probe.CHROME_BYTES, links=1):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid, st_size=size, st_nlink=links)


class CanonicalPreflightTests(unittest.TestCase):
    def inspect(self, overrides, pin=PIN):
        paths = (*reversed(preflight.BINARY.parents), preflight.BINARY)
        entries = dict.fromkeys(paths[:-1], row(stat.S_IFDIR | 0o755))
        entries[paths[-1]] = row(stat.S_IFREG | 0o755)
        entries.update(overrides)
        with (
            patch.object(
                type(preflight.BINARY), "lstat", autospec=True, side_effect=entries.__getitem__
            ) as stat_path,
            patch.object(preflight.support, "tool_pin", return_value=pin) as reader,
        ):
            result = preflight.inspect_executable()
        return result, [call.args[0] for call in stat_path.call_args_list], reader

    def test_pin_match_requires_the_canonical_root_owned_chain(self):
        result, visited, reader = self.inspect({})
        self.assertEqual(result["state"], "ELF_PIN_MATCH")
        self.assertEqual(result["executable"], PIN)
        self.assertEqual(visited, [*reversed(preflight.BINARY.parents), preflight.BINARY])
        reader.assert_called_once_with(preflight.BINARY, cap=probe.CHROME_BYTES)

    def test_refuses_to_traverse_untrusted_ancestor_or_hash_executable(self):
        ancestor = preflight.BINARY.parents[2]
        for bad in (
            row(stat.S_IFDIR | 0o777),
            row(stat.S_IFDIR | 0o755, gid=1001),
            row(stat.S_IFLNK | 0o755),
        ):
            with self.subTest(mode=bad.st_mode, gid=bad.st_gid):
                result, visited, reader = self.inspect({ancestor: bad})
                self.assertEqual(result["code"], "canonical_ancestor_untrusted")
                self.assertEqual(visited[-1], ancestor)
                self.assertNotIn(preflight.BINARY, visited)
                reader.assert_not_called()

    def test_refuses_hardlink_writable_file_or_different_size_before_hashing(self):
        for bad, code in (
            (row(stat.S_IFREG | 0o755, links=2), "canonical_executable_untrusted"),
            (row(stat.S_IFREG | 0o775), "canonical_executable_untrusted"),
            (row(stat.S_IFREG | 0o755, size=1), "canonical_elf_size_mismatch"),
        ):
            with self.subTest(bad=bad):
                result, _, reader = self.inspect({preflight.BINARY: bad})
                self.assertEqual(result["code"], code)
                reader.assert_not_called()

    def test_different_executable_hash_refuses_without_exporting_unknown_hash(self):
        result, _, _ = self.inspect({}, pin={**PIN, "sha256": "0" * 64})
        self.assertEqual(result["code"], "canonical_elf_hash_mismatch")
        self.assertNotIn("executable", result)

    def test_canonical_branch_has_separate_push_scope(self):
        env = {**ENV, "GITHUB_REF": preflight.BRANCH}
        self.assertEqual(probe.run_identity(env, branch=preflight.BRANCH)["run"], "25")
        with self.assertRaisesRegex(ValueError, "sandbox_probe_scope"):
            probe.run_identity(env)
        with self.assertRaisesRegex(ValueError, "sandbox_probe_scope"):
            probe.run_identity(ENV, branch=preflight.BRANCH)
