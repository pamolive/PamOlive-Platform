"""Adversarial checkout-capture tests; synthetic files only, no package import."""

import copy
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
c = importlib.import_module("capture_inputs")
ATTEMPTS = {}


def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "sqlite3.")) or event in {
        "os.system",
        "os.exec",
        "os.spawn",
        "os.fork",
    }:
        ATTEMPTS[event] = ATTEMPTS.get(event, 0) + 1
        raise AssertionError("capture_external_operation_refused")


class CaptureTests(unittest.TestCase):
    def fixture(self):
        # Only this explicitly named fresh tree is recursively removed.
        directory = tempfile.TemporaryDirectory(prefix="capture-test-", dir=HERE)
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()
        repo = root / "repository"
        repo.mkdir()
        notice = b"SYNTHETIC PUBLIC NOTICE\n"
        payload = {
            "schema": "pamolive.vault-installed-source-payloads/2",
            "groups": {},
            "runtime_tests": {},
            "root_notice": {"bytes": len(notice), "sha256": c.sha(notice)},
        }
        for group, count in c.COUNTS.items():
            rows = {}
            for index in range(count):
                name = (
                    "LICENSE"
                    if index == 0 and group in {"runtime", "contracts"}
                    else (
                        ("tests/" if group == "runtime-tests" else "") + group + str(index) + ".txt"
                    )
                )
                raw = notice if name == "LICENSE" else (group + str(index)).encode()
                path = repo / c.BASES[group] / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                rows[name] = {"bytes": len(raw), "sha256": c.sha(raw)}
            if group == "runtime-tests":
                payload["runtime_tests"] = rows
            else:
                payload["groups"][group] = rows
        (repo / "LICENSE").write_bytes(notice)
        return repo, root / "captured", payload

    def test_closed_capture_preserves_source_and_excludes_unselected_files(self):
        repo, destination, payload = self.fixture()
        (repo / "not-selected.txt").write_bytes(b"SYNTHETIC UNSELECTED")
        result = c.capture(repo, destination, payload)
        self.assertEqual(result["captured_files"], 35)
        self.assertEqual(len(result["files"]), 35)
        self.assertFalse(result["actual_build_install_or_authority"])
        self.assertEqual(len([p for p in destination.rglob("*") if p.is_file()]), 35)
        self.assertEqual((repo / "not-selected.txt").read_bytes(), b"SYNTHETIC UNSELECTED")

    def test_changed_source_refuses_before_first_destination_write(self):
        repo, destination, payload = self.fixture()
        (repo / "components/vault-registry/LICENSE").write_bytes(b"CHANGED")
        with self.assertRaises(ValueError):
            c.capture(repo, destination, payload)
        self.assertFalse(destination.exists())

    def test_existing_destination_is_never_overwritten(self):
        repo, destination, payload = self.fixture()
        destination.mkdir()
        marker = destination / "existing.txt"
        marker.write_bytes(b"PRESERVE")
        with self.assertRaises(ValueError):
            c.capture(repo, destination, payload)
        self.assertEqual(marker.read_bytes(), b"PRESERVE")
        self.assertEqual(list(destination.iterdir()), [marker])

    def test_traversal_absolute_and_false_size_are_rejected(self):
        _, _, payload = self.fixture()
        for name in ("../foreign", "/foreign", "a/../foreign", "a\\foreign", "a//foreign"):
            mutated = copy.deepcopy(payload)
            rows = mutated["groups"]["runtime"]
            rows[name] = rows.pop("LICENSE")
            with self.subTest(name=name), self.assertRaises(ValueError):
                c.selected(mutated)
        mutated = copy.deepcopy(payload)
        mutated["groups"]["runtime"]["LICENSE"]["bytes"] = True
        with self.assertRaises(ValueError):
            c.selected(mutated)

    def test_duplicate_repository_source_cannot_fill_two_roles(self):
        repo, destination, payload = self.fixture()
        rows = payload["runtime_tests"]
        rows["LICENSE"] = copy.deepcopy(payload["groups"]["runtime"]["LICENSE"])
        del rows[next(name for name in rows if name != "LICENSE")]
        with self.assertRaises(ValueError):
            c.capture(repo, destination, payload)
        self.assertFalse(destination.exists())

    def test_wrong_root_notice_refuses_before_writes(self):
        repo, destination, payload = self.fixture()
        (repo / "LICENSE").write_bytes(b"ANOTHER NOTICE")
        with self.assertRaises(ValueError):
            c.capture(repo, destination, payload)
        self.assertFalse(destination.exists())

    def test_changed_second_read_retains_failed_capture_without_success(self):
        repo, destination, payload = self.fixture()
        original = c.read_regular
        observed = {}

        def read(path, cap):
            observed[path] = observed.get(path, 0) + 1
            if path == repo / "components/vault-registry/LICENSE" and observed[path] == 2:
                return b"SYNTHETIC SECOND READ CHANGE"
            return original(path, cap)

        with patch.object(c, "read_regular", read), self.assertRaises(ValueError):
            c.capture(repo, destination, payload)
        self.assertTrue(destination.exists())
        self.assertEqual(len([p for p in destination.rglob("*") if p.is_file()]), 35)


if __name__ == "__main__":
    sys.addaudithook(audit)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CaptureTests)
    if suite.countTestCases() != 7:
        raise SystemExit("Closed seven capture tests required")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": len(result.skipped),
        "external_attempts": ATTEMPTS,
        "synthetic_files_only": True,
        "build_install_Docker_SQL_or_product_import": False,
    }
    print(json.dumps(summary))
    raise SystemExit(
        0
        if result.wasSuccessful() and result.testsRun == 7 and not result.skipped and not ATTEMPTS
        else 1
    )
