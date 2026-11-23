"""Verify classifications in the native Debian glibc test summary."""

import subprocess
import unittest
from pathlib import Path

SUMMARY = Path(__file__).resolve().parents[2] / "deploy/glibc-trixie-backport/test-summary.awk"


def summarize(*lines):
    return subprocess.run(
        ["awk", "-v", "flavour=libc", "-f", str(SUMMARY)],
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


class TestSuiteSummary(unittest.TestCase):
    def test_all_passes_are_reported(self):
        result = summarize("PASS: intl/case-one", "PASS: intl/case-two")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("suite.libc.PASS=2", result.stdout.splitlines())
        self.assertIn("suite.libc.result=no_unexpected_failures", result.stdout.splitlines())

    def test_expected_failure_and_unsupported_retain_their_details(self):
        details = ("XFAIL: intl/known-issue", "UNSUPPORTED: intl/unavailable-locale")
        result = summarize("PASS: intl/case-one", *details)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("suite.libc.result=no_unexpected_failures", result.stdout.splitlines())
        for detail in details:
            self.assertIn(f"suite.libc.detail={detail}", result.stdout.splitlines())

    def test_all_unexpected_outcomes_require_review(self):
        for label in ("FAIL", "XPASS", "UNRESOLVED"):
            with self.subTest(label=label):
                result = summarize("PASS: intl/case-one", f"{label}: intl/case-two")
                self.assertEqual(result.returncode, 0, result.stderr)
                output = result.stdout.splitlines()
                self.assertIn(f"suite.libc.{label}=1", output)
                self.assertIn(f"suite.libc.detail={label}: intl/case-two", output)
                self.assertIn("suite.libc.result=reported_failures", output)
                self.assertNotIn("suite.libc.result=no_unexpected_failures", output)

    def test_empty_suite_and_unknown_outcome_refuse_classification(self):
        for lines in ((), ("PASS: intl/case-one", "UNKNOWN: intl/case-two")):
            with self.subTest(lines=lines):
                result = summarize(*lines)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("suite.libc.result=", result.stdout)
