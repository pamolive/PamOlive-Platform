"""CI artifacts must not expose fixture credentials from scanner diagnostics."""

import io
import json
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import TestCase

from deploy.redact_security_reports import main, redact_files, redact_report


class SecurityReportRedactionTests(TestCase):
    def report(self):
        return {
            "results": [{
                "filename": "deploy/synthetic.py", "line_number": 7,
                "test_id": "B105", "test_name": "hardcoded_password_string",
                "issue_severity": "LOW", "issue_confidence": "MEDIUM",
                "issue_cwe": {"id": 259, "link": "secret-in-untrusted-extra-field"},
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b105.html",
                "code": "password = 'synthetic-value-must-not-be-in-artifact'",
                "issue_text": "Possible password: 'synthetic-value-must-not-be-in-artifact'",
                "unknown": {"secret": "synthetic-value-must-not-be-in-artifact"},
            }],
            "errors": [{"reason": "synthetic-value-must-not-be-in-artifact"}],
            "metrics": {"raw": "synthetic-value-must-not-be-in-artifact"},
        }

    def test_only_review_metadata_survives_and_scan_errors_remain_counted(self):
        safe = redact_report(self.report())
        serialized = json.dumps(safe)
        self.assertNotIn("synthetic-value-must-not-be-in-artifact", serialized)
        self.assertNotIn("secret-in-untrusted-extra-field", serialized)
        self.assertNotIn("issue_text", serialized)
        self.assertNotIn('"code"', serialized)
        self.assertEqual(safe["scan_error_count"], 1)
        self.assertEqual(safe["results"][0]["test_id"], "B105")
        self.assertEqual(safe["results"][0]["issue_cwe"], {"id": 259})

    def test_malformed_second_report_prevents_any_replacement_or_raw_logging(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = (Path(directory) / name for name in ("first.json", "second.json"))
            raw = json.dumps(self.report())
            first.write_text(raw, encoding="utf-8")
            second.write_text('{"results": "synthetic-secret-invalid-report"}', encoding="utf-8")
            output = io.StringIO()
            with redirect_stderr(output), redirect_stdout(output):
                status = main([str(first), str(second)])
            self.assertEqual(status, 1)
            self.assertEqual(first.read_text(encoding="utf-8"), raw)
            self.assertNotIn("synthetic-secret", output.getvalue())

    def test_files_are_replaced_by_sanitized_json_and_missing_report_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(self.report()), encoding="utf-8")
            self.assertEqual(redact_files([path]), 1)
            self.assertEqual(json.loads(path.read_text()), redact_report(self.report()))
            with self.assertRaises(OSError):
                redact_files([Path(directory) / "absent.json"])
