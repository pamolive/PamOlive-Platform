"""Remove source snippets and free-text diagnostics before CI artifact upload."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

SCHEMA = "pamolive.bandit-report/1"
FIELDS = (
    "filename", "line_number", "test_id", "test_name", "issue_severity",
    "issue_confidence", "more_info",
)


def redact_report(document):
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise ValueError("Invalid scanner report")
    errors = document.get("errors", [])
    if not isinstance(errors, list):
        raise ValueError("Invalid scanner error list")
    results = []
    for finding in document["results"]:
        if not isinstance(finding, dict):
            raise ValueError("Invalid scanner finding")
        if any(key not in finding for key in FIELDS):
            raise ValueError("Incomplete scanner finding")
        if any(
            not isinstance(finding[key], str)
            for key in FIELDS if key != "line_number"
        ) or type(finding["line_number"]) is not int:
            raise ValueError("Invalid finding metadata")
        if (
            finding["issue_severity"] not in {"LOW", "MEDIUM", "HIGH"}
            or finding["issue_confidence"] not in {"LOW", "MEDIUM", "HIGH"}
            or finding["line_number"] < 1
        ):
            raise ValueError("Invalid finding classification")
        safe = {key: finding[key] for key in FIELDS}
        cwe = finding.get("issue_cwe")
        if cwe is not None:
            if not isinstance(cwe, dict) or type(cwe.get("id")) is not int:
                raise ValueError("Invalid CWE metadata")
            safe["issue_cwe"] = {"id": cwe["id"]}
        results.append(safe)
    # Scanner error messages may also contain source fragments. Keep their count
    # so an incomplete scan remains visible without carrying free-form text.
    return {"schema": SCHEMA, "results": results, "scan_error_count": len(errors)}


def redact_files(paths):
    paths = [Path(path) for path in paths]
    # Validate every input before replacing any report. Missing or malformed
    # reports fail the CI step; its artifact upload requires this step to pass.
    documents = [redact_report(json.loads(path.read_text(encoding="utf-8"))) for path in paths]
    for path, document in zip(paths, documents, strict=True):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent, delete=False
            ) as stream:
                temporary = Path(stream.name)
                json.dump(document, stream, ensure_ascii=False, sort_keys=True)
                stream.write("\n")
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return len(documents)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+")
    args = parser.parse_args(argv)
    try:
        count = redact_files(args.reports)
    except (OSError, ValueError, TypeError):
        # Never echo malformed input, a source snippet, or a scanner diagnostic.
        print("Security report redaction failed.", file=sys.stderr)
        return 1
    print(f"Redacted {count} security reports.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
