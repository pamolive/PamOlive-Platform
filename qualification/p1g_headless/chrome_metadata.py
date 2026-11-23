"""Authenticate the current public Chrome repository metadata in the Linux lab."""

import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))

from qualification.p1g_headless import chrome_bootstrap as bootstrap  # noqa: E402
from qualification.p1g_headless import chrome_gpg, chrome_key_scope, lab_support  # noqa: E402

BRANCH = "refs/heads/agent/p1g-chrome-metadata-refresh"
REPOSITORY = "pamolive/PamOlive-Platform"
INDEX_FILES = {
    "Release": ("dists/stable/Release", 64 * 1024),
    "Release.gpg": ("dists/stable/Release.gpg", 64 * 1024),
    "Packages": ("dists/stable/main/binary-amd64/Packages", 256 * 1024),
}
PACKAGE_FIELDS = ("Package", "Architecture", "Version", "Filename", "Size", "SHA256", "Depends")


def run_identity(env):
    bootstrap.need(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("GITHUB_REPOSITORY") == REPOSITORY
        and env.get("GITHUB_EVENT_NAME") == "push"
        and env.get("GITHUB_REF") == BRANCH,
        "metadata_job_scope",
    )
    identity = {
        "revision": env.get("GITHUB_SHA", ""),
        "run": env.get("GITHUB_RUN_ID", ""),
        "attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
    }
    for name, pattern in (
        ("revision", r"[0-9a-f]{40}"),
        ("run", r"[1-9][0-9]{0,19}"),
        ("attempt", r"[1-9][0-9]{0,7}"),
    ):
        bootstrap.need(re.fullmatch(pattern, identity[name]), "metadata_job_identity")
    return identity


def fetch_indexes(commands):
    data = {}
    for name, (path, cap) in INDEX_FILES.items():
        response = commands.run(
            [
                "/usr/bin/curl",
                "--disable",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "15",
                "--max-filesize",
                str(cap),
                "--write-out",
                "\n%{response_code}",
                bootstrap.BASE_URL + path,
            ],
            seconds=20,
            cap=cap + 4,
        )
        body, divider, status = response.rpartition(b"\n")
        bootstrap.need(
            divider and status == b"200" and 0 < len(body) <= cap, "metadata_http_response"
        )
        data[name] = body
    return data


def package_record(raw):
    rows = [bootstrap.fields(part) for part in raw.split(b"\n\n") if part.strip()]
    rows = [
        row
        for row in rows
        if row.get("Package") == "google-chrome-stable" and row.get("Architecture") == "amd64"
    ]
    bootstrap.need(
        len(rows) == 1 and all(key in rows[0] for key in PACKAGE_FIELDS), "metadata_package_shape"
    )
    package = {key: rows[0][key] for key in PACKAGE_FIELDS}
    bootstrap.package_check(raw, package)
    return package


def acquire(commands, staged, private, original, previous):
    indexes = fetch_indexes(commands)
    for name, raw in {**indexes, "google-key.asc": original}.items():
        lab_support.fresh_write(staged / name, raw, mode=0o400)
    signature, proof, _, _ = chrome_key_scope.authenticate(
        commands,
        lab_support,
        staged,
        private,
        chrome_gpg,
        original,
    )
    release_time = bootstrap.release_check(
        indexes["Release"], indexes["Packages"], int(time.time())
    )
    package = package_record(indexes["Packages"])
    return indexes, {
        "state": "AUTHENTICATED_VENDOR_METADATA",
        "signature": signature,
        "scoped_certificate_sha256": proof["scoped_sha256"],
        "release_timestamp": release_time,
        "materials": {
            name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for name, raw in indexes.items()
        },
        "package": package,
        "previous_package_version": previous["Version"],
        "same_package_as_previous_pin": package == previous,
    }


def main():
    bootstrap.need(
        sys.platform == "linux" and os.geteuid() == os.getuid() > 0, "metadata_linux_nonroot"
    )
    identity = run_identity(os.environ)
    scratch = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    public = scratch / ("pamolive-chrome-metadata-" + identity["run"] + "-" + identity["attempt"])
    public.mkdir(mode=0o700)
    receipt = {
        "schema": "pamolive.chrome-metadata-measurement/1",
        **identity,
        "browser_package_downloaded": False,
        "browser_executed": False,
        "operational_GO": False,
    }
    phase = "input"
    try:
        original = bootstrap.read(
            ROOT / "qualification/p1g_headless/chrome_materials/google-key.asc",
            chrome_key_scope.LIMIT,
        )
        bootstrap.need(
            bootstrap.sha(original) == chrome_key_scope.ORIGINAL_SHA256, "metadata_key_pin"
        )
        pins = json.loads(
            bootstrap.read(ROOT / bootstrap.PIN_PATH, 131072), object_pairs_hook=bootstrap.unique
        )
        bounded = lab_support.bounded(ROOT)
        phase = "verify"
        with tempfile.TemporaryDirectory(
            prefix="pamolive-chrome-metadata-private-", dir=scratch
        ) as d:
            private = Path(d)
            staged = private / "metadata"
            staged.mkdir(mode=0o700)
            journals = private / "journals"
            journals.mkdir(mode=0o700)
            commands = bootstrap.Commands(lab_support, bounded, private, journals, horizon=195)
            indexes, facts = acquire(commands, staged, private, original, pins["package"])
        phase = "publish"
        for name, raw in indexes.items():
            lab_support.fresh_write(public / name, raw, mode=0o400)
        receipt.update(facts)
    except (OSError, ValueError, KeyError, TypeError) as error:
        code = str(error) if type(error) is ValueError else ""
        receipt.update(
            state="REFUSED",
            phase=phase,
            code=(code if re.fullmatch(r"[A-Za-z0-9_]{1,70}", code) else "metadata_refused"),
        )
    lab_support.fresh_write(
        public / "metadata-receipt.json", (json.dumps(receipt, indent=2) + "\n").encode()
    )
    return 0 if receipt["state"] == "AUTHENTICATED_VENDOR_METADATA" else 42


if __name__ == "__main__":
    raise SystemExit(main())
