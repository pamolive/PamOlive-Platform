"""Authenticate the current public Chrome repository metadata in the Linux lab."""

import argparse
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
from qualification.p1g_headless import (  # noqa: E402
    chrome_bundle,  # noqa: E402
    chrome_gpg,
    chrome_key_scope,
    lab_support,
)

BRANCH = "refs/heads/agent/p1g-chrome-metadata-refresh"
REPOSITORY = "pamolive/PamOlive-Platform"
INDEX_FILES = {
    "Release": ("dists/stable/Release", 64 * 1024),
    "Release.gpg": ("dists/stable/Release.gpg", 64 * 1024),
    "Packages": ("dists/stable/main/binary-amd64/Packages", 256 * 1024),
}
PACKAGE_FIELDS = ("Package", "Architecture", "Version", "Filename", "Size", "SHA256", "Depends")
# This pins only the stanza authenticated by run 45163889050, for inventory.
INVENTORY_PACKAGE_RECORD = "64e4fdd36d04a88b49b9a5a067dd42aa84814645cf5a7a6ee9775563a2b05406"


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


def inspect_package(commands, private, expected, receipt):
    encoded = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
    bootstrap.need(bootstrap.sha(encoded) == INVENTORY_PACKAGE_RECORD, "inventory_package_pin")
    package = private / "browser-candidate.deb"
    receipt["browser_package_download_attempted"] = True
    with package.open("xb") as sink:
        commands.run(
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
                "120",
                "--max-filesize",
                expected["Size"],
                bootstrap.BASE_URL + expected["Filename"],
            ],
            seconds=130,
            cap=int(expected["Size"]),
            sink=sink,
        )
    receipt["browser_package_downloaded"] = True
    package.chmod(0o400)
    raw = bootstrap.read(package, 256 * 1024**2)
    bootstrap.need(
        len(raw) == int(expected["Size"]) and bootstrap.sha(raw) == expected["SHA256"],
        "inventory_package_bytes",
    )
    del raw
    bootstrap.control_check(
        commands.run(
            [
                "/usr/bin/dpkg-deb",
                "--field",
                str(package),
                "Package",
                "Version",
                "Architecture",
                "Depends",
            ],
            seconds=10,
        ),
        expected,
    )
    with (private / "payload.tar").open("xb+") as stream:
        commands.run(
            ["/usr/bin/dpkg-deb", "--fsys-tarfile", str(package)],
            seconds=60,
            cap=1024**3,
            sink=stream,
        )
        until = commands.until - 10
        bootstrap.payload_target(stream, until=until)
        return chrome_bundle.inventory(stream, expected["SHA256"], until=until)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--inventory-only", action="store_true")
    args = parser.parse_args(argv)
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
        "browser_package_download_attempted": False,
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
            horizon = 395 if args.inventory_only else 195
            commands = bootstrap.Commands(lab_support, bounded, private, journals, horizon=horizon)
            indexes, facts = acquire(commands, staged, private, original, pins["package"])
            tree = None
            if args.inventory_only:
                phase = "inventory"
                tree = inspect_package(commands, private, facts["package"], receipt)
        phase = "publish"
        for name, raw in indexes.items():
            lab_support.fresh_write(public / name, raw, mode=0o400)
        if tree is not None:
            data = chrome_bundle.canonical(tree)
            lab_support.fresh_write(public / "bundle-inventory.json", data, mode=0o400)
            facts["inventory"] = {"bytes": len(data), "sha256": bootstrap.sha(data)}
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
