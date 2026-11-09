"""A real, offline-installable test wheel; no build backend or remote dependency runs."""

import base64
import csv
import hashlib
import io
import json
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from platform_core.extensions.manifest import ModuleManifest
from platform_core.extensions.release import sign_payload
from platform_core.extensions.releases import canonical, inspect_wheel

SOURCE = Path(__file__).resolve().parents[1] / "examples" / "notes-extension"


def build_wheel(directory, extra=None):
    directory = Path(directory)
    root = SOURCE / "pamolive_ext_notes"
    files = {
        path.relative_to(SOURCE).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    metadata = "pamolive_example_notes-1.0.0.dist-info"
    files[f"{metadata}/METADATA"] = (
        b"Metadata-Version: 2.4\nName: pamolive-example-notes\nVersion: 1.0.0\n"
        b"License-Expression: AGPL-3.0-or-later\nRequires-Python: >=3.12\n"
        b"Requires-Dist: Django>=5.2,<5.3\n\n"
    )
    files[f"{metadata}/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: pamolive-test-fixture\n"
        b"Root-Is-Purelib: true\nTag: py3-none-any\n"
    )
    files[f"{metadata}/entry_points.txt"] = (
        b"[pamolive.modules]\nexample_notes = pamolive_ext_notes.manifest:module\n"
    )
    files.update(extra or {})
    record = io.StringIO(newline="")
    writer = csv.writer(record)
    for name, data in sorted(files.items()):
        checksum = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        writer.writerow([name, "sha256=" + checksum, len(data)])
    writer.writerow([f"{metadata}/RECORD", "", ""])
    files[f"{metadata}/RECORD"] = record.getvalue().encode()
    wheel = directory / "pamolive_example_notes-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as output:
        for name, data in sorted(files.items()):
            output.writestr(name, data)
    return wheel


def signed_fixture(directory, *, periodic=False):
    directory = Path(directory)
    manifest_path = "pamolive_ext_notes/manifest.json"
    data = json.loads((SOURCE / manifest_path).read_bytes())
    extra = {}
    if periodic:
        data["api_version"] = "3"
        data["periodic_signals"] = [
            {
                "name": "sample_refresh_v1",
                "handler": "pamolive_ext_notes.events.record_periodic_receipt",
                "interval_minutes": 60,
            }
        ]
        extra[manifest_path] = canonical(data)
    wheel = build_wheel(directory, extra)
    manifest = ModuleManifest.from_dict(data)
    key = Ed25519PrivateKey.generate()
    envelope = sign_payload(inspect_wheel(wheel, manifest), key, "test-publisher")
    trust = {"test-publisher": base64.b64encode(key.public_key().public_bytes_raw()).decode()}
    catalog = directory / "catalog.json"
    catalog.write_bytes(
        canonical({"schema": "pamolive.extension-catalog.v1", "releases": [envelope]})
    )
    return wheel, manifest, key, envelope, trust, catalog
