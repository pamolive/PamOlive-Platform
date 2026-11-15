"""Synthetic in-memory wheel/installation data; no backend, pip or imports."""

import base64
import csv
import io
import json
import posixpath
import stat
import zipfile

import records
import wheel_gate
from support import ROOT, sha


def packed(files, info):
    values = {name: value for name, value in files.items() if name != info + "/RECORD"}
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name, value in values.items():
        digest = base64.urlsafe_b64encode(bytes.fromhex(sha(value))).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, str(len(value))])
    writer.writerow([info + "/RECORD", "", ""])
    values[info + "/RECORD"] = output.getvalue().encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in values.items():
            entry = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, value)
    return buffer.getvalue()


def fixture(kind):
    source = ROOT / "inputs" / kind
    name, module, info, project, files = wheel_gate.expected(source, kind)
    metadata = {
        "Metadata-Version": "2.4",
        "Name": name,
        "Version": wheel_gate.VERSION,
        "Summary": project["description"],
        "Requires-Python": ">=3.12",
        "License-Expression": "AGPL-3.0-or-later",
        "Description-Content-Type": "text/markdown",
        "Dynamic": "license-file",
    }
    text = "".join(key + ": " + value + "\n" for key, value in metadata.items())
    text += "".join("License-File: " + value + "\n" for value in project["license-files"])
    text += "".join("Requires-Dist: " + value + "\n" for value in project.get("dependencies", []))
    files[info + "/METADATA"] = (text + "\n").encode() + (
        source / "README.md"
    ).read_bytes().replace(b"\r\n", b"\n")
    files[info + "/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: setuptools (84.2.1)\n"
        b"Root-Is-Purelib: true\nTag: py3-none-any\n\n"
    )
    files[info + "/top_level.txt"] = (module + "\n").encode()
    return packed(files, info), files, info


def skeleton(directory):
    runtime = ROOT / "inputs/runtime"
    for path in runtime.rglob("*"):
        if path.is_file():
            target = directory / "components/vault/runtime" / path.relative_to(runtime)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    (directory / "LICENSE").write_bytes((runtime / "LICENSE").read_bytes())


def install_data(prefix, inventory, wheel, files):
    """Writes a filesystem fixture only, never runs code from the simulated wheel."""
    site = prefix / "lib/python3.12/site-packages"
    written = {}
    for name, raw in files.items():
        if name.endswith(".dist-info/RECORD"):
            continue
        relative = (
            "share/pamolive/vault-reservation/schema.sql"
            if ".data/data/" in name
            else "lib/python3.12/site-packages/" + name
        )
        written[relative] = raw
    info = inventory["info"]
    written["lib/python3.12/site-packages/" + info + "/INSTALLER"] = b"pip\n"
    written["lib/python3.12/site-packages/" + info + "/REQUESTED"] = b""
    written["lib/python3.12/site-packages/" + info + "/direct_url.json"] = json.dumps(
        records.expected_direct_url(wheel, inventory["wheel_sha256"]), sort_keys=True
    ).encode()
    table = io.StringIO(newline="")
    writer = csv.writer(table, lineterminator="\n")
    for relative, raw in written.items():
        target = prefix / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        digest = base64.urlsafe_b64encode(bytes.fromhex(sha(raw))).rstrip(b"=").decode()
        record_relative = posixpath.relpath(relative, "lib/python3.12/site-packages")
        writer.writerow([record_relative, "sha256=" + digest, str(len(raw))])
    writer.writerow([info + "/RECORD", "", ""])
    record = site / info / "RECORD"
    record.write_bytes(table.getvalue().encode())
    return written, record
