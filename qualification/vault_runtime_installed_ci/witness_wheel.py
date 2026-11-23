"""Verify the W1 wheel as a separate material, before target Python is launched."""

import csv
import io
import json
import sys
import tomllib
from base64 import urlsafe_b64encode
from email.parser import BytesParser
from pathlib import Path

sys.path.insert(0, "/inputs/controller")
from adapter_v2 import runtime_prelaunch  # noqa: E402
from records import expected_direct_url  # noqa: E402
from support import load, need, read_regular, sha  # noqa: E402
from wheel_gate import members  # noqa: E402

NAME = "pamolive-usage-anchor"
MODULE = "pamolive_usage_anchor"
VERSION = "0.1.0a1"
STEM = MODULE + "-" + VERSION
INFO = STEM + ".dist-info"
SQL = "share/pamolive/usage-anchor/schema.sql"
DATA = STEM + ".data/data/" + SQL
WITNESS = Path("/witness")
WHEEL = WITNESS / "wheels" / (STEM + "-py3-none-any.whl")
SOURCE = WITNESS / "source"
PREFIX = Path("/opt/vault")
SITE = PREFIX / "lib/python3.12/site-packages"
METADATA = frozenset(INFO + "/" + name for name in ("METADATA", "WHEEL", "RECORD", "top_level.txt"))
LICENSE = INFO + "/licenses/LICENSE"


def pins(directory):
    lines = read_regular(directory / "witness-source.sha256", 16384).decode("ascii").splitlines()
    return {name: digest for digest, name in (line.split("  ", 1) for line in lines)}


def wheel_contents(raw, approved):
    sources = {name: sha256 for name, sha256 in approved.items() if name.startswith(MODULE + "/")}
    need(len(sources) == 18)
    pinned = {**sources, DATA: approved["sql/schema.sql"], LICENSE: approved["LICENSE"]}
    files = members(raw, METADATA | pinned.keys())
    need(all(sha(files[name]) == expected for name, expected in pinned.items()))
    checked = load("qualify_installed.py").zip_inventory(raw, name=NAME, version=VERSION)
    need(checked["RECORD_checked"] is True)
    metadata = BytesParser().parsebytes(files[INFO + "/METADATA"])
    need(not metadata.defects and not metadata.is_multipart())
    need(metadata.get_all("Name") == [NAME] and metadata.get_all("Version") == [VERSION])
    need(metadata.get_all("License-Expression") == ["AGPL-3.0-or-later"])
    need(files[INFO + "/top_level.txt"] == (MODULE + "\n").encode())
    need(
        files[INFO + "/WHEEL"]
        == (
            b"Wheel-Version: 1.0\nGenerator: setuptools (84.2.1)\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n\n"
        )
    )
    return files, metadata


def verify_source():
    approved = pins(WITNESS)
    actual = {path.relative_to(SOURCE).as_posix() for path in SOURCE.rglob("*") if path.is_file()}
    expected = {
        name
        for name in approved
        if name.startswith(MODULE + "/")
        or name in {"README.md", "LICENSE", "pyproject.toml", "sql/schema.sql"}
    }
    need(expected == actual)
    need(all(sha(read_regular(SOURCE / name, 65536)) == approved[name] for name in expected))


def build_lock():
    need({path.name for path in WHEEL.parent.iterdir()} == {WHEEL.name})
    raw = read_regular(WHEEL, 2 * 1024**2)
    _, metadata = wheel_contents(raw, pins(WITNESS))
    project = tomllib.loads(read_regular(SOURCE / "pyproject.toml", 65536).decode())["project"]
    need(metadata.get_all("Requires-Python") == [project["requires-python"]])

    # Packaging may change the quote style and spaces in a marker.
    def normalize(value):
        return value.replace(" ", "").replace("'", '"')

    need(
        sorted(map(normalize, metadata.get_all("Requires-Dist")))
        == sorted(map(normalize, project["dependencies"]))
    )
    description = metadata.get_payload(decode=True).replace(b"\r\n", b"\n").rstrip(b"\n")
    expected = read_regular(SOURCE / "README.md", 65536).replace(b"\r\n", b"\n").rstrip(b"\n")
    need(description == expected)
    with (WITNESS / "wheel.lock").open("x", encoding="ascii") as stream:
        stream.write(f"{NAME} @ {WHEEL.as_uri()} --hash=sha256:{sha(raw)}\n")


def verify_record(installed):
    record_name = INFO + "/RECORD"
    raw = read_regular(SITE / record_name, 65536)
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8"), newline="")))
    expected = {(record_name, "", "")}
    for name, data in installed.items():
        digest = urlsafe_b64encode(bytes.fromhex(sha(data))).rstrip(b"=").decode()
        expected.add((name, "sha256=" + digest, str(len(data))))
    need(len(rows) == len(expected) and {tuple(row) for row in rows} == expected)
    return sha(raw)


def verify_install():
    runtime_prelaunch(SITE)
    raw = read_regular(WHEEL, 2 * 1024**2)
    files, _ = wheel_contents(raw, pins(WITNESS))
    installed = {name: data for name, data in files.items() if name not in {DATA, INFO + "/RECORD"}}
    installed.update({INFO + "/INSTALLER": b"pip\n", INFO + "/REQUESTED": b""})
    need(read_regular(PREFIX / SQL, 65536) == files[DATA])
    for name, data in installed.items():
        need(read_regular(SITE / name, 65536) == data)
    direct = read_regular(SITE / INFO / "direct_url.json", 4096)
    need(json.loads(direct) == expected_direct_url(WHEEL, sha(raw)))
    expected = set(installed) | {INFO + "/direct_url.json", INFO + "/RECORD"}
    seen = {
        path.relative_to(SITE).as_posix()
        for directory in (SITE / MODULE, SITE / INFO)
        for path in directory.rglob("*")
        if path.is_file()
    }
    need(seen == expected)
    need(not SOURCE.exists())
    installed.update({INFO + "/direct_url.json": direct, "../../../" + SQL: files[DATA]})
    return {
        "wheel_sha256": sha(raw),
        "installed_record_sha256": verify_record(installed),
        "installed_files_verified": True,
    }


if __name__ == "__main__":
    try:
        {"source": verify_source, "wheel": build_lock, "installed": verify_install}[sys.argv[1]]()
    except Exception:
        print("Witness package verification refused.", file=sys.stderr)
        raise SystemExit(42) from None
