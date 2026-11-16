"""Offline migration DATA: physical cJSON absence and exact Debian Jansson package.

This does not qualify vulnerabilities, replace the scan gate, or execute an ELF.
The existing Docker-save parser supplies all path/link/whiteout/stream budgets.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import tarfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

try:
    from deploy import qualify_image_scan as gate
except ModuleNotFoundError:
    import qualify_image_scan as gate


ARCHIVE_LIMIT = 2 * 1024**3


def _identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
    )


@contextmanager
def _regular_input(path, maximum):
    """A single bounded regular FD, stable through the positive result.

    This detects ordinary mutation/replacement. It is not a kernel snapshot or
    a claim about hostile kernel/root actors preserving arbitrary metadata.
    """
    path = Path(path)
    before = path.lstat()
    gate.require(
        stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, "input_regular_or_budget"
    )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        gate.require(_identity(opened) == _identity(before), "input_changed")
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with stream:
        yield stream
        after_fd = os.fstat(stream.fileno())
        after_path = path.lstat()
        # ctime is compared within each API. Some Windows Python builds expose
        # creation time through lstat and change time through fstat; comparing
        # these across APIs would reject an unchanged rewritten file.
        gate.require(
            _identity(after_fd) == _identity(before)
            and _identity(after_path) == _identity(before)
            and after_fd.st_ctime_ns == opened.st_ctime_ns
            and after_path.st_ctime_ns == before.st_ctime_ns,
            "input_changed",
        )


def _hash_stream(stream, maximum):
    stream.seek(0)
    count = 0
    digest = hashlib.sha256()
    while block := stream.read(min(1024**2, maximum + 1 - count)):
        count += len(block)
        gate.require(count <= maximum, "input_byte_budget")
        digest.update(block)
    return digest.hexdigest()


def examine(archive, os_sbom):
    with _regular_input(archive, ARCHIVE_LIMIT) as stream:
        # Both TAR passes consume this FD. Content is bound before parsing and
        # checked again before returning; no late pathname hash can replace it.
        initial = _hash_stream(stream, ARCHIVE_LIMIT)
        stream.seek(0)
        result = _examine_stream(stream, os_sbom)
        gate.require(_hash_stream(stream, ARCHIVE_LIMIT) == initial, "input_changed")
        result["archive_sha256"] = initial
        return result


def _examine_stream(archive_stream, os_sbom):
    facts = gate.archive_facts(
        None,
        [{"kind": "elf_set"}],
        read_paths=["/var/lib/dpkg/status"],
        reject_cjson_elf=True,
        archive_stream=archive_stream,
    )
    # names intentionally covers ALL layers, even deleted files. A fresh Jansson
    # image must not have installed cJSON and hidden it in a later layer.
    for path in facts[0]:
        name = PurePosixPath(path).name.lower()
        gate.require(
            not (
                name.startswith("libcjson")
                or name in ("cjson.c", "cjson_utils.c", "cjson.h", "cjson_utils.h")
            ),
            "cjson_physical_file",
        )
    status = facts.captured.get("/var/lib/dpkg/status")
    gate.require(isinstance(status, bytes), "jansson_dpkg_status_missing")
    installed = {}
    for paragraph in status.decode("utf-8").split("\n\n"):
        if "Status: install ok installed" not in paragraph.splitlines():
            continue
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line)
        name = fields.get("Package", "")
        gate.require(name and name not in installed, "jansson_dpkg_duplicate")
        gate.require(not name.lower().startswith(("libcjson", "cjson")), "cjson_dpkg_package")
        installed[name] = fields.get("Version")
    gate.require(installed.get("libjansson4") == "2.14-2+b3", "jansson_dpkg_version")
    gate.require(
        isinstance(os_sbom, dict)
        and os_sbom.get("bomFormat") == "CycloneDX"
        and isinstance(os_sbom.get("components"), list),
        "jansson_os_sbom",
    )
    pending = [(row, 0) for row in os_sbom["components"]]
    count, jansson = 0, False
    while pending:
        row, depth = pending.pop()
        count += 1
        gate.require(
            isinstance(row, dict) and count <= 100000 and depth <= 32, "jansson_sbom_budget"
        )
        name = row.get("name", "")
        purl = row.get("purl", "")
        gate.require(isinstance(name, str) and isinstance(purl, str), "jansson_sbom_name")
        gate.require(
            not name.lower().startswith(("libcjson", "cjson"))
            and not re.search(r"/(?:lib)?cjson(?:[0-9_-]|@|/|$)", purl, re.I),
            "cjson_sbom_package",
        )
        if name == "libjansson4":
            gate.require(row.get("version") == "2.14-2+b3", "jansson_sbom_version")
            jansson = True
        children = row.get("components", [])
        gate.require(isinstance(children, list) and len(children) <= 100000, "jansson_sbom_budget")
        pending.extend((child, depth + 1) for child in children)
    gate.require(jansson, "jansson_sbom_missing")
    archive_stream.seek(0)
    with tarfile.open(fileobj=archive_stream, mode="r:", tarinfo=gate.BoundedTarInfo) as outer:
        manifest = gate.docker_manifest(outer, require_config=True)
        config = gate.qualified_image.tar_metadata(outer, manifest["Config"], 2 * 1024**2)
    return {
        "schema": "pamolive.jansson-migration-data.v1",
        "physical_checks_passed": True,
        "image_config_id": "sha256:" + hashlib.sha256(config).hexdigest(),
        "elf_set": facts.elf_set,
        "layer_diff_ids": facts.layer_digests,
        "jansson_debian_version": "2.14-2+b3",
        "os_sbom_components": count,
        "limits": [
            "Symbol markers detect ordinary static or shared cJSON copies; "
            "they are not a formal proof against renamed/obfuscated code.",
            "The exact-image OS/compiled scans, native verification and "
            "P0/NLA/SSH gates remain mandatory.",
            "This report grants no CVE disposition or product promotion.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--os-sbom", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    # Exclusive output is reserved before reading any input; failures remain empty.
    with args.output.open("x", encoding="utf-8") as stream:
        with _regular_input(args.os_sbom, gate.MAX_JSON) as sbom_stream:
            raw = sbom_stream.read(gate.MAX_JSON + 1)
            gate.require(len(raw) <= gate.MAX_JSON, "json_byte_budget")
            sbom = gate.json_bytes(raw, gate.MAX_JSON)
            result = examine(args.archive, sbom)
            # Digest the identical captured buffer passed to the parser.
            result["os_sbom_sha256"] = hashlib.sha256(raw).hexdigest()
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
