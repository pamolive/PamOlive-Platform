"""Exact archive Expat DATA, using the existing bounded Docker-save reader."""

import argparse
import hashlib
import json
import os
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath

from deploy import qualified_image as image
from deploy import qualify_image_scan as gate

PREFIX = "/usr/share/pamolive/expat4/"
PATHS = [
    PREFIX + name
    for name in (
        "before.json",
        "after/ABI.json",
        "python-xml-build.json",
        "source-rebuild.json",
        "snapshot.json",
        "runtime-product/RUNTIME.json",
    )
]
PATHS.append("/var/lib/dpkg/status")
MODULES = {
    "pyexpat": "/usr/local/lib/python3.12/lib-dynload/pyexpat.cpython-312-x86_64-linux-gnu.so",
    "_elementtree": (
        "/usr/local/lib/python3.12/lib-dynload/_elementtree.cpython-312-x86_64-linux-gnu.so"
    ),
}
KEYS = {"libexpat.so.1", "libexpatw.so.1", *MODULES}
BASE_ENV = [
    "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG=C.UTF-8",
    "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
    "PYTHON_VERSION=3.12.16",
    "PYTHON_SHA256=b5796915dc45ff745cfb4e990a7e7c93d6f546328a102ce31448d69ebc37575c",
]
RUNTIME_ENV = BASE_ENV + [
    "LD_LIBRARY_PATH=/opt/pamolive-freerdp/lib:/opt/pamolive-guac/lib",
    "PYTHONDONTWRITEBYTECODE=1",
    "PYTHONUNBUFFERED=1",
    "PSYCOPG_IMPL=c",
]


def check_config(config):
    value = config["config"]
    gate.require(
        value["Env"] == RUNTIME_ENV
        and value.get("User") == "root"
        and value.get("WorkingDir") == "/app"
        and value.get("Cmd") == ["python", "deploy/runtime.py"]
        and value.get("Entrypoint") is None
        and value.get("ExposedPorts") == {"8000/tcp": {}},
        "expat_runtime_config",
    )
    health = value["Healthcheck"]
    gate.require(
        health["Test"]
        == [
            "CMD-SHELL",
            'python -c "import urllib.request; '
            "urllib.request.urlopen('http://localhost:8000/health/', timeout=4)\"",
        ]
        and health["Interval"] == 20_000_000_000
        and health["Timeout"] == 5_000_000_000
        and health["StartPeriod"] == 20_000_000_000,
        "expat_healthcheck",
    )


def check_package(raw):
    matches = []
    for paragraph in raw.decode("utf8").split("\n\n"):
        if "Package: libexpat1" not in paragraph.splitlines():
            continue
        fields = {}
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")):
                continue
            name, separator, value = line.partition(": ")
            gate.require(separator and name not in fields, "expat_dpkg_field")
            fields[name] = value
        matches.append(fields)
    gate.require(
        len(matches) == 1
        and matches[0].get("Version") == "2.10.0-1+pamolive1"
        and matches[0].get("Status") == "install ok installed"
        and matches[0].get("Architecture") == "amd64",
        "expat_dpkg_identity",
    )


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns)


def examine(archive, expected_image_id):
    gate.require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image_id)), "expat_image_id")
    path = Path(archive)
    before = path.lstat()
    gate.require(
        stat.S_ISREG(before.st_mode) and 0 < before.st_size <= image.MAX_ARCHIVE_SIZE,
        "expat_archive_regular_budget",
    )
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        gate.require(identity(opened) == identity(before), "expat_archive_changed")
        archive_sha = image.archive_hash(None, archive_stream=stream)
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:", tarinfo=gate.BoundedTarInfo) as outer:
            manifest = gate.docker_manifest(outer, require_config=True)
            config_raw = image.tar_metadata(outer, manifest["Config"], 2 * 1024**2)
        gate.require(
            "sha256:" + hashlib.sha256(config_raw).hexdigest() == expected_image_id,
            "expat_configuration_changed",
        )
        check_config(gate.json_bytes(config_raw))
        stream.seek(0)
        facts = gate.archive_facts(
            None, [{"kind": "elf_set"}], read_paths=PATHS, archive_stream=stream
        )
        data = {name: gate.json_bytes(facts.captured[name]) for name in PATHS[:-1]}
        check_package(facts.captured[PATHS[-1]])
        old, active = data[PATHS[0]], data[PATHS[1]]
        gate.require(set(old) == set(active) == KEYS, "expat_ABI_closure")
        forbidden = set()
        for key in KEYS:
            gate.require(gate.SHA.fullmatch(old[key]["sha256"]), "expat_old_hash")
            forbidden.add(old[key]["sha256"])
        gate.require(len(forbidden) == 4, "expat_old_hash_count")
        stream.seek(0)
        gate.archive_facts(
            None, [{"kind": "elf_set"}], archive_stream=stream, forbidden_elf_sha256=forbidden
        )
        allowed = set()
        for key, row in active.items():
            expected = MODULES.get(key, "/usr/lib/x86_64-linux-gnu/" + key)
            gate.require(
                row["alias"] == expected and row["sha256"] != old[key]["sha256"],
                "expat_active_identity",
            )
            target = row["target"]
            gate.require(
                PurePosixPath(target).parent == PurePosixPath(expected).parent,
                "expat_active_target",
            )
            gate.require(
                facts[1].get(target) == {"sha256": row["sha256"], "class": 64}, "expat_active_bytes"
            )
            gate.require(facts.entries[target].get("machine") == 62, "expat_active_machine")
            gate.require(row["rpath"] == [] and row["runpath"] == [], "expat_search_override")
            needed = {"libc.so.6", "libexpat.so.1"} if key == "pyexpat" else {"libc.so.6"}
            gate.require(
                type(row["needed"]) is list
                and len(row["needed"]) == len(needed)
                and set(row["needed"]) == needed,
                "expat_dynamic_dependencies",
            )
            if target != expected:
                alias = facts.entries.get(expected, {})
                gate.require(
                    alias.get("type") == "symlink"
                    and alias.get("target") in (target, PurePosixPath(target).name),
                    "expat_provider_alias",
                )
            if key not in MODULES:
                gate.require(row["soname"] == key, "expat_soname")
                allowed.update((expected, target))
        for name in facts[0]:
            if re.fullmatch(r"libexpatw?\.so(?:\..+)?", PurePosixPath(name).name):
                gate.require(name in allowed, "expat_other_physical_provider")
        runtime = data[PATHS[5]]
        gate.require(
            runtime["package_version"] == "2.10.0-1+pamolive1"
            and runtime["fixed4_admitted"] is False,
            "expat_runtime_receipt",
        )
        snapshot = data[PATHS[4]]
        gate.require(
            snapshot["metadata_equal"] is True and snapshot["base_origin_attested"] is False,
            "expat_snapshot_receipt",
        )
        build = data[PATHS[2]]
        gate.require(
            build["optimization"]["policy"] == "xml-local-no-pgo-v1", "expat_optimization_policy"
        )
        # Same FD/buffer identity through all passes; never a late pathname hash.
        gate.require(
            image.archive_hash(None, archive_stream=stream) == archive_sha, "expat_archive_changed"
        )
        after_fd, after_path = os.fstat(stream.fileno()), path.lstat()
        gate.require(
            identity(after_fd) == identity(before)
            and identity(after_path) == identity(before)
            and after_fd.st_ctime_ns == opened.st_ctime_ns
            and after_path.st_ctime_ns == before.st_ctime_ns,
            "expat_archive_changed",
        )
    return {
        "schema": "pamolive.expat-product-image/1",
        "image_id": expected_image_id,
        "archive_sha256": archive_sha,
        "active": active,
        "old_ELF_hashes_absent_all_layers": sorted(forbidden),
        "source_rebuild": data[PATHS[3]],
        "python_build": build,
        "snapshot": snapshot,
        "runtime": runtime,
        "native_report_metadata_attested": False,
        "fixed4_admitted": False,
        "product_qualified": False,
        "operational_GO": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    value = examine(args.archive, args.image_id)
    with Path(args.output).open("x", encoding="utf8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
