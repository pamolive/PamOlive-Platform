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
SOURCE_AUDIT = PREFIX + "source-audit.json"
REBUILD_VERSION = "2.10.0-1+pamolive2"
SOURCE_AUDIT_SHA256 = "3ac295e87e7cc8c0d9c92ecc18b18ad6c2a89b2da6955c6e93fcf091b369a156"
SOURCE_REBUILD_SHA256 = "96dc874aaa9d48cddea9eb926c3fd0d1839bddcf67abcfe41e99ed0cc2af79f0"
REVIEWED_ELF = {
    "_elementtree": "08986d651312fef49e9c2450193d7ceecb43b65605ce880c96051953cc0a6629",
    "libexpat.so.1": "4bea107cfb1ec4dcbe2bc0062967cd8ee1df80f830da203dc60b477bc8beecef",
    "libexpatw.so.1": "d1d98efa5cfd37046f66e8f065e927667548147e78a0780bf6642b0776a9cd03",
    "pyexpat": "4e9d0af8b9b0af4bb998f0bff493d608adebe11f534fc5d771e860cf1b2f9e92",
}
REVIEWED_OLD_ELF = {
    "36e7e50d21edcabed383bfddc594bb261c1c7cce456afdf23c5f53e849cda67c",
    "47441b4b394664b6efd5b4ad6780a627962d4f105fcc8407929175fce0c0b013",
    "5c099081b395cf25acfca1feda283c6730dc3647a70f3221f4d95b48fffe0219",
    "c57ac6e6d574898e3b38e82217264b7a5da9531fd0b98fb82577a9f69512accf",
}
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
        and matches[0].get("Version") == REBUILD_VERSION
        and matches[0].get("Status") == "install ok installed"
        and matches[0].get("Architecture") == "amd64",
        "expat_dpkg_identity",
    )


LOCAL_BACKPORT_PROOF = {
    "schema": "pamolive.expat-local-backports/1",
    "policy": "expat-2.10.0-local-two-advisory-v1",
    "local_package_version": "2.10.0-1+pamolive2",
    "patches": {
        "CVE-2026-124317.patch": "453f41710ea2394887a8fa5f4b3121ebce36ffb5eadcc4404de2e0dbdf204d1a",
        "CVE-2026-128241.patch": "78203c87cb0d854e3a7a6d36840e90c9370070cb2e49e36cb4ce5e01c8a974f1",
    },
    "files": {
        "expat/lib/xmltok.c": {
            "base_sha256": "44baab2a4970749f6f29992bbbc1b3c62239ef9ec2a20de96332ef4659b9e32d",
            "post_sha256": "07dda873d9d75643f9e4a1b83878ba0230f7782966375449928387c85a62caf8",
        },
        "expat/tests/misc_tests.c": {
            "base_sha256": "a2e4bd074fbd83a87ab298e79a13599e5a4afe65f542d6026a314b98a4ddfd9b",
            "post_sha256": "828923bf773317386dff577ccf26c0e2b04d3b6762fdd633bbe6324214a13dcf",
        },
        "expat/xmlwf/xmltchar.h": {
            "base_sha256": "3ca28b7ff0f149de1e022ce4031aed1092a8981cc86e62e45131fa1b04964755",
            "post_sha256": "c92e56aec7e5803b2213e9bcd276515b554041d6474ecabaa7def8a4876d29d5",
        },
        "expat/xmlwf/xmlwf.c": {
            "base_sha256": "12b11917c336ab01e580c17f02018986838482a51f7c61708a50e55cc5e83afc",
            "post_sha256": "94d0aeeb889b06f9cb6e3865427510804216797a5ece71fe60653976e7bc5c37",
        },
    },
    "base_authentication_required_before_extraction": True,
    "upstream_signature_covers_local_changes": False,
    "fixed4_admitted": False,
    "new_advisories_admitted": False,
    "product_qualified": False,
    "operational_go": False,
}


def check_source_rebuild(value):
    # Receipt DATA, never crypto/Root admission. Exact current policy; no V1 fallback.
    gate.require(
        type(value) is dict and value.get("schema") == "pamolive.expat-source-rebuild/2",
        "expat_local_rebuild_schema",
    )
    gate.require(
        json.dumps(value.get("local_backports"), sort_keys=True)
        == json.dumps(LOCAL_BACKPORT_PROOF, sort_keys=True),
        "expat_local_backport_proof",
    )
    rows = value.get("packages")
    gate.require(
        type(rows) is list
        and len(rows) == 2
        and {r.get("package") for r in rows} == {"libexpat1", "libexpat1-dev"}
        and all(r.get("version") == REBUILD_VERSION for r in rows),
        "expat_local_rebuild_packages",
    )
    gate.require(value.get("fixed4_admitted") is False, "expat_local_rebuild_authority")


def check_reviewed_rebuild(facts, active, source):
    from qualification.debian_138_refresh.verify_refresh import controls

    gate.require(SOURCE_AUDIT in facts.captured, "expat_source_audit_missing")
    audit = facts.captured[SOURCE_AUDIT]
    gate.require(
        0 < len(audit) <= 64 * 1024 and hashlib.sha256(audit).hexdigest() == SOURCE_AUDIT_SHA256,
        "expat_source_audit_changed",
    )
    gate.require(
        {name: row["sha256"] for name, row in active.items()} == REVIEWED_ELF,
        "expat_reviewed_ELF",
    )
    gate.require(
        hashlib.sha256(gate.canonical(source).encode()).hexdigest() == SOURCE_REBUILD_SHA256,
        "expat_reviewed_rebuild",
    )
    rows = [row for row in controls(facts.captured[PATHS[-1]]) if (
        row.get("Package") in {"libexpat1", "libexpat1-dev"}
        or row.get("Source", row.get("Package", "")).partition(" ")[0] == "expat"
    ) and row.get("Status", "").endswith(" installed")]
    gate.require(
        len(rows) == 1
        and rows[0].get("Package") == "libexpat1"
        and rows[0].get("Source") in ("expat", f"expat ({REBUILD_VERSION})"),
        "expat_reviewed_dpkg_source",
    )


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns)


def examine(archive, expected_image_id, *, reviewed_rebuild=False):
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
        read_paths = [*PATHS, SOURCE_AUDIT] if reviewed_rebuild else PATHS
        facts = gate.archive_facts(
            None, [{"kind": "elf_set"}], read_paths=read_paths, archive_stream=stream
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
        if reviewed_rebuild:
            gate.require(forbidden == REVIEWED_OLD_ELF, "expat_reviewed_old_ELF")
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
            if reviewed_rebuild:
                gate.require(
                    target == MODULES.get(key, expected + ".13.1"),
                    "expat_reviewed_target",
                )
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
            runtime.get("schema") == "pamolive.expat-runtime/2"
            and runtime["package_version"] == REBUILD_VERSION
            and runtime["fixed4_admitted"] is False,
            "expat_runtime_receipt",
        )
        check_source_rebuild(data[PATHS[3]])
        if reviewed_rebuild:
            check_reviewed_rebuild(facts, active, data[PATHS[3]])
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
        "schema": "pamolive.expat-product-image/2",
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


def report_bytes(report):
    return (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    value = examine(args.archive, args.image_id)
    with Path(args.output).open("xb") as stream:
        stream.write(report_bytes(value))


if __name__ == "__main__":
    main()
