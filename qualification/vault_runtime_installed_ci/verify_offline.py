"""Offline build/installation verification only. Never connects to PostgreSQL.

Trusted parent verifies this source/context before Docker build. Uses existing
controller parsers/RECORD checks and deploy driver primitives; no monolith import.
All inputs are public wheel/source DATA. This is not a build attestation.
"""

import argparse
import importlib
import importlib.metadata
import json
import os
import re
import sys
import time
from pathlib import Path
from types import SimpleNamespace

INPUTS = Path("/inputs")
DERIVED = Path("/derived")
PREFIX = Path("/opt/vault")
LIBPQ = "17.12-0+deb13u1"
C_WHEEL = "psycopg_c-3.2.10-cp312-cp312-linux_x86_64.whl"
KINDS = {
    "runtime": ("pamolive-vault-reservation-runtime", "pamolive_vault_runtime"),
    "contracts": ("pamolive-vault-contracts", "pamolive_vault_contracts"),
    "verifier": ("pamolive-pam-trust-verifier", "pamolive_pam_trust_verifier"),
}
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def need(value):
    if not value:
        raise ValueError("vault_consumer_refused")


def modules():
    sys.path[:0] = [str(INPUTS / "controller"), str(INPUTS / "util")]
    loaded = {
        name: importlib.import_module(name)
        for name in (
            "support",
            "schema",
            "adapter_v2",
            "records",
            "wheel_gate",
            "check_database_driver",
            "native_inventory",
        )
    }
    for name, module in loaded.items():
        parent = "util" if name in {"check_database_driver", "native_inventory"} else "controller"
        need(Path(module.__file__) == INPUTS / parent / (name + ".py"))
    loaded["materials"] = loaded["support"].load("python_materials.py")
    loaded["qualifier"] = loaded["support"].load("qualify_installed.py")
    loaded["bounded"] = loaded["support"].load("bounded_io.py")
    return SimpleNamespace(**loaded)


def lines(raw):
    return [
        line
        for line in raw.replace(b"\r\n", b"\n").splitlines()
        if line and not line.startswith(b"#")
    ]


def check_internal_members(m, data, inventory):
    # Generic zip_inventory checks RECORD but intentionally exports no source map.
    checked = m.qualifier.zip_inventory(data, name=inventory["name"], version="0.1.0a1")
    need(checked["RECORD_checked"] is True)
    wanted = set(inventory["files"]) | {inventory["info"] + "/RECORD"}
    files = m.wheel_gate.members(data, wanted)
    need(
        all(
            len(files[path]) == record["bytes"] and m.support.sha(files[path]) == record["sha256"]
            for path, record in inventory["files"].items()
        )
    )
    return True


def check_inputs(m, args):
    read, sha = m.support.read_regular, m.support.sha
    need(sys.platform == "linux" and sys.version_info[:3] == (3, 12, 16))
    m.materials.check_target()
    raw = read(INPUTS / "descriptor.json", 65536)
    need(m.schema.digest(args.descriptor_sha256) and sha(raw) == args.descriptor_sha256)
    descriptor = m.adapter_v2.descriptor(m.schema.parse(raw, 65536))
    raw_inventory = read(INPUTS / "inventories.json", m.schema.MAX_CHILD)
    need(m.schema.digest(args.inventories_sha256) and sha(raw_inventory) == args.inventories_sha256)
    inventories = m.schema.parse(raw_inventory, m.schema.MAX_CHILD)
    need(type(inventories) is dict and set(inventories) == set(KINDS))
    material_path = INPUTS / "util/python-materials.linux-amd64.json"
    need(sha(read(material_path, 262144)) == m.adapter_v2.MANIFEST)
    manifest, manifest_sha = m.materials.load_manifest(material_path)
    need(manifest_sha == m.adapter_v2.MANIFEST)
    rows = {row["name"]: row for row in manifest["materials"]}
    plan = m.adapter_v2.materials()
    selected = {
        **plan["selected_materials"],
        **{name: rows[name] for name in ("psycopg", "psycopg-c")},
    }
    public = INPUTS / "public"
    need({p.name for p in public.iterdir()} == {row["filename"] for row in selected.values()})
    for name, row in selected.items():
        data = m.materials.verify_file(public / row["filename"], row)
        if row["kind"] == "wheel":
            m.qualifier.zip_inventory(data, name=name, version=row["version"])
        else:
            need(name == "psycopg-c")
            m.materials.source_inventory(public / row["filename"], row)
    for short, original in (
        ("bootstrap", "requirements-bootstrap.lock"),
        ("build", "requirements-build.lock"),
        ("runtime", "requirements-runtime-linux.lock"),
    ):
        need(
            read(INPUTS / "locks" / (short + ".lock"), 65536)
            == read(INPUTS / "controller" / original, 65536)
        )
    for short, name in (("database-build", "psycopg-c"), ("psycopg", "psycopg")):
        need(
            lines(read(INPUTS / "locks" / (short + ".lock"), 65536))
            == lines(m.materials.lock_bytes([rows[name]]))
        )
    expected_names, urls = set(), []
    for kind, (name, module) in KINDS.items():
        inventory = inventories[kind]
        need(
            type(inventory) is dict
            and set(inventory)
            == {
                "name",
                "module",
                "version",
                "info",
                "wheel_sha256",
                "wheel_bytes",
                "files",
                "wheel_RECORD_checked",
                "source_notice_metadata_exact",
            }
        )
        need(inventory["name"] == name and inventory["module"] == module)
        need(
            inventory["version"] == "0.1.0a1"
            and inventory["wheel_RECORD_checked"] is True
            and inventory["source_notice_metadata_exact"] is True
        )
        filename = name.replace("-", "_") + "-0.1.0a1-py3-none-any.whl"
        path = INPUTS / "wheels" / filename
        data = read(path, 2 * 1024**2)
        need(len(data) == inventory["wheel_bytes"] and sha(data) == inventory["wheel_sha256"])
        check_internal_members(m, data, inventory)
        expected_names.add(filename)
        urls.append(
            (
                name
                + " @ "
                + m.records.canonical_url(path)
                + " --hash=sha256:"
                + inventory["wheel_sha256"]
            ).encode()
        )
    need({p.name for p in (INPUTS / "wheels").iterdir()} == expected_names)
    internal = lines(read(INPUTS / "locks/internal.lock", 65536))
    need(len(internal) == 3 and set(internal) == set(urls))
    return descriptor, inventories, rows


class NativeCommands:
    """Bounded adapter used only by existing driver.dpkg_owner and local probes."""

    def __init__(self, bounded):
        self.bounded = bounded
        self.deadline = time.monotonic() + 120
        self.facts = []

    def run(self, command, *, env=ENV, cwd="/", timeout=5, **options):
        need(
            type(command) is list
            and command[0] in {"/usr/bin/dpkg-query", "/usr/bin/ldd", "/usr/bin/pg_config"}
        )
        need(len(self.facts) < 128)
        remaining = self.deadline - time.monotonic()
        need(remaining > 0)
        result = self.bounded.run_capped(
            command,
            env=env,
            cwd=cwd,
            timeout=min(timeout, remaining),
            stdout_cap=32768,
            stderr_cap=16384,
        )
        self.facts.append(result.facts())
        need(result.ok and result.spawn_attempted and not result.killed_owned_child)
        need(
            result.owned_child_reaped
            and result.drains_complete
            and result.exception_type is None
            and result.cleanup_exception_type is None
        )
        need(not result.stderr)
        return SimpleNamespace(
            returncode=result.returncode, stdout=result.stdout.decode("utf-8"), stderr=""
        )


def package_version(native, name):
    value = native.run(["/usr/bin/dpkg-query", "-W", "-f=${Version}\t${db:Status-Abbrev}", name])
    fields = value.stdout.split("\t")
    need(len(fields) == 2 and fields[0] == LIBPQ and fields[1].strip() == "ii")
    return fields[0]


def derived_wheel(m, rows, *, create_lock):
    names = {C_WHEEL} if create_lock else {C_WHEEL, "database-derived.lock"}
    need({p.name for p in DERIVED.iterdir()} == names)
    raw = m.materials.regular(DERIVED / C_WHEEL)
    extensions = m.materials.wheel_inventory(
        DERIVED / C_WHEEL, "psycopg-c", "3.2.10", verified_bytes=raw
    )
    m.qualifier.zip_inventory(raw, name="psycopg-c", version="3.2.10")
    source = rows["psycopg-c"]
    m.materials.source_inventory(INPUTS / "public" / source["filename"], source)
    lock = m.materials.lock_bytes(
        [{"name": "psycopg-c", "version": "3.2.10", "sha256": m.support.sha(raw)}]
    )
    if create_lock:
        with (DERIVED / "database-derived.lock").open("xb") as stream:
            stream.write(lock)
    else:
        need(m.support.read_regular(DERIVED / "database-derived.lock", 65536) == lock)
    return {
        "source_sha256": source["sha256"],
        "wheel_sha256": m.support.sha(raw),
        "wheel_bytes": len(raw),
        "extensions": extensions,
        "build_attestation": False,
    }


def installed(m, descriptor, inventories, derived, native):
    need(Path(sys.prefix).resolve(strict=True) == PREFIX and sys.prefix != sys.base_prefix)
    base = PREFIX / "lib/python3.12/site-packages"
    need(
        "include-system-site-packages = false"
        in m.support.read_regular(PREFIX / "pyvenv.cfg", 4096).decode().lower()
    )
    m.adapter_v2.runtime_prelaunch(base)
    distributions = list(importlib.metadata.distributions(path=[str(base)]))
    actual = {
        re.sub(r"[-_.]+", "-", row.metadata["Name"]).lower(): row.version for row in distributions
    }
    need(len(actual) == len(distributions))
    need(actual == {**descriptor["distributions"], "psycopg": "3.2.10", "psycopg-c": "3.2.10"})
    need(all(Path(row.locate_file("")).resolve(strict=True) == base for row in distributions))
    # Existing three exact RECORD gates, including direct_url and SQL relocation.
    records = [
        m.records.check(
            PREFIX,
            inventories[kind],
            INPUTS / "wheels" / (name.replace("-", "_") + "-0.1.0a1-py3-none-any.whl"),
        )
        for kind, (name, _) in KINDS.items()
    ]
    for module, files in descriptor["module_files"].items():
        for filename, digest in files.items():
            need(m.support.sha(m.support.read_regular(base / module / filename, 1024**2)) == digest)
    sql = PREFIX / "share/pamolive/vault-reservation/schema.sql"
    need(m.support.sha(m.support.read_regular(sql, 65536)) == descriptor["sql_sha256"])
    driver = m.check_database_driver
    need(os.environ.get("PSYCOPG_IMPL") == "c")
    need(not any(os.environ.get(name) for name in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")))
    driver.reject_binary_packages({base})
    for path, facts in derived["extensions"].items():
        raw = m.materials.regular(base / path)
        need(len(raw) == facts["size"] and m.support.sha(raw) == facts["sha256"])
    import psycopg
    import psycopg_c
    from psycopg import pq

    driver.validate_versions(
        psycopg.__version__, psycopg_c.__version__, pq.__impl__, pq.version(), pq.__build_version__
    )
    need(pq.version() == pq.__build_version__ == 170012)
    need(Path(psycopg.__file__).resolve(strict=True).is_relative_to(base / "psycopg"))
    need(Path(psycopg_c.__file__).resolve(strict=True).is_relative_to(base / "psycopg_c"))
    package_version(native, "libpq5")
    # Only this module's subprocess binding is adapted; stdlib subprocess is not patched.
    driver.subprocess = SimpleNamespace(run=native.run)
    distribution = importlib.metadata.distribution("psycopg-c")
    dependencies = {}
    for path in driver.extension_paths(distribution):
        path, dynamic = driver.validate_extension(path, base / "psycopg_c")
        loaded = importlib.import_module("psycopg_c." + path.name.split(".")[0])
        need(Path(loaded.__file__).resolve(strict=True) == path)
        probe = native.run(
            ["/usr/bin/ldd", str(path)],
            env={**ENV, "LD_LIBRARY_PATH": "", "LD_PRELOAD": "", "LD_AUDIT": ""},
        )
        links = m.native_inventory.parse_ldd(probe.stdout)
        need(len(links) <= 64)
        for link in links:
            resolved = driver.trusted_file(Path(link["path"]), prefix=driver.SYSTEM)
            if link["soname"] not in dependencies:
                dependencies[link["soname"]] = {
                    "path": str(resolved),
                    "sha256": driver.digest(resolved),
                    **driver.dpkg_owner(resolved),
                }
            need(dependencies[link["soname"]]["path"] == str(resolved))
    need("libpq.so.5" in dependencies)
    libpq = dependencies["libpq.so.5"]
    need(libpq["package"].split(":")[0] == "libpq5" and libpq["version"] == LIBPQ)
    need(
        driver.loaded_libpq(driver.read_maps(Path("/proc/self/maps")), Path(libpq["path"]))
        == libpq["sha256"]
    )
    return {
        "three_RECORDs": records,
        "sql_sha256": descriptor["sql_sha256"],
        "implementation": pq.__impl__,
        "libpq_runtime": pq.version(),
        "libpq_build": pq.__build_version__,
        "system_libraries": dependencies,
        "database_connection_tested": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("inputs", "derived", "prelaunch", "installed"))
    parser.add_argument("--descriptor-sha256", required=True)
    parser.add_argument("--inventories-sha256", required=True)
    args = parser.parse_args()
    stage = "helpers"
    try:
        m = modules()
        if args.phase == "prelaunch":
            stage = "prelaunch"
            need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
            m.adapter_v2.runtime_prelaunch(PREFIX / "lib/python3.12/site-packages")
            return 0
        stage = "input_bindings"
        descriptor, inventories, rows = check_inputs(m, args)
        native = NativeCommands(m.bounded)
        report = {
            "schema": "pamolive.vault-consumer-offline/1",
            "phase": args.phase,
            "ok": False,
            "authority": False,
            "build_attestation": False,
            "descriptor_sha256": args.descriptor_sha256,
            "inventories_sha256": args.inventories_sha256,
        }
        stage = args.phase
        if args.phase == "inputs":
            package_version(native, "libpq-dev")
            package_version(native, "libpq5")
        else:
            derived = derived_wheel(m, rows, create_lock=args.phase == "derived")
            report["derived"] = derived
            if args.phase == "derived":
                package_version(native, "libpq-dev")
                package_version(native, "libpq5")
                need(
                    native.run(["/usr/bin/pg_config", "--version"]).stdout.startswith(
                        "PostgreSQL 17.12 "
                    )
                )
            else:
                report["installed"] = installed(m, descriptor, inventories, derived, native)
        report["native_processes"] = native.facts
        report["ok"] = True
        output = Path("/evidence") / (args.phase + ".json")
        output.parent.mkdir(mode=0o755, exist_ok=True)
        raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        need(len(raw) <= 128 * 1024)
        with output.open("xb") as stream:
            stream.write(raw)
        print(json.dumps({"phase": args.phase, "ok": True, "authority": False}))
        return 0
    except BaseException:
        # Public failure only; never print local values, subprocess output or traceback.
        print(json.dumps({"phase": args.phase, "stage": stage, "ok": False, "authority": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
