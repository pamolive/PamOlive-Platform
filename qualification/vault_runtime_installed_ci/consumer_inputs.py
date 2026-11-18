"""Prepare the isolated Vault consumer build from the same job's accepted wheels."""

import argparse
import os
import stat
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import adapter_v2  # noqa: E402
import orchestrate  # noqa: E402
import schema  # noqa: E402
import wheel_gate  # noqa: E402
import wheel_transfer  # noqa: E402
import workload_prepare  # noqa: E402
from lab.fixture_stage import FIXTURE_SHA256  # noqa: E402
from support import load, need, read_regular, sha  # noqa: E402

DRIVERS = {"psycopg", "psycopg-c"}
UTILS = {
    "check_database_driver.py": "5093b743958bf3c920d58caa66389676b5f5ecc5ed554c0f9cfd18c2b903f42f",
    "native_inventory.py": "0ae411ff3971470b7d62aba8d27bf307e948258aac2853ed82fdddcf8edd20c1",
}
CONTEXT = "verified-consumer-context"
TEST_SHA = "f0911729caf6907b56b24c98a32f415c51babdd4019153dd79f27b55b5caee5e"
LAB_FILES = {
    "fixture_stage.py",
    "fixtures.source",
    "installed_ten.py",
    "pg_bootstrap.py",
    "postgres_stage.py",
    "restore_child.py",
    "restore_inputs.py",
    "restore_probe.py",
    "role_files.py",
}


def verify_reception(frame, public, cleanup, *, bindings):
    need(public["schema"] == "pamolive.vault-installed-host-reception/2")
    for key in ("ok", "container_released", "clients_released", "resources_released"):
        need(public[key] is True)
    for key in ("container_released", "clients_released", "resources_released"):
        need(cleanup[key] is True)
    need(public["failure"] is None and cleanup["failure"] is None)
    need(public["authority"] is False and cleanup["authority"] is False)
    code = public["container_exit_code"]
    need(type(code) is int and code == 0 and public["container_OOMKilled"] is False)
    packet, descriptor, wheels = wheel_transfer.decode(frame, bindings=bindings)
    need(packet == public["packet"])
    return descriptor, wheels


def received_files(work, *, bindings):
    frame = work / wheel_transfer.FILENAME
    metadata = frame.lstat()
    need(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600)
    need(metadata.st_uid == os.getuid() and metadata.st_nlink == 1)
    return verify_reception(
        read_regular(frame, wheel_transfer.MAX_FRAME),
        schema.parse(
            read_regular(work / "public-report.json", schema.MAX_PACKET), schema.MAX_PACKET
        ),
        schema.parse(read_regular(work / "cleanup-public.json", 8192)),
        bindings=bindings,
    )


def installation_inputs(repository, source_root, wheels):
    inventories, lines = {}, []
    for kind, filename in wheel_transfer.wheel_names().items():
        inventory = wheel_gate.validate(
            wheels[filename], source_root / kind, kind, repository=repository
        )
        inventories[kind] = inventory
        lines.append(
            f"{inventory['name']} @ file:///inputs/wheels/{filename}"
            f" --hash=sha256:{inventory['wheel_sha256']}\n"
        )
    return inventories, "".join(lines).encode("ascii")


def put(directory, name, raw):
    target = directory / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(raw)


def pinned_utils(directory):
    files = {name: read_regular(directory / name, 65536) for name in UTILS}
    need(all(sha(raw) == UTILS[name] for name, raw in files.items()))
    return files


def put_lab(stage, repository, descriptor):
    lines = read_regular(ROOT / "source-checksums.sha256", 32768).decode("ascii").splitlines()
    pins = {path: digest for digest, path in (line.split("  ", 1) for line in lines)}
    for source in [
        *("lab/" + name for name in sorted(LAB_FILES)),
        "lab_prepare.py",
        "run_lab_role.py",
    ]:
        raw = read_regular(ROOT / source, 65536)
        need(sha(raw) == pins[source])
        put(stage, "lab/" + Path(source).name, raw)
    fixtures = repository / "components/vault/runtime"
    for source, target, digest in (
        ("tests/fixtures.py", "lab/signing-fixture.py", FIXTURE_SHA256),
        (
            "integration/serve_lab.py",
            "runtime/integration/serve_lab.py",
            descriptor["stage_files"]["integration/serve_lab.py"],
        ),
        ("integration/test_lab.py", "runtime/integration/test_lab.py", TEST_SHA),
    ):
        raw = read_regular(fixtures / source, 65536)
        need(sha(raw) == digest)
        put(stage, target, raw)


def prepare(work, material_directory, assets_sha):
    control, gate = load("controller.py"), load("python_materials.py")
    control.ci_guard(work)
    need(work == work.resolve(strict=True) and stat.S_IMODE(work.stat().st_mode) == 0o700)
    need(work.stat().st_uid == os.getuid())
    material_name = "vault-public-materials-" + work.name.removeprefix("pamolive-p2-installed-")
    need(material_directory == work.parent / material_name)
    need(material_directory == material_directory.resolve(strict=True))
    asset_rows = workload_prepare.assets(ROOT, assets_sha)["controller_files"]
    source_root, repository = ROOT / "inputs", ROOT.parents[1]
    utils = pinned_utils(repository / "deploy")
    payload, _ = orchestrate.source_payloads(source_root)
    bindings = {
        "expected_source": orchestrate.PAYLOAD_SHA,
        "expected_input": sha(schema.encode(orchestrate.description(payload))),
        "expected_sql": adapter_v2.SQL_SHA,
        "expected_materials": adapter_v2.MATERIALS,
    }
    descriptor, wheels = received_files(work, bindings=bindings)
    inventories, internal_lock = installation_inputs(repository, source_root, wheels)
    plan = adapter_v2.materials()
    manifest_path = repository / "deploy/python-materials.linux-amd64.json"
    manifest, manifest_sha = gate.load_manifest(manifest_path)
    need(manifest_sha == adapter_v2.MANIFEST)
    gate.check_locks(manifest, repository)
    drivers = {row["name"]: row for row in manifest["materials"] if row["name"] in DRIVERS}
    need(set(drivers) == DRIVERS and all(row["version"] == "3.2.10" for row in drivers.values()))
    materials = plan["selected_materials"]
    need(len(materials) == 16 and not (set(materials) & DRIVERS))
    stage = work / CONTEXT
    stage.mkdir(mode=0o700)
    for row in materials.values():
        filename = row["filename"]
        put(stage, "public/" + filename, gate.verify_file(material_directory / filename, row))
    deadline = time.monotonic() + 650
    opener = gate.https_opener()
    for row in drivers.values():
        filename = row["filename"]
        gate.download(row, stage / "public", opener, deadline=deadline)
        gate.verify_file(stage / "public" / filename, row)
    source_row = drivers["psycopg-c"]
    gate.source_inventory(stage / "public" / source_row["filename"], source_row)
    for filename, raw in wheels.items():
        put(stage, "wheels/" + filename, raw)
    for name, filename in (
        ("bootstrap", "requirements-bootstrap.lock"),
        ("build", "requirements-build.lock"),
        ("runtime", "requirements-runtime-linux.lock"),
    ):
        raw = read_regular(ROOT / filename, 65536)
        need(sha(raw) == asset_rows[filename]["sha256"])
        put(stage, "locks/" + name + ".lock", raw)
    for name in DRIVERS:
        filename = "database-build" if name == "psycopg-c" else "psycopg"
        put(stage, "locks/" + filename + ".lock", gate.lock_bytes([drivers[name]]))
    put(stage, "locks/internal.lock", internal_lock)
    put(stage, "descriptor.json", descriptor)
    put_lab(stage, repository, adapter_v2.descriptor(schema.parse(descriptor)))
    put(stage, "inventories.json", schema.encode(inventories, schema.MAX_PACKET))
    for name, row in asset_rows.items():
        raw = read_regular(ROOT / name, 2 * 1024**2)
        need(sha(raw) == row["sha256"])
        put(stage, "controller/" + name, raw)
    for name, raw in utils.items():
        put(stage, "util/" + name, raw)
    manifest_raw = read_regular(manifest_path, 65536)
    need(sha(manifest_raw) == manifest_sha)
    put(stage, "util/" + manifest_path.name, manifest_raw)
    put(stage, "verify_offline.py", read_regular(ROOT / "verify_offline.py", 65536))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--materials", required=True, type=Path)
    parser.add_argument("--assets-sha256", required=True)
    args = parser.parse_args()
    try:
        prepare(args.work, args.materials, args.assets_sha256)
    except Exception:
        print("Vault consumer material verification failed.", file=sys.stderr)
        raise SystemExit(42) from None
    print("Vault consumer build materials verified in this job.")


if __name__ == "__main__":
    main()
