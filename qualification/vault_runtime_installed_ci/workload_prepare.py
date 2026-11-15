"""Fresh three-RO-mount staging from one externally pinned source asset list."""

import uuid
from pathlib import Path

import adapter_v2
import host_seam
import orchestrate
import schema
from support import load, need, read_regular, sha

S0_SHA = "33b0cfd98d7eb3aa6a5c1d509cc559bddb77988dc1135b9ecde880689b9151a1"
CONTROLLER_FILES = {
    "support.py",
    "schema.py",
    "host_seam.py",
    "guards.py",
    "adapter_v2.py",
    "installed_runner.py",
    "orchestrate.py",
    "records.py",
    "wheel_gate.py",
    "workload_schema.py",
    "workload_entry.py",
    "workload_host.py",
    "workload_prepare.py",
    "helper-pins.json",
    "materials-plan.json",
    "payloads.json",
    "requirements-bootstrap.lock",
    "requirements-build.lock",
    "requirements-runtime-linux.lock",
    "s0-pins.json",
    *{
        "helpers/" + name
        for name in (
            "controller.py",
            "legacy_controller.py",
            "bounded_io.py",
            "entrypoint.py",
            "base-config.json",
            "installed_tests.py",
            "qualify_installed.py",
            "python_materials.py",
            "check_wheel.py",
        )
    },
}


def s0_pins(value):
    raw = read_regular(Path(__file__).parent / "s0-pins.json", 65536)
    need(sha(raw) == S0_SHA)
    expected = schema.parse(raw, 65536)
    need(type(value) is dict and value == expected)
    return expected


def assets(root, digest):
    raw = read_regular(root / "source-assets.json", 65536)
    need(sha(raw) == digest)
    value = schema.parse(raw, 65536)
    need(type(value) is dict and set(value) == {"schema", "controller_files", "payloads_sha256"})
    need(value["schema"] == "pamolive.vault-installed-source-assets/2")
    need(value["payloads_sha256"] == orchestrate.PAYLOAD_SHA)
    need(
        type(value["controller_files"]) is dict
        and set(value["controller_files"]) == CONTROLLER_FILES
    )
    control = load("controller.py")
    for name, row in value["controller_files"].items():
        control.safe_name(name)
        need(type(row) is dict and set(row) == {"bytes", "sha256"})
        raw = read_regular(root / name, 2 * 1024**2)
        need({"bytes": len(raw), "sha256": sha(raw)} == row)
    return value


def prepare(work, source_root, material_directory, *, assets_sha256, pins):
    """No daemon call. This function must only be invoked under a later Root GO."""
    control, gate, qualifier = (
        load("controller.py"),
        load("python_materials.py"),
        load("qualify_installed.py"),
    )
    control.ci_guard(work)
    s0_pins(pins)
    need(not work.exists())
    inventory = assets(source_root, assets_sha256)
    payload, buffers = orchestrate.source_payloads(source_root / "inputs")
    plan = adapter_v2.materials()
    rows = plan["selected_materials"]
    receipt_raw = read_regular(material_directory / "acquisition.json", 65536)
    receipt = schema.parse(receipt_raw, 65536)
    need(type(receipt) is dict and set(receipt) == {"schema", "state", "files", "authority"})
    need(
        receipt["schema"] == "pamolive.vault-runtime-sixteen-acquisition/1"
        and receipt["state"] == "SIXTEEN_PUBLIC_WHEELS_CHECKED"
        and receipt["authority"] is False
    )
    need(set(receipt["files"]) == {row["filename"] for row in rows.values()})
    control.closed_files(material_directory, set(receipt["files"]) | {"acquisition.json"}, 32)
    verified = {}
    for name, row in rows.items():
        raw = gate.verify_file(material_directory / row["filename"], row)
        need(
            receipt["files"][row["filename"]]
            == {"bytes": len(raw), "sha256": sha(raw), "ZIP_RECORD_checked": True}
        )
        need(
            qualifier.zip_inventory(raw, name=name, version=row["version"])["RECORD_checked"]
            is True
        )
        verified[row["filename"]] = raw
    work.mkdir(mode=0o700)
    identities = {}

    def stage(name, raw):
        control.stage_file(work / name, raw)
        identities[name] = sha(raw)

    for name in inventory["controller_files"]:
        stage("controller/" + name, read_regular(source_root / name, 2 * 1024**2))
    for (group, name), raw in buffers.items():
        stage("source/" + group + "/" + name, raw)
    for name, raw in verified.items():
        stage("materials/" + name, raw)
    stage("materials/acquisition.json", receipt_raw)
    (work / "home").mkdir(mode=0o700)
    (work / "docker-config").mkdir(mode=0o700)
    (work / "docker-config/config.json").write_bytes(b'{"auths":{},"proxies":{}}\n')
    descriptor = orchestrate.description(payload)
    state = {
        "type": host_seam.STATE,
        "phase": host_seam.PHASE,
        "run": "pamolive-p2-installed-" + uuid.uuid4().hex,
        "user": "1000:1000",
        "image_config": pins["image_config"],
        "pull": "not_attempted",
        "started": False,
        "identities": identities,
        "assets_sha256": assets_sha256,
        "IO": [],
        "IO_total": 0,
        "IO_uncertain": False,
        "failure": None,
        "bindings": {
            "expected_source": orchestrate.PAYLOAD_SHA,
            "expected_materials": adapter_v2.MATERIALS,
            "expected_sql": adapter_v2.SQL_SHA,
            "expected_input": sha(schema.encode(descriptor)),
        },
    }
    control.check_inputs(work, state)
    control.atomic(work / "state.json", state)
    return state
