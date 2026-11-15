"""Explicit public 13-wheel acquisition, separate from offline qualification."""

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ADAPTER_HASH = "649ac99037fc41fa24b80fe93bd6833dd968dbdbaf879f51127d25972b5f4878"
GATE_HASH = "0956e68ea06451fab2c3f5ce9f5aedf603b0fa5724f18366c937a48e5ebce8b2"
MANIFEST_HASH = "c3c219a7233a8fe3ef93eea81363fe9d846cfde538bb9c1fe3af967bb8b02ed0"


def load_adapter():
    path = ROOT / "qualify_installed.py"
    info = path.lstat()
    if not (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and not path.is_symlink()
        and not getattr(info, "st_file_attributes", 0) & 1024
        and 0 <= info.st_size <= 1024 * 1024
    ):
        raise ValueError("adapter_type_size")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
        ) or not (
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and not getattr(opened, "st_file_attributes", 0) & 1024
        ):
            raise ValueError("adapter_identity")
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) != info.st_size or hashlib.sha256(raw).hexdigest() != ADAPTER_HASH:
        raise ValueError("adapter_hash")

    class Loader(importlib.machinery.SourceFileLoader):
        def get_code(self, fullname):
            return compile(raw, str(path), "exec", dont_inherit=True)

    name = "integrated_materials_adapter"
    spec = importlib.util.spec_from_loader(name, Loader(name, str(path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


adapter = load_adapter()


def load_gate(path):
    raw = adapter.bootstrap_read(path, 1024 * 1024)
    adapter.require(adapter.sha(raw) == GATE_HASH, "existing_gate_hash")

    class PinnedLoader(importlib.machinery.SourceFileLoader):
        def get_code(self, fullname):
            return compile(raw, str(path), "exec", dont_inherit=True)

    name = "public_verifier_existing_materials_gate"
    spec = importlib.util.spec_from_loader(name, PinnedLoader(name, str(path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def selected_rows(gate, repository):
    manifest, digest = gate.load_manifest(repository / "deploy/python-materials.linux-amd64.json")
    adapter.require(digest == MANIFEST_HASH, "existing_manifest_hash")
    gate.check_locks(manifest, repository)
    expected, _ = adapter.document(ROOT / "materials-plan.json", adapter.MATERIALS_HASH)
    names = adapter.RUNTIME_NAMES | adapter.BUILD_NAMES | {"pip"}
    rows = {row["name"]: row for row in manifest["materials"] if row["name"] in names}
    adapter.require(
        set(rows) == names and rows == expected["selected_materials"],
        "exact_thirteen_from_existing_manifest",
    )
    adapter.require(
        all(row["kind"] == "wheel" for row in rows.values())
        and sum(row["size"] for row in rows.values()) == 8939939,
        "thirteen_wheels_budget",
    )
    adapter.check_locks(rows)
    return rows


def acquire(repository, destination, *, gate=None):
    repository = repository.resolve(strict=True)
    destination = destination.resolve()
    adapter.require(
        not destination.is_relative_to(repository) and not destination.is_relative_to(ROOT),
        "acquisition_outside_checkout",
    )
    adapter.require(not destination.exists(), "one_use_acquisition")
    gate = gate if gate is not None else load_gate(repository / "deploy/python_materials.py")
    rows = selected_rows(gate, repository)
    destination.mkdir(mode=0o700, parents=False)
    report = {
        "schema": "pamolive.public-verifier-thirteen-acquisition/1",
        "state": "INCOMPLETE",
        "existing_gate_sha256": GATE_HASH,
        "existing_manifest_sha256": MANIFEST_HASH,
        "files": {},
        "authority": False,
        "installed_or_built": False,
    }
    started = time.monotonic()
    failure = None
    try:
        opener = gate.https_opener()
        for name in sorted(rows):
            adapter.require(time.monotonic() - started <= 1800, "acquisition_budget")
            row = rows[name]
            gate.download(row, destination, opener)
            raw = gate.verify_file(destination / row["filename"], row)
            facts = adapter.zip_inventory(raw, name=name, version=row["version"])
            report["files"][row["filename"]] = {
                "sha256": adapter.sha(raw),
                "bytes": len(raw),
                "ZIP_RECORD_checked": facts["RECORD_checked"],
            }
        report["state"] = "THIRTEEN_PUBLIC_WHEELS_ACQUIRED_AND_CHECKED"
    except BaseException as error:
        report.update(state="FAILED", exception_type=type(error).__name__)
        failure = error
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        try:
            adapter.write_new(destination / "acquisition.json", adapter.encoded(report))
        except BaseException:
            if failure is not None:
                raise failure from None
            raise
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("acquire",))
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    plan, _ = adapter.document(ROOT / "acquisition-plan.json", args.plan_sha256)
    adapter.require(plan["execution_authorized_by_plan"] is False, "plan_not_permission")
    for name, digest in plan["files_sha256"].items():
        adapter.safe_path(name)
        adapter.require(
            adapter.sha(adapter.bootstrap_read(ROOT / name)) == digest,
            "acquisition_control_pin",
        )
    result = acquire(args.repository, args.destination)
    print(json.dumps({"state": result["state"], "wheels": len(result["files"])}))


if __name__ == "__main__":
    main()
