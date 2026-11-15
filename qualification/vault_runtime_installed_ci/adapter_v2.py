"""Preflight/workload contract and injectable16-material acquisition only."""

import json
import stat
import time

import schema
from support import ROOT, load, need, read_regular, sha

MATERIALS = "074356440b344b672028cd8eec33f96c0a866d36e7f3910af4b10a231872a7c6"
MANIFEST = "c3c219a7233a8fe3ef93eea81363fe9d846cfde538bb9c1fe3af967bb8b02ed0"
INTERNAL = {
    "pamolive-vault-reservation-runtime": "0.1.0a1",
    "pamolive-vault-contracts": "0.1.0a1",
    "pamolive-pam-trust-verifier": "0.1.0a1",
}
CODE = {
    "pamolive_vault_runtime": {
        "__init__.py",
        "admission.py",
        "asgi.py",
        "assembly.py",
        "bounded.py",
        "ledger.py",
        "slot.py",
        "transport.py",
    },
    "pamolive_vault_contracts": {"__init__.py", "contracts.py", "canonical.py"},
    "pamolive_pam_trust_verifier": {
        "__init__.py",
        "_v1_rules.py",
        "_crypto.py",
        "_context.py",
        "_codec.py",
        "_api.py",
    },
}
STAGE = {
    "tests/" + name
    for name in (
        "fixtures.py",
        "test_runtime.py",
        "test_ro_slot.py",
        "test_r2_boundaries.py",
        "history/r1/bounded.py",
        "history/r1/transport.py",
    )
}
SQL_SHA = "78cbd52dc5b30fa1139dedaf29b903fbd0becd5272d648ddd60ee35b4769a72f"


def materials():
    raw = read_regular(ROOT / "materials-plan.json", 65536)
    need(sha(raw) == MATERIALS)
    return schema.parse(raw, 65536)


def distributions():
    plan = materials()
    rows = plan["selected_materials"]
    return {
        **{name: rows[name]["version"] for name in plan["runtime_public_names"]},
        "pip": rows["pip"]["version"],
        **INTERNAL,
    }


def descriptor(value):
    need(
        type(value) is dict
        and set(value)
        == {"schema", "distributions", "module_files", "stage_files", "source_sha256", "sql_sha256"}
    )
    need(value["schema"] == "pamolive.vault-runtime-installed-input/2")
    need(value["distributions"] == distributions() and schema.digest(value["source_sha256"]))
    need(value["sql_sha256"] == SQL_SHA)
    need(type(value["module_files"]) is dict and set(value["module_files"]) == set(CODE))
    for module, names in CODE.items():
        records = value["module_files"][module]
        need(type(records) is dict and set(records) == names)
        need(all(schema.digest(digest) for digest in records.values()))
    need(type(value["stage_files"]) is dict and set(value["stage_files"]) == STAGE)
    need(all(schema.digest(digest) for digest in value["stage_files"].values()))
    return value


def validate_stage(stage, expected):
    need(stage.is_absolute() and stage == stage.resolve(strict=True))
    need(len(stage.parents) >= 6)
    actual = set()
    directories = {"tests", "tests/history", "tests/history/r1"}
    for path in stage.rglob("*"):
        row = path.lstat()
        need(not path.is_symlink() and not getattr(row, "st_file_attributes", 0) & 1024)
        need(stat.S_ISREG(row.st_mode) or stat.S_ISDIR(row.st_mode))
        if path.is_file():
            name = path.relative_to(stage).as_posix()
            actual.add(name)
            need(name in expected and sha(read_regular(path, 1024**2)) == expected[name])
        else:
            need(path.relative_to(stage).as_posix() in directories)
    need(actual == STAGE)


def runtime_prelaunch(site):
    """Mandatory parent-side check AFTER install and BEFORE launching target Python."""
    need(site.is_dir() and site == site.resolve(strict=True))
    need(not list(site.rglob("*.pth")))
    need(not list(site.rglob("*.pyc")))
    # -I still imports sitecustomize from the venv before the child guard.
    # Refuse both reserved startup module families, including packages,
    # extension modules and symlink names, without importing or opening them.
    hooks = {"sitecustomize", "usercustomize"}
    need(not any(path.name.partition(".")[0] in hooks for path in site.iterdir()))
    return True


def acquire(repository, destination, *, gate=None, inventory=None, clock=time.monotonic):
    """No CLI/main. Future caller supplies reviewed Root GO; tests inject fake IO."""
    gate = gate if gate is not None else load("python_materials.py")
    inventory = inventory if inventory is not None else load("qualify_installed.py").zip_inventory
    plan = materials()
    manifest, digest = gate.load_manifest(repository / "deploy/python-materials.linux-amd64.json")
    need(digest == MANIFEST)
    gate.check_locks(manifest, repository)
    names = set(plan["selected_materials"])
    rows = {row["name"]: row for row in manifest["materials"] if row["name"] in names}
    need(len(names) == 16 and rows == plan["selected_materials"])
    need(not destination.exists() and destination.is_absolute())
    need(destination.parent == destination.parent.resolve(strict=True))
    need(not destination.is_relative_to(repository.resolve(strict=True)))
    need(not destination.is_relative_to(ROOT))
    destination.mkdir(mode=0o700)
    receipt = {
        "schema": "pamolive.vault-runtime-sixteen-acquisition/1",
        "state": "INCOMPLETE",
        "files": {},
        "authority": False,
    }
    started, original = clock(), None
    try:
        opener = gate.https_opener()
        for name, row in sorted(rows.items()):
            need(clock() - started <= 1800)
            gate.download(row, destination, opener, deadline=started + 1800)
            raw = gate.verify_file(destination / row["filename"], row)
            need(type(raw) is bytes and len(raw) == row["size"] and sha(raw) == row["sha256"])
            facts = inventory(raw, name=name, version=row["version"])
            need(facts["RECORD_checked"] is True)
            receipt["files"][row["filename"]] = {
                "bytes": len(raw),
                "sha256": sha(raw),
                "ZIP_RECORD_checked": True,
            }
        receipt["state"] = "SIXTEEN_PUBLIC_WHEELS_CHECKED"
    except BaseException as error:
        original = error
        receipt["state"] = "FAILED"
        raise
    finally:
        try:
            with (destination / "acquisition.json").open("x", encoding="utf-8") as stream:
                json.dump(receipt, stream, indent=2)
                stream.write("\n")
        except BaseException:
            if original is not None:
                raise original from None
            raise
    return receipt
