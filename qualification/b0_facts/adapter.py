"""B0-D0 file facts only. Review-gated adapter; no daemon activity on import."""

import argparse
import hashlib
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path
from types import ModuleType

SOURCE = Path(__file__).resolve().parent
LEGACY_HASHES = {
    "controller.py": "7f3bfa46307673ba51c3a21fa3b70171ab9f931547e1903adce2fc02a29e02ce",
    "stage0.cjs": "b9a91608eac1ae724fc6367588813e729a49bc4598cc227d60a13486ffcbd400",
    "pins-stage0.json": ("62a37d816b3dbdf7de4ad657e38537f58d684dbab6b6bf5339f35f5328f2801e"),
    "assets-manifest.json": ("43dca7509b334e474a353aecf3bc3293ba97f7c4b91d0a2411d072fcce944e1e"),
}
ASSETS = {"facts.cjs": 65536, "facts-pins.json": 8192}
MAX_PUBLIC = 768 * 1024
PHASE = "public_file_inventory_only"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bootstrap_read(path, maximum):
    info = path.lstat()
    if not (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and not getattr(info, "st_file_attributes", 0) & 1024
        and 0 < info.st_size <= maximum
    ):
        raise ValueError("D0 bootstrap type or size")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not 0 < opened.st_size <= maximum
            or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ValueError("D0 bootstrap changed")
        raw = stream.read(maximum + 1)
        if len(raw) != opened.st_size or len(raw) > maximum:
            raise ValueError("D0 bootstrap read budget")
    return raw


def context(source, manifest_sha):
    """Hash the original lifecycle and new assets before interpreting either."""
    legacy_root = source / "legacy"
    legacy = {}
    for name, expected in LEGACY_HASHES.items():
        legacy[name] = bootstrap_read(legacy_root / name, 65536)
        if digest(legacy[name]) != expected:
            raise ValueError("D0 original stage0 identity changed")
    module = ModuleType("b0_d0_unmodified_stage0_lifecycle")
    module.__file__ = str(legacy_root / "controller.py")
    exec(compile(legacy["controller.py"], module.__file__, "exec"), module.__dict__)
    pins, _ = module.verified_assets(legacy_root, LEGACY_HASHES["assets-manifest.json"])
    raw = module.regular_bytes(source / "facts-assets.json", 8192)
    module.need(
        re.fullmatch("[a-f0-9]{64}", manifest_sha) and digest(raw) == manifest_sha,
        "B0_FACTS_MANIFEST_CHANGED",
    )
    manifest = module.strict_json(raw)
    module.closed(manifest, ("schema", "assets", "authority"))
    module.need(
        manifest["schema"] == "pamolive.b0-d0-assets/1" and manifest["authority"] is False,
        "B0_FACTS_MANIFEST_SCHEMA",
    )
    module.closed(manifest["assets"], ASSETS)
    buffers = {}
    for name, maximum in ASSETS.items():
        descriptor = manifest["assets"][name]
        module.closed(descriptor, ("bytes", "sha256"))
        module.need(
            type(descriptor["bytes"]) is int and 0 < descriptor["bytes"] <= maximum,
            "B0_FACTS_ASSET_DESCRIPTOR",
        )
        data = module.regular_bytes(source / name, maximum)
        module.need(
            len(data) == descriptor["bytes"] and digest(data) == descriptor["sha256"],
            "B0_FACTS_ASSET_CHANGED",
        )
        buffers[name] = data
    facts_pins = module.strict_json(buffers["facts-pins.json"])
    module.need(
        facts_pins
        == {
            "schema": "pamolive.b0-d0-pins/1",
            "image": pins["image"],
            "image_config": pins["image_config"],
            "node_entrypoint": "/usr/bin/node",
            "node_min_major": 20,
            "max_output_bytes": 700 * 1024,
            "authority": False,
        },
        "B0_FACTS_PINS_REFUSED",
    )
    return module, pins, buffers


def check_spool(module, work, buffers):
    directory = work / "inputs"
    module.need(
        not directory.is_symlink() and {p.name for p in directory.iterdir()} == set(ASSETS),
        "B0_FACTS_SPOOL_NOT_CLOSED",
    )
    for name, maximum in ASSETS.items():
        module.need(
            module.regular_bytes(directory / name, maximum) == buffers[name],
            "B0_FACTS_SPOOL_CHANGED",
        )


def spool(module, work, buffers):
    (work / "inputs").mkdir(mode=0o755)
    for name, data in buffers.items():
        with (work / "inputs" / name).open("xb") as stream:
            stream.write(data)
        (work / "inputs" / name).chmod(0o444)
    check_spool(module, work, buffers)


def create_arguments(module, work, pins, state):
    original = module.create_arguments(work, pins, state)
    index = original.index("--entrypoint")
    module.need(
        original[index:]
        == [
            "--entrypoint",
            "/bin/sh",
            pins["image"],
            "-c",
            "if ! command -v node >/dev/null 2>&1; then "
            + 'printf \'{"code":"B0_PRE_NODE_MISSING","ok":false}\\n\'; '
            + "exit 42; fi; exec node /inputs/stage0.cjs",
        ],
        "B0_FACTS_ORIGINAL_ARGUMENT_TAIL_CHANGED",
    )
    # All profile/mount/env/resource flags above remain inherited exactly.
    return original[:index] + [
        "--entrypoint",
        "/usr/bin/node",
        pins["image"],
        "/inputs/facts.cjs",
    ]


def validate_evidence(module, value):
    module.need(
        type(value) is dict
        and value.get("schema") == "pamolive.b0-d0-public-facts/1"
        and value.get("phase") == PHASE
        and type(value.get("ok")) is bool
        and re.fullmatch("B0_FACTS_[A-Z0-9_]+", value.get("code", "")),
        "B0_FACTS_EVIDENCE_SCHEMA",
    )
    module.need(
        value.get("stage0_passed") is False and value.get("authority") is False,
        "B0_FACTS_NONAUTHORITY_REQUIRED",
    )
    if not value["ok"]:
        allowed = {
            "schema",
            "phase",
            "ok",
            "code",
            "stage0_passed",
            "primary_fingerprints",
            "subkey_fingerprints",
            "authority",
            "release_qualified",
            "directory_entry_diagnostic",
        }
        module.need(
            set(value) <= allowed
            and value.get("primary_fingerprints") is None
            and value.get("subkey_fingerprints") is None
            and ("release_qualified" not in value or value["release_qualified"] is False),
            "B0_FACTS_FAILURE_VALUES",
        )
        if "directory_entry_diagnostic" in value:
            diagnostic = value["directory_entry_diagnostic"]
            module.need(type(diagnostic) is dict, "B0_FACTS_DIRECTORY_DIAGNOSTIC")
            module.closed(
                diagnostic,
                (
                    "code",
                    "directory_context",
                    "basename_status",
                    "basename_utf8_bytes",
                    "basename_sha256",
                ),
            )
            module.need(
                value["code"] == diagnostic["code"] == "B0_FACTS_DIRECTORY_ENTRY_REFUSED"
                and diagnostic["directory_context"] in ("sources_list_d", "trusted_gpg_d")
                and (
                    diagnostic["basename_status"] == "hashed"
                    and type(diagnostic["basename_utf8_bytes"]) is int
                    and 0 < diagnostic["basename_utf8_bytes"] <= 512
                    and type(diagnostic["basename_sha256"]) is str
                    and re.fullmatch(r"[a-f0-9]{64}", diagnostic["basename_sha256"])
                    or diagnostic["basename_status"] == "unavailable_or_refused"
                    and diagnostic["basename_utf8_bytes"] is None
                    and diagnostic["basename_sha256"] is None
                ),
                "B0_FACTS_DIRECTORY_DIAGNOSTIC",
            )
        return value
    fields = {
        "schema",
        "phase",
        "code",
        "ok",
        "os",
        "repositories",
        "keyring",
        "global_trust_inventory",
        "packages",
        "architecture_file_names",
        "nss_package_records",
        "files",
        "hashed_bytes",
        "truncation",
        "stage0_passed",
        "certutil_functional",
        "nss_empty",
        "Release_signatures_verified",
        "archives_verified",
        "dynamic_library_selection_verified",
        "TLS_observed",
        "sandbox_observed",
        "CDP_observed",
        "authority",
        "build_verified",
        "attestation_verified",
        "release_qualified",
        "nodeVersion",
    }
    module.closed(value, fields)
    module.need(
        value["code"] == "B0_FACTS_PUBLIC_INVENTORY_READY"
        and re.fullmatch(r"v\d{1,3}\.\d{1,3}\.\d{1,3}", value["nodeVersion"])
        and int(value["nodeVersion"][1:].split(".")[0]) >= 20,
        "B0_FACTS_SUCCESS_VALUES",
    )
    for key in (
        "truncation",
        "Release_signatures_verified",
        "archives_verified",
        "dynamic_library_selection_verified",
        "TLS_observed",
        "sandbox_observed",
        "CDP_observed",
        "build_verified",
        "attestation_verified",
        "release_qualified",
    ):
        module.need(value[key] is False, "B0_FACTS_QUALIFICATION_FORBIDDEN")
    module.need(
        value["certutil_functional"] is None
        and value["nss_empty"] is None
        and value["keyring"]["primary_fingerprints"] is None
        and value["keyring"]["subkey_fingerprints"] is None
        and value["keyring"]["certificate_bindings_verified"] is False,
        "B0_FACTS_KEY_OR_NSS_CLAIM_FORBIDDEN",
    )
    module.need(
        type(value["hashed_bytes"]) is int
        and 0 <= value["hashed_bytes"] <= 64 * 1024**2
        and type(value["packages"]) is list
        and len(value["packages"]) <= 2048
        and type(value["repositories"]) is list
        and 0 < len(value["repositories"]) <= 64,
        "B0_FACTS_COLLECTION_BUDGET",
    )
    return value


def bounded_json(value, maximum=MAX_PUBLIC):
    output, size = [], 0
    for piece in json.JSONEncoder(ensure_ascii=True, separators=(",", ":")).iterencode(value):
        data = piece.encode()
        size += len(data)
        if size + 1 > maximum:
            raise ValueError("D0 serialized budget")
        output.append(data)
    return b"".join(output) + b"\n"


def write_public(work, report):
    raw = bounded_json(report)
    temporary = work / (".facts-report-" + uuid.uuid4().hex)
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, work / "public-facts-report.json")


def ci_guard(module, work):
    module.ci_guard(work)
    module.need(
        not any(
            os.environ.get(key)
            for key in (
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
                "DOCKER_AUTH_CONFIG",
            )
        ),
        "B0_FACTS_AMBIENT_PROXY_OR_AUTH_REFUSED",
    )


def state_check(module, state, pins, buffers, manifest_sha):
    module.closed(
        state,
        (
            "schema",
            "phase",
            "run",
            "user",
            "image_config",
            "pins_sha256",
            "manifest_sha256",
            "create",
            "pull",
            "facts_attempted",
            "facts_sha256",
            "storage",
            "storage_after_pull",
            "storage_before_facts",
            "memory_available_bytes",
            "facts_process",
        ),
    )
    module.need(
        state.get("schema") == "pamolive.b0-d0-state/1"
        and state.get("phase") == PHASE
        and re.fullmatch("pamolive-b0-facts-[a-f0-9]{32}", state.get("run", ""))
        and state.get("user") == f"{os.getuid()}:{os.getgid()}"
        and state.get("image_config") == pins["image_config"]
        and state.get("pins_sha256") == digest(buffers["facts-pins.json"])
        and state.get("manifest_sha256") == manifest_sha
        and type(state.get("facts_attempted")) is bool
        and state.get("pull") in {"not_attempted", "pending", "unknown", "ready"},
        "B0_FACTS_STATE_REFUSED",
    )
    item = state.get("create")
    if item is not None:
        module.closed(item, ("name", "run", "image_config", "user", "cid", "attempted", "outcome"))
        module.need(
            item["name"] == state["run"] + "-stage0"
            and item["run"] == state["run"]
            and item["user"] == state["user"]
            and item["image_config"] == state["image_config"]
            and type(item["attempted"]) is bool
            and item["outcome"] in {"reserved", "pending", "unknown", "confirmed", "removed"}
            and (item["cid"] is None or re.fullmatch("[a-f0-9]{64}", item["cid"])),
            "B0_FACTS_RESERVATION_REFUSED",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "pull", "facts", "cleanup"))
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    module, pins, buffers = context(SOURCE, args.manifest_sha256)
    work = args.work_dir.resolve()
    ci_guard(module, work)
    os.umask(0o077)
    if args.mode == "prepare":
        module.need(not work.exists(), "B0_FACTS_WORK_NOT_FRESH")
        work.mkdir(mode=0o700)
        for name in ("docker-config", "evidence"):
            (work / name).mkdir(mode=0o700)
        spool(module, work, buffers)
        state = {
            "schema": "pamolive.b0-d0-state/1",
            "phase": PHASE,
            "run": "pamolive-b0-facts-" + uuid.uuid4().hex,
            "user": f"{os.getuid()}:{os.getgid()}",
            "image_config": pins["image_config"],
            "pins_sha256": digest(buffers["facts-pins.json"]),
            "manifest_sha256": args.manifest_sha256,
            "create": None,
            "pull": "not_attempted",
            "facts_attempted": False,
            "facts_sha256": None,
            "storage": None,
            "storage_after_pull": None,
            "storage_before_facts": None,
            "memory_available_bytes": None,
            "facts_process": None,
        }
    else:
        state = module.strict_json(module.regular_bytes(work / "state.json", 32768))
        state_check(module, state, pins, buffers, args.manifest_sha256)
        check_spool(module, work, buffers)
    client = module.LocalDocker(work)
    facts, code, ok = None, "B0_FACTS_CONTROLLER_REFUSED", False

    def save():
        bounded_json(state, 32768)
        module.atomic(work / "state.json", state)

    save()
    try:
        if args.mode == "cleanup":
            previous = module.strict_json(
                module.regular_bytes(work / "public-facts-report.json", MAX_PUBLIC)
            )
            module.need(
                previous.get("phase") == PHASE
                and type(previous.get("ok")) is bool
                and re.fullmatch("(?:B0_FACTS|B0_PRE)_[A-Z0-9_]+", previous.get("code", "")),
                "B0_FACTS_PREVIOUS_REPORT_REFUSED",
            )
            code, ok = previous["code"], previous["ok"]
        elif args.mode == "prepare":
            state["memory_available_bytes"] = module.memory_guard(pins["min_memory_MiB"])
            module.need(
                module.shutil.disk_usage(work).free >= pins["min_store_free_MiB"] * module.MIB,
                "B0_FACTS_WORK_DISK_INSUFFICIENT",
            )
            state["storage"] = {}
            module.storage_observation(client, pins["min_store_free_MiB"], state["storage"])
            code, ok = "B0_FACTS_RESOURCES_AND_SPOOL_READY", True
        elif args.mode == "pull":
            module.need(
                state["pull"] == "not_attempted" and state["storage"],
                "B0_FACTS_PULL_ONE_USE_REFUSED",
            )
            state["memory_available_bytes"] = module.memory_guard(pins["min_memory_MiB"])
            state["storage"] = {}
            module.storage_observation(client, pins["min_store_free_MiB"], state["storage"])
            state["pull"] = "pending"
            save()
            try:
                module.need(client.pull(pins) == 0, "B0_FACTS_PULL_FAILED")
                client.image(pins)
            except BaseException:
                state["pull"] = "unknown"
                save()
                raise module.Refusal("B0_FACTS_PULL_DAEMON_OUTCOME_UNKNOWN") from None
            state["pull"] = "ready"
            state["storage_after_pull"] = {}
            module.storage_observation(
                client, pins["min_store_free_MiB"], state["storage_after_pull"]
            )
            code, ok = "B0_FACTS_EXPLICIT_IMAGE_READY", True
        else:
            module.need(
                state["pull"] == "ready"
                and state["create"] is None
                and state["facts_attempted"] is False,
                "B0_FACTS_ONE_USE_OR_IMAGE_REFUSED",
            )
            state["facts_attempted"] = True
            save()
            client.image(pins)
            state["memory_available_bytes"] = module.memory_guard(pins["min_memory_MiB"])
            state["storage_before_facts"] = {}
            module.storage_observation(
                client, pins["min_store_free_MiB"], state["storage_before_facts"]
            )
            cid = module.reserve_create(
                client, state, save, create_arguments(module, work, pins, state)
            )
            module.validate_profile(client.inspect(cid), work)
            module.need(
                client.command("start", cid)[0] == 0,
                "B0_FACTS_NODE_ENTRYPOINT_START_FAILED",
            )
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                row = client.inspect(cid)
                module.need(
                    module.owns(row, state["create"]),
                    "B0_FACTS_RUNTIME_OWNERSHIP_REFUSED",
                )
                if not row["Running"]:
                    module.need(not row["OOMKilled"], "B0_FACTS_CONTAINER_OOM")
                    break
                time.sleep(0.2)
            else:
                raise module.Refusal("B0_FACTS_TIMEOUT")
            state["facts_process"] = {
                "container_id": cid,
                "exit_code": row["ExitCode"],
                "OOMKilled": row["OOMKilled"],
            }
            raw = module.regular_bytes(work / "evidence/facts.json", 700 * 1024)
            facts = validate_evidence(module, module.strict_json(raw))
            state["facts_sha256"] = digest(raw)
            code, ok = facts["code"], facts["ok"]
            module.need(ok and row["ExitCode"] == 0, code)
    except BaseException as error:
        code = str(error) if isinstance(error, module.Refusal) else "B0_FACTS_CONTROLLER_REFUSED"
        ok = False
    finally:
        cleanup = module.reconcile(client, state, save)
        save()
        if facts is None and state["facts_sha256"]:
            raw = module.regular_bytes(work / "evidence/facts.json", 700 * 1024)
            module.need(
                digest(raw) == state["facts_sha256"],
                "B0_FACTS_RETAINED_EVIDENCE_CHANGED",
            )
            facts = validate_evidence(module, module.strict_json(raw))
        report = {
            "schema": "pamolive.b0-d0-report/1",
            "phase": PHASE,
            "code": code,
            "ok": ok,
            "inventory_completed": bool(ok and facts and facts["ok"]),
            "image": pins["image"],
            "image_config": pins["image_config"],
            "manifest_sha256": args.manifest_sha256,
            "facts": facts,
            "facts_sha256": state["facts_sha256"],
            "facts_process": state["facts_process"],
            "storage": state["storage"],
            "storage_after_pull": state["storage_after_pull"],
            "storage_before_facts": state["storage_before_facts"],
            "memory_available_bytes": state["memory_available_bytes"],
            "pull_outcome": state["pull"],
            "cleanup": cleanup,
            "resources_released": bool(
                cleanup["released"] and state["pull"] not in {"pending", "unknown"}
            ),
            "stage0_passed": False,
            "certutil_functional": None,
            "nss_empty": None,
            "primary_fingerprints": None,
            "subkey_fingerprints": None,
            "repository_authorized": False,
            "Release_signatures_verified": False,
            "archives_verified": False,
            "TLS_observed": False,
            "sandbox_observed": False,
            "CDP_observed": False,
            "authority": False,
            "build_verified": False,
            "attestation_verified": False,
            "release_qualified": False,
        }
        try:
            write_public(work, report)
        except ValueError:
            code, ok = "B0_FACTS_PUBLIC_OUTPUT_BUDGET", False
            report.update(code=code, ok=False, inventory_completed=False, facts=None)
            write_public(work, report)
    print(json.dumps({"phase": PHASE, "code": code, "ok": ok, "stage0_passed": False}))
    raise SystemExit(0 if ok and report["resources_released"] else 42)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        print(
            '{"phase":"public_file_inventory_only","code":"B0_FACTS_CONTROLLER_REFUSED","ok":false,"stage0_passed":false}'
        )
        raise SystemExit(42) from None
