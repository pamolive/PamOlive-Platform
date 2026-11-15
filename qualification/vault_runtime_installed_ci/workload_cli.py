"""Future host CLI. Source hashes/pure gates must be checked by workflow first."""

import argparse
import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
support = importlib.import_module("support")
prepare = importlib.import_module("workload_prepare")
host = importlib.import_module("workload_host")
orchestrate = importlib.import_module("orchestrate")
adapter = importlib.import_module("adapter_v2")
schema = importlib.import_module("schema")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("verify", "acquire", "prepare", "pull", "run", "cleanup"))
    parser.add_argument("--assets-sha256", required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--materials", type=Path)
    parser.add_argument("--repository", type=Path)
    args = parser.parse_args()
    assets = prepare.assets(ROOT, args.assets_sha256)
    pins = schema.parse(support.read_regular(ROOT / "s0-pins.json", 65536), 65536)
    prepare.s0_pins(pins)
    control = support.load("controller.py")
    if args.mode == "cleanup":
        state = schema.parse(control.regular(args.work / "state.json", 256 * 1024), 256 * 1024)
        support.need(state["assets_sha256"] == args.assets_sha256)
        bindings = state["bindings"]
        support.need(
            set(bindings)
            == {"expected_source", "expected_input", "expected_sql", "expected_materials"}
        )
        support.need(all(schema.digest(value) for value in bindings.values()))
        support.need(
            bindings["expected_source"] == orchestrate.PAYLOAD_SHA
            and bindings["expected_sql"] == adapter.SQL_SHA
            and bindings["expected_materials"] == adapter.MATERIALS
        )
    else:
        payload, _ = orchestrate.source_payloads(ROOT / "inputs")
        bindings = {
            "expected_source": orchestrate.PAYLOAD_SHA,
            "expected_input": support.sha(schema.encode(orchestrate.description(payload))),
            "expected_sql": adapter.SQL_SHA,
            "expected_materials": adapter.MATERIALS,
        }
    if args.mode == "verify":
        print(schema.encode({"state": "SOURCE_ONLY_VERIFIED", "authority": False}).decode(), end="")
        return
    if args.mode == "acquire":
        support.need(args.repository is not None and args.materials is not None)
        receipt = adapter.acquire(args.repository, args.materials)
        print(
            schema.encode(
                {"state": receipt["state"], "wheels": len(receipt["files"]), "authority": False}
            ).decode(),
            end="",
        )
        return
    if args.mode == "prepare":
        support.need(args.materials is not None)
        prepare.prepare(
            args.work, ROOT, args.materials, assets_sha256=args.assets_sha256, pins=pins
        )
        print(schema.encode({"state": "STAGED_NOT_EXECUTED", "authority": False}).decode(), end="")
        return
    if args.mode != "cleanup":
        state = schema.parse(control.regular(args.work / "state.json", 256 * 1024), 256 * 1024)
    support.need(state["assets_sha256"] == args.assets_sha256 and state["bindings"] == bindings)
    entry = host.bootstrap(assets["controller_files"]["workload_entry.py"]["sha256"], bindings)
    entry_sha = support.sha(entry)
    if args.mode == "pull":
        host.pull_owned(args.work, pins, state, entry, entry_sha)
        print(
            schema.encode({"state": "S0_PULL_READY_NOT_QUALIFIED", "authority": False}).decode(),
            end="",
        )
        return
    result = (
        host.run_owned(args.work, pins, state, entry, entry_sha, bindings=bindings)
        if args.mode == "run"
        else host.cleanup_owned(args.work, pins, state, entry, entry_sha)
    )
    control.atomic(
        args.work / ("public-report.json" if args.mode == "run" else "cleanup-public.json"),
        result,
        512 * 1024,
    )
    ok = result["ok"] if args.mode == "run" else result["resources_released"]
    print(
        schema.encode(
            {"state": "PASS" if ok else "FAILED_OR_UNKNOWN", "authority": False}
        ).decode(),
        end="",
    )
    raise SystemExit(0 if ok else 42)


if __name__ == "__main__":
    main()
