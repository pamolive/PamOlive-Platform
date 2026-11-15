"""Capture the 36 pinned files from the real checkout, without package imports.

Generated inputs are never committed as another copy of the implementation.
The workflow verifies this source and its dependencies before invoking Python.
"""

import argparse
import importlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

support = importlib.import_module("support")
adapter = importlib.import_module("adapter_v2")
need, read_regular, sha = support.need, support.read_regular, support.sha

BASES = {
    "runtime": "components/vault/runtime",
    "runtime-tests": "components/vault/runtime",
    "verifier": "components/pam-trust-verifier",
    "contracts": "components/vault-registry",
}
COUNTS = {"runtime": 12, "verifier": 11, "contracts": 6, "runtime-tests": 7}


def selected(payload):
    need(
        type(payload) is dict
        and payload.get("schema") == "pamolive.vault-installed-source-payloads/2"
    )
    need(
        type(payload["groups"]) is dict
        and set(payload["groups"]) == {"runtime", "verifier", "contracts"}
    )
    groups = {**payload["groups"], "runtime-tests": payload["runtime_tests"]}
    need(set(payload["runtime_tests"]) == adapter.STAGE)
    rows = []
    for group, files in groups.items():
        need(type(files) is dict and len(files) == COUNTS[group])
        for name, pin in files.items():
            path = PurePosixPath(name)
            need(
                type(name) is str
                and not path.is_absolute()
                and path.as_posix() == name
                and "\\" not in name
                and all(part not in ("", ".", "..") for part in path.parts)
            )
            need(type(pin) is dict and set(pin) == {"bytes", "sha256"})
            need(type(pin["bytes"]) is int and 0 <= pin["bytes"] <= 1024**2)
            need(type(pin["sha256"]) is str and re.fullmatch("[a-f0-9]{64}", pin["sha256"]))
            rows.append((group, name, pin))
    need(len(rows) == 36)
    return rows


def capture(repository, destination, payload):
    repository = repository.absolute()
    destination = destination.absolute()
    need(repository == repository.resolve(strict=True))
    need(destination.parent == destination.parent.resolve(strict=True) and not destination.exists())
    buffers = {}
    observed = {}
    for group, name, pin in selected(payload):
        source = repository / BASES[group] / name
        raw = read_regular(source, 1024**2)
        need({"bytes": len(raw), "sha256": sha(raw)} == pin)
        buffers[(group, name)] = raw
        observed[source.relative_to(repository).as_posix()] = pin
    need(len(observed) == 36)
    root_notice = read_regular(repository / "LICENSE", 65536)
    need({"bytes": len(root_notice), "sha256": sha(root_notice)} == payload["root_notice"])
    need(buffers[("contracts", "LICENSE")] == root_notice)
    # Complete all source checks before creating any destination file.
    destination.mkdir(mode=0o700)
    for (group, name), raw in buffers.items():
        path = destination / group / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    # Re-read both sides; a partial or changed capture never yields success.
    for group, name, pin in selected(payload):
        for path in (repository / BASES[group] / name, destination / group / name):
            raw = read_regular(path, 1024**2)
            need({"bytes": len(raw), "sha256": sha(raw)} == pin)
    need(read_regular(repository / "LICENSE", 65536) == root_notice)
    return {
        "schema": "pamolive.vault-installed-checkout-capture/1",
        "files": observed,
        "captured_files": len(buffers),
        "actual_build_install_or_authority": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--payload-sha256", required=True)
    args = parser.parse_args()
    raw = read_regular(HERE / "payloads.json", 65536)
    need(sha(raw) == args.payload_sha256)
    result = capture(args.repository, HERE / "inputs", json.loads(raw))
    with (HERE / "checkout-capture.json").open("x", encoding="utf8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {"captured_files": result["captured_files"], "actual_build_install_or_authority": False}
        )
    )


if __name__ == "__main__":
    main()
