"""Strict DATA result gate. A successful Docker export is not a successful capture."""

import argparse
import hashlib
import json
import stat
from pathlib import Path


def need(value):
    if not value:
        raise ValueError("C_DATA_REFUSED_OR_UNKNOWN")


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result)
        result[key] = value
    return result


def parse(raw):
    need(type(raw) is bytes and len(raw) <= 4 * 1024**2)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda value: need(False))


def validate(packet_raw, result_raw, material_raw, status_raw, code_sha, policy_sha):
    packet, result, material = map(parse, (packet_raw, result_raw, material_raw))
    need(
        set(packet)
        == {
            "schema",
            "state",
            "resources_released",
            "all_OS_descendants_released",
            "build_verified",
            "materials_complete",
            "code_pins_sha256",
            "H1",
            "result_sha256",
        }
    )
    need(
        packet["schema"] == "pamolive.expat-C-supervisor/1"
        and packet["state"] == "DRIVER_NORMAL_DATA_ONLY"
        and packet["code_pins_sha256"] == code_sha
        and packet["result_sha256"] == hashlib.sha256(result_raw).hexdigest()
    )
    facts = packet["H1"]
    need(
        type(facts) is dict
        and type(facts.get("returncode")) is int
        and facts["returncode"] == 0
        and facts.get("spawn_attempted") is True
        and type(facts.get("pid")) is int
        and facts["pid"] > 0
        and facts.get("owned_child_reaped") is True
        and facts.get("drains_complete") is True
        and facts.get("killed_owned_child") is False
        and all(
            facts.get(key, "MISSING") is None
            for key in ("reason", "exception_type", "cleanup_exception_type")
        )
    )
    need(
        result["state"] == "AUTHENTICATED_UNAPPROVED_NOT_INSTALLED"
        and result["code_pins_sha256"] == code_sha
        and result["policy_sha256"] == policy_sha
        and result["material_set_sha256"] == hashlib.sha256(material_raw).hexdigest()
        and result["prestate_sha256"]
        == result["poststate_sha256"]
        == hashlib.sha256(status_raw).hexdigest()
        and material["schema"] == "pamolive.expat-prepared.material-set/2"
        and material["policy_sha256"] == policy_sha
    )
    for value in (packet, result, material):
        need(value["build_verified"] is False and value["materials_complete"] is False)
    need(packet["resources_released"] is False and packet["all_OS_descendants_released"] is False)
    return {
        "state": "AUTHENTICATED_UNAPPROVED_NOT_INSTALLED",
        "material_set_sha256": result["material_set_sha256"],
        "authority": False,
    }


def regular(path, maximum):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum)
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    need(len(raw) == info.st_size)
    return raw


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("root", type=Path)
    parser.add_argument("--code-sha", required=True)
    parser.add_argument("--policy-sha", required=True)
    args = parser.parse_args()
    root = args.root
    value = validate(
        regular(root / "supervisor.json", 32768),
        regular(root / "inputs/result.json", 4 * 1024**2),
        regular(root / "inputs/material-set.UNAPPROVED.json", 4 * 1024**2),
        regular(root / "inputs/status-before", 4 * 1024**2),
        args.code_sha,
        args.policy_sha,
    )
    print(json.dumps(value))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"state":"REFUSED_OR_UNKNOWN","authority":false}')
        raise SystemExit(42) from None
