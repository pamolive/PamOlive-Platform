"""Capture the closed W1 source and test inputs independently of the three-wheel frame."""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from support import load, need, read_regular, sha  # noqa: E402

MODULE = "pamolive_usage_anchor"
MODULES = frozenset(
    f"{MODULE}/{name}.py"
    for name in (
        "__init__",
        "administration",
        "assembly",
        "authority",
        "client",
        "codec",
        "http",
        "ledger",
        "proofs",
        "service",
        "slot",
        "transport",
    )
)
BUILD = MODULES | {"LICENSE", "README.md", "pyproject.toml", "sql/schema.sql"}
RECEPTION = {
    "integration/permissions.py",
    "integration/scenario.py",
    "sql/mirror.sql",
    "tests/fixtures.py",
    "tests/golden/auth01-r1-public.json",
    "tests/golden/codec.json",
    "tests/test_history.py",
    "tests/test_http_client.py",
    "tests/test_pure.py",
    "tests/test_r2.py",
}
LAB = {
    "lab/witness_driver.py",
    "lab/witness_fence_cases.py",
    "lab/witness_history_cases.py",
    "lab/witness_postgres.py",
    "lab/witness_prepare.py",
    "lab/witness_server.py",
}


def capture(repository, pins):
    need(type(pins) is dict and pins.keys() == BUILD | RECEPTION)
    root = repository / "components/usage-anchor"
    need({p.name for p in (root / MODULE).iterdir()} == {Path(p).name for p in MODULES})
    result = {}
    for name, expected in pins.items():
        raw = read_regular(root / name, 65536)
        need(sha(raw) == expected)
        result[name] = raw
    return result


def put(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(content)


def prepare(work):
    load("controller.py").ci_guard(work)
    need(work.is_absolute() and work == work.resolve(strict=True))
    stage = work / "verified-consumer-context"
    need(stage == stage.resolve(strict=True))
    witness = stage / "witness"
    pins = read_regular(ROOT / "witness-source.sha256", 16384).decode("ascii").splitlines()
    files = capture(
        ROOT.parents[1], {name: digest for digest, name in (line.split("  ", 1) for line in pins)}
    )
    witness.mkdir(mode=0o700)
    for name, raw in files.items():
        put(witness, ("source/" if name in BUILD else "fixtures/") + name, raw)
    for name in ("witness_wheel.py", "witness_reception.py", "witness-source.sha256"):
        put(witness, name, read_regular(ROOT / name, 65536))
    lines = read_regular(ROOT / "source-checksums.sha256", 32768).decode("ascii").splitlines()
    runner_pins = {name: digest for digest, name in (line.split("  ", 1) for line in lines)}
    for name in sorted(LAB):
        raw = read_regular(ROOT / name, 65536)
        need(sha(raw) == runner_pins[name])
        put(witness, name, raw)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    try:
        prepare(parser.parse_args().work)
    except Exception:
        print("Witness source staging refused.", file=sys.stderr)
        raise SystemExit(42) from None
