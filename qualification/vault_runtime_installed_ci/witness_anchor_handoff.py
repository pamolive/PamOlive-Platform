"""Qualify transfer of one synthetic witness checkpoint between Linux runners."""

import argparse
import json
import os
import re
import sys
from itertools import islice
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from support import need, read_regular, sha  # noqa: E402

NAME = "anchor-handoff.json"


def boot_fingerprint():
    with Path("/proc/sys/kernel/random/boot_id").open("rb") as handle:
        boot = handle.read(38)
    need(re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", boot) is not None)
    return sha(b"pamolive.witness.synthetic-boot/1\0" + boot)


def publish(work):
    """Expose the pins through job outputs, separately from the signed document."""
    report = json.loads(read_regular(work / "witness-lab-public.json", 8192))
    need(
        report["schema"] == "pamolive.witness-installed-pitr-anchor-store/3"
        and report["ok"] is True
        and report["cleaned_up"] is True
        and report["authority"] is False
        and report["native"]["anchor_store"]["restore_copy_exact"] is True
        and report["native"]["anchor_store"]["checkpoint_key_rotation_verified"] is True
        and report["native"]["anchor_store"]["custody_atomic_rotation_verified"] is True
    )
    references = read_regular(work / "anchor-reference", 130)
    need(re.fullmatch(rb"[0-9a-f]{64}\n[0-9a-f]{64}\n", references) is not None)
    public, pin = references.decode("ascii").splitlines()
    raw = read_regular(work / NAME, 1024)
    need(0 < len(raw) and sha(raw) == pin)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="ascii", newline="\n") as handle:
        handle.write(f"anchor_sha={pin}\npublic_hex={public}\nboot_sha={boot_fingerprint()}\n")


def exact_import(incoming, store, *, public, pin, codec, max_bytes):
    need([item.name for item in islice(incoming.iterdir(), 2)] == [NAME])
    raw = read_regular(incoming / NAME, max_bytes)
    need(0 < len(raw) < max_bytes)
    wrong_public = bytes([public[0] ^ 1]) + public[1:]
    for document, key in ((raw + b"\n", public), (raw, wrong_public)):
        try:
            store.save(document, public_key=key, expected_sha256=pin)
        except codec.Error as exc:
            need((exc.code, exc.status) == ("anchor_refused", 403))
        else:
            need(False)
    return raw


def receive(options):
    sys.path.insert(0, str(ROOT.parents[1] / "components/usage-anchor"))
    from pamolive_usage_anchor import codec
    from pamolive_usage_anchor.anchor_store import AnchorStore
    from pamolive_usage_anchor.signed_anchor import MAX_ANCHOR_BYTES

    pin = codec.digest(os.environ["ANCHOR_SHA"])
    public = bytes.fromhex(codec.digest(os.environ["ANCHOR_PUBLIC_HEX"]))
    source_boot = codec.digest(os.environ["ANCHOR_SOURCE_BOOT"])
    destination_boot = boot_fingerprint()
    need(source_boot != destination_boot)
    store = AnchorStore(options.store, owner_uid=os.geteuid())
    if options.mode == "import":
        options.store.mkdir(mode=0o700)
        raw = exact_import(
            options.incoming, store, public=public, pin=pin, codec=codec,
            max_bytes=MAX_ANCHOR_BYTES,
        )
        need(next(options.store.iterdir(), None) is None)
        store.save(raw, public_key=public, expected_sha256=pin)
        return

    checkpoint, raw = store.load(public_key=public, expected_sha256=pin)
    need(sha(raw) == pin and checkpoint.last_seq > 3)
    missing = sha(b"pamolive.witness.synthetic-absent-point/1")
    need(missing != pin)
    try:
        store.load(public_key=public, expected_sha256=missing)
    except codec.Error as exc:
        need((exc.code, exc.status) == ("unavailable", 503))
    else:
        need(False)
    revision, run, attempt, artifact = (
        os.environ[name] for name in (
            "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "ANCHOR_ARTIFACT_ID",
        )
    )
    need(re.fullmatch(r"[0-9a-f]{40}", revision) is not None)
    need(all(re.fullmatch(r"[1-9][0-9]{0,18}", value) for value in (run, attempt, artifact)))
    return {
        "schema": "pamolive.witness-synthetic-handoff/1",
        "revision": revision,
        "run_id": run,
        "attempt": attempt,
        "artifact_id": artifact,
        "anchor_sha256": pin,
        "source_boot_sha256": source_boot,
        "destination_boot_sha256": destination_boot,
        "exact_import_reopened": True,
        "missing_pin_refused": True,
        "authority": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(required=True, dest="mode")
    modes.add_parser("publish").add_argument("work", type=Path)
    importer = modes.add_parser("import")
    importer.add_argument("incoming", type=Path)
    importer.add_argument("store", type=Path)
    reopener = modes.add_parser("reopen")
    reopener.add_argument("store", type=Path)
    reopener.add_argument("receipt", type=Path)
    options = parser.parse_args()
    try:
        if options.mode == "publish":
            publish(options.work)
        else:
            report = receive(options)
            if options.mode == "reopen":
                with options.receipt.open("x", encoding="ascii", newline="\n") as stream:
                    stream.write(json.dumps(report, sort_keys=True) + "\n")
    except Exception:
        raise SystemExit("Synthetic witness handoff refused.") from None


if __name__ == "__main__":
    main()
