"""Check the PITR archive against a checkpoint retained by the lab driver."""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path
from threading import Barrier

from .witness_fence_cases import expect_error, require


def capture_checkpoint(slot, observer):
    from pamolive_usage_anchor.ledger import PostgresHistory

    return PostgresHistory(observer).capture_checkpoint(slot)


def sign_lab_checkpoint(checkpoint):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from pamolive_usage_anchor.audit_archive import GENESIS_SHA256
    from pamolive_usage_anchor.codec import sha
    from pamolive_usage_anchor.signed_anchor import sign_checkpoint

    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes_raw()
    raw = sign_checkpoint(checkpoint, public_key=public, sign=signer.sign)
    earlier = replace(checkpoint, last_seq=0, head_sha256=GENESIS_SHA256)
    alternate = sign_checkpoint(earlier, public_key=public, sign=signer.sign)
    return raw, public, sha(raw), alternate


def retain_lab_anchor(material, advance):
    from pamolive_usage_anchor.anchor_store import AnchorStore

    advance("anchor_store_retain")
    raw, public, pin, alternate = material
    original = Path("/work/anchor-original")
    original.mkdir(mode=0o700)
    store = AnchorStore(original, owner_uid=os.geteuid())
    with ThreadPoolExecutor(max_workers=3) as writers:
        futures = [
            writers.submit(store.save, raw, public_key=public, expected_sha256=pin)
            for _ in range(3)
        ]
        for future in futures:
            future.result(timeout=5)
    require({path.name for path in original.iterdir()} == {pin + ".json"})
    return public, pin, alternate


def restore_lab_anchor(references, advance):
    from pamolive_usage_anchor.anchor_store import AnchorStore
    from pamolive_usage_anchor.codec import sha

    advance("anchor_store_transfer")
    public, pin, alternate = references
    owner = os.geteuid()
    original = AnchorStore("/work/anchor-original", owner_uid=owner)
    point, raw = original.load(public_key=public, expected_sha256=pin)
    restored = Path("/work/anchor-restored")
    restored.mkdir(mode=0o700)
    store = AnchorStore(restored, owner_uid=owner)
    store.save(alternate, public_key=public, expected_sha256=sha(alternate))
    expect_error(
        "unavailable", 503, lambda: store.load(public_key=public, expected_sha256=pin)
    )
    store.save(raw, public_key=public, expected_sha256=pin)
    imported, imported_raw = store.load(public_key=public, expected_sha256=pin)
    require(imported == point and imported_raw == raw)

    advance("anchor_store_reopen")
    code = (
        "import os, sys\n"
        "from pamolive_usage_anchor.anchor_store import AnchorStore\n"
        "AnchorStore(sys.argv[1], owner_uid=os.geteuid()).load(\n"
        "    public_key=bytes.fromhex(sys.argv[2]), expected_sha256=sys.argv[3])\n"
        "print('W01_ANCHOR_REOPENED')\n"
    )
    reopened = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code, str(restored), public.hex(), pin],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=8, check=False,
    )
    require(reopened.returncode == 0 and reopened.stdout == b"W01_ANCHOR_REOPENED\n")
    advance("anchor_store_rotation")
    qualify_recovery_manifest(point, imported_raw, public, pin, alternate)
    return (imported_raw, public, pin, alternate), {
        "concurrent_exact_saves": True,
        "reopened_after_database_recovery": True,
        "restore_copy_exact": True,
        "missing_pin_no_fallback": True,
        "new_process_reopened": True,
        "checkpoint_key_rotation_verified": True,
        "custody_atomic_rotation_verified": True,
        "custody_cli_verified": True,
    }


def qualify_recovery_manifest(point, raw, public, pin, alternate):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from pamolive_usage_anchor import codec, recovery_manifest, recovery_store
    from pamolive_usage_anchor.audit_archive import GENESIS_SHA256
    from pamolive_usage_anchor.signed_anchor import sign_checkpoint

    governor = Ed25519PrivateKey.generate()
    scope = recovery_manifest.RecoveryScope.from_checkpoint(point)
    facts = {"governance_key": governor.public_key().public_bytes_raw(), "scope": scope}
    first_entry = {"checkpoint_sha256": pin, "generation": 1}
    body = {
        "schema": recovery_manifest.SCHEMA,
        "scope": asdict(scope),
        "revision": 1,
        "previous_sha256": recovery_manifest.GENESIS,
        "keys": [codec.b64(public)],
        "admissions": [first_entry],
    }
    initial = recovery_manifest.sign_manifest(body, sign=governor.sign, **facts)
    directory = Path("/work/anchor-custody")
    directory.mkdir(mode=0o700)
    incoming = Path("/work/anchor-custody-incoming")
    incoming.mkdir(mode=0o700)
    store = recovery_store.RecoveryStore(directory, owner_uid=os.geteuid(), **facts)

    def inputs(manifest, document):
        manifest_pin, digest = codec.sha(manifest), codec.sha(document)
        manifest_file = incoming / (manifest_pin + ".manifest")
        object_file = incoming / (digest + ".checkpoint")
        for path, data in ((manifest_file, manifest), (object_file, document)):
            with path.open("xb") as stream:
                stream.write(data)
        return manifest_pin, (
            "--manifest", str(manifest_file), "--proposal-sha256", manifest_pin,
            "--checkpoint", str(object_file),
        )

    initial_pin, flags = inputs(initial, raw)
    initialized = custody_command(directory, facts, "commission", *flags)
    custody_success(initialized, "commission", initial_pin)

    next_point = replace(point, last_seq=0, head_sha256=GENESIS_SHA256)
    proposals = []
    for _ in range(2):
        signer = Ed25519PrivateKey.generate()
        key = signer.public_key().public_bytes_raw()
        document = sign_checkpoint(next_point, public_key=key, sign=signer.sign)
        digest = codec.sha(document)
        entry = {"checkpoint_sha256": digest, "generation": 2}
        candidate = dict(
            body, revision=2, previous_sha256=initial_pin,
            keys=[codec.b64(public), codec.b64(key)],
            admissions=sorted((first_entry, entry), key=lambda item: item["checkpoint_sha256"]),
        )
        manifest = recovery_manifest.sign_manifest(candidate, sign=governor.sign, **facts)
        proposed, flags = inputs(manifest, document)
        proposals.append((proposed, digest, ("advance", "--current-sha256", initial_pin, *flags)))

    barrier = Barrier(2, timeout=3)

    def compete(proposal):
        proposed, _, command = proposal
        barrier.wait()
        child = custody_command(directory, facts, *command)
        if child.returncode == 0:
            custody_success(child, "advance", proposed)
            return proposed
        require(child.returncode == 1 and not child.stdout)
        require(child.stderr in (b"idempotency_conflict\n", b"unavailable\n"))
        return None

    with ThreadPoolExecutor(max_workers=2) as writers:
        outcomes = tuple(writers.map(compete, proposals))
    current, = [outcome for outcome in outcomes if outcome]
    _, chosen_digest, chosen = proposals[outcomes.index(current)]
    _, _, rejected = proposals[outcomes.index(None)]
    custody_success(custody_command(directory, facts, *chosen), "advance", current)
    custody_refused(custody_command(directory, facts, *rejected), b"idempotency_conflict\n")

    def restore(digest):
        return custody_command(
            directory, facts, "restore", "--current-sha256", current, "--checkpoint-sha256", digest,
        )

    with store._locked(write=True):
        custody_refused(restore(pin), b"unavailable\n")
    for digest, expected_point in ((pin, point), (chosen_digest, next_point)):
        custody_success(
            restore(digest), "restore", current, checkpoint_sha256=digest,
            checkpoint=asdict(expected_point),
        )
    alternate_digest = codec.sha(alternate)
    # An object retained before an interrupted publication is not an admission.
    with store._locked(write=True) as fd:
        store._files._retain(fd, alternate_digest + ".checkpoint", alternate)
        os.fsync(fd)
    custody_refused(restore(alternate_digest), b"anchor_refused\n")


def custody_command(directory, facts, *arguments):
    scope = facts["scope"]
    argv = [
        sys.executable, "-I", "-B", "-m", "pamolive_usage_anchor.recovery_cli",
        "--directory", str(directory), "--governance-key", facts["governance_key"].hex(),
        "--organization", scope.organization_id, "--installation", scope.installation_id,
        "--context", scope.context_id, "--slot-sha256", scope.slot_sha256, *arguments,
    ]
    return subprocess.run(
        argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=8, check=False
    )


def custody_success(child, operation, manifest_pin, **result):
    require(child.returncode == 0 and not child.stderr and 0 < len(child.stdout) <= 1024)
    require(json.loads(child.stdout) == {
        "schema": "pamolive.witness-custody-result/1", "operation": operation,
        "manifest_sha256": manifest_pin, **result,
    })


def custody_refused(child, code):
    require(child.returncode == 1 and not child.stdout and child.stderr == code)


def receive_lab_checkpoint(slot, material, advance):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from pamolive_usage_anchor.signed_anchor import verify_checkpoint

    raw, public, pin, alternate = material
    advance("signed_anchor_receive")
    checkpoint = verify_checkpoint(raw, public_key=public, expected_sha256=pin)
    checkpoint.require_slot(slot)

    advance("signed_anchor_refusals")
    wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    expect_error(
        "anchor_refused", 403,
        lambda: verify_checkpoint(raw, public_key=wrong_key, expected_sha256=pin),
    )
    expect_error(
        "anchor_refused", 403,
        lambda: verify_checkpoint(alternate, public_key=public, expected_sha256=pin),
    )
    return checkpoint, {
        "signature_verified": True,
        "wrong_signer_refused": True,
        "valid_alternate_refused": True,
    }


def check_restored_archive(slot, checkpoint, factories, snapshot, advance):
    from fixtures import uid
    from pamolive_usage_anchor.audit_archive import ArchiveVerifier
    from pamolive_usage_anchor.ledger import PostgresHistory

    observer = factories["restored_observer"]
    vault = factories["vault_n0_runtime"]
    history = PostgresHistory(observer)
    before = snapshot(observer, vault)

    advance("audit_archive_pages")
    verifier = ArchiveVerifier(checkpoint)
    require(checkpoint.last_seq > 3)
    while verifier.after_seq < checkpoint.last_seq:
        page = history.archive_page(slot, checkpoint, verifier.after_seq, limit=3)
        verifier.accept(page)
    require(verifier.finish() == checkpoint)

    advance("audit_archive_refusals")
    different_hash = "1" * 64 if checkpoint.head_sha256 != "1" * 64 else "2" * 64
    wrong_head = replace(checkpoint, head_sha256=different_hash)
    expect_error("context_refused", 403, history.archive_page, slot, wrong_head, 0)
    wrong_org = replace(checkpoint, organization_id=uid(997))
    require(wrong_org.organization_id != slot.expected()["organization_id"])
    expect_error("context_refused", 403, history.archive_page, slot, wrong_org, 0)

    advance("audit_archive_unchanged")
    require(snapshot(observer, vault) == before)
    return {
        "checkpoint_from_original": True,
        "restored_pages_match": True,
        "wrong_head_refused": True,
        "foreign_organization_refused": True,
        "databases_unchanged": True,
    }
