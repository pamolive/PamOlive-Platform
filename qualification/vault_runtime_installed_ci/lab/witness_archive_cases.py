"""Check the PITR archive against a checkpoint retained by the lab driver."""

from dataclasses import replace

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
