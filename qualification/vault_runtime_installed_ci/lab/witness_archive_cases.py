"""Check the PITR archive against a checkpoint retained by the lab driver."""

from dataclasses import replace

from .witness_fence_cases import expect_error, require
from .witness_history_cases import check_witness_fence


def capture_checkpoint(slot, observer):
    from pamolive_usage_anchor.audit_archive import Checkpoint

    check_witness_fence(observer, slot, "closed", slot.lease_epoch + 1)
    with observer() as conn, conn.cursor() as cursor:
        cursor.execute(
            """SELECT seq,head_sha256 FROM pam_usage_anchor.audit_heads
               WHERE context_id=%s""",
            (slot.context_id,),
        )
        head = cursor.fetchone()
        require(head is not None and cursor.fetchone() is None)
    expected = slot.expected()
    return Checkpoint(
        slot.context_id,
        slot.source_sha256,
        expected["organization_id"],
        expected["installation_id"],
        head[0],
        head[1],
    )


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
