"""Exercise historical receipt reads after synthetic Vault and witness closure."""

import re

from .witness_fence_cases import expect_error, require

OBSERVE = "/v1/operations/observe-terminal"


def owned_witness_admin(connect):
    conn = connect()
    try:
        require(conn.info.user == "usage_anchor_admin")
        require(re.fullmatch(r"w01_[a-f0-9]{16}_wpg", conn.info.dbname) is not None)
    except BaseException:
        conn.close()
        raise
    return conn


def check_vault_mirror(connect, reservation_id, bound_raw):
    with connect() as conn, conn.cursor() as cursor:
        cursor.execute(
            """SELECT s.serving_state,m.state,m.bound_response,m.terminal_response
               FROM vault_reservation.reservations AS r
               JOIN vault_reservation.commissioned_state AS s
                 ON s.slot_sha256=r.slot_sha256 AND s.incarnation=r.incarnation
               JOIN vault_reservation.usage_mirrors AS m
                 ON m.reservation_id=r.reservation_id
               WHERE r.reservation_id=%s""",
            (reservation_id,),
        )
        require(cursor.fetchone() == ("closed", "bound", bound_raw, None))


def check_witness_fence(connect, slot, state, epoch):
    with connect() as conn, conn.cursor() as cursor:
        cursor.execute(
            """SELECT c.serving_state,l.serving_state,l.epoch
               FROM pam_usage_anchor.contexts AS c
               JOIN pam_usage_anchor.leases AS l ON l.context_id=c.context_id
               WHERE c.context_id=%s AND c.slot_sha256=%s AND l.service_id=%s""",
            (slot.context_id, slot.source_sha256, "vault-w1"),
        )
        require(cursor.fetchone() == (state, state, epoch))


def observe_while_witness_locked(connect, slot, operation_id, observe):
    # The owner holds the row locks that a mutating W request would need.
    # The historical query should still read the previously committed receipt.
    with owned_witness_admin(connect) as conn, conn.transaction(), conn.cursor() as cursor:
        cursor.execute("SET LOCAL ROLE usage_anchor_owner")
        cursor.execute(
            """SELECT context_id FROM pam_usage_anchor.contexts
               WHERE context_id=%s AND slot_sha256=%s FOR UPDATE""",
            (slot.context_id, slot.source_sha256),
        )
        require(cursor.fetchone() is not None)
        cursor.execute(
            """SELECT operation_id FROM pam_usage_anchor.operations
               WHERE context_id=%s AND operation_id=%s FOR UPDATE""",
            (slot.context_id, operation_id),
        )
        require(cursor.fetchone() is not None)
        return observe()


def proof_from(fixture, bound_raw, *, spaced):
    from pamolive_usage_anchor.codec import parse, unb64
    from pamolive_vault_contracts import parse_transcript

    bound = parse(bound_raw, 196608, string=90000, special=True)
    transcript = parse_transcript(unb64(bound["transcript_b64"], 32768))
    return fixture.final_bundle(transcript, bound["operation_id"], negative=True, spaced=spaced)


def run_history_cases(
    *,
    fixture,
    clients,
    factories,
    reservation_id,
    bundle_raw,
    terminal_raw,
    terminal_bound_raw,
    pending_reservation_id,
    pending_bound_raw,
    snapshot,
    advance,
):
    from fixtures import uid
    from pamolive_usage_anchor.administration import Administration
    from pamolive_usage_anchor.client import VaultMirror
    from pamolive_usage_anchor.codec import bundle, encode, parse

    vault = factories["vault_n0_runtime"]
    observer = factories["usage_anchor_observer"]
    witness_admin = factories["usage_anchor_admin"]
    witness_client = clients["vault"]
    mirror = VaultMirror(vault, witness_client)
    slot = fixture.slot
    original = bundle(bundle_raw)

    advance("history_vault_closed")
    check_vault_mirror(vault, reservation_id, terminal_bound_raw)
    check_witness_fence(observer, slot, "open", slot.lease_epoch)
    before = snapshot(observer, vault)
    response = observe_while_witness_locked(
        witness_admin,
        slot,
        original["operation_id"],
        lambda: mirror.observe_terminal(reservation_id, bundle_raw),
    )
    require(response == terminal_raw)
    terminal = parse(terminal_raw, 4096, special=True)
    require(terminal["state"] == "refused_no_release" and terminal["authorized"] is False)

    advance("history_refusals")
    pending = proof_from(fixture, pending_bound_raw, spaced=True)
    expect_error("context_refused", 403, mirror.observe_terminal, pending_reservation_id, pending)
    missing = encode({**original, "operation_id": uid(880)}, 2097152, string=90000)
    expect_error("context_refused", 403, witness_client.request, OBSERVE, missing)
    expect_error("caller_refused", 403, clients["activation"].request, OBSERVE, bundle_raw)
    different = proof_from(fixture, terminal_bound_raw, spaced=False)
    alternative = bundle(different)
    require(different != bundle_raw)
    require(alternative["operation_id"] == original["operation_id"])
    require(alternative["body_hash"] == original["body_hash"])
    expect_error("idempotency_conflict", 409, mirror.observe_terminal, reservation_id, different)
    require(snapshot(observer, vault) == before)

    advance("history_witness_closed")
    administration = Administration(lambda: owned_witness_admin(witness_admin))
    administration.close_and_fence(slot.context_id, slot.source_sha256)
    check_witness_fence(observer, slot, "closed", slot.lease_epoch + 1)
    after_close = snapshot(observer, vault)
    require(after_close[1] == before[1])
    require(mirror.observe_terminal(reservation_id, bundle_raw) == terminal_raw)
    expect_error("context_refused", 403, mirror.observe_terminal, pending_reservation_id, pending)

    advance("history_unchanged")
    require(snapshot(observer, vault) == after_close)
    return {
        "closed_vault_terminal_exact": True,
        "pending_refused": True,
        "missing_refused": True,
        "wrong_purpose_refused": True,
        "different_bundle_conflict": True,
        "closed_witness_terminal_exact": True,
        "history_rows_unchanged": True,
    }


def run_recovery_cases(
    *,
    fixture,
    client,
    factories,
    evidence,
    pending_reservation_id,
    pending_bound_raw,
    bind_raw,
    snapshot,
    advance,
    restart,
):
    from fixtures import uid
    from pamolive_usage_anchor.client import VaultMirror
    from pamolive_usage_anchor.codec import encode

    vault = factories["vault_n0_runtime"]
    observer = factories["usage_anchor_observer"]
    check_witness_fence(observer, fixture.slot, "closed", fixture.slot.lease_epoch + 1)
    before = snapshot(observer, vault)
    restart()

    advance("recovery_reads")
    mirror = VaultMirror(vault, client)
    original = evidence["bundle_raw"]
    require(
        mirror.observe_terminal(evidence["reservation_id"], original) == evidence["terminal_raw"]
    )
    pending = proof_from(fixture, pending_bound_raw, spaced=True)
    expect_error("context_refused", 403, mirror.observe_terminal, pending_reservation_id, pending)

    advance("recovery_write_refusal")
    for route, raw in (
        ("/v1/operations/bind", bind_raw),
        ("/v1/operations/consume", original),
        ("/v1/activations/begin", encode({"person_id": uid(20)}, 4096)),
        ("/v1/activations/finish", b"{}"),
    ):
        expect_error("context_refused", 403, client.request, route, raw)

    advance("recovery_unchanged")
    require(snapshot(observer, vault) == before)
    return {
        "closed_terminal_exact": True,
        "pending_refused": True,
        "mutation_routes_refused": True,
        "historical_rows_unchanged": True,
    }
