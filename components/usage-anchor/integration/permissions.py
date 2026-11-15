"""Rollback-only native SQL probes for a quiescent, explicitly isolated lab.

Nothing here is called by production or the pure runner. The caller supplies
closed connector factories; no DSN, listener or role is created automatically.
"""

from contextlib import contextmanager

from psycopg.rows import tuple_row


class _RollbackProbe(Exception):
    """Normal read/prepare probe completion must still leave through rollback."""


class _ExpectedRefusal(Exception):
    pass


class _UnexpectedAllowed(Exception):
    pass


@contextmanager
def rollback_only(connect):
    try:
        with (
            connect() as connection,
            connection.transaction(),
            connection.cursor(row_factory=tuple_row) as cursor,
        ):
            yield cursor
            raise _RollbackProbe
    except _RollbackProbe:
        pass


def denied(connect, sql, params=(), states=("42501",), *, prepare=None):
    try:
        with rollback_only(connect) as cursor:
            if prepare is not None:
                prepare(cursor)
            # Only this precise statement may provide the expected SQLSTATE.
            # Setup/teardown errors and cancellation must propagate, not pass.
            try:
                cursor.execute(sql, params)
            except Exception as error:
                if getattr(error, "sqlstate", None) in states:
                    raise _ExpectedRefusal from None
                raise
            # INSIDE both contexts: unexpected SQL success is rolled back too.
            raise _UnexpectedAllowed
    except _ExpectedRefusal:
        return
    except _UnexpectedAllowed:
        raise AssertionError("forbidden SQL unexpectedly succeeded") from None


def _context(cursor, context_id):
    cursor.execute(
        "SELECT context_id FROM pam_usage_anchor.contexts WHERE context_id=%s FOR UPDATE",
        (context_id,),
    )
    assert cursor.fetchone() is not None, "probe context missing"


def counter_monotonicity_probe(connect, context_id, credential_id):
    """Prepare exact1 in the same rollback-only transaction, then try1→0.

    Both values satisfy the range CHECK. state_version+1 satisfies its monotone
    rule, so P0001 must come from the decreasing-counter trigger, not23514.
    Setup errors cannot be mistaken for the targeted expected failure.
    """

    def prepare(cursor):
        _context(cursor, context_id)
        cursor.execute(
            """SELECT sign_count,state_version,status FROM pam_usage_anchor.activations
               WHERE context_id=%s AND credential_id=%s FOR UPDATE""",
            (context_id, credential_id),
        )
        row = cursor.fetchone()
        assert row is not None and row[2] == "active", "active probe credential required"
        assert row[0] in (0, 1), "fresh probe credential counter0/1 required"
        if row[0] == 0:
            cursor.execute(
                """UPDATE pam_usage_anchor.activations SET sign_count=1,
                   state_version=state_version+1 WHERE context_id=%s AND credential_id=%s
                   AND sign_count=0 AND status='active'""",
                (context_id, credential_id),
            )
            assert cursor.rowcount == 1
        cursor.execute(
            """SELECT sign_count FROM pam_usage_anchor.activations
               WHERE context_id=%s AND credential_id=%s""",
            (context_id, credential_id),
        )
        assert cursor.fetchone() == (1,), "positive within-range counter not established"

    denied(
        connect,
        """UPDATE pam_usage_anchor.activations SET sign_count=0,state_version=state_version+1
           WHERE context_id=%s AND credential_id=%s AND sign_count=1""",
        (context_id, credential_id),
        ("P0001",),
        prepare=prepare,
    )


def terminal_shape_probe(connect, context_id, pending_operation_id):
    """Native CHECK probes on a real pending row; every attempt rolls back."""

    def prepare(cursor):
        _context(cursor, context_id)
        cursor.execute(
            """SELECT state,baseline,transcript,body_hash,bound_response
               FROM pam_usage_anchor.operations WHERE context_id=%s AND operation_id=%s
               FOR UPDATE""",
            (context_id, pending_operation_id),
        )
        row = cursor.fetchone()
        assert row is not None and row[0] == "pending_proofs"
        assert all(value is not None for value in row[1:]), "complete pending row required"

    # NonNULL bundle, but either/both digest/response NULL. All must be FALSE,
    # never SQL UNKNOWN accepted by CHECK. These aren't signature/auth probes.
    for digest, response in ((None, None), (None, b"public-probe"), ("0" * 64, None)):
        denied(
            connect,
            """UPDATE pam_usage_anchor.operations SET state='consumed_no_release',
               final_bundle=%s,final_digest=%s,terminal_response=%s
               WHERE context_id=%s AND operation_id=%s AND state='pending_proofs'""",
            (b"public-non-null-shape-probe", digest, response, context_id, pending_operation_id),
            ("23514",),
            prepare=prepare,
        )


def role_boundaries(
    *, witness_runtime_connect, forbidden_witness_connects, context_id, credential_id, operation_id
):
    with rollback_only(witness_runtime_connect) as cursor:
        cursor.execute(
            """SELECT state,final_bundle,final_digest,terminal_response
               FROM pam_usage_anchor.operations WHERE context_id=%s AND operation_id=%s""",
            (context_id, operation_id),
        )
        row = cursor.fetchone()
        assert row is not None and row[0] in ("consumed_no_release", "refused_no_release")
        assert all(value is not None for value in row[1:]), "real complete terminal required"
    for statement, params in [
        ("CREATE TABLE pam_usage_anchor.forbidden_probe(n int)", ()),
        ("DELETE FROM pam_usage_anchor.operations WHERE operation_id=%s", (operation_id,)),
        (
            "UPDATE pam_usage_anchor.contexts SET serving_state='closed' WHERE context_id=%s",
            (context_id,),
        ),
        (
            """UPDATE pam_usage_anchor.activations SET
               person_id='00000000-0000-0000-0000-000000000099'
               WHERE context_id=%s AND credential_id=%s""",
            (context_id, credential_id),
        ),
        ("UPDATE pam_usage_anchor.leases SET epoch=epoch+1 WHERE context_id=%s", (context_id,)),
    ]:
        denied(witness_runtime_connect, statement, params)
    denied(
        witness_runtime_connect,
        "UPDATE pam_usage_anchor.operations SET state='pending_proofs' WHERE operation_id=%s",
        (operation_id,),
        ("P0001",),
    )
    counter_monotonicity_probe(witness_runtime_connect, context_id, credential_id)
    for connect in forbidden_witness_connects:
        denied(connect, "SELECT * FROM pam_usage_anchor.operations", states=("42501",))
    return {
        "runtime_ddl_metadata_delete_denied": True,
        "terminal_and_counter_guards": True,
        "all_probes_rollback_only": True,
        "counter_probe": "positive1-to0/P0001/state_version+1",
        "forbidden_principals": len(forbidden_witness_connects),
        "real_host_independence_received": False,
    }
