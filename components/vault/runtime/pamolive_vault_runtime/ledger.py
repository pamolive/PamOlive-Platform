"""PostgreSQL transaction boundary; connector is supplied by trusted startup only."""

import secrets
from dataclasses import dataclass
from uuid import uuid4

from .bounded import Refusal, integer, need, uuid


@dataclass(frozen=True, slots=True)
class Pending:
    reservation_id: str
    issued_at: int
    expires_at: int
    state: str = "pending_proofs"

    def __post_init__(self):
        uuid(self.reservation_id)
        integer(self.issued_at)
        integer(self.expires_at)
        need(self.state == "pending_proofs" and type(self.state) is str)
        need(self.issued_at < self.expires_at <= self.issued_at + 30)

    def public(self):
        self.__post_init__()
        return {
            "state": self.state,
            "reservation_id": self.reservation_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "authorized": False,
        }


def role_guard(cursor):
    cursor.execute("SET LOCAL search_path = pg_catalog")
    cursor.execute("""
        SELECT current_user = session_user AND current_user = 'vault_n0_runtime',
               r.rolsuper, r.rolcreatedb, r.rolcreaterole,
               r.rolreplication, r.rolbypassrls, c.relowner = r.oid,
               pg_has_role(current_user, c.relowner, 'MEMBER'),
               has_schema_privilege(current_user, 'vault_reservation', 'CREATE'),
               has_database_privilege(current_user, current_database(), 'CREATE'),
               pg_has_role(current_user, 'pg_read_server_files', 'MEMBER'),
               pg_has_role(current_user, 'pg_write_server_files', 'MEMBER'),
               pg_has_role(current_user, 'pg_execute_server_program', 'MEMBER'),
               EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = r.oid)
          FROM pg_catalog.pg_roles r JOIN pg_catalog.pg_class c ON c.relname = 'reservations'
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE r.rolname = current_user AND n.nspname = 'vault_reservation'
    """)
    row = cursor.fetchone()
    need(
        type(row) is tuple
        and len(row) == 14
        and row[0] is True
        and all(item is False for item in row[1:]),
        "unavailable",
        503,
    )


class PostgresLedger:
    def __init__(self, connect):
        self.connect = connect

    def startup(self, slot):
        """No automatic schema creation, state repair, incarnation update or open default."""
        try:
            with self.connect() as connection, connection.cursor() as cursor:
                role_guard(cursor)
                cursor.execute(
                    """
                    SELECT incarnation::text, slot_sha256, serving_state
                    FROM vault_reservation.commissioned_state WHERE slot_id = %s
                """,
                    (slot.slot_id,),
                )
                need(
                    cursor.fetchone()
                    == (slot.expected()["ledger_incarnation"], slot.source_sha256, "open"),
                    "context_refused",
                    403,
                )
            return
        except Refusal as error:
            code, status = error.code, error.status
        except Exception:
            code, status = "unavailable", 503
        raise Refusal(code, status)

    def reserve(self, *, slot, peer, draft, canonical_draft, draft_sha256, now, end, recheck):
        """Return after commit; unknown commit errors are unavailable, never retried here."""
        try:
            result = self._transaction(
                slot, peer, draft, canonical_draft, draft_sha256, now, end, recheck
            )
            after, _, _, _ = recheck()
            need(after < result.expires_at, "reservation_expired", 410)
            return result
        except Refusal as error:
            code, status = error.code, error.status
        except Exception:
            # Never export DSN, SQL, certificate, draft, raw DB error or uncertain commit claim.
            code, status = "unavailable", 503
        raise Refusal(code, status)

    def _transaction(self, slot, peer, draft, canonical_draft, draft_sha256, now, end, recheck):
        expected = slot.expected()
        key = (
            expected["organization_id"],
            expected["installation_id"],
            peer.service_id,
            draft.operation,
            draft.idempotency_key,
        )
        with self.connect() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                    cursor.execute("SET LOCAL statement_timeout = '3000ms'")
                    cursor.execute("SET LOCAL lock_timeout = '2000ms'")
                    role_guard(cursor)
                    # This row serializes quota/insert even for concurrent first writers.
                    cursor.execute(
                        """
                        SELECT incarnation::text, slot_sha256, serving_state
                          FROM vault_reservation.commissioned_state WHERE slot_id = %s FOR UPDATE
                    """,
                        (slot.slot_id,),
                    )
                    state = cursor.fetchone()
                    need(
                        state == (expected["ledger_incarnation"], slot.source_sha256, "open"),
                        "context_refused",
                        403,
                    )
                    cursor.execute(
                        """
                        SELECT reservation_id::text, issued_at, expires_at, certificate_sha256,
                               draft_sha256, canonical_draft, slot_sha256, incarnation::text,
                               broker_instance_id::text, state
                          FROM vault_reservation.reservations
                         WHERE tenant_id=%s AND installation_id=%s AND service_id=%s
                           AND operation=%s AND idempotency_key=%s
                    """,
                        key,
                    )
                    row = cursor.fetchone()
                    if row is not None:
                        need(
                            row[3:]
                            == (
                                peer.certificate_sha256,
                                draft_sha256,
                                canonical_draft,
                                slot.source_sha256,
                                expected["ledger_incarnation"],
                                peer.broker_instance_id,
                                "pending_proofs",
                            ),
                            "idempotency_conflict",
                            409,
                        )
                        result = Pending(row[0], row[1], row[2])
                    else:
                        cursor.execute(
                            """
                            SELECT count(*) FROM vault_reservation.reservations
                             WHERE tenant_id=%s AND installation_id=%s AND service_id=%s
                        """,
                            key[:3],
                        )
                        need(cursor.fetchone()[0] < slot.quota, "quota_exceeded", 429)
                        before_write, before_end, before_peer, before_slot = recheck()
                        need(before_peer == peer and before_slot == slot, "context_refused", 403)
                        need(now <= before_write < end <= before_end, "reservation_expired", 410)
                        nonce = secrets.token_bytes(32)
                        need(type(nonce) is bytes and len(nonce) == 32, "unavailable", 503)
                        result = Pending(str(uuid4()), now, end)
                        cursor.execute(
                            """
                            INSERT INTO vault_reservation.reservations
                             (reservation_id, tenant_id, installation_id, service_id, operation,
                              idempotency_key, certificate_sha256, draft_sha256, canonical_draft,
                              slot_sha256, incarnation, broker_instance_id, nonce,
                              issued_at, expires_at, state)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending_proofs')
                        """,
                            (
                                result.reservation_id,
                                *key,
                                peer.certificate_sha256,
                                draft_sha256,
                                canonical_draft,
                                slot.source_sha256,
                                expected["ledger_incarnation"],
                                peer.broker_instance_id,
                                nonce,
                                now,
                                end,
                            ),
                        )
                        cursor.execute(
                            """
                            INSERT INTO vault_reservation.audit
                             (reservation_id, event, issued_at, slot_sha256)
                            VALUES (%s,'reserved_pending_proofs',%s,%s)
                        """,
                            (result.reservation_id, now, slot.source_sha256),
                        )
                    current, current_end, current_peer, current_slot = recheck()
                    need(current_peer == peer and current_slot == slot, "context_refused", 403)
                    need(
                        result.issued_at
                        <= current
                        < result.expires_at
                        <= min(current_end, result.issued_at + 30),
                        "reservation_expired",
                        410,
                    )
                    cursor.execute("SELECT extract(epoch FROM clock_timestamp())")
                    database_now = cursor.fetchone()[0]
                    need(
                        abs(database_now - current) <= 2 and database_now < result.expires_at,
                        "unavailable",
                        503,
                    )
                    # Context managers commit both row and audit. No response before both exit.
            return result
