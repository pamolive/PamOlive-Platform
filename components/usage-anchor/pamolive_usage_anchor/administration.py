"""Explicit offline close/revoke helpers, never exposed through the W HTTP app.

The supplied migration/administration login must separately be allowed to SET
ROLE to the NOLOGIN owner. Runtime/V/Web identities must not have that grant.
There is intentionally no restore/open/reset-counter or automatic renewal API.
"""

from contextlib import contextmanager

from psycopg.rows import dict_row

from .codec import encode, need, sha, uuid


class Administration:
    def __init__(self, connect):
        self.connect = connect

    @contextmanager
    def _locked(self, context_id, expected_slot_sha256):
        uuid(context_id)
        with self.connect() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as c:
            c.execute("SET LOCAL ROLE usage_anchor_owner")
            c.execute("SET LOCAL search_path=pg_catalog")
            c.execute("SET LOCAL statement_timeout='3000ms'")
            c.execute("SET LOCAL lock_timeout='2000ms'")
            c.execute("SET LOCAL synchronous_commit=on")
            c.execute(
                "SELECT * FROM pam_usage_anchor.contexts WHERE context_id=%s FOR UPDATE",
                (context_id,),
            )
            context = c.fetchone()
            need(
                context is not None and context["slot_sha256"] == expected_slot_sha256,
                "context_refused",
                403,
            )
            # The order is shared with runtime, including administration and negative paths.
            c.execute(
                """SELECT service_id FROM pam_usage_anchor.quotas WHERE context_id=%s
                   ORDER BY service_id COLLATE "C" FOR UPDATE""",
                (context_id,),
            )
            c.fetchall()
            c.execute(
                """SELECT service_id FROM pam_usage_anchor.leases WHERE context_id=%s
                   ORDER BY service_id COLLATE "C" FOR UPDATE""",
                (context_id,),
            )
            c.fetchall()
            c.execute(
                """SELECT operation_id FROM pam_usage_anchor.operations WHERE context_id=%s
                   ORDER BY broker_service COLLATE "C",operation COLLATE "C",
                   idempotency_key FOR UPDATE""",
                (context_id,),
            )
            c.fetchall()
            c.execute(
                """SELECT credential_id FROM pam_usage_anchor.activations WHERE context_id=%s
                   ORDER BY credential_id COLLATE "C" FOR UPDATE""",
                (context_id,),
            )
            c.fetchall()
            # Rank6 is last. All mutations below touch already locked rows only.
            c.execute(
                "SELECT * FROM pam_usage_anchor.audit_heads WHERE context_id=%s FOR UPDATE",
                (context_id,),
            )
            head = c.fetchone()
            need(head is not None, "context_refused", 403)
            yield c, head

    @staticmethod
    def _audit(c, head, context_id, event, subject):
        c.execute("SELECT extract(epoch FROM clock_timestamp()) AS now")
        now = int(c.fetchone()["now"])
        raw = encode({"event": event, "operation_id": subject, "at": now, "digest": ""}, 4096)
        digest = sha(b"pamolive.vault.usage-audit.v1\0" + bytes.fromhex(head["head_sha256"]) + raw)
        c.execute(
            "INSERT INTO pam_usage_anchor.audit_events VALUES(%s,%s,%s,%s,%s)",
            (context_id, head["seq"] + 1, raw, head["head_sha256"], digest),
        )
        c.execute(
            "UPDATE pam_usage_anchor.audit_heads SET seq=%s,head_sha256=%s WHERE context_id=%s",
            (head["seq"] + 1, digest, context_id),
        )

    def close_and_fence(self, context_id, expected_slot_sha256):
        with self._locked(context_id, expected_slot_sha256) as (c, head):
            c.execute(
                "UPDATE pam_usage_anchor.contexts SET serving_state='closed' WHERE context_id=%s",
                (context_id,),
            )
            c.execute(
                """UPDATE pam_usage_anchor.leases SET serving_state='closed',epoch=epoch+1
                   WHERE context_id=%s""",
                (context_id,),
            )
            self._audit(c, head, context_id, "closed_and_fenced", context_id)

    def revoke_activation(self, context_id, expected_slot_sha256, credential_id):
        with self._locked(context_id, expected_slot_sha256) as (c, head):
            c.execute(
                """UPDATE pam_usage_anchor.activations SET status='revoked',
                   state_version=state_version+1 WHERE context_id=%s AND credential_id=%s""",
                (context_id, credential_id),
            )
            need(c.rowcount == 1, "context_refused", 403)
            self._audit(
                c, head, context_id, "activation_revoked", sha(credential_id.encode("ascii"))
            )
