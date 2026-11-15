"""Actual psycopg transactions; no in-memory fallback or runtime migrations."""

from contextlib import contextmanager

from psycopg.rows import dict_row

from .codec import encode, need, sha


def role_guard(cursor):
    cursor.execute("SET LOCAL search_path = pg_catalog")
    cursor.execute(
        """SELECT current_user=session_user AND current_user='usage_anchor_runtime'
            AS correct,
            r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolbypassrls,
            pg_has_role(current_user,c.relowner,'MEMBER') AS owner_member,
            has_schema_privilege(current_user,'pam_usage_anchor','CREATE') AS
            schema_create,
            has_database_privilege(current_user,current_database(),'CREATE') AS
            db_create, pg_has_role(current_user,'pg_read_server_files','MEMBER') AS
            read_files, pg_has_role(current_user,'pg_write_server_files','MEMBER')
            AS write_files,
            pg_has_role(current_user,'pg_execute_server_program','MEMBER') AS
            execute_program, EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE
            m.member=r.oid) AS memberships FROM pg_catalog.pg_roles r JOIN
            pg_catalog.pg_class c ON c.relname='operations' JOIN
            pg_catalog.pg_namespace n ON c.relnamespace=n.oid WHERE
            r.rolname=current_user AND n.nspname='pam_usage_anchor'"""
    )
    row = cursor.fetchone()
    need(
        row is not None and row.pop("correct") is True and all(v is False for v in row.values()),
        "unavailable",
        503,
    )
    cursor.execute("SHOW fsync")
    need(next(iter(cursor.fetchone().values())) == "on", "unavailable", 503)


class PostgresLedger:
    def __init__(self, connect):
        self.connect = connect

    def startup(self, slot):
        with self.connect() as connection, connection.cursor(row_factory=dict_row) as cursor:
            role_guard(cursor)
            cursor.execute(
                "SELECT * FROM pam_usage_anchor.contexts WHERE context_id=%s", (slot.context_id,)
            )
            row = cursor.fetchone()
            need(
                row is not None
                and row["slot_sha256"] == slot.source_sha256
                and str(row["witness_incarnation"]) == slot.witness_incarnation
                and row["serving_state"] == "open",
                "context_refused",
                403,
            )

    @contextmanager
    def transaction(self, slot, peer, *, vault):
        with self.connect() as connection:
            with connection.transaction():
                with connection.cursor(row_factory=dict_row) as cursor:
                    cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                    cursor.execute("SET LOCAL statement_timeout='3000ms'")
                    cursor.execute("SET LOCAL lock_timeout='2000ms'")
                    cursor.execute("SET LOCAL synchronous_commit=on")
                    role_guard(cursor)
                    tx = Transaction(cursor, slot, peer)
                    tx.start(vault)
                    yield tx
                    # Last application check after every write/audit, before
                    # cursor/transaction exit. No business-row locks are acquired
                    # by this local authority+clock callback. This is not a
                    # guarantee of the physical durability instant of COMMIT.
                    tx.commit_guard()
        # No response may escape before both contexts commit/close.


class Transaction:
    def __init__(self, cursor, slot, peer):
        self.c, self.slot, self.peer = cursor, slot, peer
        self.lease = None
        self._commit_callback = None
        self._mutated = False

    def before_commit(self, callback):
        need(self._commit_callback is None and callable(callback), "unavailable", 503)
        self._commit_callback = callback

    def commit_guard(self):
        need(not self._mutated or self._commit_callback is not None, "unavailable", 503)
        if self._commit_callback is not None:
            self._commit_callback()

    def now(self):
        self.c.execute("SELECT extract(epoch FROM clock_timestamp()) AS now")
        return self.c.fetchone()["now"]

    def start(self, vault):
        # RANK1 context; one context/tenant serializes all N0 mutations.
        self.c.execute(
            """SELECT * FROM pam_usage_anchor.contexts WHERE context_id=%s FOR UPDATE""",
            (self.slot.context_id,),
        )
        self.context = self.c.fetchone()
        s, e = self.slot, self.slot.expected()
        need(
            self.context is not None
            and str(self.context["installation_id"]) == e["installation_id"]
            and str(self.context["tenant_id"]) == e["organization_id"]
            and str(self.context["witness_incarnation"]) == s.witness_incarnation
            and self.context["slot_sha256"] == s.source_sha256,
            "context_refused",
            403,
        )
        # RANK2 quota; every principal is precommissioned, no runtime INSERT.
        self.c.execute(
            (
                """SELECT * FROM pam_usage_anchor.quotas WHERE context_id=%s AND
                service_id=%s FOR UPDATE"""
            ),
            (s.context_id, self.peer.service_id),
        )
        need(self.c.fetchone() is not None, "context_refused", 403)
        # RANK3 lease. Read even for terminal observation; liveness is checked only for mutations.
        if vault:
            self.c.execute(
                (
                    """SELECT * FROM pam_usage_anchor.leases WHERE context_id=%s AND
                    service_id=%s FOR UPDATE"""
                ),
                (s.context_id, self.peer.service_id),
            )
            self.lease = self.c.fetchone()
            need(self.lease is not None, "context_refused", 403)

    def live(self, now, end):
        need(self.context["serving_state"] == "open", "context_refused", 403)
        need(
            self.slot.not_before <= now < min(end, self.slot.not_after, self.peer.expires_at),
            "expired",
            410,
        )
        database_now = self.now()
        need(abs(database_now - now) <= 2 and database_now < end, "unavailable", 503)
        if self.lease is not None:
            lease = self.lease
            need(
                lease["serving_state"] == "open"
                and lease["owner_der"] == self.peer.certificate_sha256
                and lease["epoch"] == self.slot.lease_epoch
                and str(lease["incarnation"]) == self.slot.expected()["ledger_incarnation"]
                and lease["issued_at"] <= database_now < lease["expires_at"],
                "context_refused",
                403,
            )

    def operation(self, draft=None, operation_id=None):
        # RANK4; a lookup by ID never locks before context/quota/lease.
        if draft is not None:
            self.c.execute(
                """SELECT * FROM pam_usage_anchor.operations WHERE context_id=%s AND
                broker_service=%s AND operation=%s AND idempotency_key=%s FOR UPDATE""",
                (
                    self.slot.context_id,
                    draft.broker_service_id,
                    draft.operation,
                    draft.idempotency_key,
                ),
            )
        else:
            self.c.execute(
                (
                    """SELECT * FROM pam_usage_anchor.operations WHERE context_id=%s AND
                    operation_id=%s FOR UPDATE"""
                ),
                (self.slot.context_id, operation_id),
            )
        return self.c.fetchone()

    def states(self, selected, *, active=True):
        # RANK5 explicit ASCII credential order, including all snapshot members.
        states = {}
        auths = {auth["id"]: auth for _, _, auth in selected}
        for cred in sorted(auths):
            self.c.execute(
                (
                    """SELECT * FROM pam_usage_anchor.activations WHERE context_id=%s AND
                    credential_id=%s FOR UPDATE"""
                ),
                (self.slot.context_id, cred),
            )
            row, auth = self.c.fetchone(), auths[cred]
            need(
                row is not None
                and str(row["person_id"]) == auth["person_id"]
                and row["spki_sha256"] == auth["spki_sha256"]
                and str(row["enrollment_id"]) == auth["enrollment_id"]
                and row["rp_id"] == auth["rp_id"]
                and row["origin"] == auth["origin"]
                and row["status"] == ("active" if active else "commissioned"),
                "context_refused",
                403,
            )
            states[cred] = row
        return states

    def quota(self, extra=0, *, new=False):
        self.c.execute(
            (
                """SELECT count(*) AS
                count,coalesce(sum(octet_length(binding)+coalesce(octet_length(baseline),0)
                +coalesce(octet_length(transcript),0)+coalesce(octet_length(bound_response),0)+coalesce(octet_length(final_bundle),0)),0)
                AS bytes FROM pam_usage_anchor.operations WHERE context_id=%s AND
                vault_service=%s"""
            ),
            (self.slot.context_id, self.peer.service_id),
        )
        row = self.c.fetchone()
        need(
            row["count"] + int(new) <= self.slot.quota
            and row["bytes"] + extra <= self.slot.quota_bytes,
            "quota_exceeded",
            429,
        )

    def insert_operation(self, row):
        self._mutated = True
        columns = (
            "operation_id",
            "context_id",
            "broker_service",
            "operation",
            "idempotency_key",
            "vault_service",
            "vault_instance",
            "vault_der",
            "reservation_id",
            "lease_epoch",
            "slot_sha256",
            "binding",
            "baseline",
            "transcript",
            "body_hash",
            "bound_response",
            "issued_at",
            "expires_at",
            "state",
        )
        # Closed constant column identifiers, never derived from a request.
        self.c.execute(
            "INSERT INTO pam_usage_anchor.operations ("
            "operation_id,context_id,broker_service,operation,idempotency_key,"
            "vault_service,vault_instance,vault_der,reservation_id,lease_epoch,"
            "slot_sha256,binding,baseline,transcript,body_hash,bound_response,"
            "issued_at,expires_at,state) VALUES ("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            tuple(row[k] for k in columns),
        )

    def finish_bind(self, row):
        self._mutated = True
        self.c.execute(
            (
                """UPDATE pam_usage_anchor.operations SET
                baseline=%s,transcript=%s,body_hash=%s,
                bound_response=%s,expires_at=%s,state='pending_proofs' WHERE
                context_id=%s AND operation_id=%s AND state='binding'"""
            ),
            (
                row["baseline"],
                row["transcript"],
                row["body_hash"],
                row["bound_response"],
                row["expires_at"],
                self.slot.context_id,
                row["operation_id"],
            ),
        )
        need(self.c.rowcount == 1, "unavailable", 503)

    def challenge(self, challenge_id):
        self.c.execute(
            (
                """SELECT * FROM pam_usage_anchor.activation_challenges WHERE context_id=%s
                AND challenge_id=%s FOR UPDATE"""
            ),
            (self.slot.context_id, challenge_id),
        )
        return self.c.fetchone()

    def insert_challenge(self, challenge_id, credential, binding, challenge, expires):
        self._mutated = True
        self.c.execute(
            (
                """SELECT count(*) AS count FROM pam_usage_anchor.activation_challenges
                WHERE context_id=%s AND service_id=%s"""
            ),
            (self.slot.context_id, self.peer.service_id),
        )
        need(self.c.fetchone()["count"] < self.slot.quota, "quota_exceeded", 429)
        self.c.execute(
            (
                """INSERT INTO pam_usage_anchor.activation_challenges
                (challenge_id,context_id,service_id,certificate_sha256,credential_id,binding,challenge,expires_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s)"""
            ),
            (
                challenge_id,
                self.slot.context_id,
                self.peer.service_id,
                self.peer.certificate_sha256,
                credential,
                binding,
                challenge,
                expires,
            ),
        )

    def activate(self, challenge_id, cred, count, now):
        self._mutated = True
        self.c.execute(
            (
                """UPDATE pam_usage_anchor.activation_challenges SET used_at=%s WHERE
                context_id=%s AND challenge_id=%s AND used_at IS NULL"""
            ),
            (now, self.slot.context_id, challenge_id),
        )
        need(self.c.rowcount == 1, "idempotency_conflict", 409)
        self.c.execute(
            (
                """UPDATE pam_usage_anchor.activations SET
                status='active',sign_count=%s,state_version=state_version+1 WHERE
                context_id=%s AND credential_id=%s AND status='commissioned'"""
            ),
            (count, self.slot.context_id, cred),
        )
        need(self.c.rowcount == 1, "context_refused", 403)

    def terminal(self, row, state, bundle, final_digest, response, updated, uses):
        self._mutated = True
        for cred in sorted(updated):
            self.c.execute(
                (
                    """UPDATE pam_usage_anchor.activations SET
                    sign_count=%s,state_version=state_version+1 WHERE context_id=%s AND
                    credential_id=%s"""
                ),
                (updated[cred], self.slot.context_id, cred),
            )
        for person, role, decision, cred, challenge, assertion, count in uses:
            self.c.execute(
                (
                    """INSERT INTO pam_usage_anchor.proof_uses
                    (context_id,operation_id,person_id,role,decision,credential_id,challenge_sha256,assertion_sha256,sign_count)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
                ),
                (
                    self.slot.context_id,
                    row["operation_id"],
                    person,
                    role,
                    decision,
                    cred,
                    sha(challenge),
                    sha(assertion),
                    count,
                ),
            )
        self.c.execute(
            (
                """UPDATE pam_usage_anchor.operations SET
                state=%s,final_bundle=%s,final_digest=%s, terminal_response=%s WHERE
                operation_id=%s AND context_id=%s AND state='pending_proofs'"""
            ),
            (state, bundle, final_digest, response, row["operation_id"], self.slot.context_id),
        )
        need(self.c.rowcount == 1, "idempotency_conflict", 409)

    def audit(self, event, operation_id, at, digest=""):
        self._mutated = True
        # RANK6 last lock, no lower-rank lock/FK is acquired afterwards.
        self.c.execute(
            """SELECT * FROM pam_usage_anchor.audit_heads WHERE context_id=%s FOR
            UPDATE""",
            (self.slot.context_id,),
        )
        head = self.c.fetchone()
        need(head is not None, "context_refused", 403)
        raw = encode(
            {"event": event, "operation_id": operation_id, "at": at, "digest": digest}, 4096
        )
        seq = head["seq"] + 1
        current = sha(b"pamolive.vault.usage-audit.v1\0" + bytes.fromhex(head["head_sha256"]) + raw)
        self.c.execute(
            "INSERT INTO pam_usage_anchor.audit_events VALUES(%s,%s,%s,%s,%s)",
            (self.slot.context_id, seq, raw, head["head_sha256"], current),
        )
        self.c.execute(
            """UPDATE pam_usage_anchor.audit_heads SET seq=%s,head_sha256=%s WHERE
            context_id=%s""",
            (seq, current, self.slot.context_id),
        )
