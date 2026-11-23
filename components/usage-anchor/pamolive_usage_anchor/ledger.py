"""Actual psycopg transactions; no in-memory fallback or runtime migrations."""

from contextlib import contextmanager

from psycopg import Error as PsycopgError
from psycopg.rows import dict_row

from .audit_archive import GENESIS_SHA256, MAX_PAGE_EVENTS, Checkpoint, encode_archive_page
from .codec import Error, encode, integer, need, sha


def role_guard(cursor, *, observer=False):
    cursor.execute("SET LOCAL search_path = pg_catalog")
    cursor.execute(
        """SELECT current_user=session_user AND current_user=%s
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
            r.rolname=current_user AND n.nspname='pam_usage_anchor'""",
        ("usage_anchor_observer" if observer else "usage_anchor_runtime",),
    )
    row = cursor.fetchone()
    need(
        row is not None and row.pop("correct") is True and all(v is False for v in row.values()),
        "unavailable",
        503,
    )
    cursor.execute("SHOW fsync")
    need(next(iter(cursor.fetchone().values())) == "on", "unavailable", 503)
    if observer:
        _observer_guard(cursor)


def _observer_guard(cursor):
    # Effective privileges include column grants, PUBLIC and implicit ownership.
    cursor.execute(
        """SELECT
            NOT EXISTS(SELECT 1 FROM pg_roles AS r
                       WHERE r.rolname=current_user AND r.rolcanlogin) AS no_login,
            EXISTS(SELECT 1 FROM pg_database AS d
                   WHERE d.datname=current_database()
                     AND pg_has_role(current_user,d.datdba,'MEMBER')) AS database_owner,
            has_database_privilege(current_user,current_database(),'TEMP') AS temporary_create,
            EXISTS(SELECT 1 FROM pg_namespace AS n
                   WHERE pg_has_role(current_user,n.nspowner,'MEMBER')
                      OR has_schema_privilege(current_user,n.oid,'CREATE')) AS schema_ddl,
            EXISTS(SELECT 1 FROM pg_class AS c JOIN pg_namespace AS n ON n.oid=c.relnamespace
                   WHERE n.nspname='pam_usage_anchor' AND c.relkind IN ('r','p','v','m','f')
                     AND (pg_has_role(current_user,c.relowner,'MEMBER')
                       OR has_table_privilege(current_user,c.oid,
                           'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
                       OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
                AS relation_write,
            EXISTS(SELECT 1 FROM pg_class AS c JOIN pg_namespace AS n ON n.oid=c.relnamespace
                   WHERE n.nspname='pam_usage_anchor' AND c.relkind='S'
                     AND (pg_has_role(current_user,c.relowner,'MEMBER')
                       OR has_sequence_privilege(current_user,c.oid,'UPDATE,USAGE')))
                AS sequence_write,
            EXISTS(SELECT 1 FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid=p.pronamespace
                   WHERE n.nspname='pam_usage_anchor' AND p.prosecdef
                     AND has_function_privilege(current_user,p.oid,'EXECUTE'))
                AS elevated_execute"""
    )
    row = cursor.fetchone()
    need(row is not None and all(flag is False for flag in row.values()), "unavailable", 503)


@contextmanager
def _read_transaction(connect, *, observer=False):
    with connect() as connection, connection.transaction():
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            cursor.execute("SET LOCAL statement_timeout='3000ms'")
            cursor.execute("SET LOCAL lock_timeout='2000ms'")
            role_guard(cursor, observer=observer)
            yield cursor


def _terminal_row(cursor, slot, peer, operation_id):
    expected = slot.expected()
    cursor.execute(
        """SELECT o.reservation_id,o.state,o.body_hash,o.final_bundle,o.final_digest,
                  o.terminal_response
           FROM pam_usage_anchor.operations AS o
           JOIN pam_usage_anchor.contexts AS c ON c.context_id=o.context_id
           JOIN pam_usage_anchor.quotas AS q
             ON q.context_id=c.context_id AND q.service_id=o.vault_service
           JOIN pam_usage_anchor.leases AS l
             ON l.context_id=c.context_id AND l.service_id=o.vault_service
           WHERE o.operation_id=%s AND c.context_id=%s AND c.installation_id=%s
             AND c.tenant_id=%s AND c.witness_incarnation=%s AND c.slot_sha256=%s
             AND o.vault_service=%s AND o.vault_instance=%s AND o.vault_der=%s
             AND o.state IN ('consumed_no_release','refused_no_release')""",
        (
            operation_id,
            slot.context_id,
            expected["installation_id"],
            expected["organization_id"],
            slot.witness_incarnation,
            slot.source_sha256,
            peer.service_id,
            peer.broker_instance_id,
            peer.certificate_sha256,
        ),
    )
    return cursor.fetchone()


def _closed_fence(cursor, slot):
    expected = slot.expected()
    purposes = dict(slot.purposes)
    vault_principal = next(
        principal
        for principal in slot.principals
        if purposes[principal.service_id] == "usage-anchor.vault/1"
    )
    cursor.execute(
        """SELECT EXISTS(
               SELECT 1 FROM pam_usage_anchor.contexts AS c
               JOIN pam_usage_anchor.leases AS l ON l.context_id=c.context_id
               JOIN pam_usage_anchor.quotas AS q
                 ON q.context_id=c.context_id AND q.service_id=l.service_id
               WHERE c.context_id=%s AND c.installation_id=%s AND c.tenant_id=%s
                 AND c.witness_incarnation=%s AND c.slot_sha256=%s AND c.serving_state='closed'
                 AND l.service_id=%s AND l.incarnation=%s AND l.owner_der=ANY(%s::text[])
                 AND l.serving_state='closed' AND l.epoch>%s
           ) AS fenced""",
        (
            slot.context_id,
            expected["installation_id"],
            expected["organization_id"],
            slot.witness_incarnation,
            slot.source_sha256,
            vault_principal.service_id,
            expected["ledger_incarnation"],
            list(vault_principal.certificate_sha256),
            slot.lease_epoch,
        ),
    )
    row = cursor.fetchone()
    need(row is not None and row["fenced"] is True, "context_refused", 403)


class PostgresHistory:
    """Cold reader with an observer connection and no write transaction API."""

    def __init__(self, connect):
        self.connect = connect

    def startup(self, slot):
        with _read_transaction(self.connect, observer=True) as cursor:
            _closed_fence(cursor, slot)

    def read_terminal(self, slot, peer, operation_id):
        with _read_transaction(self.connect, observer=True) as cursor:
            _closed_fence(cursor, slot)
            return _terminal_row(cursor, slot, peer, operation_id)

    def archive_page(self, slot, checkpoint, after_seq, *, limit=MAX_PAGE_EVENTS):
        """Read a bounded page anchored to the caller's independently pinned head."""
        need(type(checkpoint) is Checkpoint)
        checkpoint.require_slot(slot)
        integer(after_seq, 0, checkpoint.last_seq)
        integer(limit, 1, MAX_PAGE_EVENTS)
        need(after_seq < checkpoint.last_seq or checkpoint.last_seq == 0)

        try:
            with _read_transaction(self.connect, observer=True) as cursor:
                _closed_fence(cursor, slot)
                cursor.execute(
                    "SELECT seq,head_sha256 FROM pam_usage_anchor.audit_heads WHERE context_id=%s",
                    (slot.context_id,),
                )
                head = cursor.fetchone()
                need(
                    head is not None
                    and type(head["seq"]) is int
                    and head["seq"] == checkpoint.last_seq
                    and head["head_sha256"] == checkpoint.head_sha256,
                    "context_refused",
                    403,
                )

                previous_sha256 = GENESIS_SHA256
                if after_seq:
                    cursor.execute(
                        """SELECT event_sha256 FROM pam_usage_anchor.audit_events
                           WHERE context_id=%s AND seq=%s""",
                        (slot.context_id, after_seq),
                    )
                    previous = cursor.fetchone()
                    need(previous is not None, "context_refused", 403)
                    previous_sha256 = previous["event_sha256"]

                cursor.execute(
                    """SELECT seq,event_bytes,previous_sha256,event_sha256
                       FROM pam_usage_anchor.audit_events
                       WHERE context_id=%s AND seq>%s AND seq<=%s ORDER BY seq LIMIT %s""",
                    (slot.context_id, after_seq, checkpoint.last_seq, limit),
                )
                rows = cursor.fetchall()
        except (PsycopgError, OSError):
            raise Error("unavailable", 503) from None

        return encode_archive_page(checkpoint, after_seq, previous_sha256, rows, limit=limit)


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

    def read_terminal(self, slot, peer, operation_id):
        """Look up a committed receipt in the peer's current witness context."""
        with _read_transaction(self.connect) as cursor:
            return _terminal_row(cursor, slot, peer, operation_id)

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
