"""V-side authenticated W client plus durable SQL mirror; no secret SDK."""

import http.client
import ssl

from pamolive_vault_contracts import body_hash, parse_transcript
from psycopg.rows import dict_row

from .codec import (
    BASELINE,
    Error,
    b64,
    baseline,
    closed,
    commitment,
    digest,
    encode,
    need,
    parse,
    sha,
    unb64,
    uuid,
)


class MTLSClient:
    def __init__(self, *, host, port, context, server_der_sha256):
        need(
            type(context) is ssl.SSLContext
            and context.verify_mode == ssl.CERT_REQUIRED
            and context.check_hostname
            and context.keylog_filename is None,
            "unavailable",
            503,
        )
        need(
            type(host) is str
            and 0 < len(host) <= 253
            and type(port) is int
            and 1024 <= port <= 65535
        )
        self.host, self.port, self.context, self.pin = (
            host,
            port,
            context,
            digest(server_der_sha256),
        )

    def request(self, route, raw):
        from .http import LIMITS

        need(route in LIMITS and type(raw) is bytes and 0 < len(raw) <= LIMITS[route])
        connection = http.client.HTTPSConnection(
            self.host, self.port, context=self.context, timeout=3
        )
        try:
            connection.connect()
            need(
                sha(connection.sock.getpeercert(binary_form=True)) == self.pin,
                "caller_refused",
                403,
            )
            connection.putrequest("POST", route, skip_accept_encoding=True)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Accept", "application/json")
            connection.putheader("Content-Length", str(len(raw)))
            connection.endheaders(raw)
            response = connection.getresponse()
            need(response.getheader("Content-Type") == "application/json", "unavailable", 503)
            body = response.read(196609)
            need(len(body) <= 196608, "unavailable", 503)
            if response.status not in (200, 201):
                error = parse(body, 4096, special=True)
                raise Error(error.get("error", "unavailable"), response.status)
            return response.status, body
        except Error:
            raise
        except Exception:
            raise Error("unavailable", 503) from None
        finally:
            connection.close()


class VaultMirror:
    def __init__(self, connect, client):
        self.connect, self.client = connect, client

    def prepare_reserved(self, reservation_id):
        try:
            return self._prepare_reserved(reservation_id)
        except Error as error:
            code, status = error.code, error.status
        except Exception:
            code, status = "unavailable", 503
        raise Error(code, status) from None

    def _prepare_reserved(self, reservation_id):
        uuid(reservation_id)
        # The authoritative V0 row must already be committed in ADR024's real ledger.
        with self.connect() as conn, conn.cursor(row_factory=dict_row) as c:
            c.execute(
                (
                    """SELECT canonical_draft,nonce,issued_at,expires_at,state FROM
                    vault_reservation.reservations WHERE reservation_id=%s"""
                ),
                (reservation_id,),
            )
            row = c.fetchone()
        need(row is not None and row["state"] == "pending_proofs", "context_refused", 403)
        raw = encode(
            {
                "draft_b64": b64(bytes(row["canonical_draft"])),
                "reservation_id": reservation_id,
                "nonce": b64(bytes(row["nonce"])),
                "issued_at": row["issued_at"],
                "expires_at": row["expires_at"],
            },
            32768,
            string=24000,
        )
        _, response = self.client.request("/v1/operations/bind", raw)
        bound = parse(response, 196608, string=90000, special=True)
        closed(
            bound,
            {
                "schema",
                "operation_id",
                "reservation_id",
                "body_hash",
                "authority_materials_sha256",
                "baseline_b64",
                "transcript_b64",
                "authorized",
            },
        )
        need(
            bound.get("authorized") is False
            and bound.get("schema") == "pamolive.vault.usage-bound/1"
            and bound.get("reservation_id") == reservation_id,
            "context_refused",
            403,
        )
        transcript = parse_transcript(unb64(bound["transcript_b64"], 32768))
        baseline_raw = unb64(bound["baseline_b64"], 65536)
        baseline(baseline_raw)
        need(
            body_hash(transcript) == bound["body_hash"]
            and bound["authority_materials_sha256"] == transcript.draft.authority_materials_sha256
            and commitment(BASELINE, baseline_raw) == transcript.authenticator_counter_baseline_hash
            and b64(bytes(row["nonce"])) == transcript.operation_nonce
            and transcript.issued_at == row["issued_at"]
            and transcript.expires_at <= row["expires_at"],
            "context_refused",
            403,
        )
        from pamolive_vault_contracts import serialize_draft

        need(
            serialize_draft(transcript.draft) == bytes(row["canonical_draft"]),
            "context_refused",
            403,
        )
        # Commit mirror before exposing the transcript. Retries compare bytes.
        with self.connect() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as c:
            c.execute(
                (
                    """SELECT canonical_draft,nonce,issued_at,expires_at,state FROM
                    vault_reservation.reservations WHERE reservation_id=%s FOR UPDATE"""
                ),
                (reservation_id,),
            )
            current = c.fetchone()
            need(
                current is not None
                and all(
                    current[k] == row[k]
                    for k in ("canonical_draft", "nonce", "issued_at", "expires_at", "state")
                ),
                "context_refused",
                403,
            )
            c.execute(
                "SELECT * FROM vault_reservation.usage_mirrors WHERE reservation_id=%s",
                (reservation_id,),
            )
            old = c.fetchone()
            if old:
                need(bytes(old["bound_response"]) == response, "idempotency_conflict", 409)
            else:
                c.execute(
                    (
                        """INSERT INTO vault_reservation.usage_mirrors
                        (reservation_id,operation_id,body_hash,bound_response,state)
                        VALUES(%s,%s,%s,%s,'bound')"""
                    ),
                    (reservation_id, bound["operation_id"], bound["body_hash"], response),
                )
        return response

    def consume(self, reservation_id, bundle_raw):
        try:
            return self._consume(reservation_id, bundle_raw)
        except Error as error:
            code, status = error.code, error.status
        except Exception:
            code, status = "unavailable", 503
        raise Error(code, status) from None

    def _consume(self, reservation_id, bundle_raw):
        from .codec import bundle

        value = bundle(bundle_raw)
        with self.connect() as conn, conn.cursor(row_factory=dict_row) as c:
            c.execute(
                "SELECT * FROM vault_reservation.usage_mirrors WHERE reservation_id=%s",
                (reservation_id,),
            )
            row = c.fetchone()
        need(
            row is not None
            and str(row["operation_id"]) == value["operation_id"]
            and row["body_hash"] == value["body_hash"],
            "context_refused",
            403,
        )
        try:
            _, terminal_raw = self.client.request("/v1/operations/consume", bundle_raw)
            terminal = parse(terminal_raw, 4096, special=True)
            closed(
                terminal,
                {
                    "schema",
                    "operation_id",
                    "reservation_id",
                    "state",
                    "body_hash",
                    "final_assertions_digest",
                    "issued_at",
                    "expires_at",
                    "terminal_at",
                    "authorized",
                },
            )
            need(
                terminal.get("authorized") is False
                and terminal.get("schema") == "pamolive.vault.usage-terminal/1"
                and terminal.get("state") in ("consumed_no_release", "refused_no_release")
                and terminal.get("operation_id") == value["operation_id"]
                and terminal.get("body_hash") == value["body_hash"]
                and terminal.get("reservation_id") == reservation_id,
                "context_refused",
                403,
            )
            from pamolive_vault_contracts import final_assertions_digest

            need(
                terminal.get("final_assertions_digest") == final_assertions_digest(bundle_raw),
                "context_refused",
                403,
            )
            with self.connect() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as c:
                c.execute(
                    (
                        """SELECT * FROM vault_reservation.usage_mirrors WHERE reservation_id=%s
                        FOR UPDATE"""
                    ),
                    (reservation_id,),
                )
                old = c.fetchone()
                need(
                    old is not None
                    and (
                        old["terminal_response"] is None
                        or bytes(old["terminal_response"]) == terminal_raw
                    ),
                    "idempotency_conflict",
                    409,
                )
                c.execute(
                    (
                        """UPDATE vault_reservation.usage_mirrors SET state=%s,terminal_response=%s
                        WHERE reservation_id=%s"""
                    ),
                    (terminal["state"], terminal_raw, reservation_id),
                )
            return terminal_raw
        except Exception as failure:
            if isinstance(failure, Error) and failure.status != 503:
                raise Error(failure.code, failure.status) from None
            # A lost W response/unknown commit burns availability; never regenerate nonce or proofs.
            try:
                with self.connect() as conn, conn.transaction(), conn.cursor() as c:
                    c.execute(
                        (
                            """UPDATE vault_reservation.usage_mirrors SET state='uncertain' WHERE
                            reservation_id=%s AND terminal_response IS NULL"""
                        ),
                        (reservation_id,),
                    )
            except Exception:
                pass
            raise Error("unavailable", 503) from None
