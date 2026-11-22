"""W1 vertical transaction orchestration: real proofs, SQL, terminal no-release."""

import secrets
import time
from uuid import uuid4

from pamolive_pam_trust_verifier import InvalidMaterials
from pamolive_vault_contracts import (
    FullTranscript,
    body_hash,
    final_assertions_digest,
    parse_draft,
    parse_transcript,
    serialize_transcript,
)
from pamolive_vault_contracts.canonical import ContractError

from .codec import (
    BASELINE,
    Error,
    b64,
    baseline,
    bundle,
    closed,
    commitment,
    encode,
    integer,
    need,
    parse,
    sha,
    terminal_receipt,
    unb64,
    uuid,
)
from .proofs import final_proofs, verify

OBSERVE_TERMINAL = "/v1/operations/observe-terminal"


def check_snapshot(snap, selected, states):
    need(
        [(a["person_id"], a["role"], a["credential_id"]) for a in snap["activations"]]
        == [(p, role, auth["id"]) for p, role, auth in selected],
        "context_refused",
        403,
    )
    for a in snap["activations"]:
        current = states.get(a["credential_id"])
        need(
            current is not None
            and all(
                current[k] == a[k] for k in ("sign_count", "state_version", "activation_version")
            ),
            "baseline_stale",
            409,
        )


class HistoryService:
    def __init__(self, guard, ledger, clock=None):
        self.guard, self.ledger = guard, ledger
        self.clock = clock or (lambda: int(time.time()))

    def dispatch(self, route, raw, der):
        try:
            return self._dispatch(route, raw, der)
        except Error as error:
            code, status = error.code, error.status
        except ContractError:
            code, status = "invalid_request", 400
        except InvalidMaterials:
            code, status = "context_refused", 403
        except Exception:
            code, status = "unavailable", 503
        raise Error(code, status) from None

    def _dispatch(self, route, raw, der):
        need(route == OBSERVE_TERMINAL, "context_refused", 403)
        return self.observe_terminal(raw, der)

    def _caller(self, der, purpose):
        slot = self.guard.check()
        now = integer(self.clock())
        return slot, slot.peer(der, now, purpose), now

    def observe_terminal(self, raw, der):
        """Read an existing receipt in W even when the operation lease is closed."""
        purpose = "usage-anchor.vault/1"
        slot, peer, _ = self._caller(der, purpose)
        value = bundle(raw)
        final_digest = final_assertions_digest(raw)
        row = self.ledger.read_terminal(slot, peer, value["operation_id"])
        need(row is not None, "context_refused", 403)
        need(
            row["body_hash"] == value["body_hash"]
            and row["final_digest"] == final_digest
            and bytes(row["final_bundle"]) == raw,
            "idempotency_conflict",
            409,
        )
        response = bytes(row["terminal_response"])
        terminal = terminal_receipt(
            response,
            reservation_id=str(row["reservation_id"]),
            operation_id=value["operation_id"],
            body_hash=value["body_hash"],
            final_digest=final_digest,
        )
        need(terminal["state"] == row["state"], "context_refused", 403)
        current_slot, current_peer, _ = self._caller(der, purpose)
        need((current_slot, current_peer) == (slot, peer), "context_refused", 403)
        return 200, response


class Service(HistoryService):
    def __init__(self, authority, ledger, clock=None):
        super().__init__(authority.guard, ledger, clock)
        self.authority = authority

    def _dispatch(self, route, raw, der):
        actions = {
            "/v1/operations/bind": self.bind,
            "/v1/operations/consume": self.consume,
            OBSERVE_TERMINAL: self.observe_terminal,
            "/v1/activations/begin": self.begin_activation,
            "/v1/activations/finish": self.finish_activation,
        }
        need(route in actions)
        return actions[route](raw, der)

    def _check(self, slot, peer, der, tx, end, draft=None):
        now = integer(self.clock())
        current = self.authority.guard.check()
        need(
            current == slot
            and current.peer(der, now, dict(slot.purposes)[peer.service_id]) == peer,
            "context_refused",
            403,
        )
        if draft is None:
            _, _, current_end = self.authority.current(now)
        else:
            _, current_end, _, _, _ = self.authority.operation(draft, now)
        tx.live(now, min(end, current_end))
        return now

    def begin_activation(self, raw, der):
        v = parse(raw, 4096)
        closed(v, {"person_id"})
        person = uuid(v["person_id"])
        slot, peer, now = self._caller(der, "usage-anchor.activation/1")
        _, head, end = self.authority.current(now)
        auth = self.authority.credential(slot, head, person)
        end = min(end, now + 30, peer.expires_at)
        challenge_id = str(uuid4())
        binding = encode(
            {
                "schema": "pamolive.vault.activation-challenge/1",
                "id": challenge_id,
                "installation_id": slot.expected()["installation_id"],
                "organization_id": slot.expected()["organization_id"],
                "witness_incarnation": slot.witness_incarnation,
                "slot_sha256": slot.source_sha256,
                "registry_hash": slot.expected()["registry_hash"],
                "trust_generation": slot.expected()["trust_generation"],
                "person_id": person,
                "credential_id": auth["id"],
                "spki_sha256": auth["spki_sha256"],
                "enrollment_id": auth["enrollment_id"],
                "rp_id": auth["rp_id"],
                "origin": auth["origin"],
                "nonce": b64(secrets.token_bytes(32)),
                "issued_at": now,
                "expires_at": end,
            },
            8192,
        )
        challenge = bytes.fromhex(sha(b"pamolive.vault.activation-challenge.v1\0" + binding))
        with self.ledger.transaction(slot, peer, vault=False) as tx:
            tx.live(now, end)
            # New challenge row is operation-rank4, before the activation-rank5 lock.
            tx.insert_challenge(challenge_id, auth["id"], binding, challenge, end)
            tx.states([(person, "activation", auth)], active=False)
            self._check(slot, peer, der, tx, end)
            tx.audit("activation_challenge", challenge_id, now)
            tx.before_commit(lambda: self._check(slot, peer, der, tx, end))
        return 201, encode(
            {
                "challenge_id": challenge_id,
                "challenge": b64(challenge),
                "person_id": person,
                "credential_id": auth["id"],
                "expires_at": end,
                "authorized": False,
            },
            4096,
            special=True,
        )

    def finish_activation(self, raw, der):
        v = parse(raw, 131072, string=90000)
        closed(v, {"challenge_id", "assertion_b64"})
        uuid(v["challenge_id"])
        assertion = unb64(v["assertion_b64"], 65536)
        slot, peer, now = self._caller(der, "usage-anchor.activation/1")
        _, head, end = self.authority.current(now)
        with self.ledger.transaction(slot, peer, vault=False) as tx:
            row = tx.challenge(v["challenge_id"])
            need(
                row is not None
                and row["used_at"] is None
                and row["certificate_sha256"] == peer.certificate_sha256
                and row["service_id"] == peer.service_id,
                "idempotency_conflict",
                409,
            )
            binding = parse(bytes(row["binding"]), 8192)
            need(binding["slot_sha256"] == slot.source_sha256, "context_refused", 403)
            auth = self.authority.credential(slot, head, binding["person_id"])
            need(row["credential_id"] == auth["id"], "context_refused", 403)
            states = tx.states([(binding["person_id"], "activation", auth)], active=False)
            need(states[auth["id"]]["sign_count"] == 0, "context_refused", 403)
            tx.live(now, min(end, row["expires_at"]))
            count = verify(
                assertion,
                auth=auth,
                person_id=binding["person_id"],
                organization_id=slot.expected()["organization_id"],
                challenge=bytes(row["challenge"]),
                current=0,
                allow_zero=slot.allow_zero,
            )
            self._check(slot, peer, der, tx, row["expires_at"])
            tx.activate(v["challenge_id"], auth["id"], count, now)
            tx.audit("activated", v["challenge_id"], now, sha(assertion))
            tx.before_commit(lambda: self._check(slot, peer, der, tx, row["expires_at"]))
        return 200, encode(
            {"state": "active", "person_id": binding["person_id"], "authorized": False},
            4096,
            special=True,
        )

    def bind(self, raw, der):
        v = parse(raw, 32768, string=24000)
        closed(v, {"draft_b64", "reservation_id", "nonce", "issued_at", "expires_at"})
        draft = parse_draft(unb64(v["draft_b64"], 16384))
        uuid(v["reservation_id"])
        need(len(unb64(v["nonce"], 32)) == 32)
        integer(v["issued_at"])
        integer(v["expires_at"])
        need(v["issued_at"] < v["expires_at"] <= v["issued_at"] + 30)
        slot, peer, now = self._caller(der, "usage-anchor.vault/1")
        need(peer.service_id == draft.vault_service_id, "caller_refused", 403)
        broker = dict(slot.broker)
        need(
            draft.broker_service_id == draft.requested_caller_service_id == broker["service_id"]
            and draft.broker_instance_id == broker["instance_id"]
            and draft.broker_certificate_sha256 == broker["certificate_sha256"],
            "caller_refused",
            403,
        )
        _, end, selected, effective, effective_hash = self.authority.operation(draft, now)
        need(v["issued_at"] <= now < v["expires_at"], "expired", 410)
        with self.ledger.transaction(slot, peer, vault=True) as tx:
            row = tx.operation(draft=draft)
            if row is not None:
                need(
                    bytes(row["binding"]) == raw
                    and row["vault_der"] == peer.certificate_sha256
                    and str(row["vault_instance"]) == peer.broker_instance_id
                    and row["slot_sha256"] == slot.source_sha256,
                    "idempotency_conflict",
                    409,
                )
                need(row["state"] == "pending_proofs", "idempotency_conflict", 409)
                self._check(slot, peer, der, tx, row["expires_at"], draft)
                tx.before_commit(lambda: self._check(slot, peer, der, tx, row["expires_at"], draft))
                response, status = bytes(row["bound_response"]), 200
            else:
                tx.live(now, min(end, v["expires_at"]))
                expires = min(end, v["expires_at"], peer.expires_at, tx.lease["expires_at"])
                tx.quota(new=True)
                row = {
                    "operation_id": str(uuid4()),
                    "context_id": slot.context_id,
                    "broker_service": draft.broker_service_id,
                    "operation": draft.operation,
                    "idempotency_key": draft.idempotency_key,
                    "vault_service": peer.service_id,
                    "vault_instance": peer.broker_instance_id,
                    "vault_der": peer.certificate_sha256,
                    "reservation_id": v["reservation_id"],
                    "lease_epoch": slot.lease_epoch,
                    "slot_sha256": slot.source_sha256,
                    "binding": raw,
                    "baseline": None,
                    "transcript": None,
                    "body_hash": None,
                    "bound_response": None,
                    "issued_at": v["issued_at"],
                    "expires_at": expires,
                    "state": "binding",
                }
                tx.insert_operation(row)  # rank4 INSERT before any rank5 activation lock
                states = tx.states(selected)
                snap = {
                    "schema": "pamolive.vault.counter-baseline/1",
                    "installation_id": draft.installation_id,
                    "organization_id": draft.organization_id,
                    "trust_generation": draft.trust_generation,
                    "registry_revision": draft.registry_revision,
                    "registry_hash": draft.registry_hash,
                    "policy_binding_id": draft.policy_revision,
                    "policy_hash": draft.policy_hash,
                    "effective_policy_sha256": effective_hash,
                    "witness_incarnation": slot.witness_incarnation,
                    "witness_slot_sha256": slot.source_sha256,
                    "activations": [],
                }
                for person, role, auth in selected:
                    state = states[auth["id"]]
                    snap["activations"].append(
                        {
                            "person_id": person,
                            "role": role,
                            "credential_id": auth["id"],
                            "spki_sha256": auth["spki_sha256"],
                            "enrollment_id": auth["enrollment_id"],
                            "rp_id": auth["rp_id"],
                            "origin": auth["origin"],
                            "activation_version": state["activation_version"],
                            "state_version": state["state_version"],
                            "sign_count": state["sign_count"],
                        }
                    )
                row["baseline"] = encode(snap, 65536)
                baseline(row["baseline"])
                transcript = FullTranscript(
                    draft,
                    v["nonce"],
                    commitment(BASELINE, row["baseline"]),
                    v["issued_at"],
                    v["issued_at"],
                    expires,
                )
                row["transcript"] = serialize_transcript(transcript)
                row["body_hash"] = body_hash(transcript)
                response = encode(
                    {
                        "schema": "pamolive.vault.usage-bound/1",
                        "operation_id": row["operation_id"],
                        "reservation_id": v["reservation_id"],
                        "body_hash": row["body_hash"],
                        "authority_materials_sha256": draft.authority_materials_sha256,
                        "baseline_b64": b64(row["baseline"]),
                        "transcript_b64": b64(row["transcript"]),
                        "authorized": False,
                    },
                    196608,
                    string=90000,
                    special=True,
                )
                row["bound_response"] = response
                self._check(slot, peer, der, tx, expires, draft)
                tx.finish_bind(row)
                tx.quota()
                tx.audit("bound", row["operation_id"], now, row["body_hash"])
                tx.before_commit(lambda: self._check(slot, peer, der, tx, expires, draft))
                status = 201
        return status, response

    def consume(self, raw, der):
        value = bundle(raw)
        final_digest = final_assertions_digest(raw)
        slot, peer, now = self._caller(der, "usage-anchor.vault/1")
        with self.ledger.transaction(slot, peer, vault=True) as tx:
            row = tx.operation(operation_id=value["operation_id"])
            need(row is not None and row["vault_service"] == peer.service_id, "caller_refused", 403)
            need(
                row["vault_der"] == peer.certificate_sha256
                and str(row["vault_instance"]) == peer.broker_instance_id
                and row["body_hash"] == value["body_hash"],
                "idempotency_conflict",
                409,
            )
            if row["state"] in ("consumed_no_release", "refused_no_release"):
                need(
                    bytes(row["final_bundle"]) == raw and row["final_digest"] == final_digest,
                    "idempotency_conflict",
                    409,
                )
                response = bytes(row["terminal_response"])
            else:
                need(row["state"] == "pending_proofs", "unavailable", 503)
                transcript = parse_transcript(bytes(row["transcript"]))
                need(body_hash(transcript) == row["body_hash"], "context_refused", 403)
                _, end, selected, effective, _ = self.authority.operation(transcript.draft, now)
                need(
                    row["lease_epoch"] == slot.lease_epoch
                    and row["slot_sha256"] == slot.source_sha256,
                    "context_refused",
                    403,
                )
                tx.live(now, min(end, row["expires_at"]))
                states = tx.states(selected)
                snap = baseline(bytes(row["baseline"]))
                need(
                    commitment(BASELINE, bytes(row["baseline"]))
                    == transcript.authenticator_counter_baseline_hash,
                    "context_refused",
                    403,
                )
                check_snapshot(snap, selected, states)
                state, updated, uses = final_proofs(
                    value,
                    transcript,
                    selected,
                    states,
                    slot.allow_zero,
                    effective["required_reviewers"],
                )
                tx.quota(extra=len(raw))
                terminal_at = self._check(slot, peer, der, tx, row["expires_at"], transcript.draft)
                response = encode(
                    {
                        "schema": "pamolive.vault.usage-terminal/1",
                        "operation_id": value["operation_id"],
                        "reservation_id": str(row["reservation_id"]),
                        "state": state,
                        "body_hash": row["body_hash"],
                        "final_assertions_digest": final_digest,
                        "issued_at": row["issued_at"],
                        "expires_at": row["expires_at"],
                        "terminal_at": terminal_at,
                        "authorized": False,
                    },
                    4096,
                    special=True,
                )
                tx.terminal(row, state, raw, final_digest, response, updated, uses)
                tx.audit(state, value["operation_id"], terminal_at, final_digest)
                tx.before_commit(
                    lambda: self._check(slot, peer, der, tx, row["expires_at"], transcript.draft)
                )
        return 200, response
