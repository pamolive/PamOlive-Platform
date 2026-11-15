"""Real SQL/mTLS qualification driver, NOT imported/run by run_pure.

Root supplies explicitly provisioned NEW isolated databases/roles and clients.
This module never creates a listener, container, role or default connection.
Calling its functions performs real SQL/network and requires separate execution.
"""

import json
from dataclasses import replace

from fixtures import MemoryReader, assertion, uid
from pamolive_usage_anchor.client import VaultMirror
from pamolive_usage_anchor.codec import b64, encode, parse, parse_materials, sha, unb64
from pamolive_vault_contracts import parse_transcript, serialize_draft
from pamolive_vault_runtime.admission import Reservations
from pamolive_vault_runtime.ledger import PostgresLedger as VaultLedger
from pamolive_vault_runtime.slot import parse_slot as parse_v_slot
from psycopg.rows import dict_row


def vault_slot(fixture):
    w = fixture.slot_value
    v = {
        "schema": "pamolive.vault.local-reservation-slot/1",
        "slot_id": uid(92),
        "serving_state": "open",
        "installation_p0": w["installation_p0"],
        "expectations": w["expectations"],
        "commissioning_keys": w["commissioning_keys"],
        "checkpoint_keys": w["checkpoint_keys"],
        "principals": [
            {
                "service_id": "broker-w1",
                "broker_instance_id": fixture.draft.broker_instance_id,
                "certificate_sha256": [fixture.draft.broker_certificate_sha256],
                "san_uri": "urn:pamolive:broker:w1",
            }
        ],
        "not_before": fixture.now - 10,
        "not_after": fixture.now + 3600,
        "quota": 64,
        "registry_max_seconds": 86400,
        "checkpoint_max_seconds": 40,
    }
    raw = encode(v, 65536, special=True)
    return parse_v_slot(raw, sha(raw))


def seed_new_databases(*, witness_owner_connect, vault_owner_connect, fixture):
    """Explicit owner commissioning, only after empty isolated schemas are installed."""
    s = fixture.slot
    e = s.expected()
    with witness_owner_connect() as conn, conn.transaction(), conn.cursor() as c:
        c.execute("SET LOCAL ROLE usage_anchor_owner")
        c.execute("SELECT count(*) FROM pam_usage_anchor.contexts")
        assert c.fetchone()[0] == 0, "requires new empty isolated W database"
        c.execute(
            (
                """INSERT INTO
                pam_usage_anchor.contexts(context_id,installation_id,tenant_id,witness_incarnation,slot_sha256,serving_state)
                VALUES(%s,%s,%s,%s,%s,%s)"""
            ),
            (
                s.context_id,
                e["installation_id"],
                e["organization_id"],
                s.witness_incarnation,
                s.source_sha256,
                "open",
            ),
        )
        for p in sorted(s.principals, key=lambda p: p.service_id):
            c.execute(
                """INSERT INTO pam_usage_anchor.quotas(context_id,service_id) VALUES(%s,%s)""",
                (s.context_id, p.service_id),
            )
        c.execute(
            (
                """INSERT INTO
                pam_usage_anchor.leases(context_id,service_id,incarnation,owner_der,epoch,issued_at,expires_at,serving_state)
                VALUES(%s,%s,%s,%s,%s,%s,%s,'open')"""
            ),
            (
                s.context_id,
                "vault-w1",
                e["ledger_incarnation"],
                sha(fixture.vault_der),
                s.lease_epoch,
                fixture.now,
                fixture.now + 30,
            ),
        )
        _, head, _ = fixture.authority.current(fixture.now)
        auths = [fixture.authority.credential(s, head, person) for person, _ in s.credentials]
        for auth in sorted(auths, key=lambda a: a["id"]):
            c.execute(
                (
                    """INSERT INTO
                    pam_usage_anchor.activations(context_id,credential_id,person_id,spki_sha256,enrollment_id,rp_id,origin,
                    activation_version,sign_count,state_version,status)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,1,0,1,'commissioned')"""
                ),
                (
                    s.context_id,
                    auth["id"],
                    auth["person_id"],
                    auth["spki_sha256"],
                    auth["enrollment_id"],
                    auth["rp_id"],
                    auth["origin"],
                ),
            )
        c.execute(
            "INSERT INTO pam_usage_anchor.audit_heads VALUES(%s,0,%s)", (s.context_id, "0" * 64)
        )
    v = vault_slot(fixture)
    with vault_owner_connect() as conn, conn.transaction(), conn.cursor() as c:
        c.execute("SET LOCAL ROLE vault_n0_owner")
        c.execute("SELECT count(*) FROM vault_reservation.commissioned_state")
        assert c.fetchone()[0] == 0, "requires new empty isolated V database"
        c.execute(
            (
                """INSERT INTO
                vault_reservation.commissioned_state(slot_id,incarnation,slot_sha256,serving_state)
                VALUES(%s,%s,%s,'open')"""
            ),
            (v.slot_id, e["ledger_incarnation"], v.source_sha256),
        )


def activate_over_mtls(client, fixture):
    for person in sorted(fixture.auths):
        status, raw = client.request("/v1/activations/begin", encode({"person_id": person}, 4096))
        assert status == 201
        challenge = parse(raw, 4096, special=True)
        proof = encode(
            assertion(
                fixture.keys[person], fixture.auths[person], unb64(challenge["challenge"], 32)
            ),
            65536,
            depth=4,
            nodes=64,
            string=12000,
            special=True,
        )
        status, raw = client.request(
            "/v1/activations/finish",
            encode(
                {"challenge_id": challenge["challenge_id"], "assertion_b64": b64(proof)},
                131072,
                string=90000,
            ),
        )
        assert status == 200 and parse(raw, 4096, special=True)["state"] == "active"


def vertical_round_trip(
    *, fixture, witness_client, vault_runtime_connect, witness_observer_connect
):
    """V0 real ledger -> W mTLS -> real W SQL/proofs -> commit -> real V SQL mirror."""
    vslot = vault_slot(fixture)
    reservations = Reservations(MemoryReader(vslot), VaultLedger(vault_runtime_connect))
    mirror = VaultMirror(vault_runtime_connect, witness_client)
    chain, cp = parse_materials(fixture.materials)
    from cryptography.hazmat.primitives import serialization

    broker_der = fixture.broker_cert.public_bytes(serialization.Encoding.DER)
    observations = []
    for index, negative in enumerate((False, True)):
        draft = replace(
            fixture.draft, idempotency_key=uid(600 + index), request_id=uid(700 + index)
        )
        request = json.dumps(
            {
                "draft": json.loads(serialize_draft(draft)),
                "registry_chain": [b64(x) for x in chain],
                "checkpoint": b64(cp),
            },
            separators=(",", ":"),
        ).encode()
        pending = reservations.prepare(request, broker_der)  # real V SQL commit
        bound_raw = mirror.prepare_reserved(
            pending.reservation_id
        )  # real mTLS W bind, then real V mirror commit
        bound = parse(bound_raw, 196608, string=90000, special=True)
        transcript = parse_transcript(unb64(bound["transcript_b64"], 32768))
        proofs = fixture.final_bundle(
            transcript, bound["operation_id"], negative=negative, spaced=True
        )
        first = mirror.consume(pending.reservation_id, proofs)
        retry = mirror.consume(pending.reservation_id, proofs)
        assert first == retry
        terminal = parse(first, 4096, special=True)
        assert terminal["state"] == ("refused_no_release" if negative else "consumed_no_release")
        assert terminal["authorized"] is False
        with witness_observer_connect() as conn, conn.cursor(row_factory=dict_row) as c:
            c.execute(
                (
                    """SELECT state,final_bundle,terminal_response FROM
                    pam_usage_anchor.operations WHERE operation_id=%s"""
                ),
                (bound["operation_id"],),
            )
            row = c.fetchone()
            assert (
                row["state"] == terminal["state"]
                and bytes(row["final_bundle"]) == proofs
                and bytes(row["terminal_response"]) == first
            )
            c.execute(
                """SELECT count(*) AS count FROM pam_usage_anchor.proof_uses WHERE
                operation_id=%s""",
                (bound["operation_id"],),
            )
            assert c.fetchone()["count"] == (1 if negative else 4)
        with vault_runtime_connect() as conn, conn.cursor(row_factory=dict_row) as c:
            c.execute(
                (
                    """SELECT state,terminal_response FROM vault_reservation.usage_mirrors
                    WHERE reservation_id=%s"""
                ),
                (pending.reservation_id,),
            )
            row = c.fetchone()
            assert row["state"] == terminal["state"] and bytes(row["terminal_response"]) == first
        observations.append(
            {"state": terminal["state"], "retry_byte_exact": True, "authorized": False}
        )
    return {
        "type": "W1_REAL_SQL_MTLS_VERTICAL_ONLY",
        "operations": observations,
        "production_or_host_independence_received": False,
    }
