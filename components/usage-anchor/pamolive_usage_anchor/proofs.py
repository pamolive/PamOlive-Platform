"""Real maintained WebAuthn verification over original signed clientDataJSON bytes."""

import hashlib

from pamolive_vault_contracts import confirmation_challenge
from webauthn import verify_authentication_response

from .codec import Error, closed, need, parse, unb64


def assertion(raw, *, credential_id, person_id, organization_id, challenge, rp_id, origin, current):
    try:
        value = parse(raw, 65536, depth=4, nodes=64, string=12000, special=True)
        closed(value, {"id", "rawId", "type", "response"})
        need(value["id"] == value["rawId"] == credential_id and value["type"] == "public-key")
        unb64(value["id"], 1024)
        response = value["response"]
        closed(response, {"clientDataJSON", "authenticatorData", "signature", "userHandle"})
        client_raw = unb64(response["clientDataJSON"], 8192)
        # C01: never canonicalize/rewrite signed bytes; each serialization needs its own signature.
        client = parse(
            client_raw, 8192, canonical=False, depth=4, nodes=64, string=4096, special=True
        )
        need(
            set(client)
            in ({"type", "challenge", "origin"}, {"type", "challenge", "origin", "crossOrigin"})
        )
        need(
            client["type"] == "webauthn.get"
            and client["origin"] == origin
            and client.get("crossOrigin", False) is False
        )
        need(unb64(client["challenge"], 32) == challenge and len(challenge) == 32)
        data = unb64(response["authenticatorData"], 37)
        need(len(data) == 37 and not data[32] & 0xC0)
        unb64(response["signature"], 8192)
        handle = response["userHandle"]
        if handle is not None:
            expected = hashlib.sha256(
                f"pamolive.pam.person.v1/{organization_id}/{person_id}".encode()
            ).digest()
            need(unb64(handle, 32) == expected)
        return value, int.from_bytes(data[33:37], "big")
    except Exception:
        raise Error("proof_refused", 403) from None


def verify(raw, *, auth, person_id, organization_id, challenge, current, allow_zero):
    value, count = assertion(
        raw,
        credential_id=auth["id"],
        person_id=person_id,
        organization_id=organization_id,
        challenge=challenge,
        rp_id=auth["rp_id"],
        origin=auth["origin"],
        current=current,
    )
    need(allow_zero or count > 0, "proof_refused", 403)
    try:
        result = verify_authentication_response(
            credential=value,
            expected_challenge=challenge,
            expected_rp_id=auth["rp_id"],
            expected_origin=auth["origin"],
            credential_public_key=unb64(auth["public_key"], 8192),
            credential_current_sign_count=current,
            require_user_verification=True,
        )
    except Exception:
        # Counter failures precede signatures in webauthn3.0.1. No quarantine exists.
        raise Error("proof_refused", 403) from None
    need(result.new_sign_count == count, "proof_refused", 403)
    return count


def final_proofs(value, transcript, selected, states, allow_zero, required):
    auths = {(p, role): auth for p, role, auth in selected}
    grouped, uses = {}, []
    for member in value["assertions"]:
        key = (member["person_id"], member["role"])
        auth = auths.get(key)
        need(auth is not None and auth["id"] == member["credential_id"], "proof_refused", 403)
        challenge = confirmation_challenge(
            transcript, person_id=key[0], role=key[1], decision=member["decision"]
        )
        raw = unb64(member["assertion_b64"], 65536)
        _, count = assertion(
            raw,
            credential_id=auth["id"],
            person_id=key[0],
            organization_id=transcript.draft.organization_id,
            challenge=challenge,
            rp_id=auth["rp_id"],
            origin=auth["origin"],
            current=states[auth["id"]]["sign_count"],
        )
        grouped.setdefault(auth["id"], []).append((count, key, member, raw, challenge, auth))
    updated = {}
    for cred in sorted(grouped):
        current = states[cred]["sign_count"]
        for _, key, member, raw, challenge, auth in sorted(
            grouped[cred], key=lambda item: (item[0], item[1])
        ):
            current = verify(
                raw,
                auth=auth,
                person_id=key[0],
                organization_id=transcript.draft.organization_id,
                challenge=challenge,
                current=current,
                allow_zero=allow_zero,
            )
            uses.append((key[0], key[1], member["decision"], cred, challenge, raw, current))
        updated[cred] = current
    if any(m["decision"] == "refuse" for m in value["assertions"]):
        return "refused_no_release", updated, uses
    decisions = {(m["person_id"], m["role"], m["decision"]) for m in value["assertions"]}
    d = transcript.draft
    need((d.requester_person_id, "requester", "launch") in decisions, "proof_refused", 403)
    need(
        len({p for p, r, dec in decisions if r == "reviewer" and dec == "approve"}) >= required,
        "proof_refused",
        403,
    )
    need(
        not d.sponsor_person_id or (d.sponsor_person_id, "sponsor", "sponsor") in decisions,
        "proof_refused",
        403,
    )
    return "consumed_no_release", updated, uses
