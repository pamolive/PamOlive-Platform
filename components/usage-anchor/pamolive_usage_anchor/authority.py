"""Verify actual RO public V1 bytes and derive W1 authority from signed fields."""

import json
from datetime import datetime

from pamolive_pam_trust_verifier import verify_current_registry_materials
from pamolive_pam_trust_verifier._crypto import public_key_fingerprint
from pamolive_vault_contracts import p0_canonical

from .codec import EFFECTIVE, commitment, encode, need, parse_materials, sha


def epoch(text):
    dt = datetime.fromisoformat(text)
    need(dt.tzinfo is not None, "context_refused", 403)
    return int(dt.timestamp())


class Authority:
    def __init__(self, slot_guard, materials_reader):
        self.guard, self.reader = slot_guard, materials_reader

    def current(self, now):
        slot = self.guard.check()
        raw = self.reader.check()
        e = slot.expected()
        need(sha(raw) == e["authority_materials_sha256"], "context_refused", 403)
        chain, cp = parse_materials(raw)
        verified = verify_current_registry_materials(chain, cp, slot.context(now))
        head = json.loads(verified.canonical_head_envelope)["body"]
        checkpoint = json.loads(verified.canonical_checkpoint)["body"]
        cp_doc = json.loads(verified.canonical_checkpoint)
        keys = [k for k in slot.checkpoint_keys if k.key_id == cp_doc["key_id"]]
        need(len(keys) == 1 and keys[0].active, "context_refused", 403)
        key = keys[0]
        need(
            epoch(key.not_before) <= now < epoch(key.not_after)
            and (not key.revoked_at or now < epoch(key.revoked_at)),
            "context_refused",
            403,
        )
        end = min(
            slot.not_after,
            epoch(head["expires_at"]),
            epoch(checkpoint["expires_at"]),
            epoch(key.not_after),
        )
        if key.revoked_at:
            end = min(end, epoch(key.revoked_at))
        need(slot.not_before <= now < end, "context_refused", 403)
        need(verified.checkpoint_sha256 == e["checkpoint_hash"], "context_refused", 403)
        return slot, head, end

    @staticmethod
    def credential(slot, head, person):
        need(
            person in head["persons"] and head["persons"][person]["active"], "context_refused", 403
        )
        chosen = dict(slot.credentials).get(person)
        matches = [
            a
            for a in head["persons"][person]["authenticators"]
            if a["id"] == chosen and a["active"]
        ]
        need(len(matches) == 1, "context_refused", 403)
        auth = matches[0]
        need(
            auth["rp_id"] == "confirm.pamolive.invalid"
            and auth["origin"] == "https://confirm.pamolive.invalid",
            "context_refused",
            403,
        )
        return dict(auth, spki_sha256=public_key_fingerprint(auth["public_key"]), person_id=person)

    def operation(self, draft, now):
        slot, head, end = self.current(now)
        # W-only commissioned intention owner. The request's id/hash and a valid
        # P0 requester role alone do not establish this semantic relationship.
        need(draft.requester_person_id == slot.intent_requester_person_id, "context_refused", 403)
        for name, expected in slot.expectations:
            need(getattr(draft, name) == expected, "context_refused", 403)
        policy = head["policy"]
        need(set(policy) == {"standard_min", "critical_min"}, "context_refused", 403)
        need(draft.policy_hash == sha(p0_canonical(policy)), "context_refused", 403)
        target = head["targets"].get(draft.target_id)
        need(
            type(target) is dict
            and not set(target)
            - {
                "scope",
                "critical",
                "min_reviewers",
                "contract_id",
                "contract_authority",
                "sponsor_person",
                "contract_required",
                "sponsor_required",
            },
            "context_refused",
            403,
        )
        need(
            not target.get("contract_id") and not target.get("contract_required"),
            "context_refused",
            403,
        )
        need(not target.get("contract_authority"), "context_refused", 403)
        scope = target["scope"]
        need(
            sha(p0_canonical(scope)) == draft.destination_scope_hash
            and scope["epoch"] == draft.destination_epoch,
            "context_refused",
            403,
        )
        sponsor = target.get("sponsor_person", "")
        need(
            sponsor == draft.sponsor_person_id and (not target.get("sponsor_required") or sponsor),
            "context_refused",
            403,
        )
        need(
            draft.requester_person_id not in draft.approver_person_ids
            and draft.requester_person_id != sponsor,
            "proof_refused",
            403,
        )
        required = max(
            policy["critical_min" if target["critical"] else "standard_min"],
            target.get("min_reviewers", 1),
            slot.minimum_reviewers,
        )
        need(1 <= required <= len(draft.approver_person_ids) <= 16, "context_refused", 403)
        roles = [(draft.requester_person_id, "requester")]
        roles += [(p, "reviewer") for p in draft.approver_person_ids]
        if sponsor:
            roles.append((sponsor, "sponsor"))
        selected = []
        for person, role in sorted(roles):
            entry = head["persons"].get(person, {})
            need(
                entry.get("active")
                and role in entry.get("roles", [])
                and draft.target_id in entry.get("endpoint_ids", []),
                "proof_refused",
                403,
            )
            selected.append((person, role, self.credential(slot, head, person)))
        effective = {
            "schema": "pamolive.vault.effective-policy/1",
            "registry_hash": draft.registry_hash,
            "target_id": draft.target_id,
            "destination_scope_hash": draft.destination_scope_hash,
            "standard_min": policy["standard_min"],
            "critical_min": policy["critical_min"],
            "criticality": "critical" if target["critical"] else "standard",
            "target_min_reviewers": target.get("min_reviewers", 1),
            "commissioned_min_reviewers": slot.minimum_reviewers,
            "required_reviewers": required,
            "sponsor_person_id": sponsor,
            "contract_id": "",
        }
        return (
            slot,
            end,
            selected,
            effective,
            commitment(EFFECTIVE, encode(effective, 4096, nodes=512)),
        )
