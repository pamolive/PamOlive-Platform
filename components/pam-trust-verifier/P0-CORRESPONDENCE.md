# V1 correspondence and deliberate differences

Reference commit: `a57350fe908c5c2fc57ee1dd6dc8a74e0a836ea8`.

| Reference source | SHA256 |
| --- | --- |
| `platform_modules/pam/trust_registry.py` | `373c63a0a0190d5856a0855abf809c1ef8416b9228ee3d18bab98c414e599b88` |
| `platform_modules/pam/trust_auth.py` | `986ef7d85eeb6953b6814642db6e3b22a9dfa418c8b9458e937e3f20621e0adc` |
| `platform_core/attestations.py` | `d1f716a5c280e89e6cbccf42caefdadb366d5c73e50f21ac0efd4df3e78e61fe` |

| P0 function / rule | Prototype | Evidence / difference |
| --- | --- | --- |
| `attestations.canonical` | `_codec.canonical` | Same JSON encoding for admitted raw JSON values; 164 static byte oracles. No datetime/UUID object conversion API; input is bytes. Bounded structure and incremental retained output. |
| `signature_message`, `checkpoint_message` | `_api` domain constants + canonical entire body | Exact NUL-terminated V1 domains. Unknown signed fields retained; NFC/NFD and timestamp strings never normalized. |
| `registry_digest` | `_api._digest_document`, `digest` | Entire body and both signature maps, same empty defaults; 72 static commitments and omitted-empty-map test. Raw input SHA distinguishes wire formatting. |
| `_decode`, `_verify` | `_crypto.decode`, `verify` | Padded base64url V1 material, exact public/signature lengths, maintained Ed25519. Constant outer error hides raw cryptography exceptions. |
| `_timestamp` | `_context.timestamp` | Stdlib fromisoformat and compatible fallback to Django's dateparse pattern; no Django import. Text kept intact; aware dates required. Attribution included. |
| `_configured_keys`, `_external_key` | frozen context, `external_key` | No settings/lookup. Historical periods and revocation use signing time, ignore active; current checkpoint additionally requires active. Context validates key objects/IDs/periods. |
| `_validate_body` | `_v1_rules._validate_body` | Direct bounded port of public checks: strict registry integers, roles/aliases/credential types, three unique active custody keys, 12-field target scope, sponsor/contract and policy. Context replaces organization/settings; all transitions use historical 24h limit. |
| `trust_auth.b64decode/public_key_fingerprint` | `_crypto.public_key_fingerprint` | Canonical credential COSE encoding; maintained decoding and SPKI DER SHA256; ES256/EdDSA/RS256 whitelist, no new crypto parser. |
| `_affected_people` | `_v1_rules._affected_people` | Person/custody differences and affected target sponsors; affected cosigner negative preserved. |
| `_preserve_people` | `_v1_rules._preserve_people` | No removal of people/aliases/bindings or update reactivation; independent signed negatives. |
| `_verify_transition` | `_api._transition` | Bootstrap1, exact prior hash/revision/time, old eligible custody minus affected people, fresh commissioned generation without authenticators. No UUID ordering or self-authorizing new keys. |
| `_history`, `_remember_owners` | `_api._history`, `_v1_rules._remember_owners` | Full supplied order only, no SQL sorting. Five lifetime maps, not reset by recommission. Exact independent expected head; all five validly signed historical reassignment negatives fail. No ORM row audit/uniqueness equivalence claimed. |
| `_checkpoint` | `_api._current` | Raw checkpoint bytes rather than path; exact three top-level members, expected tenant/install/generation/revision/hash, witness signature, periods/active and exclusive freshness. V1 revision `4.0==4` / `true==1` preserved explicitly. |
| `recognized_registry` | `verify_current_registry_materials` | Head freshness only, no active Organization DB check or locks. Optional shorter registry duration is new context restriction; default corpus agrees. |
| `read_document` | `_codec.parse` | UTF-8 bytes only, no file. Pre-length/depth, post-node/string/int64 bounds, duplicate aliases rejected and finite floats retained. Other encodings/oversize archives outside new profile, not migrated. |
| `publish_registry`, `consume_enrollment`, `registry_person`, action/assertion/counter logic | **Excluded** | No mutation, proof-of-possession replay, enrollment consumption, account/org membership, audit anchors or release authority. |

The public API returns only constant errors; it intentionally does not expose a
mutable P0 row, semantic rejection stage or authorization Boolean. The prior
P0 witness recorded exact stages; comparison here is verdict and byte/digest
compatibility, supported by the independent fixture-isolation review. A matching
generic error is not claimed as proof of the internal individual predicate.

R2 adds an exact 36-character precondition before the UUID parser, preserving
the already required canonical UUID set. The new method first reproduced five
premature-parser calls, then verifies that all UUID parser calls have length36.

The 30-method suite includes direct frozen-oracle comparisons and supplements
constructed with temporary in-memory test keys. Those supplements are not
independent oracle generation. No existing generator or private key is retained.
This transient rule duplication requires future differential maintenance before
any caller migration; the current monolith remains the original authority.
