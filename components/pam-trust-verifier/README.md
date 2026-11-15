# Public PAM V1 trust material verifier â€” integration candidate

This is the **R1b.1 r2 library**, prepared as a source integration candidate under
the Root decision of 15 November 2026. The candidate retains the reviewed code
and static test data; repository integration and isolated installed qualification
remain separate gates. It is not connected to Vault, an HTTP service or any
application caller. A successful result inspects public materials for
explicit caller expectations. It is never a capability, release authorization,
identity authentication, human quorum, proof of possession or production approval.

The development r2 retains r1 unchanged in the external evidence archive at freeze
`9ddc776b5189d5a915054f8cd73984669db948557006fdcee6a551963e92cd2b`.
The r2 source freeze is
`476f4ac4ba06f773daade2840eebc7646e4469810875f447e5f7447df1ebac06`.
Development logs, caches, runners and freeze trees are not part of this component.
The sole library-code delta is a precondition `type(value) is str and len(value)
==36` before the shared UUID parser. It covers contexts and all registry-body
UUID checks, without changing the admitted set of canonical UUIDs or V1 crypto.

The package is `pamolive_pam_trust_verifier` (`pamolive-pam-trust-verifier`).
It has no application, Django, SQL, network, file-path or implicit configuration
API. It consumes only exact bytes, a tuple of envelopes in supplied order, and
an independently provisioned immutable context. It does not sign or generate keys.

## Separate APIs and contexts

```python
verify_archived_registry_chain(raw_envelopes, historical_context) -> HistoricalRegistry
verify_current_registry_materials(raw_envelopes, raw_checkpoint, current_context) -> CurrentRegistry
```

`HistoricalContext` and `CurrentContext` are separate frozen dataclasses. Both
contain installation (opaque P0 string), organization, expected generation,
revision, envelope hash, and a tuple of `ExternalKey` commissioning keys.
`CurrentContext` also requires checkpoint keys, an explicit UTC timestamp string
and administratively bounded registry/checkpoint TTLs. There is no context JSON
loader: trusted caller code constructs these objects outside an untrusted request.
No administration, independent-context commissioning, rotation or distribution
workflow is delivered by this prototype; frozen objects alone do not supply it.
`ExternalKey` contains an opaque key identifier, exact 32 public Ed25519 bytes,
active flag and optional timezone-aware `not_before`, `not_after`, `revoked_at`
strings. Key tuples, IDs, lengths and periods are validated at construction and
again at the public API boundary. No mutable dictionary is retained.

History must begin with bootstrap revision 1 and continue contiguously through
the **exact independently expected head**. No sorting, suffix acceptance, window,
last-generation shortcut or UUID ordering is applied. Five owner maps survive
recommissioning. A lexically lower new generation can be legitimate.

Historical external keys are judged at signing time; an administrative
`active=False` alone does not erase the past. Current inspection verifies the
same historical transitions, then head and checkpoint freshness at `now_utc`,
and checkpoint-key active/period/revocation checks. Expiration is exclusive.
Results have different types and deeply immutable bytes/string/int/tuple fields,
input hashes, context fingerprint, committed envelope hashes, owner counts and
the complete canonical head envelope. Current results additionally bind the
checkpoint bytes and explicit inspection time. Neither API accepts a result of
the other API as input.

The context fingerprint is only a link to caller-supplied expectations, not a
proof of independent administration or anti-rollback storage. A head restored
from the same backup as the proof does not create independent freshness.
No Vault UUID is derived from the opaque installation identifier.

## Exact V1 commitments and explicit profile restrictions

V1 domains, sorted compact JSON with `ensure_ascii=False`, signed unknown body
fields, Unicode NFC/NFD, finite floats, timestamp text and both signature maps
are preserved. The envelope commitment supplies the same empty-map defaults as
P0 `registry_digest`; raw-input hashes still distinguish omitted fields/spacing.
ES256, EdDSA and RS256 COSE-to-SPKI use the maintained WebAuthn and cryptography
helpers, not a custom COSE parser or a hash of raw COSE bytes. P0 base64url
differences are retained: padded Ed25519 material is permitted, credential IDs
and COSE encodings have their stricter canonical profiles.

The V1 checkpoint compares revision using Python equality. As explicitly
arbitrated by Root, a **validly signed** `4.0` can equal registry revision 4, and
`true` can equal registry revision 1. Those historical bodies are not rewritten.
Registry revisions and context revisions remain strict positive integers.
Supplementary unit tests sign such checkpoints with a fresh in-memory synthetic
witness; they are not independent static oracle generation.

New-profile refusals, not archive migration or changes to P0:

| Limit | Maximum |
| --- | ---: |
| Exact tuple length | 1â€“256 envelopes |
| Envelope / aggregate before parsing | 2 MiB / 32 MiB |
| Checkpoint before parsing | 64 KiB |
| JSON container depth before parsing | 16 |
| Post-parse nodes, including object keys | 8192/document |
| String/key length | 65536 Unicode characters |
| Signed integers | `-2^63` to `2^63-1` |
| External keys per authority | 64 |
| External key ID / installation | 128 characters |
| Context period/time text | 128 characters |
| Current registry / checkpoint TTL | 1â€“86400 / 1â€“60 seconds |

Inputs are UTF-8 JSON bytes only: UTF-16/32 and a UTF-8 BOM are rejected, although
P0's bytes parser can recognize other encodings. Non-finite floats, duplicate
keys including escaped aliases, mutable containers, surrogate text that cannot
be encoded as UTF-8, excessive structure and out-of-range integers fail.
Finite JSON floats are kept, including unknown signed fields and the V1
checkpoint equality exception. Historical wire encodings, large integers or
documents outside these bounds are not declared corrupt or invalid for P0.

The canonical encoder validates structure first and retains a chunk only after
its UTF-8 length fits the remaining output budget. Individual strings were
already bounded before encoding. This is not a process RAM or CPU quota. Parsing
is stdlib JSON, with depth checked first and nodes checked afterward. Errors use
the constant `Invalid public PAM trust materials.` without a raw-data exception
chain. Python call stacks and a compromised in-process caller are not isolated.

Current `registry_max_seconds` is an explicit new context constraint on the head
duration. With its default 86400 seconds the static P0 corpus agrees. A shorter
value can intentionally reject material accepted by P0 `recognized_registry`,
which checks freshness following historical `_history` without calling
`_validate_body(historical=False)` again. This difference is not hidden as V1
equivalence. No past transition is reinterpreted under that shorter limit.

## Static tests and installed qualification

`tests/` and `fixtures/` must remain siblings beneath this component root.
The test module computes ROOT as the parent of tests. The fixture set retains
all 17 original public files, 320 signed adversarial files and the exact prior
selected-P0 function report as a fixed differential test input. The latter is
required by the tests; it is not a new P0 run or a claim about complete P0.
See `FIXTURES-NOTICE.md` for provenance, licence scope and synthetic limitations.
No generator, private key or regenerated oracle is distributed.

The source test runner is deliberately excluded. The standalone controller in
`qualification/pam_trust_verifier` builds and installs the wheel in fresh Linux
venvs, then copies tests/ and fixtures/ together outside src. It installs IO
counters before importing the installed package, checks origins and hashes, and
runs the **30 methods**, requiring zero skips/errors/failures and 20 current
case comparisons. This does not qualify the two older P2 packages or vice versa.
The exact reviewed command and control hashes are in that controller's plan.
Only a new successful installed run can supply installed evidence.

## Dependency and integration limits

The direct requirements in pyproject are not a closed runtime lock. The Linux
qualification selects nine runtime wheels plus four build tools from the existing
public Linux material manifest. The nine runtime wheels include WebAuthn's
pyasn1, pyasn1-modules, pyOpenSSL and typing-extensions dependencies, plus
cryptography's cffi and pycparser. Exact acquired wheel metadata, hash/RECORD
checks and pip check in both isolated venvs remain mandatory. Linux cp312 hashes
do not qualify Windows or CPython 3.13; requires-python is packaging metadata,
not a test matrix claim. No dependency acquisition occurs when importing this
library, and no dependency installation has occurred during candidate preparation.

No P0 caller/model/migration, Vault API, transcript contract, app dependency,
Dockerfile or runtime image is changed by adding this component. Publication,
enrollment, WebAuthn possession/MFA/counters, membership, ledger, KMS, transport,
release, independent administration and anti-rollback storage remain outside its
scope. The five maps are private mutable scratch during one inspection.

Source r1/r2 results and independent reviews remain external historical evidence.
The integrated PAYLOAD-MANIFEST binds this selected component tree, including
this README delta; it does not pretend that excluded development evidence is
present. No delivery, service or production gate is lifted by the candidate.
See `P0-CORRESPONDENCE.md`, `ADR-PROPOSED.md` and `NOTICE.txt`.
