# Independent usage anchor W1

## HTTP client interoperability

The client writes explicit HTTP headers and a byte-length Content-Length after
checking the TLS peer pin. It suppresses stdlib's automatic Accept-Encoding;
the server's closed header profile is unchanged. The durable regression runs
the actual client framing through h11 and the W HTTP parser with fake sockets,
TLS and service dispatch: before correction 62 tests had one expected failure;
after correction all 62 pass, with no skipped tests or external I/O attempts.
The original 59 methods remain. This does not receive a real TLS handshake,
PostgreSQL transaction, service installation or independent host.

Linux packaging selects psycopg-c 3.2.10; non-Linux development keeps
psycopg-binary 3.2.10, matching the existing platform lock. Metadata checks do
not establish a successful W wheel build or installation.

## R2 targeted corrections after independent review

R1's source and receipts are retained unchanged in Root's separate archive.
R2 requires `intent_requester_person_id`, a canonical UUID in the **W-only**
commissioned slot. It comes from the independent intention, not the draft or a
P0 role/alias. `Authority.operation` compares it before opening a transaction.
Shared ADR024 EXPECTED_FIELDS, P0 and V contracts are unchanged; the existing
whole-slot baseline commitment covers the additional pin. An R1 slot missing
the pin fails closed and is not auto-upgraded. This is the narrow one-intention
profile, not a general delegation or ContextService.

Every mutable Service path and live pending bind retry registers a local
authority/RO-context plus SQL clock callback. The real ledger executes it after
all business writes/audit and before transaction exit; business mutations without
a callback cannot commit. The callback acquires no new business lock and performs
no network call. Exact terminal observations are deliberately excluded. The final
application check does not promise the physical durability instant of COMMIT;
unknown ACK remains503/uncertain, never an assumed new authorization.

Terminal CHECK branches explicitly require nonNULL final bundle, digest and
response, retaining digest/size bounds. Negative SQL probes raise their rollback
sentinels **inside** their transactions even if forbidden SQL unexpectedly
succeeds. Setup/teardown errors and cancellation propagate. The counter probe
prepares exact positive1 within that same rollback-only transaction (a fresh
active counter0/1 is required), then tests1→0 with state_version+1 and expects
P0001 only;23514 is not accepted as proof of the monotonic trigger. The rearm
probe first observes a complete real terminal. `terminal_shape_probe` requires a
complete real pending row and tests each NULL digest/response combination with
guaranteed rollback. These native probes are prepared code, not SQL receipts.

`tests/test_r2.py` preserves the public AUTH01 counterexample with its four real
synthetic signatures, proves those signatures remain valid for their substituted
transcript, then refuses bind403 before SQL against the commissioned intention.
Clock/cursor and request-order spies test the final callback and rollback
control flow; they do not emulate PostgreSQL permissions or establish atomicity.
The original39 tests remain in the runner alongside these regressions.

The future laboratory must preflight **both** new subjects and bounded connector
factories before commissioning. Separate W/V commits are not distributed atomic;
any partial seed remains unadmitted and must not be automatically repaired/opened.
R2 does not change that lifecycle or execute a laboratory.

ADR-026 source implementation for a separate synthetic witness. No secret,
envelope, KMS/provider, release endpoint, Django caller migration or automatic
commissioning exists in this component. `consumed_no_release` and
`refused_no_release` are terminal; a retry observes their stored response.

The source implements the entire W path: independently pinned RO public V1
materials and context; fresh WebAuthn activation; PostgreSQL binding and baseline;
real V2 proof verification; atomic counters/CAS/usages/terminal/audit; connection-
local DER mTLS adaptation; and a separate V-side SQL mirror client. Real database,
handshake, crash and rollback qualification has **not** been executed here.

## Source ownership and reuse

Only this new component is changed. Public signatures/canonical encodings and
contracts come from the existing independent packages. The per-connection H11
adapter/TLS settings are imported directly from `pamolive_vault_runtime.transport`;
its eight modules are not modified. The W ASGI application accepts four explicit
routes and rejects an unbound ASGI call. No forwarded identity header is accepted.

`Authority` reconstructs and verifies actual local material bytes; it derives
policy and target from the verified head, not a client DTO or digest. The slot
has a commissioned policy binding, credential reference/version and intention,
exact broker and V identities, independent keys, incarnation and lease epoch.
Nonempty contracts and unknown current policy/target members are outside W1 and
fail closed. This profile does not replace Governance for existing targets.

`sql/schema.sql` is an **explicit migration**, to be run by a separate migration
identity on a new isolated W database. Provision NOLOGIN `usage_anchor_owner` and
restricted `usage_anchor_runtime` separately. Revoke PUBLIC CREATE on database
and schema; the runtime must have no memberships, SUPERUSER, CREATEDB,
CREATEROLE, REPLICATION, BYPASSRLS or server-files/program privileges. Runtime
startup and every transaction check its role; fsync must be on and transactions
use synchronous_commit=on. No schema creation, context seeding, re-opening or
incarnation repair occurs in the service.

All mutations lock context, principal quota, lease, operation/challenge,
activations sorted by canonical ASCII credential ID, then audit head. New bind
rows have an internal `binding` state inserted at operation rank before locking
activations, and are completed in that same transaction. No successful public
path commits that internal state. Transition triggers inspect OLD/NEW only,
acquire no further rows, disallow terminal rearm or decreasing counters, and do
not grant business authority. Context FKs refer only to the already locked
context; audit and proof tables have no FK which would acquire an earlier-rank
operation/activation lock. N0 serializes one context/tenant; no multitenant
transaction is implemented. There is no SECURITY DEFINER function.

`Administration` provides only offline close/fence and activation revocation
using the same complete lock order. It requires a separate owner-capable login,
is absent from HTTP routing and has no open/restore/reset-counter API. A new
incarnation/RO context is an explicit commissioning action outside the runtime.

`sql/mirror.sql` is an explicit new V laboratory extension. `VaultMirror` reads
an already committed ADR024 reservation, sends its exact draft/nonce/dates to W,
checks and durably mirrors W0 before returning the confirmation transcript, then
mirrors a terminal response only after W's commit. Unknown consumption results
become `uncertain`; retry uses the original exact bundle and never emits a
secret. This client is not wired into any existing PAM caller.

## Pure source checks

```text
python -I -B components/usage-anchor/tests/run_pure.py
python -I -B -m ruff check --no-cache components/usage-anchor
```

The runner requires the pinned dependencies already available. It imports only
the new component and the three explicit source packages, prohibits socket,
subprocess, SQLite and psycopg connections, and receives real **synthetic**
Ed25519/WebAuthn signatures. It does not qualify filesystem guards, SQL, TLS,
hardware, browser display or independent humans. No in-memory ledger is used as
a substitute for PostgreSQL reception.

`tests/golden/codec.json` is byte-identical to the independent addendum94257
golden (SHA256 `bfd2db31fbaacf2500645439efc9a35738366c76fd14dfcbd407386aba30fcad`).
Its signature placeholders are used only for framing/codec tests. Separate
fresh fixture keys are generated in test RAM. The fixture constructs bootstrap
and contiguous cosigned update, validates real registration and P0-format
possession evidence with maintained WebAuthn, and makes fresh W activation and
V2 proofs. It does not execute Django's enrollment/publication SQL lifecycle.
That historical seam remains to be received separately; no old proof becomes
a V2 authorization automatically.

## Prepared real qualification (not executed)

Root supplies two new isolated databases, restricted runtime logins, owner
connections, RO slot/material files, CA-issued synthetic TLS identities and
owned process lifecycle. Do not point these drivers at an existing laboratory
or shared database. `integration/scenario.py` exposes:

1. `seed_new_databases`: requires empty schemas, explicitly commissions W
   context, quotas, a lease of at most30s, immutable activation metadata, audit
   head and a separate V context. It does not create roles or schemas.
2. `activate_over_mtls`: uses the separate activation principal and fresh W
   challenges, not P0 possession replay.
3. `vertical_round_trip`: uses the actual ADR024 V PostgreSQL ledger, actual W
   HTTP client, new SQL mirrors and fresh real proofs. It exercises positive
   and one-reviewer negative terminals, exact retries and independent SQL
   inspection of stored bundle/usages/mirror.

Use `Fixture(now=int(time.time()))`, not the deterministic pure-test timestamp,
and finish inside the original cp40s/lease30s windows. No script silently
refreshes these materials. Add the tests/ directory explicitly to the isolated
driver path so the synthetic fixture import is intentional. The fixture provides
a CA and client/server certificates with EKU, key usage, SAN, SKI and AKI;
server SAN covers the two already permitted laboratory bind IPs. Serialize keys
only in the owned private ephemeral harness if needed, never into this checkout.
`assembly.application` performs RO/startup checks but starts no listener;
`transport.configuration` supplies the existing pinned TLS/H11 runtime settings.

`integration/permissions.py` supplies SQL-direct runtime/forbidden-principal and
transition probes, including no metadata/DDL/delete and terminal/counter guards.
Concurrency, fencing/admin lock races, rollback V within30s, crash/commit loss,
expiry waited with real clocks, PK/fsync failure and hostile OS tests remain
additional required qualification cases. Prepared code is not their receipt.

W's SQL, administrators, backup and host must remain independent of V. Two roles
or containers on one host do not establish that property. W restore stays closed
until independently verified continuity or new activation. Generic KMS unwrap
available to a compromised V would bypass W; a future independent per-operation
release guard remains required. These sources grant no operational approval,
and do not resolve the35High or build provenance gates.
