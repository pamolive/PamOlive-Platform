# R13 source: exact admission for private stage and cleanup only

Root explicitly admitted the source policy for STAGE_CLEANUP_ONLY on
18 November 2026, decision SHA256
63a6b68c0c8b6ec2df10c26a844fb1e59d94515a9b45c31a44a0c75db0293fd2.
The separate stage-only profile is admitted:true for the exact package, full
tree and unique chrome-sandbox SUID role documented in ADR-036. The operational
v1 profile remains commissioned:false. This source preparation executes no
payload and produces no operational v3 receipt.

No native execution is permitted before independent review of this exact
admission delta and Root's final source freeze. A later first synthetic Linux
measurement must repeat all existing authentication, freshness, purpose/scope,
Root interpreter, package, context and cache checks. Missing or expired evidence
refuses; no clock or permission guard is relaxed.

The complete public fixture chrome-stage-inventory.DATA.json is autonomous:
42,741 bytes, SHA256 c132e7c97c82f326019632044c35e916336f482a9dae6d8765b7997ab3eea738.
Its 261 records remain admitted:false and operational_GO:false. The actual
pinned source profile is a distinct explicit decision; DATA cannot admit it.
Tests apply the real profile to every record and keep coherent false-policy
negatives. No key fixture or private output path is added. Source/test/vendor
closure is 16/11/4; bootstrap TEST_PATHS includes this JSON.

The existing cycle is unchanged: the derived exclusive prefix stays Root-owned
0700, identities enter an in-memory ledger only after exclusive creation, and
R12 FD/preflight/hash helpers verify the full tree. A distinct private receipt
cannot authorize v3. Work stops before the original 20-second cleanup reserve.
Cleanup revalidates the profile/inventory, objects and FD/name anchors; unknown
entries, drift, links/hardlinks, failures and late completion remain UNKNOWN.
Only ledger objects are removed; no old prefix is adopted or repaired.

The frontend still requires normal bounded Root completion, the historical
interpreter verifier with independent observations and its own FD-anchored
observation of prefix absence. Partial removal or uncertain closure never
claims complete cleanup. A hard kill can bypass finally and retain a private
prefix. Root/kernel remain trusted; checks are not atomic unlink conditions
against hostile Root. Native timing/fsync/closure behavior remains unmeasured.

The workflow retains the exact historical UI step and imperative HOLD exit42
before it. A positive private cycle may publish bounded DATA, but the existing
p1g-headless job remains failed and UI stays skipped. Stage-only admission does
not remove HOLD. No payload, helper, service, cron or AppArmor file is executed
or activated. No host-global permission repair, sysctl or fallback is allowed.

Pure tests total 223 Chrome methods (153 historical + 43 R12 unchanged, 27 Phase A),
plus 14 UI source contracts and six HOLD challenges. They use memory TARs/OS
actors and public JSON metadata, with no real package/archive/browser execution.
The published workflow regression rejects removal of UI or HOLD, conditional or
ignored HOLD, and a successful HOLD exit. It runs in the normal pure CI suite;
it does not depend on a private review script.
Phase B separately requires an active sandbox and AppArmor/relocation evidence,
refusing absent/unknown sandbox before UI. No UI/image/production GO or CVE
closure is granted by this source admission.
