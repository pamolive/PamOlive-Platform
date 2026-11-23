# ADR-036 — Authenticated browser bundle for isolated UI tests

Status: accepted for source implementation; operational profile uncommissioned.
Root admitted the exact private stage/cleanup profile only; execution awaits
independent review of that delta and Root's final source freeze.

## Problem and evidence

The public runner observation in run 44132636559 found the canonical Chrome
path, its /opt ancestors and its executable root-owned but mode 0777. The
existing tool guard correctly refuses that configuration. This measurement
does not establish the exact failing instruction in the historical dfb1296 run.
Repairing those existing directories or relaxing the guard would undermine
the qualification boundary.

The UI objective remains a real browser journey with TLS, MFA, WebAuthn,
tenant isolation and subsequent native transport validation. Pure source tests
and package inventory do not replace that objective.

## Decision

Use a separate authenticated TEST bundle under a new, exclusive Root-owned
`/usr/lib/pamolive-p1g-chrome-<run>-<attempt>` prefix. Obtain the complete Chrome
resource subtree from the already authenticated, exactly hashed supplier DEB.
Never copy the existing writable installation or qualify only its executable.
Construct the destination from the admitted job identity; a receipt cannot
select an arbitrary path.

The v3 test receipt is distinct from the historical installed/2 contract. It
binds the package, resource inventory, source/context/pins and current run and
attempt. It is protected by the Root-owned tree and checked independently by
finite consumers. It is not a new cryptographic attestation, does not prove
how the supplier built the package, and grants no image or production approval.
Legacy installed/2 verification and its strict canonical-path checks remain.

All resources are bounded and stream-hashed. Filesystem operations use owned
directory descriptors, exclusive creation and no-follow checks. The initial
staging policy rejects links and special files. Any privileged sandbox helper
requires its exact independently admitted path, digest and mode. A boolean
asserted by inventory or receipt is insufficient. No global permission repair,
AppArmor change, sysctl change or no-sandbox fallback is permitted.

The committed profile starts with commissioned:false. First obtain an
authenticated Linux inventory, or its bounded refusal, then review the real
roles and resources before committing any admission. An uncommissioned profile
must refuse before creating the staging prefix or launching the UI.

## Alternatives

Relocating just the executable omits resources and runtime dependencies and
cannot establish a browser identity. It is rejected.

A private mount namespace could preserve the canonical path, but needs one
owner for bootstrap and the whole UI lifetime. An empty /opt also hides the
observed setup-python toolcache; mount isolation does not isolate the dpkg
database or other filesystem writes. This adds lifecycle and privileged setup
complexity and is not the first implementation.

A separately provisioned VM or test image remains an option if the supplier
bundle cannot be relocated or its real sandbox cannot be qualified. It still
needs an admitted runtime, active sandbox and complete journey evidence.

## Independent review corrections

R11 review found two assurance gaps. R12 adds a physical 512-byte TAR preflight
before the stdlib extension parser and a stream wrapper that rejects reads
over 64 KiB before forwarding them. PAX/global/GNU longname/sparse extensions
are refused explicitly; ordinary USTAR prefixes remain supported. Metadata is
sealed against post-preflight mutation. The legacy payload reader uses the
same protection. Unsupported genuine input requires a new reviewed policy.

R12 also restores independent use of the historical Root interpreter verifier
in the v3 frontend and the three browser consumers. Source, context, pins,
revision, identity, UID and interpreter flags remain mandatory. A protected
receipt containing root_interpreter:true is not sufficient.

## Validation, limits and consequences

The prepared R12 source passes 196 Chrome tests and 14 UI contracts. The
independent review adds ten adversarial checks; none performs native or
external operations. All 153 historical Chrome tests remain unchanged. These
counts qualify source behavior under doubles, not the actual browser.

Real DEB extensions and links, relocation, Ubuntu AppArmor/user namespaces,
the exact SUID role and active browser sandbox remain to be measured. The
first Linux run is for inventory and expected refusal, not operational use.
Keep unknown, cleanup and approval flags conservative; owned-prefix cleanup
has not yet been implemented. No NAS or production environment is involved.

Before UI admission, verify staging and the complete resource tree, positive
and negative runtime receipts, sandbox engagement and the actual TLS/NSS/MFA/
WebAuthn/tenant journey. Historical V2 receipts remain historical evidence;
they are never upgraded silently into the V3 space.

## R13 addendum — private staging and cleanup, Phase A

Initial R13 status: source proposal for independent review. Both profiles were
disabled in that freeze; no native staging, sandbox or UI result was claimed.
The earlier paragraph about missing cleanup describes R12, not this proposal.

Two authenticated inventory receptions describe the same 261-entry payload
tree. Their metadata supports proposing an exact stage-only profile; it does
not commission that profile. The proposed package is SHA256
`4d740636b5c96f687798602c5aad6a5a270f44dd02e48db0638ae77aa4867b1b`, tree
`bde1999adb166df18728a4de24ceef9799e5d23442c43ce8d1e37eb1d97a3e6c`.
The only proposed privileged role is `chrome-sandbox`, mode 04755, SHA256
`8f93aa6b8dbf07073b2baedf2ae7b169515922bc097043de9dca27f6c7905704`.
This is an explicit source proposal about a supplier helper, not an authority
learned from an observed SUID bit. Operational `chrome-bundle-profile.json`
and all three v3 browser consumers remain unchanged.

The selected first increment is `--stage-cleanup-only`. It repeats the existing
authentication, freshness, purpose/scope, negative fixtures, Root interpreter,
package and cache checks. It inventories the payload before refusing the
default `admitted:false` stage-only profile, before dependencies or staging.
Inventory-only remains separately available. Explicit source admission, after
independent review, would permit only this private finite cycle:

1. Create the derived run/attempt prefix exclusively, mode 0700. Keep that
   mode throughout its lifetime. No pre-existing prefix is adopted or repaired.
2. Use the R12 physical TAR preflight and exact complete-tree verifier. Record
   the identities of newly created objects in a private in-memory ledger in
   the same existing Root bootstrap. No received ledger is adopted.
3. Write a distinct `pamolive.chrome-private-stage-receipt/1`, never v3. Rehash
   the complete staged tree while private. No payload is executed.
4. In the same owner and original absolute horizon, use a 20-second cleanup
   reserve. Revalidate the profile, inventory, ledger, names, FD identities,
   owners, modes, links and complete-file hashes before removal. A partial
   file is removable only with its exclusive creation identity, regular type,
   nlink 1 and bounded partial metadata; it cannot count as verified staging.
5. Revoke the exact owned helper to 0600 through its checked FD, then unlink
   only ledger leaves, remove ledger directories deepest first, and remove
   only the derived owned prefix. Parents `/`, `/usr` and `/usr/lib` are never
   chmodded or deleted. Unexpected entries and identity drift cause UNKNOWN.
6. Close every acquired FD. Only normal Root command completion, unchanged
   independent Root interpreter checks, a closed bound Phase A result and an
   independent non-root observation of prefix absence permit Phase A success.

The result is `pamolive.chrome-private-stage-cleanup/1`, purpose
`STAGE_CLEANUP_ONLY`, bound to source/context/pins, package/tree/profile,
run/attempt, root identity and staged-receipt digest. Exact removal counts and
absence are DATA, not new attestation. UI eligibility, v3 receipt emission,
browser execution, universal descendant release and operational GO stay false.
Unchanged v3 consumers reject the private mode and distinct receipt/profile;
the workflow also retains an imperative failing HOLD before the unchanged
historical UI step. This boundary does not rely solely on a workflow condition.

Creation, stage, revalidation, removal, closure, late completion or postchecks
that fail remain UNKNOWN. The reserve is never reset. A failed creation before
identity capture cannot safely enter the ledger and may leave a private
prefix. A hard kill can bypass Python cleanup. Neither a private prefix nor VM
disposal proves cleanup; a collision is refused on the next invocation, with
no retry, adoption or broad removal. Descriptor closure is attempted once;
uncertain close results do not claim universal release. Root and the kernel
remain trusted: pre-mutation identity checks do not provide an atomic unlink
condition against a hostile Root process.

Keeping the v3 receipt and only disabling UI in YAML was rejected: another
consumer could interpret it as usable authority. Publishing mode 0755 and then
cleaning was rejected for Phase A. A detached cleanup service, persisted
adoptable ledger, global recursive deletion, hooks, cron, AppArmor or sysctl
changes add authority and are not needed for this increment. Small hooks in
the existing stage/verify helpers reuse their bounded copy and tree checks.

Source tests use memory TARs and OS actors. They cover successful cleanup,
partial writes, fsync/close failures, collisions, wrong identities, extra
entries, links/hardlinks, deadlines, wrong run/context and strict frontend
postconditions. The 153 historical Chrome tests and 43 R12 bundle tests remain
byte-identical. No native filesystem cleanup is tested on Windows.

Phase B remains a separate source decision and measurement: relocation, real
Root staging/removal, sandbox activation and AppArmor compatibility are still
unproved. Sandbox absence or ambiguity must refuse; no no-sandbox, global
permission repair or permissive fallback is authorized. Phase A cannot qualify
the UI journey, SSH/RDP, an image, or CVE closure.


## R13 r2 correction — retain the full headless acceptance gate

Independent review confirmed P2 R13-CI-UI-GATE: removing the historical UI step
allowed the existing p1g-headless job to turn green after a later admitted
positive Phase A, without the full UI journey. The R13/r2 false profiles
already refused earlier; no operational v3 bypass was found.

Restore the historical UI step byte-exactly from base 6d4c7db. Insert an
unconditional normal-success-path HOLD step, `run: exit 42`, immediately after
the Phase A bootstrap and before that UI step. It has no condition or
continue-on-error. Positive cycle DATA may be retained by the existing always
artifact step, but the job remains failed and the UI step is skipped. With
default false admission, the bootstrap still refuses before this HOLD.

Phase B requires a separate reviewed source change and measurements before the
HOLD can be removed or altered. Changing the stage-only profile must not remove
the HOLD or qualify this full headless gate. No helper, runtime body, profile,
pin or source/test/vendor aggregate changes are part of this correction.


## Limited stage-only source admission — 18 November 2026

Root explicitly admits the exact STAGE_CLEANUP_ONLY policy after independent
R13 review and correction of R13-CI-UI-GATE. The decision is SHA256
`63a6b68c0c8b6ec2df10c26a844fb1e59d94515a9b45c31a44a0c75db0293fd2`.
It permits preparing this source and a later first reviewed synthetic Linux
measurement; it does not permit execution before independent delta review and
Root's final source freeze. No native staging or cleanup has occurred here.

The separate source profile now has admitted:true for package SHA256
`4d740636b5c96f687798602c5aad6a5a270f44dd02e48db0638ae77aa4867b1b`, tree
`bde1999adb166df18728a4de24ceef9799e5d23442c43ce8d1e37eb1d97a3e6c`, and
only chrome-sandbox, 04755, Root:Root, 15,248 bytes, SHA256
`8f93aa6b8dbf07073b2baedf2ae7b169515922bc097043de9dca27f6c7905704`.
This source decision is the admission authority. Neither receipt booleans nor
the two historical inventory observations commission the policy automatically.

The autonomous public test fixture chrome-stage-inventory.DATA.json retains
the exact 42,741 inventory bytes, SHA256
`c132e7c97c82f326019632044c35e916336f482a9dae6d8765b7997ab3eea738`.
It contains 261 records, 253 regular files and eight directories, all Root:Root;
its admitted and operational_GO fields remain false. A pure positive applies
the actual pinned admitted profile to these complete records. Mutated records,
DATA admission claims and explicitly false/unpinned policies are refused.
No test depends on a private output path or a new key fixture.

The finite source/test/vendor closure is now 16/11/4: TEST_PATHS and test_files
include that JSON fixture. Bootstrap function bodies, the lifecycle bodies,
the bundle implementation and three operational consumers are unchanged.
Only the stage profile's boolean, the lifecycle PROFILE_SHA constant, the
bootstrap TEST_PATHS constant, related tests and the closed source pins evolve.
The 153 historical and 43 R12 test methods remain unchanged; 27 Phase A methods
make 223 Chrome tests, plus 14 UI contracts and six HOLD challenges. The added
published gate regression rejects removed UI/HOLD, conditional or ignored HOLD
and a zero exit, so this CI property persists beyond the private review scripts.

Operational chrome-bundle-profile.json remains commissioned:false. The exact
imperative HOLD exit42 and historical UI step are preserved. Even a positive
private cycle produces only DATA, then a failed headless job with the UI step
skipped. The false-policy test is now an explicit coherent synthetic negative,
not a claim about the admitted source default.

Any later measurement must repeat the existing package/signature/clocks/scope,
Root interpreter and source/context/cache checks under a fresh disposable
GitHub Linux job. The prefix stays 0700, payloads and the helper are never
executed, embedded cron/services/AppArmor files stay inert, and cleanup uses
the unchanged original horizon/reserve. Drift, missing privilege, expired
signature, incomplete cleanup, kill/FD uncertainty or late completion refuse
without retry, broad deletion or guard relaxation.

Sandbox activation, relocation for actual use, AppArmor and the complete UI
journey still require separately reviewed Phase B source and measurements.
No no-sandbox/sysctl/global fallback, image approval, production approval or
CVE closure follows from this limited admission.

## Contrôle du bac à sable avant le parcours P1-G

Le test vérifie l'exécutable en cours d'exécution et la version du
bundle. Le même navigateur ouvre deux pages de contrôle jetables, dont
le diagnostic Chromium et un document local inerte, avant le premier
accès au portail synthétique. Les requêtes réseau de ces pages sont
bloquées. Le diagnostic doit confirmer les namespaces PID et réseau,
seccomp et au moins une des deux voies d'isolation Chromium.
[Diagnostic Chromium 157](https://github.com/chromium/chromium/blob/157.0.8103.78/chrome/browser/ui/webui/sandbox/sandbox_internals_ui.cc)

Les identifiants de processus rapportés par Chromium servent à lire
les faits du noyau. Les renderers observés doivent disposer d'un
namespace PID et de filtres seccomp supplémentaires, être sans
capacité effective et avoir `NoNewPrivs`. Le résultat refuse un
processus disparu ou une lecture incomplète. Il conserve les modes
AppArmor du navigateur et des renderers. Le mode `unconfined` constitue
une observation explicite de la politique du runner.
[Métadonnées Linux](https://docs.kernel.org/filesystems/proc.html) ·
[AppArmor pour Chromium](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md)

Le worker et le contrôleur exigent ce reçu avant de déclarer le
parcours terminé. L'admission du bundle opérationnel et le passage de
la phase A à la phase B requièrent encore leurs mesures. Le manifeste
signé du 15 novembre a dépassé la fenêtre de sept jours. Une nouvelle
campagne exige des métadonnées fournisseur fraîches et une identité
de paquet confirmée.
[Reçu de staging et nettoyage](https://github.com/pamolive/PamOlive-Platform/actions/runs/44268892672/artifacts/14411418231)
