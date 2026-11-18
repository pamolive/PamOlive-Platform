# ADR-036 — Authenticated browser bundle for isolated UI tests

Status: accepted for source implementation; native profile uncommissioned.

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
