# R12 — pre-parse TAR bounds and independent Root runtime validation

R12 supersedes the two SOURCE reservations found in the independent R11 review.
R11 remains frozen as historical evidence. These are verification/hardening
corrections; no unprivileged Root privilege escalation was demonstrated.

## Physical TAR preflight, before extension processing

The old logical-member loop ran after `tarfile` had processed extension headers.
A synthetic 512-byte PAX header could ask the underlying stream for 536,871,424
bytes before the loop's size check. Empty extension chains were not charged to
that loop's member count. The same inherited behavior affected the old
`payload_target` reader and the staging pass.

All three readers now share the pinned `chrome_bundle.checked_tar` primitive.
Before constructing `TarFile`, it walks physical 512-byte headers with
`TarInfo.frombuf` only, without `_proc_member` or another extension parser.
It validates the checksum, canonical names/collisions, types, numeric ranges,
member and aggregate size, non-file zero size, zero padding, two zero terminator
blocks and a zero-only remaining tail. Physical archive bytes and header work
are independently capped at one GiB and 20,000 headers. Ordinary USTAR name
prefixes remain supported.

PAX local/global, GNU longname/longlink and GNU sparse extensions are explicitly
unsupported and refused before reading their bodies or invoking the stdlib
extension processor. Unknown physical types also refuse. A real supplier TAR
requiring such an extension needs a separately reviewed bounded policy; there
is no dynamic permission, fallback or constant-only workaround. Its first
authenticated Linux reception may therefore stop with a closed extension-kind
diagnostic instead of producing inventory. It must not be called a successful
complete inventory in that state.

The stream adapter rejects any read request above 64 KiB, negative/unbounded or
non-integer request *before* forwarding it. It does not clamp a rejected request.
Every read/seek is checked against the deadline before and after the underlying
IO, and seeks stay inside the captured finite physical size. It seals the actual
physical metadata blocks, so replacing a validated header with PAX/GNU metadata
before parsing is also rejected before those bytes reach the parser. Metadata
storage is bounded by the header count (about ten MiB of header bytes), rather
than an extension's declared size.

Staging prepares this preflight before creating the prefix. Ordinary resource
bytes remain stream-hashed; the entire ELF is not buffered. Kernel IO that blocks
inside a call still requires the existing outer H172 owner. No hostile-Root or
filesystem transaction atomicity is claimed.

The legacy `payload_target` implementation intentionally changes: its unguarded
`tarfile.open` and initial raw seek are replaced by a pinned invocation of this
same primitive. The helper's digest is embedded in the committed bootstrap and
the complete source pin manifest. The main call supplies its existing owner
deadline minus reserve. Historical helper AST identity is no longer claimed for
`payload_target`; all 153 historical test methods remain unchanged.

## Independent Root runtime receipt check on v3

R11's v3 frontend omitted the historical `check_root_interpreter` call when it
removed `root_interpreter` from its expected resource bindings. A protected
synthetic receipt containing `root_interpreter:true` could pass that resource
check. The real Root producer still checked its own runtime and the protected
prefix was not shown writable by an ordinary user: the finding was an assurance
regression, not proof of a privilege escalation.

The frontend now reuses the unchanged historical checker with the independently
observed system-interpreter role, source revision, context digest, bootstrap
digest, pins, metadata, real/effective UID, flags and running-image identity.
It observes the role before the bounded sudo command, after normal completion,
and after receipt/resource verification. Unknown or changed identity refuses.

The nonroot resource verifier requires a trusted runtime checker whenever the
caller does not already provide its verified Root runtime binding. The three
browser reader locations construct that checker from the source-pinned
bootstrap, validate the source/context before compiling it and use the same
historical contract. The Root producer's pre/post checks are retained. Producer
booleans, malformed/missing flags, replayed context/source/revision/pins, wrong
UID or running identity are not substitutes for this validation.

The callback is source code chosen by these finite consumers, never a callback
or name supplied by JSON, an inventory or an HTTP request. Root authority is not
inferred from a producer success boolean. The existing cooperative
runner/kernel/Root/stdlib-loader TCB and protected-tree assumptions remain.

## Validation and remaining gates

R12 runs 196 Chrome source tests (153 historical, 29 R11 and 14 new test methods)
plus 14 UI source contracts, without skips or attempted external operations.
The new methods include many synthetic RawIO and runtime subcases: oversized
PAX/GNU/global/sparse at all three readers, hidden chains, header-count boundary,
truncation/checksum/padding/tail, USTAR prefixes, post-preflight header mutation,
read/seek/deadline boundaries, and positive/negative composed frontend checks
against the real historical Root runtime validator. Only synthetic memory TARs
are decoded on the preparation PC; no real DEB/external TAR or native program
was executed.

The source-pinned profile remains `commissioned:false`; all links/special files
still refuse staging, and a SUID helper still requires the exact independently
admitted role, path, digest and mode. No native inventory, staging, relocation,
Ubuntu AppArmor/userns/SUID sandbox, browser or UI result is claimed. Owned-prefix
cleanup remains unimplemented; all release/operational flags remain false.

After independent SOURCE review, first receive authenticated Linux inventory
or its expected bounded refusal. Independently review any real extension, link,
resource and privilege role before committing authority. Then qualify exact
staging, runtime receipts, active sandbox, actual UI/TLS/NSS/MFA/WebAuthn/tenant
behavior and precise owned cleanup. Do not disable a guard or use `--no-sandbox`
to make that sequence pass.
