# OpenSSL W1 — SOURCE preparation, uncommissioned

This directory is a reviewable source proposal for the system OpenSSL package
`3.5.7-1~deb13u3`, with proposed local version
`3.5.7-1~deb13u3+pamolive1`. It is not an authenticated Debian source kit, a
four-patch buildable result, a built package or a qualified image. No CVE is
closed. `source-status.json` is documentation, never signature or approval
authority. The three recipe trust/plan/dependency pins remain **NULL**.

## Public materials and remaining source conflict

The 47 received UTF-8 materials retain their public source URLs and reception
hashes in `materials-reception.json` and `supplementary-text-reception.json`.
They include the four official patch texts and their parent/postimage texts,
an upstream 3.5.7 reference, public advisory text, and ASCII Debian DSC/InRelease.
The supplier license is retained at
`materials/baseline/upstream-3.5.7/LICENSE.txt`; supplier source headers and public
metadata remain intact. Reception/hash matching is not cryptographic
authentication. No GPG verification, Debian archive, ELF, C regression, TLS
consumer, compiler, Linux build or source extraction was executed here.

`proposal/` contains three reference-only rebased patches and their exact text
postimages. `static-source-replay.json` records their scope and hashes. These
upstream tag replays do not prove applicability to Debian's applied u3 source.
The fourth fix, QUIC, remains `REFUSED_SOURCE_CONTEXT_CONFLICT`: two SFRAME_SET
paths are missing from the SFRAME_LIST reference. No blind transplant or claim
that the old dependency lock excludes that CVE is permitted.

The separate cryptography wheel's OpenSSL 4.0.3 is outside W1 and remains
uncorrected. The received advisory's fixing releases scheduled for 1 December
2026 were future releases at source preparation on 18 November; they were not
silently substituted for Debian u3.

## Implemented SOURCE controls

- One absolute 180-second acquisition horizon, including a five-second cleanup
  reserve, is enforced by the existing H172 owned-process boundary. The worker
  shares the work deadline across DNS/TLS/headers, all bounded read1 bodies,
  hashes, real future gpgv, freshness checks and source snapshots. Socket timeouts
  never exceed the remaining work time. Late completion, incomplete drains/reap,
  runtime/source drift and ambiguous control remain UNKNOWN.
- The explicit future trust-policy v2 requires an exact non-alias ELF Python
  role, hash/metadata, non-root UID, protected parents, isolated runtime flags
  and nine pinned source buffers. The loader compiles the captured verified
  bytes. The role is uncommissioned; no runtime metadata or pin is learned from
  DATA or a successful boolean.
- Actual patch targets must exactly equal both declared before/after inventories
  before dependencies/extraction or any application. All four patches and their
  pre/postimages are checked/simulated before the first quilt mutation. Only a
  bounded plain unified diff for existing files is supported. Extra targets,
  ambiguous contexts, path aliases, renames, creates/deletes, modes/links,
  binary patches and unsupported syntax refuse.
- Target reads use FD-anchored parents and a leaf opened with NOFOLLOW and
  NONBLOCK. The FD must be a bounded regular single-link file before any read.
  The FIFO actor verifies refusal without reading and exact closure of every
  acquired descriptor. No real FIFO or native syscall was exercised.

The Root/kernel/stdlib/cooperative source-loader assumptions remain explicit.
There is no hostile-Root resistance, filesystem transaction, universal syscall
preemption or proof that all possible descendants have been released. Unknown
partial acquisition files are retained in the new isolated work area for
explicit review; they are not automatically reused or deleted.

## Standalone, read-only pure tests

From the repository root, using the existing Python interpreter:

```text
python -I -B -S deploy/openssl-remediation/run_pure.py
```

The runner needs only Python stdlib and this directory. It forbids process,
network, ctypes, SQL and filesystem mutation under an audit hook and writes
only a JSON summary to stdout. It uses synthetic HTTP/clocks/process/FD actors,
never invokes the future Linux commands, and does not decode supplier archives.
All Linux open constants used on Windows are confined to already mocked actors.
The former host-gated Windows refusal test now explicitly models `sys.platform`
as `win32` in that single test and calls the unchanged real Linux guard, with
IO/native entry points forbidden. It runs on every host without a skip and
does not execute or claim native Linux. The other 81 tests retain their own
platform context. Every test is required: any skip is reported and makes the
runner fail. No prior output/review
directory, installed product dependency, authority secret or remote system is
required.

The autonomous suite contains 82 methods: the original 35, 33 r2 regression
methods (including the two original findings), the converted FIFO actor,
11 locally copied independent challenges and two public selection/reference
replay checks. Of the original 35 methods, 34 retain their ASTs and the platform
guard test is explicitly adapted as described above. All 33 r2 methods and the
FIFO actor retain their ASTs. The independent methods
retain their ASTs except two fixture filename bindings moved to
`source-status.json`; former global ROOT/SOURCE bindings now point here. The two
historical freeze checks depended on private work directories, so the local
manifest-completeness test and reference replay replace them explicitly.
Formatting and removal of unused test imports do not alter method bodies.
Repository style also replaces the module's datetime timezone spelling with
the equivalent UTC alias. The hardening test's `common` namespace binds to
`future_linux._common`, the same already imported helper, so import sorting
cannot move its lookup before the approved helper path is initialized.
Runtime imports are sorted, a module docstring is wrapped, and the embedded
loader line is split without changing its parsed AST; runtime function/class
bodies and other executable module ASTs remain unchanged.

The fixture-only adaptations are explicit:

| Location | Adaptation |
|---|---|
| `EarlierIndependent.test_baseline_references_are_not_four_patch_Debian_plan` | `report.json` becomes the curated local `source-status.json`; assertions remain identical. |
| `RecentIndependent.test_08_NULL_authority_and_QUIC_still_refuse` | `report-r2.json` becomes `source-status.json`; assertions remain identical. |
| Independent module globals | `ROOT` and `SOURCE` point to this directory rather than prior review work directories. |
| Hardening module global | `common` binds to the same `future_linux._common` module; no test method changes. |
| Initial test module global | `timezone.utc` becomes the equivalent `UTC` alias required by repository lint; NOW and method bodies retain their meaning. |
| Initial platform guard test | `test_no_linux_execution_from_this_windows_task` becomes `test_linux_guard_rejects_non_linux_model`; an explicit per-test platform mock replaces the host-dependent skip, retaining the real guard and refusal assertion. |

`test_manifest_pin_and_all_frozen_UTF8_files` and
`test_01_external_gel_pins_all_records_old_unchanged` depended on historical
work-directory freezes. They are replaced by
`test_public_source_manifest_is_complete_UTF8_and_not_authority` and
`test_three_reference_proposals_replay_exact_public_postimages`. The latter
applies the three reference patches in their recorded order before comparing
the cumulative public postimages. These are new checks, not claims that the
historical freeze methods are unchanged.

`source-manifest.json` is a finite selection of public paths, byte counts and
SHA-256 values on base `6d4c7db`. It excludes itself from its rows and is not an
authority, signature, commissioning decision or license grant. Runtime source
hashes must be explicitly approved afresh for any future context; this manifest
does not fill the NULL recipe pins.

## Next gates

Independent SOURCE review must precede commissioning and a separately authorized
disposable Linux exercise. Provision and review the exact Debian archive trust,
runtime/tool/source identities and complete installed dependency lock; receive
and authenticate exact Debian u3 source; inspect the applied series and resolve
QUIC before admitting the four-CVE plan. Baseline/candidate build, C regressions,
SONAME/symbol/provider/ABI checks, real consumers, cleanup and image scans are
subsequent evidence. The existing future functions are not evidence those steps
have passed. No native workflow, Dockerfile, publication, NAS, deployment or GO
is activated by adding this directory.
