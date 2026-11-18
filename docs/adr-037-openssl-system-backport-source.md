# ADR-037 — Prepare a bounded OpenSSL system backport without granting build authority

Status: accepted for source implementation only; trust and build inputs uncommissioned.

## Problem

The exact image policy received for the two fixture-fix CI runs refuses 35
vulnerability groups. Four concern the Debian OpenSSL source package and its
three runtime packages. The existing scanner policy remains the release gate.
Upstream rates these issues Low; that classification does not silently replace
the scanner's High classification or close its findings.

The [10 November upstream advisory](https://openssl-library.org/news/secadv/20261110.txt)
publishes fixes and schedules the containing releases for 1 December 2026.
As checked on 18 November, the announcement is a future release plan, not an
available or qualified PamOlive dependency.

System OpenSSL 3.5.7 and the OpenSSL 4.0.3 embedded in the cryptography wheel
are distinct providers. Updating one is insufficient to qualify the other.

A later [PR run for the browser candidate](https://github.com/pamolive/PamOlive-Platform/actions/runs/44251298352)
reports 37 blocked groups rather than the 35 of the fixture-fix runs. The 35
common group records are unchanged; two additional OpenSSL groups are reported:
CVE-2026-107493 and CVE-2026-124709. The image/config and scanner database also
differ between the browser push and PR runs; this observation alone does not
establish the cause. This kit's initial four-CVE scope does not address those
two additional findings. They require separate primary-source validation and
remediation before any claim of complete OpenSSL or image qualification.

## Decision and alternatives

Prepare a small, standalone SOURCE kit for a Debian-compatible backport on the
existing 3.5 branch. Keep the exact Debian base identity and authenticate all
future inputs before extraction or compilation. Reuse the reviewed source
contracts and owned-process IO primitive; do not create a new service.

Waiting for a future distribution release leaves current findings open.
Replacing system OpenSSL with 4.x or copying one shared object disregards
ABI, provider, dependency and provenance requirements. Both are rejected as
the immediate correction. A completed, authenticated, tested upstream update
can be reconsidered when available.

The selected upstream 3.5 fixes are:

| Finding | Upstream commit |
|---|---|
| CVE-2026-88823 | `159e1de0c448d7b9f09ad768c8e141def4aa1eb4` |
| CVE-2026-107496 | `a0051cfe699bf5a047bc1c4faef65f80f7987366` |
| CVE-2026-95692 | `257a3427aa0ef8d9dd2ef5b3e2d1c021a221b116` |
| CVE-2026-95691 | `f6244675833e097c2429a40d1b206d95385bd42f` |

The public text reference supports replay of three proposed patches against
the upstream 3.5.7 tag. It does not establish applicability to the exact Debian
u3 sources. The QUIC fix has an unresolved source-context conflict and must
continue to refuse. No automatic transplant, generated authority or inferred
four-CVE completion is permitted.

## Boundaries and review corrections

The committed trust, exact Debian patch plan and full dependency-lock pins
remain null. The default configuration refuses before authority acquisition
or a command. Public HTTPS text, a matching hash and synthetic signature-status
records are not substitutes for cryptographic source authentication.

Future acquisition has one absolute 180-second owned-process budget including
five seconds reserved for cleanup. The worker, HTTP fragments, validation and
nested verifier cannot reset that horizon. Runtime and the closed source set
are captured and checked; incomplete cleanup or a late success remains unknown.

Every patch target must equal its declared preimage and postimage sets before
any transformation. Only the finite supported existing-file text format is
admitted. All proposed patches are simulated before the first quilt operation.
Target reads use anchored descriptors, no-follow traversal and a nonblocking
leaf open, then reject nonregular files, hardlinks and excessive lengths before
reading. The nonblocking flag fixes the independent review's modeled FIFO hang.

The source kit changes no application model, migration, existing P0 control,
Docker runtime, library provider or scanner disposition. Its acquisition and
build entrypoint is preparation, not authorization to run with guessed pins.

## Acceptance and remaining work

Source acceptance requires standalone automated tests of refusal and positive
contracts, static checks, secret scanning and independent review. Mechanical
publication adaptations must be listed separately from the reviewed runtime.
Pure doubles do not qualify Linux cleanup, signatures, compiler results or TLS.

Before integration into a product image, authenticate the Debian source chain,
admit the exact runtime/tool roles and dependency lock, resolve the QUIC source
context, build baseline and candidate, and verify upstream/regression results.
Rebuild the three runtime packages and SDK consistently; check ABI, SONAME,
providers, Python ssl, PostgreSQL TLS, native SSH/RDP/NLA and P0 regressions.
Then receive an exact new image's inventory, SBOM, strict scans and provenance.
The wheel's separate 4.x provider needs its own correction and evidence.

Historical reports and data remain unchanged. The proposed local package suffix
is an honest local identifier, not proof of fixes or a new Debian release.
No CVE, image, deployment or production qualification is granted by this ADR.
