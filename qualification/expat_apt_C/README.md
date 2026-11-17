# ADR-021 C: authenticated package capture, separate approval

## Refusing solver diagnostic (source candidate)

The b9 capture's APT command 5 returned normal rc100; its original 6970/183-byte
stdout/stderr buffers were not received. Its cause remains UNKNOWN. The received
dpkg status identifies APT 3.0.4. The official source permits a no-download refusal
before simulation, but that condition has not been established for this run.

The diagnostic is restricted to the existing exact fourteen-request simulation,
its fixed environment and 90/10-second bounds. It scans both complete existing
bounded buffers, prioritizes stderr errors, and exports at most 32 line hashes
inside 16KiB. Export omissions do not invalidate an otherwise complete input.
Invalid encoding, CR/NUL, unterminated or oversized lines invalidate specific
message classification; no matching is performed on truncated prefixes. A finite
literal message can identify an observed APT message, not prove the full solver
cause. Other severity lines export only a finite class and SHA256.

Normal rc100 plus complete H1 and the same post-checked tool identity/SHA are
required for a REFUSED message packet. Uncertain lifecycle or tool checks remain
UNKNOWN. Reading the already measured tool again adds no process or authority.
The original fatal guard still runs: no plan parsing, material approval or
installation follows an error. A failed diagnostic writer/callback cannot replace
that refusal. No raw text, exception, argv, environment, URL or path is exported.
The packet is linked to the current code-pins and run by the existing independent
artifact/source reception; its presence alone is not evidence of success.

APT flags, authentication, sources, sandbox, caps and deadlines are unchanged.
Native behavior and the actual error class await a fresh reviewed Linux run.

This development laboratory captures the exact `expat-prepared` APT boundary.
It does not install packages during capture, modify the product Dockerfile,
publish an image, or qualify a compiler or the finished product.

The dedicated `expat-apt-C-capture.yml` workflow runs only on
`agent/adr021-expat-apt-C-capture`, in a fresh Ubuntu 24.04 GitHub-hosted VM.
It passes a finite Git archive to Docker, requests the pinned amd64 supplier
parent, and retains authenticated public metadata, dependency DEBs, the solver
plan, before state and command-completion facts. The capture result remains
`AUTHENTICATED_UNAPPROVED`. A successful Docker DATA export alone is insufficient:
the subsequent strict checker requires normal driver completion and unchanged
dpkg state. No opaque failure is treated as a successful capture.

## Root commission, 17 November 2026

The qualification policy SHA-256 is
`3bab6351fe8cb82cb557fe6d334cc2e386e05a2a6c19cd7cf6613a015b7323f4`.
The workflow supplies this value independently of the captured material set.
The empty `deploy/expat_apt/policy.uncommissioned.json` remains a refusing template.
The nine source modules are bound by `code-pins.json`; changing them requires
another review and an explicit workflow pin update.

Certificate purpose is selected from the existing pinned parent keyring
`506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017`.
The [Debian FTP-master key list](https://ftp-master.debian.org/keys.html)
independently corroborates the five public primary fingerprints. The website
is a cross-check; it does not replace the pinned keyring or native signature
verification. No fingerprint is learned from capture output.

| Repository | At least one required current primary | Additional co-signature allowed | Maximum age | Valid-Until required |
| --- | --- | --- | --- | --- |
| trixie | Debian 13 archive or Debian 13 stable | Debian 12 archive | 90 days | No |
| trixie-updates | Debian 13 archive | Debian 12 archive | 7 days | Yes |
| trixie-security | Debian 13 security | Debian 12 security | 7 days | Yes |

An old certificate alone always refuses. This is an explicit ANY-current-key
policy, not a requirement for two independent signatures. Stable releases have
a longer publication cadence: the [Debian 13.7 announcement](https://www.debian.org/News/2026/20260912)
is dated 12 September 2026. Its date is not evidence of the Date in a newly
received signed Release. The 90-day limit is a deliberate replay window, matching
the existing data-codec policy and the guard's maximum, rather than an exemption
granted after observing a failure. Security and updates retain seven days.
Every present Valid-Until remains enforced, including for stable. Future dates,
expired metadata and bounds exceeded by one second refuse. No clock adjustment,
expiry bypass, weak-signature flag or package-authentication exception is used.

Bootstrap SQV 1.5.0 uses the previously reviewed official Debian HTTPS DEB and
exact executable SHA. This supplier/bootstrap trust is not a compiled-source
attestation. Loader compatibility, native verifier behavior, current signed
metadata and availability of historical exact package pins still require Linux
evidence. Vendor maintainer scripts execute as root only during a separately
approved apply; they remain an explicit trusted dependency.

## Capture is not approval or product admission

After capture, independently receive the GitHub artifact and its API digest;
review the exact signed records, all dependency DEBs and transitions, before
state, origin and package scripts. Only then supply the unchanged material-set
SHA as an external approval input to a separate offline application. A solver
version or the capture job's own output cannot approve itself. Missing pinned
versions refuse; no global `apt-get upgrade` or `dist-upgrade` is substituted.

`integration/Dockerfile.product.hunk` is an unapplied proposal. Its direct strict
path propagates failure; the DATA supervisor is not a product ancestor.
Integration into product builds still requires exact context, recipe, named
context and source-pin reviews, followed by native apply, installed state,
compiler/SDK/generated-state measurements and full image qualification.
Build verification, complete materials and operational approval remain false.

## Tests and independent review

The 48 source/data tests pass on the actual checkout with zero skips and an
empty external-I/O audit. Native boundaries are fakes in those tests. Independent
source review added six targeted adverse cases; the policy review exercised
30 combinations of purposes, dates and expiry. These are not native crypto,
Docker, APT or installation results. Run `run_pure.py` with a new report path;
the script refuses to overwrite an earlier report.

The first Linux capture must establish actual OCI/diffID binding, SQV execution
and signatures, bounded network-worker completion, APT cache and Inst/Conf
framing, dependency retention and unchanged dpkg state. Exact offline apply,
tamper, unavailable-pin, timeout and package-state drift cases remain mandatory
before applying this boundary to the product.

## First native capture and closed failure observation

Commit d1d357b reached two verified OCI metadata downloads on a fresh Linux VM,
then refused during the config-blob worker. The strict DATA gate failed and no
SQV, repository signature, APT solver or installation was reached. Its internal
cause was not received; no HTTP, TLS, CDN or hash cause is inferred.

The next worker revision retains only a closed diagnostic: a numeric index into
57 literal source-bound error codes, nine literal phases and six error kinds.
The parent accepts that projection only after complete normal exit42, drained
streams, no kill/exception and exact bounded fields. No raw exception, URI,
anonymous token, response body or header leaves the worker through this channel.
Projection failure preserves the original fatal guard and sticky UNKNOWN.
No TLS, origin, redirect, size, hash, timeout or package consent is relaxed.
Seven added pure cases preserve all 41 earlier test methods; they do not prove
the historical cause or any native success.
