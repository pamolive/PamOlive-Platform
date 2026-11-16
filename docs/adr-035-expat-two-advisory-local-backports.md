# ADR035 — Two local Expat 2.10.0 security backports

Status: SOURCE candidate; native qualification and Root integration pending.

Base: runtime 75813d8de9291fb6be6023b51aa6db5e6164f992. This delta must be
composed as hunks with later restore/Jansson work, never as an older Dockerfile
replacement. It has no production, publication, CVE-closure or operational authority.

The authenticated inputs remain the same Debian source 2.10.0-1 and upstream
2.10.0 release, Python 3.12.16, three signature purposes and ten material pins.
No extraction or native build precedes the existing authentication in either
builder. The native source-audit CLI now also authenticates before reading TAR
members; its importable DATA audit deliberately claims no cryptographic proof.

After authentication and extraction, both Debian and upstream UBSan apply the same
two locally pinned patches. A closed in-memory unified-diff reader verifies both
patch digests, every exact preimage, declared hunk positions/counts and every full
postimage before any write; no offset/fuzz, duplicate path or second application.
The four targets are xmltok.c, misc_tests.c, xmltchar.h and xmlwf.c. Re-reading
all captured inputs before writes and all postimages afterwards detects ordinary
mutation in the private cooperative build TCB; it does not promise atomicity
against a malicious root build supervisor. These local modifications are not
covered by the original upstream signatures. SOURCE-REBUILD/2 and the local
backports receipt say so explicitly.

The proposed package revision is 2.10.0-1+pamolive2, a LOCAL RECONSTRUCTION,
not a new upstream release or Debian publication. Current runtime/image/SBOM
readers require this version and the V2 local-backport proof. Historical V1
receipts remain immutable historical DATA under their old frozen readers; they
do not qualify a V2 image. The SBOM upstream component remains expat 2.10.0 and
records the explicit local revision/patch proof, rather than inventing 2.11.

CVE-2026-124317: apply bf26290, 3d77567 and the 0507597 regression. Its sole
base-compatibility port asserts the fixed input length is 10, then uses the
public XML_GetBuffer(int) API because XML_GetBuffer64 is absent in 2.10.0.
No public header/export or unsigned-short XML_Char type is changed. The old
seven-file C11 test port remains byte-exact; only misc_tests.c pre/post pins and
case/registration metadata advance from 444 to 445 cases. 5,340 checks per
width over twelve configurations is a prediction, not an observed result.

The native before witness compiles the same bounded C fixture against the
unmodified authenticated upstream static library. A guarded converter records
an actual request beyond the ten-byte input and refuses BEFORE reading out of
bounds. Before mode requires that unsafe-callback fact; after mode requires it
absent. No crash or expected failed process is relabelled as successful. The
existing four-fix cases remain in default mode and run against narrow and
unsigned-short SDK libraries. This guarded witness is not an ASan crash proof.

CVE-2026-128241: exact upstream 7e52b22 and 26f00fc hunks change the xmlwf -d
leaf open to O_NOFOLLOW and close the fd on fdopen failure. A private synthetic
victim demonstrates old overwrite versus new rc3 refusal; the victim must stay
unchanged and the symlink intact after patching. The genuine normal-nonzero
H1 facts, PID/argv/tool hashes and UNKNOWN journal are validated and retained;
command.ok remains false. This covers Linux leaf symlinks, not hardlinks,
parent traversal, ordinary output overwrite or Windows (whose O_NOFOLLOW is 0).
xmlwf physical presence in an image is not inferred and does not delay fixing
the vendor source. No image/KDC/AD/NAS/user data is used.

Both native paths retain existing authentication, compiler flags, ABI/header,
PGO, full C corpus, SDK, Python import-order/capsule and provider guards. The
snapshot comparator, common/bounded H1, scanner thresholds and PG/P0 controls
are unchanged. New bounded calls use the same common/H1 with compile 60s and
execution 5s, plus a second make build with the existing 300s/8MiB limit; the
workflow horizon is not extended. A budget failure stays a failure. Source-audit
authentication adds the same three purposes, not a new trust root.

Required later Linux evidence: original and patched guarded witnesses, real
xmlwf victim facts and rc3 H1, exact patch/readback receipts, both complete C
suites/12 configurations, UBSan checks, three signature purposes, ABI symbols
and public-header identity, Python consumers, complete product Platform and
strict new image scans. No fixed4/new-advisory admission, ignore, threshold
change or source-only CVE closure is granted here.

Primary lineage is captured in the immutable source plan c50f71/bf245:
https://github.com/libexpat/libexpat/pull/1492 and
https://github.com/libexpat/libexpat/pull/1502 ; Debian trackers
https://security-tracker.debian.org/tracker/CVE-2026-124317 and
https://security-tracker.debian.org/tracker/CVE-2026-128241.
