# R11 — authenticated Chrome TEST bundle, explicit v3 contract

This is a qualification fixture, not a PamOlive deployment or operating-system
package installation. The old `pamolive.chrome-bootstrap/2` path, canonical
`/opt/google/chrome/chrome` guard and R10 APT cache controls remain in the source.
No refusal in that path triggers a fallback to the new role.

The fresh public runner observation `44132636559` found the canonical Chrome
parents and leaf owned by root but writable by group and others (0777). Its
strict refusal is correct. This observation does not establish the precise
historical failure location in an older run. No chmod/chown repair, AppArmor
change, sysctl change, mount namespace or `--no-sandbox` is introduced here.

The new explicit `--test-bundle` mode follows the existing source/context,
Google certificate purpose, actual native negative cases, GPG validity, key
scope, seven-day Release freshness, exact package SHA and control checks. It
reads the complete Chrome subtree from the authenticated payload. A profile
pinned by the committed helper must independently approve the exact tree digest
and any privileged role before Root staging can occur.

The initial `chrome-bundle-profile.json` deliberately has `commissioned:false`.
It is part of the reviewed source pin set; it cannot be replaced by an
environment variable, a collector's observation or a producer's success boolean.
The present workflow explicitly selects v3 and therefore stops at this admission
gate after publishing authenticated inventory DATA. It does not make the UI job
green or pretend a staged bundle exists. `--bundle-inventory-only` is a separate
non-root mode which returns after the same authentication and payload inventory,
before dependencies, Root staging or browser launch.

## Source implementation

`chrome_bundle.inventory` walks only a bounded, uncompressed payload TAR; it
does not extract it. All names, duplicates, declared sizes and sparse entries
are checked, including entries outside the selected Chrome subtree. The result
is DATA with `admitted:false` and `operational_GO:false`. Regular resources are
stream-hashed; link metadata is projected as DATA but staging currently refuses
all symlinks, hardlinks and special files. A real package requiring those needs
a separate reviewed policy revision; a partial bundle is never silently used.

The admission profile binds package SHA, canonical whole-tree digest and exact
privileged roles. Only the `chrome-sandbox` path can receive 04755, and only when
the source-pinned profile includes its exact digest, role and mode. A boolean,
unknown SUID/SGID path, mismatched helper or observed mode never grants this
authority. The target `chrome` must be a root-owned regular 0755 ELF. Other files
have only the finite 0444, 0555, 0644 or 0755 modes. Directories are 0755.

`stage` requires Linux bootstrap Root authority and creates the exact fresh
`/usr/lib/pamolive-p1g-chrome-<run>-<attempt>` prefix. It never adopts an existing
prefix. `/`, `/usr` and `/usr/lib` are opened through held directory FD anchors,
must be real root:root directories and must not be group/world writable. Every
new directory/file is created exclusively below the owned root FD, no-follow;
bytes, sizes, modes, owners, links and FD/name identity are validated. Only new
owned objects are chmodded. The top prefix remains 0700 until the complete tree
and receipts are written and fsynced, then becomes 0755. No existing permission
is repaired. Budgets are checked before mutation and around chunk work/syncs;
the existing outer H172 supervisor is still needed for blocked kernel calls.

The new receipt is `pamolive.chrome-test-bundle/3`, state
`STAGED_AUTHENTICATED_TEST_BUNDLE`. It is stored with the full resource manifest
as root-owned, single-link 0444 files inside that protected prefix. It binds the
run, attempt, source revision, bootstrap pins, context receipt, package,
independently approved profile and whole-tree manifest. It says neither dpkg
installed the package nor that the browser, sandbox or UI succeeded.

The frontend requires normal completion of its bounded Root command and checks
the resulting bundle. The owner, worker and browser all use the same
`lab_support.chrome_target` resolver. Mode `test-bundle-v3` is explicit and is
propagated into the worker; unknown modes refuse. The resolver validates its
source helper/profile against the same committed context, derives the prefix
from the current run/attempt (not a received path), and rehashes every resource
and exact metadata. The existing strong ELF and ancestry guard is an additional
check. Browser setup and its final recheck use this same resolver. TLS, NSS,
origin restrictions, MFA, independent votes and `chromium_sandbox=True` remain.

## Budgets, ownership and limits

The existing payload cap remains one GiB declared and 20,000 members, at most
512 MiB per regular file. The canonical manifest is capped at four MiB. Resource
verification streams chunks of at most 64 KiB rather than buffering the complete
Chrome ELF. The Root/frontend/worker horizons and cleanup reserves are not
extended. The UI resolver has an additional finite 30-second work deadline.

No Root prefix deletion or universal descendant cleanup is implemented here.
Failures may retain the freshly-owned protected prefix; no replacement,
permission rollback or retry is automatic. A late post-publication failure does
not prove the prefix is still 0700. Normal process completion is required by the
owner. The receipt retains `all_OS_descendants_released:false` and
`operational_GO:false`; VM teardown is not cleanup evidence. A follow-up must
qualify the exact owned cleanup after actual browser/SDK closure.

The cooperative runner/kernel/Root, supplier code, Python loader and host
libraries remain part of the TCB. FD checks are not hostile-root atomicity.
Hashing the complete Chrome subtree does not inventory every dynamic host
library. No cryptographic primitive, product authentication, organization data,
PAM target, SCIM destination or P0 protection is modified.

## Required next Linux reception

1. Review this source and its finite manifests independently, then run only in
   the dedicated disposable GitHub qualification job.
2. Receive the actual authenticated package inventory and exact aliases/SUID
   metadata. Do not copy an observed profile into authority automatically.
3. Independently review the complete inventory and explicitly commit a new
   source-pinned profile if its resources and privileged roles are acceptable.
   Any unsupported link or special role requires a reviewed implementation.
4. Re-run exact-revision staging, resource verification, Root H1 and immutable
   receipt checks. Refuse a pre-existing prefix, changed context, package or tree.
5. Measure actual relocation and sandbox engagement on the Ubuntu runner. Its
   path-based AppArmor userns policy and this package's SUID helper are not yet
   qualified. Do not disable a sandbox to make relocation work.
6. Run the real JavaScript/MFA/WebAuthn/approvals/TLS/NSS/tenant UI increment and
   verify worker/browser/SDK closure, resource rechecks and owned-prefix cleanup.
   This increment still does not qualify the complete SSH/RDP P1-G journey.

No native executable, real DEB or external payload TAR was executed or decoded
on the preparation PC. Tests use synthetic in-memory archives and OS doubles.
