# Offline restore corpus: tenant context and safe diagnostics

## Confirmed local defect

The exact synthetic corpus produced by `deploy.prepare_restore_fixture`
populated successfully on isolated PostgreSQL. Running the complete offline
application verifier without an organization context then failed with
`PermissionDenied`:

`verify_application → TeamViewer verify_evidence → verify_observation →
_verified_origin → AccessProvenanceReceipt.objects → current_organization`.

The global offline reader had not supplied the tenant context required by the
normal scoped V8 receipt reader. This reproduces a concrete application defect
in the same populated corpus used by the failing restore CI stage; the original
CI child output was withheld, so its exact exception is not claimed as observed.

The correction sets `organization_context(link.organization)` for each normalized
TeamViewer observation in the existing offline global traversal. The product
observation verifier, organization equality checks, scoped receipt manager,
V7/V8 evidence formats, signatures, encryption and restoration-role guards are
unchanged. A failed or successful check restores the previous ambient context.

## Reproduction and regression

`tests.test_restore_full_corpus` creates the exact CI corpus and a second
synthetic tenant with its own normalized TeamViewer observation. It verifies the
complete corpus without ambient tenant context, checks preservation of every
managed-model fingerprint, checks the tenant context is restored, and rejects
an observation presented under the foreign tenant. No stored proof is rewritten.
Network connection creation is forbidden while constructing the fixtures.

This class runs only on PostgreSQL with the exact disposable test database
`test_pamolive_restore_source`; generic suites explicitly skip it. Its sole
test-only patch bypasses `database_guard` because this database is the synthetic
source, not the separately named restricted restoration role/database. All
application evidence verifiers execute normally. This gate complements, and
does not replace, the Docker archive/role/transport restoration gate.

Local results:

- Before correction: the complete-corpus reproduction failed at the scoped V8
  receipt lookup with `PermissionDenied`.
- Initial corrected complete corpus: 1 test passed in 6.221 seconds.
- PostgreSQL campaign `tests.test_restore_full_corpus
  tests.test_restore_diagnostics tests.test_restore tests.test_teamviewer_access
  tests.test_event_provenance_restore`: 42 tests in 37.815 seconds, OK,
  1 explicitly skipped (SQLite-only receipt-deletion scenario; PostgreSQL tests
  its append-only trigger instead).
- Final diagnostics suite, including full public CLI and cleanup failures:
  6 tests in 0.013 seconds, OK, no skips.
- Ruff passed for the five changed/new Python files.
- Independent Red Team rerun: full corpus, TeamViewer access and provenance
  restore suites ran 27 PostgreSQL tests in 28.022 seconds, OK, with the same
  single SQLite-only skip; diagnostics 6/6 passed in 0.013 seconds. The reviewer
  confirmed rejection of the foreign link, unchanged fingerprints, scoped
  receipt/HMAC checks, public failure and cleanup categories, and preservation
  of the wrong-key/password subprocess failures.

The isolated PostgreSQL service used loopback port 53452 and synthetic keys.
No NAS, production database, real identity or real connector was contacted.

## Public failure boundary

The child verifier emits a fixed failure category alongside its phase and
exception type. The parent accepts only a bounded JSON object with exact keys,
recognized phases and exception names, and an exact static code allowlist;
duplicate keys, arbitrary messages, malformed fields and extra fields become
`unclassified_verification_failure`. No raw child stdout/stderr is added to
public reports. Existing wrong-key/wrong-password negative probes retain their
original `CalledProcessError` handling and must still fail for the expected reason.

The public CLI preserves the primary verification category if cleanup also
fails and adds only the fixed secondary
`cleanup_code=isolated_copy_cleanup_failed`. Cleanup failure alone remains fatal.
Tests inject private markers in subprocess output and prove they do not appear
in public JSON. The existing private-error path for other direct subprocess
failures remains unchanged; wrapped positive-verification output is reduced to
the approved category and is not copied into that file.

## Remaining validation

Independent Red Team review passed; the next GitHub run provides separate evidence.
The local corpus run does not qualify Docker networking, archive transport, or
login as the restricted restored role. Those checks must pass the original
populated-archive CI gate before claiming end-to-end restore qualification.
No restoration safety guard or verifier should be weakened to obtain that result.
