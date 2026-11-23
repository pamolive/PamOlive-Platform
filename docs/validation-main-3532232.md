# Validation of main 3532232 and subsequent isolated observations

The exact main [Platform run](https://github.com/pamolive/PamOlive-Platform/actions/runs/44129981192)
completed with a failure. This report updates the as-of status in the development
delivery notes. Results below belong to their named source revision and run.

## Main 3532232

The global PostgreSQL report says Ran 1,747 tests in 593.772 seconds: one error,
42 skip events and no assertion failures. A passing count is not inferred by
subtracting all skip events: class-level skips are counted separately by unittest.
Directory ran 130 tests in 19.322 seconds without failures, errors or skips.

The error is test_68_main_closes_then_opens_unique_CLOEXEC_FD_then_filter_marker_exec.
Its main_model fixture inherits the Django runner's interpreter flags, but the
real solver entrypoint requires an isolated interpreter, no site initialization
and disabled bytecode writes. The isolated pure runner had hidden this fixture
dependency. Reproduction with the actual 82-test pure runner without -I/-S gives
the same single fence_interpreter error, zero skips and no attempted external
IO. The production guard must remain mandatory; the synthetic fixture must set
its intended interpreter state explicitly and test negative flag combinations.

Dedicated source and restore-corpus invocations preceding the global suite
passed: 52+17, 62, 194+22 and four tests respectively. They do not validate the
later image restore steps. The read-only source job passed fourteen tests.
Installed Vault passed 52 tests and the public PAM verifier passed thirty,
without skips. These scopes do not establish full P2 or production readiness.

The global-suite error skipped subsequent product builds, image security scans,
native SSH/RDP, WebSocket and image restore qualification. No new High/compiled
finding count, image digest or qualified image may be inferred from this run.
Earlier e841fb8 scan results remain historical evidence for that revision only.

## Read-only runner observation

The separate [metadata run](https://github.com/pamolive/PamOlive-Platform/actions/runs/44132636559)
completed successfully. Workflow 296b3e6 checked out immutable source 3532232,
verified eleven source pins, passed fourteen pure contracts, measured nine fixed
vendor versions and collected only the fixed public parent/leaf metadata.
Artifact 14349384608 contains four JSON records from five allowed paths; the
failure record is correctly absent. Source and workflow identities are distinct.

On that fresh runner, /opt, /opt/google, /opt/google/chrome and its chrome leaf
were root:root mode 0777. The strict Chrome path guard therefore rejects this
configuration. The dpkg-query path and parents were root:root mode 0755 and
compatible. These observations neither prove the exact failure location in an
older run nor authorize ownership, mode or ACL repair. No policy inspection,
namespace setup or profile admission was performed.

## Expat native follow-up

The [C4 diagnostic run](https://github.com/pamolive/PamOlive-Platform/actions/runs/44132214975)
on b11fc81 passed ninety pure tests, exported DATA and then refused strict driver
validation. Its first child exited with SIGILL. Seventeen source/PID-bound
checkpoint files were received, ending at holes_before. A checkpoint is written
before its own fsync, validation and close: that final file alone does not prove
return from the checkpoint or identify a particular syscall as the cause.

The kernel filter, ABI, H172 ownership, deadlines and positive terminal criteria
remain unchanged. Capture refusal grants no material approval, kernel policy
qualification or image publication. Next work is the explicit fixture repair,
safe native oracle probes, a fresh exact-revision PostgreSQL run and a secure
browser qualification fixture preserving all existing authentication guards.

No NAS, production target, real account or real secret was used in these runs.


## Separate Python fixture correction

The first corrective change is limited to the unit-test fixture. It explicitly
models isolated/no-site interpreter flags and disabled bytecode writes, instead
of inheriting those values from the process running the suite. Two regressions
check each invalid setting against the unchanged interpreter guard and verify
that nested mocks restore the parent's original state.

The actual pure runner now passes 84 tests, zero failures, errors or skips,
under both ordinary and isolated launchers, with no attempted external IO.
This result is local source/test validation. It does not replace PostgreSQL or
image CI on the eventual commit. The native oracle proposal remains separate
and awaits its independent review and a fresh Linux test.

## Exact corrective candidate 96f7fa7

Both the push run 44174958647 and PR run 44174987438 completed. The global
reports say Found 1,754, Ran 1,749, OK (skipped=42). Direct reconciliation of
each log identifies 1,709 successful methods, 40 skipped methods and two
separate skipped-class records. The five discovered methods absent from the
Ran count are not assigned to particular classes without further evidence.
The original test and both new regressions are explicitly successful on both
runs. Directory reports 130 tests, OK, without skips.

The sole failing job step on each run is the exact-image scan, with 35 groups
reported as untriaged_high. These are each image's own reports: push and PR
have distinct image identities. No image is qualified or promoted. The source
PR remains subject to the unchanged validation and publication gates.
