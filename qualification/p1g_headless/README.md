# P1-G headless: first runnable synthetic UI increment

First synthetic increment, prepared for an actual disposable Linux CI run.
No browser, Django/SQL lab or native transport has run in the source review.
Full P1-G remains open. The scoped job is part of `.github/workflows/ci.yml`;
all existing Platform gates remain in place. It accepts only the exact
`agent/p1-g-headless` push or a same-repository PR from that branch.
This branch depends on the reviewed bounded helper already in the Expat branch;
it does not qualify that branch's future product image. The test-tool lock also
has an explicit vulnerability audit in the security job.

## Delivered path and honest boundaries

| Step | Actual test action when the lab runs | Limit |
|---|---|---|
| Authentication | Password and fresh real TOTP through shipped forms | Fixture accounts only |
| P0 ceremonies | Real pam-trust.js and Chromium WebAuthn enrollment/assertions | CDP simulates UP/UV; fixture custodians are not independent humans |
| Request | Identity360 link, request form and signed PAM intention | No pre-authorized lease injected |
| Approval | Two separately logged-in fixture people vote through UI/JS | No actual PAM transport in this increment |
| Audit | Existing contract/audit pages and backend chain verification | UI rendering is not target effect |
| Observe | PC-483/PC-991 seeded in-memory observation/evaluation/withdrawal history | Separate subject, not causally produced by the new intention |
| Withdrawal | New local Grant, UI-created frozen campaign, actual grant-review revoke click and signed decision | Local revocation only, no provider or live PAM lease closure |
| Refusals | Foreign/missing/deleted identity, suspended identity, disabled module, inactive user | Scoped PAM business counts must remain unchanged |

`NEXT-NATIVE.md` names the real SSH/WebSocket, expiry, revocation and recording
raccord using existing fixtures and routes. Hooks `after_approval` and
`install_websocket_policy` isolate that next step. WSGI cannot serve WebSockets;
the initial case refuses any WebSocket. No route or product module is invented.
The full path needs an admitted native/browser execution context and real
transport/closure receipts; neither is supplied by pure tests or seeded graphs.

## Execution contract

The fragment captures only committed `GITHUB_SHA` via existing
`deploy/build_context.py`, then installs and runs from that capture. Twenty-four
reviewed fixture/template/P0 inputs are checked against both source bytes and
the context receipt. The pin manifest itself is bound to that receipt before parsing,
and the current set must contain exactly twenty-four entries; drift refuses. Repinning changed inputs requires review.
The fixture lives in a new `test_pamolive_p1g_browser` database on a dedicated
ephemeral PostgreSQL 17.12 service at the already pinned amd64 manifest. It
requires the test database to be absent before Django's runner and absent after
it, with the base database OID preserved. Never point this driver at an existing
service. The guard accepts only loopback, the exact database names and CI context.

The future runner needs Linux nonroot, 3072 MiB MemAvailable and 8 GiB workspace
free at preflight. The job has a 25-minute ceiling; the observed test owner has
600 seconds work plus 60 seconds kill/reap/drain reserve, below its 12-minute
step. Public certutil commands each use 10+5 seconds and 64 KiB per stream.
Parent worker streams are capped at 256 KiB each / 512 KiB combined. PENDING and
PID precede results. A timeout, drain/reap failure or exception remains UNKNOWN;
VM teardown is never resource-release evidence. SDK close/thread termination and
test-database deletion are separate facts, not proof that all OS descendants
were reaped. No automatic retry or fallback follows a refused browser/tool.

The literal root-owned Chrome binary and its root/nonwritable ancestors are
checked before NSS/SQL and before/after launch (full SHA, up to 512 MiB). The SDK
Node ELF is separately measured (128 MiB). A fresh private HOME receives a
short-lived synthetic TLS CA in modern Chromium NSS storage. CA private material
is never written; the temporary server key/NSS files stay private. TLS errors
are not ignored, Chromium sandbox is explicitly enabled, and application
requests stay on the exact HTTPS lab origin. There is no no-sandbox, security
disable, real target or secret in the page. The runner Chrome must actually be
146+ for the chosen modern NSS location; older or unavailable binaries refuse.

## Tool bootstrap and evidence

Playwright Python 1.65.2 (published 2026-11-14) and greenlet 3.5.6 CPython 3.12
manylinux x86_64 are pinned by exact wheel SHA/URL/size in the lock and metadata
receipt. Only their official versioned PyPI metadata was acquired here; no wheel
or browser was downloaded/imported. Public distro development packages/certutil
and preinstalled Chrome are an explicit GitHub-runner/public-APT development
TCB, measured at runtime rather than claimed reproducible or build-attested.
Existing application dependencies reuse `requirements-dev.lock`; pip check is
mandatory. No product image or prior NSS/sandbox qualification is inherited.

Primary references: [Playwright 1.65.2](https://pypi.org/project/playwright/1.65.2/),
[greenlet 3.5.6](https://pypi.org/project/greenlet/3.5.6/),
[launch options](https://playwright.dev/python/docs/api/class-browsertype),
[virtual authenticator](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/#method-addVirtualAuthenticator),
[Chromium Linux NSS locations](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md).
These pages do not authenticate future installed bytes; runtime measurements
and source bindings have their own, narrower purpose.

Only typed public JSON facts, hashes/counts, source error line numbers and the
committed-context receipt are uploaded. Browser DOM, screenshots, HAR, session
capabilities, TOTP, signed proofs, private logs, HOME/NSS and keys are excluded.
Virtual authentication and all fixture preparation remain visibly synthetic.

Pure command (does not import Django/Playwright or open a database):

```text
python -I -B -S qualification/p1g_headless/run_pure.py
```

Future actual lab command, only inside the reviewed fragment's fresh CI context:

```text
$RUNNER_TEMP/p1g-venv/bin/python -I -B $RUNNER_TEMP/p1g-source/qualification/p1g_headless/run_lab.py
```

Pure contracts cover context refusal, closed origins, atime-safe tool identity,
actual command supervision under doubles, WebAuthn/TLS source guards, diagnostic
capture before refusal and fresh database requirements. They do not prove that
any UI selector, browser, TLS chain, database or native session has run.

## First execution and bounded diagnostic

The first actual PR run at a4e47f1 (43841987751, job 133212654142) refused
before TLS, database setup or Chrome launch. The ten source contracts passed;
the worker returned 42 with a normal reaped/drained receipt and zero UI tests.
Its original report identified a ValueError at the Chrome tool preflight but
did not export the precise predicate. No cause or browser success is inferred.

This follow-up retains the exact Chrome admission and source-manifest checks.
It records a separate chrome_tool_preflight phase and only six closed error
codes, plus bounded numeric/type metadata for the fixed Chrome leaf. It never
publishes exception text, resolved targets, file content, environment or keys.
The metadata is observed after refusal and cannot attest the original failed
stat or admit a tool. Four new pure tests bring the suite to 14, all passing
with no external attempts. Independent review passed those 14 and three
additional adversarial tests. Actual Chrome metadata and all UI assertions
remain pending a new Linux run; this diagnostic grants no qualification.

## Authenticated browser bootstrap candidate

[ADR-032](../../docs/adr-032-authenticated-ci-browser-bootstrap.md) selects an
exact authenticated Google package in the disposable CI VM. The pinned public
Release/key/Packages metadata is checked before native package processing;
actual GPG, payload inspection, dependency refusal and local-only reinstall
remain required in Linux. The original Chrome guard and UI source manifest
are unchanged. A mode0777 observation is never repaired into an admission.

Only typed command/installation JSON receipts are published. Private command
output, DEB, payload, HOME, keyrings and fixture credentials remain excluded.
The ten source tests do not qualify an installed browser, sandbox or UI session.

## Authentication refusal and diagnostic follow-up

The actual 9c9d61f push run 43860529318 refused in authenticate with
status_bad, before installation and the UI. Three supervised commands returned
zero with reaped/drained frontend receipts. Their private GPG output was not
exported, so no particular BAD status, key expiration or signature result is
inferred. All browser assertions remained unexecuted.

The follow-up writes a bounded, typed GPG diagnostic before passing the original
unchanged status to the existing strict validator. It contains only closed status
names, counts, framing/budget flags and expected-key state labels; raw key
fingerprints, UID, arguments, stderr and private output remain excluded. This
diagnostic cannot authorize authentication or installation. The original BAD
predicates, package bytes, supplier metadata, Chrome permissions and UI guards
remain unchanged. Fifteen bootstrap pure tests and fourteen UI contracts pass;
independent review adds four adversarial cases to the fifteen. Actual GPG and
Chrome qualification still require a new Linux receipt.

This branch now incorporates the runtime composition from PR #19, including its
one-line Expat SDK C-header dependency fix. Its earlier 293 selected pure tests
passed before the diagnostic delta; the changed bootstrap and retained UI tests
were rerun afterward. Native image qualification, all remaining High findings,
SSH/RDP browser execution and complete P1-G remain open.


### ADR034 selected-signer certificate candidate (SOURCE/LAB only)

The new purpose is `google-release-selected-signer-certificate-v1`; the original
vendor key, Release/signature/Packages and `chrome_gpg.py` remain byte-exact.
`chrome_key_scope.py` checks finite public packet DATA and signed-block lineage,
then both supervisors independently run the unchanged strict GPG predicates on
the derived subject. This does not qualify the historical whole-certificate
verification. See [ADR034](../../docs/adr-034-google-certificate-scope.md).

The native preflight is mandatory before download/package/install. R2 connects
the separately reviewed NSS TEST producer R3, purpose/2, six immutable public
buffers, to an independent native consumer. Actual signature identity, key dates,
future/expiry and revoked-subkey state must be received in Linux; source test
success cannot admit them. The17-row receipt explicitly separates native crypto,
native state/authority guards, DATA guards and models; all_rows_are_native_crypto
is false. Read ADR034 for exact coverage and limits. R1 remains frozen INCOMPLETE.

The TEST-only owned agent is foreground/supervised, with180s total,150s work and
30s cleanup on the dedicated Ubuntu24/Python3.12 profile. It may create synthetic
private keys only in its fresh private home, remove its owned socket and private
tree, and return public buffers only after confirmed cleanup. No autostart,
global kill, weak flags, BAD suppression, key server or production authority is
introduced. The Google key, Release, signature, Packages and001d predicates stay
byte-exact. Root reauthenticates the selected Google subject independently.

The CI hunk retains40min/job,15min/bootstrap,870s/frontend,450s/root,480s/rootcall,
and600s+60s/browser. Every negative lane shares the frontend deadline and keeps
UNKNOWN sticky. Only fixed typed metadata/H1 JSON and the six public TEST files
are uploaded; homes, UID, stderr and raw status stay private. Real GPG/agent,
installation, browser/UI/native SSH/RDP and product qualification remain PENDING.

## Hosted runner sandbox comparison

The hosted runner matrix checks the same authenticated Chrome 158 package,
staged tree, driver pin and non-root network isolation on Ubuntu 22.04,
24.04 and 26.04. Each receipt identifies its runner and kernel. It records
the public user-namespace settings and a temporary user-namespace creation
check with the same dropped privileges as the browser.

The control records whether the worker can create one user namespace. The
Chrome verdict still requires the genuine namespace sandbox and renderer
checks. Differences between runners establish evidence about those runner
environments. Attribution to AppArmor would require matching effective policy
or audit evidence. The Ubuntu 22.04 job is a temporary diagnostic.
[GitHub runner lifecycle](https://github.com/actions/runner-images/issues/14254)

Each job publishes only its typed receipt. The application and its synthetic
user journeys are outside this comparison. A result applies to the exact
browser package and environment named by the receipt.

Run 45234729103 authenticated the same package and staged tree on all
three runners. Ubuntu 24.04 created a test user namespace, then refused
Chromium's sandbox at launch. Ubuntu 22.04 returned exit 1 from the
isolated launcher. Ubuntu 26.04 stopped at the canonical sudo role check.
The follow-up measures the launcher failure class and resolves only a
known sudo provider on Ubuntu 26.04. The original canonical role, mode,
ownership and digest checks apply to the executable before it runs.
[First comparison](https://github.com/pamolive/PamOlive-Platform/actions/runs/45234729103)
