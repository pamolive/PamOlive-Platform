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
the context receipt; drift refuses. Repinning changed inputs requires review.
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
