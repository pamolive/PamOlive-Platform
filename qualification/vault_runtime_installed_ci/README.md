# Installed Vault runtime qualification

This runner qualifies installation of the reservation runtime, separately from
the installed public verifier and the envelope/contracts libraries. It grants
no action or secret-release authority and does not migrate existing callers.

The source was integrated from the reviewed phase2 preparation (freeze
`351f8b0b0d01300d229a37857973872c3364329ba18985d6bee287bf1526892b`).
Its nine inherited helpers and 45 of the 46 selected source/data files remain
byte-exact. Root strengthens only `adapter_v2.runtime_prelaunch` after an
independent counterexample: -I does not suppress venv sitecustomize. Reserved
top-level sitecustomize/usercustomize module families are now refused before
each runtime Python invocation, alongside the existing PTH/PYC guards.
The original source-only results are 55 harness tests, not 52 installed runtime
tests. Root adds the real-checkout capture, seven adversarial capture tests and
six inert startup-hook regressions. No hook bytes are imported or executed.
The second CI subject `1e81df6` reached all three real wheel builds, installations,
RECORD gates and pip checks, then its 52-test child reported zero failures and one
error. This remains a failed campaign, without an installed52 success receipt.
The source staging contained six test fixtures but omitted the public
`integration/serve_lab.py` loaded by one original test; the missing-file boundary
is independently reproduced without executing a package or a build.

The workflow must check the source checksum list before invoking Python, then
capture exactly 36 files (29 build inputs plus seven fixtures) from the actual
component paths using `capture_inputs.py`.
The generated `inputs/` and `checkout-capture.json` are ignored by Git. There is
no second committed implementation. Every selected byte must match the pinned
payload manifest, including the contracts license metadata and root notice.
The capture finishes its source checks before writing a new destination, refuses
an existing destination, and rechecks source and copy after writing. A partial
or changed copy never yields a successful receipt.

Before allocation, run the closed 65-test harness, the separate seven capture,
six startup, eight mount-profile and six real-helper source tests, and the existing
17 wheel DATA tests. The original 52 runtime methods remain byte-exact. Acquire 16 hash-pinned public
wheels on the host, stage three closed read-only mounts, then explicitly pull
the pinned public Python S0. No registry credential or source checkout is mounted.
The inherited guard accepts only an ephemeral GitHub-hosted nonroot Linux runner,
an exclusive classic-store Docker daemon, at least 2048MiB effective available
memory and 4096MiB free storage at DockerRootDir. It refuses unknown storage or
ambient Docker/auth/proxy overrides. Windows Docker Desktop is not silently
substituted for that subject.

The only workload container uses user1000, init, RO root, no capabilities,
no-new-privileges, network none, private IPC, one CPU, 512MiB RAM/swap512,
128 PIDs and bounded tmpfs/logs. No network, volume, service, privileged account,
or database is created by the installed pure campaign. Existing containers are
never stopped, restarted or removed.

Sixteen bounded calls share a 900-second deadline: create two venvs without pip,
bootstrap the pinned pip, install four build tools offline, probe the build
environment, build and inspect three wheels, install their closed dependencies,
check pip and installed RECORD/metadata/license/SQL, then run the original
52 tests from the installed packages. PTH/PYC are refused before every runtime
Python invocation. Sources and installed files are rechecked afterwards.

Success requires all phases, three wheel/RECORD gates, both pip checks, the
guarded installed52 result, complete drain/reap, and confirmed container exit0
with OOMKilled false. Resource release is a separate observation. Failed early
phases export child:null rather than inventing a child result. Pending or unknown
ownership/IO remains unknown across cleanup; a second cleanup cannot heal it.

Always reconcile the same durable reservation after a successful preparation.
Upload only the public runtime/cleanup reports and checkout/material receipts,
never raw build logs, state, keys or source trees. No automatic second run after
failure. Receiving this campaign will not qualify SQL/mTLS, restore, a minimal
Vault image, build attestation, KMS, or independent secret release. Those are
separate gates. The application's 35 High groups remain blocking.

The seventh fixture is the exact public lab helper, not a production module added
to the runtime wheel. Its import leaves `sys.path` unchanged and does not import a
database driver. Only the explicit `__main__` startup adds the source path; psycopg
is imported lazily inside the returned connection callable. The installed child
still refuses every driver import before connection, and installs or stubs none.
An independent R2 counterexample found that the host helper tests still needed
Core's third-party environment. R3 also loads the RO slot reader only inside
`local_bytes`, and the real Uvicorn/application/TLS stack only inside `main`
after argument parsing. Import and manifest/connector validation use the actual
stdlib-only bounded module. All six source tests must pass with `-I -B -S`, with
no site-packages or dependency stubs. Operational startup still requires and
loads the actual reviewed libraries; installed52 keeps its separate environment.

Child schema `/3` requires `test_errors`, an array of at most eight unique pairs
of original52 test identifiers and closed exception-type enums. `addError` keeps
the error count but never formats the exception or traceback. Unknown/class-level
identifiers and excess diagnostics are omitted, not converted into invented test
methods; their errors still prevent success. No messages, paths, bodies or local
variables are exported. Old child `/2` is refused, including when rehashed. Empty
diagnostics are required for success; diagnostic observations never promote a
failed child or relax guards, profiles, RECORD, source or SQL bindings.

An explicit `transfer_verified_wheels` workflow dispatch can retain a private
handoff for a subsequent laboratory step in the same job. The existing
offline builder sends a bounded frame containing its normal success packet,
its exact installed-input descriptor and the three verified wheels. The host
checks the original success packet and bindings, then checks each wheel's size
and digest. It retains `verified-wheels.bin` with mode 0600 only after the
existing exit, reap and cleanup checks pass. The workflow uploads the public
report through its existing allowlist. The frame stays in the job's private
temporary directory, outside that allowlist. The default run keeps its original
packet protocol. The handoff only receives verified installation materials.
The PostgreSQL and mutual TLS laboratory has its own acceptance requirements.

The opt-in job then reopens the private handoff alongside both host cleanup
receipts. It revalidates the three archives against the checkout and builds a
separate test image with those exact wheels. Its database driver uses the
project's pinned psycopg 3.2.10 C source and Debian libpq 17.12. APT installs the
pinned Debian dependencies in the build stages. Wheel construction, installation
and verification run without network. The image stays in the ephemeral runner's
local store for the laboratory. This step performs no database connection or
mutual TLS exchange. [Dockerfile network modes](https://docs.docker.com/reference/dockerfile/#run---network).
