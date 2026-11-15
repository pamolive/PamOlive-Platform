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
No actual Linux build or installation has yet been received for this integration.

The workflow must check the source checksum list before invoking Python, then
capture exactly 35 files from the actual component paths using `capture_inputs.py`.
The generated `inputs/` and `checkout-capture.json` are ignored by Git. There is
no second committed implementation. Every selected byte must match the pinned
payload manifest, including the contracts license metadata and root notice.
The capture finishes its source checks before writing a new destination, refuses
an existing destination, and rechecks source and copy after writing. A partial
or changed copy never yields a successful receipt.

Before allocation, run the closed 55-test harness, the separate seven capture
and six startup tests, and the existing 17 wheel DATA tests. Acquire 16 hash-pinned public
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
