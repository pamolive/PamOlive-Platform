Candidate P2 public-verifier installed-library Linux CI runner, 2026-11-15.

R2 is a separate candidate, never a replacement of frozen2eec. Runtime found
four pure counterexamples in R1: the container had been removed, yet a client
Popen was unreaped or its drains incomplete and resources_released was true.
Qualification ok remained false. That R1/HOLD evidence is preserved unchanged.

R2 records each client attempt as PENDING in state.json BEFORE run_capped/Popen,
then replaces that row with its complete bounded facts. At most32 observations
are retained, with an exact total counter. No silent pruning or new client resets
history. Missing/malformed facts, abandoned pending records, count mismatch or
history overflow latch IO_uncertain=true permanently. A later cleanup can set
container_released=true while clients_released/resources_released remain false.
Global release requires confirmed container cleanup AND every past owned client
reaped with complete drains AND a non-uncertain pull. No-spawn observations with
spawn_attempted=false, no PID and no process/output facts do not invent a child.
Overflow/timeout/nonzero exit with confirmed reap/drains can release resources,
while qualification and the original failure remain false/preserved. Repeated
cleanup never heals historical uncertainty, even with a freshly loaded client.
The pending journal is durable against a process interruption; it is not an
attestation of host storage/power-loss durability or of daemon shutdown.

Repository integration, not an installed result. Before publication of this
candidate, only pure tests of data, mocked system boundaries and synthetic
protocol packets have run. The original frozen prototypes remain outside this
repository. Execution needs a separate Root decision after independent review;
execution_GO=false in the descriptive plan is not an authorization mechanism.

This is an adapter around the public V1 syntax/signature verifier candidate. It
grants no service authority, publication, membership, possession, MFA, counters,
human independence, Vault identity binding, full P0 acceptance or build attestation.

Inputs retain the a234 source review as origin, with its repository-style mapping
applied to the selected 366 files (component354 and qualification12). The current
selected-inputs manifest is pinned in pins.json. PAYLOAD-MANIFEST3628 and public
materials998489 remain unchanged (13 wheels,
8,939,939 bytes, nine runtime plus four build including pip). Source acquisition
uses the existing hash-pinned helper and its verified public HTTPS gate; no npm,
apt, package install hook, Docker credential or alternate index is introduced.

The workflow template first verifies its checksum file by a separately pinned
digest, then every runtime/test source. It checks all selected package, qualifier
and acquisition bytes BEFORE invoking the host acquisition helper. Host acquisition
is a separate phase with a fresh destination. Only verified public bytes become
the three read-only mounts. No checkout root, .git, socket, host profile or private
diagnostics enters the container. Only public-report.json is uploaded.

The concrete repository-style mapping updates selected-inputs, qualifier, adapter,
acquisition, checksum and workflow pins together, without OR/fallback acceptance.
The corrected mapping metadata is identified in plan.json. The bounded IO helper
changes only standard-library import order; the remaining style changes preserve
ASTs except the explicitly rebound file hashes. materials-plan998489 retains
exact200CRLF, preserved by narrowly scoped Git attributes. New pins, assets, plans
and checksum files use LF. Never normalize a pinned input silently.

The host guard admits only nonroot GitHub-hosted Linux CI, a fresh RUNNER_TEMP
work path and the fixed unix:///var/run/docker.sock. Ambient Docker context/auth/
config/proxy overrides are refused even when empty. CLI absolute bytes are hashed
as observed, not claimed authenticated by that hash. Fresh HOME and empty Docker
config are used. The daemon must have no active containers before pull/run.
Docker storage and host memory are measured independently. This first profile
supports only an observed classic store: containerd or unknown storage refuses.
It does NOT reuse the local Docker29 cache-manifest20215 profile or RepoDigest
assumptions. Source OCI manifest05a, raw config789 and all four diffIDs are distinct
typed pins. A future CI backend mismatch requires a new reviewed profile.

S0 is pulled by exact amd64 manifest only. The measured classic image ID must equal
raw config789, linux/amd64, four diffIDs, no configured Volumes. The container uses
--pull never; explicit --init; user1000:1000; RO root; no capabilities; NNP; network
none; private IPC; CPU1; memory512MiB with same swap ceiling; pids128; shm16MiB;
core0; Docker json log64KiB/onefile. Its command/env/init/group/log/resource/mount
profile is independently inspected before start and during cleanup. Three RO bind
mounts are /controller, /source, /materials. /work is tmpfs256MiB EXEC for new venvs
and native dlopen, uid/gid1000, mode0700. /tmp is64MiB noexec/nosuid/nodev.
The entrypoint also observes its own UID/GID/groups/caps/NNP and kernel mount flags.

Entrypoint bytes are passed by python -I -B -c, avoiding a fourth mount. It hashes
the qualifier buffer before compile/import. The original qualifier creates two
venvs without pip, bootstraps from the pinned wheel, builds and installs offline
with hash locks/no-index/no-deps, stages tests and fixtures together without src,
and checks exact distributions, installed bytes, guards and all30 test methods.
This wrapper does not alter its source or substitute signatures/validation.

Raw qualifier stdout/stderr is bounded8192B each; only an exact three-field summary
is admitted from stdout, stderr is discarded. The execution file is read once
with type/nlink/pre-size/fstat identity checks, maximum320KiB. Closed top-level
fields, JSON duplicate/depth/nodes/string/finite limits and forbidden raw-output
keys are checked. The parsed public execution plus raw-file SHA/size and summary
is streamed as one JSON packet <=480KiB to stdout and FLUSHED BEFORE exit, while
the /work tmpfs exists. There is no docker cp after exit. The host bounded attach
retains <=512KiB stdout/16KiB stderr; it validates the packet and all30/0/0/0,
20 case comparisons, exact guard counters, reaped children and input hashes.
Only metadata about that packet enters durable state; the host public report is
<=512KiB. Oversized report metadata produces a bounded failure retaining cleanup.

Durable reserve_create, owns, reconcile and remove are the unchanged legacy B0r2
functions, byte-pinned7f3. The private loaded module's LABEL is P2-specific; the
inspect projection changes only that label plus explicit command/profile fields.
The inherited '-stage0' suffix is only an internal container name, never a phase
or success assertion. P2 state/report/packet schemas and phase are distinct.
Bounded IO is pinned to the concrete repository helper98233. Work deadline900s and separate
cleanup60s apply; pull300s is separate. A lost create response is reconciled by
unique name+nonce+image+user+full profile. Missing/late/foreign/inaccessible objects
remain UNKNOWN; only confirmed owned objects can be stopped/removed. Prior failure
is never erased by cleanup; repeat cleanup preserves only previous confirmed
exit/OOM facts. Pull timeout does not prove daemon download stopped. The pinned
public image cache remains, and no global reset/prune/removal is performed.

These are technical controls inside a trusted ephemeral host/daemon/CLI, not an
attestation of those producers or an OS sandbox against the host administrator.
Python audit guards complement the container profile; neither is claimed complete
dynamic-loader/maintainer-script closure. Resource figures and identity facts are
not observed until a future run. Job cancellation/daemon loss can leave UNKNOWN.

Pure command ONLY (safe to review/replay after verifying frozen files):
CorePython -I -B <this-folder>/run_pure.py
No Node/Chromium/Django/P0/package-source import, real child, SQL or network is
allowed in pure tests. The AST contract test uses the fixed sibling qualifier in
this repository. The original prototype's fixed a234 sibling is only a test-data
choice in that prototype, never a runtime acceptance fallback.

Only owned4Python files use Core Ruff line100. Legacy7f3 keeps its reviewed
bytes/profile; IO98233 has the independently reviewed import ordering. Ruff checks MUST specify --no-cache for both
ruff check and ruff format --check; Python must use -B. Do not remove or ignore
.ruff_cache from a closed source manifest to make a failed check pass. Preserve
unexpected files as evidence and repair the producing step instead.

Repository integration: package payload unchanged; qualifier inputs rebound via the independently reviewed Root style map. The helper differs only in standard-library import order; its concrete hash is pinned. Current pins accept one concrete set, never old-or-new. H1 is corrected before real execution. No installed result is claimed by integration.
