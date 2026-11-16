# Public containerd prerequisites for the disposable CI runner

This extends the shared collector published at 4671f6f (parent collector SHA256
`a35f8f55e9086ef7171acfb385ccd71d51cc54cfd41bda7b2acc65ff739b7e9c`).
It is for one disposable GitHub-hosted Platform job, after Root and independent
review. The existing Platform workflow wires it for a bounded trial; this is not an A1/WV profile or operational GO.
No live Docker, sudo, ctr, filesystem-root probe, SQL or network action was run
while preparing this candidate. All process/FD tests are doubles.

The existing four nonroot Docker queries retain their commands, socket, closed
environment, output caps and H1 supervisor. Their version/info templates add
only containerd Version/GitCommit from Server.Components and Containerd
Address/Namespaces. Other components are excluded in the template. Unexpected
values are redacted without their hashes or lengths. Image projections and
their presence semantics are unchanged.

Root explicitly permits one sudo -n child solely for public read-only metadata
in that disposable VM. This exception does not authorize a PC or NAS probe.
The entry point now requires the explicit scope flag shown in the integration
fragment; the flag records the caller's decision, it does not attest the host.
The bootstrap TCB is the accepted GitHub runner image, pinned checkout/setup
actions, reviewed source, system Python/stdlib, sudo/env, Docker and containerd.
Observed hashes and version declarations are not reproducible-build proof.

## Exact ecfe reception and the next source correction

Both exact ecfe Platform jobs received their four nonroot Docker queries but
refused before recording the initial sudo/env/Python tools. No root child,
ctr CLI version, storage export or filesystem capacity was observed. The public
**daemon** containerd version2.4.2 is not evidence of the CLI version.

The new source chooses the explicit regular executable `/usr/lib/cargo/bin/sudo`,
never a resolved alternative or fallback. Official [Ubuntu sudo-rs packaging](https://packages.ubuntu.com/resolute/sudo-rs)
[alternatives and scripts](https://archive.ubuntu.com/ubuntu/pool/main/r/rust-sudo-rs/rust-sudo-rs_0.2.13-0ubuntu1.2.debian.tar.xz)
identify that target; this is packaging evidence, not a stat of either CI VM.
The [0.2.13 source](https://archive.ubuntu.com/ubuntu/pool/main/r/rust-sudo-rs/rust-sudo-rs_0.2.13.orig.tar.gz)
supports `-n -- <command>`. Parents, regular type, link count, ownership, size,
held-FD/path identity and hashes remain checked before/after. Missing or unsafe
tools refuse. A closed phase/predicate code now identifies a refusal without
raw exceptions, unexpected paths or private values. Partial tools never imply
COMPLETE, and a post-spawn failure remains UNKNOWN with the durable intention.

The exact additional CLI2.4.2 policy follows [its local version printer](https://raw.githubusercontent.com/containerd/containerd/v2.4.2/cmd/ctr/app/main.go),
[urfave3.11 version handling](https://raw.githubusercontent.com/urfave/cli/v3.11.0/command_run.go),
[NewClient suppression](https://raw.githubusercontent.com/containerd/containerd/v2.4.2/cmd/ctr/commands/client.go),
[Plugins command](https://raw.githubusercontent.com/containerd/containerd/v2.4.2/cmd/ctr/commands/plugins/plugins.go)
and [separate service paths](https://raw.githubusercontent.com/containerd/containerd/v2.4.2/plugins/services/introspection/local.go).
No vendor suffix, unexamined2.4.3, positional `version`, Server/UUID or runtime
inspection is admitted. Environment, filters, caps and nested H1 are unchanged.
36 local pure tests and six independent countercases pass; a new real trial
remains necessary. No operating profile or image/PGDATA authority is learned.

## Closed root read

Before sudo, the parent measures the actual regular root-owned nonwritable
`/usr/lib/cargo/bin/sudo`, `/usr/bin/env`, `/usr/bin/python3.14`, then checks them again
afterwards. The fixed 3.14 path matches the observed Ubuntu 26.04 job image
and its [documented system Python](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2604-Readme.md);
a missing or incompatible executable refuses the observation.
It invokes the real interpreter explicitly; the usual python3
symlink is neither rejected as an executable nor accepted as an arbitrary
resolved target. No PATH search is used. Source pins are checked before use.
The root Python program is passed as a closed -c argument made from the pinned
bounded_io bytes and containerd_public bytes, so it does not reopen a mutable
checkout script as root. env -i removes sudo's generated environment before
Python starts; -I -B -S disables site/user/import-environment hooks. The root
program requires exactly PATH, HOME=/nonexistent, LANG=C, LC_ALL=C.

The root child measures `/usr/bin/ctr` before, between and after these calls:

1. `ctr --version`, the local global flag, with a 3s work limit and 512B/1KiB caps.
2. Only for the examined CLI declarations 2.2.3/v2.2.3 or 2.4.2/v2.4.2, the closed command
   `ctr --address <allowed> --namespace moby --connect-timeout 3s --timeout 5s plugins ls --detailed`
   with three fixed Type/ID filters, 8s work limit and 32KiB/4KiB caps.

The daemon version and CLI version are separate fields. A different valid CLI
version is retained with its tool digest and typed refusal, but Plugins is not
called. A version declaration alone does not authenticate binary/source identity.
The runner/tool bootstrap TCB is explicit. Sources v2.2.3 and v2.4.2 have been examined;
no permissive vendor/version suffix or runtime profile is learned.

`CONTAINERD_SUPPRESS_DEPRECATION_WARNINGS=true` is set explicitly for both ctr
calls. This is necessary: NewClient otherwise calls Introspection.Server for
deprecation warnings. The positional `ctr version` command is forbidden because
it also calls Server. No Server/UUID/configuration API or private config read is
used. The plugin filters are OR between three arguments, AND within each one.

Detailed stdout is bounded and parsed only in memory. Exactly content/content,
snapshotter/overlayfs and metadata/bolt must occur once, without Error headings.
Only the content root, snapshotter root and metadata meta.db path are projected.
Other exports and ancillary fields are discarded, never dumped or hashed.
Endpoint and path allowlists are source policy, not observations: see ENDPOINTS,
BASES and TYPES in containerd_public.py. Unexpected paths are refused before any
open/stat, with no path disclosure. There is no fallback to guessed defaults.

## Actual storage objects and lifecycle

capacity() is a small reusable A1/WV function. It walks held directory FDs with
O_NOFOLLOW, checks object type before opening, compares inode/type after open,
and calls fstatvfs on that same FD. For metadata it opens meta.db itself, not an
assumed parent filesystem. It reads no file content, writes no file, follows no
symlink and creates no directory. The Docker root is measured separately. Free
space is available blocks times fragment size; shared filesystem capacities are
not added. These are point-in-time facts about exported objects, not reserved
space, durable path immutability or a proof that all daemon storage is covered.
There is no inference from DockerRootDir's device to containerd's true root.

The root child has a 25s internal SIGALRM work deadline; nested received H1 cleanup
may use up to 5s reap plus 5s drains. The parent allows 45s work plus the received
helper's cleanup reserve. Each existing Docker call remains 15s plus cleanup;
the proposed existing-job step cap is 4 minutes. The helper is byte-identical
98233b..., no replacement supervisor. No global kill, extra sudo, shell or retry.

Before spawn the parent fsyncs exclusive root-read-intent.json PENDING, then an
exclusive PID record when available, then actual final facts. UNKNOWN is durable
on exceptions. COMPLETE requires both nested ctr processes and the sudo frontend
to be confirmed exit0/reaped/drained, empty stderr, valid projections and stable
tools. Reaping sudo alone never proves descendants closed. A nonroot parent may
be unable to kill root descendants: timeout, failed kill/reap/drain or missing
nested facts remain UNKNOWN. The VM's teardown never means resources_released.
No release field or operational authority is emitted. The three lifecycle
journals must be uploaded alongside the projected report even after failure.

Permission refusal, unexamined CLI, data refusal and UNKNOWN are distinct. The
four legacy query receipt and new all_prerequisites_received are separate; no
redacted/missing root input can produce a complete prerequisite receipt. A
complete packet is public DATA only and does not commission an A1 or W/V profile.

## Primary sources examined

- [Docker separate containerd storage](https://docs.docker.com/engine/storage/containerd/).
- [Moby docker-v29.4.2 daemon info](https://raw.githubusercontent.com/moby/moby/docker-v29.4.2/daemon/info.go) and
  [containerd version component](https://raw.githubusercontent.com/moby/moby/docker-v29.4.2/daemon/info_unix.go).
- [ctr local VersionPrinter](https://raw.githubusercontent.com/containerd/containerd/v2.2.3/cmd/ctr/app/main.go),
  [version package](https://raw.githubusercontent.com/containerd/containerd/v2.2.3/version/version.go),
  [pinned urfave version dependency](https://raw.githubusercontent.com/containerd/containerd/v2.2.3/go.mod) and
  [global flag early return](https://raw.githubusercontent.com/urfave/cli/v2.27.7/command.go).
- [NewClient suppression guard](https://raw.githubusercontent.com/containerd/containerd/v2.2.3/cmd/ctr/commands/client.go),
  [Plugins CLI](https://raw.githubusercontent.com/containerd/containerd/v2.2.3/cmd/ctr/commands/plugins/plugins.go),
  [filter semantics](https://raw.githubusercontent.com/containerd/containerd/v2.2.3/pkg/filters/parser.go),
  [Plugins versus Server service](https://raw.githubusercontent.com/containerd/containerd/v2.2.3/plugins/services/introspection/local.go).
- [Content export](https://raw.githubusercontent.com/containerd/containerd/v2.2.3/plugins/content/local/plugin/plugin.go),
  [snapshotter effective root override](https://raw.githubusercontent.com/containerd/containerd/v2.2.3/plugins/snapshots/overlay/plugin/plugin.go),
  [metadata database export](https://raw.githubusercontent.com/containerd/containerd/v2.2.3/plugins/metadata/plugin.go).

Source review establishes the intended path for the named tags, not the actual
runner binary build or an observed result. Missing supported tools, unexpected
endpoint/path/version, insufficient privilege or unknown lifecycle remain a
closed receipt requiring Root review. The original d47 DATA did not measure any
of these missing fields. No previous success or build attestation is transferred.
