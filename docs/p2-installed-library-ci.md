# Installed P2 library checks

The additional `p2-installed-libraries` CI job tests the two independent Python
libraries. It creates no Vault service, provider, ledger, authority, application
dependency or delivery exception. The installed-library job is appended with
`contents: read`, no persisted
checkout credential, no secret input, service, sudo or Docker invocation.
The existing security job separately audits the seven explicit build/test
versions using the three hash locks and includes both library `src` directories
in its existing medium/high Bandit gate. Its thresholds are unchanged. The audit
report is retained alongside the existing application/security reports.

The profile is Linux x86_64, regular CPython **3.12.16**, glibc 2.34 or later in
the 2.x family. It uses Ubuntu24.04 and the pinned setup-python action. These
checks do not generalize cp312/cp311-abi3 manylinux wheel hashes to Windows,
CPython3.13, free-threaded Python or another architecture. This is a separate
seven-wheel test profile: the existing32-material builder and its stricter
glibc2.41 target validation remain unchanged.

## Inputs and three environments

The explicit acquisition phase selects seven public wheel records from the
reviewed Linux manifest: pip, setuptools, wheel, packaging, cryptography, cffi
and pycparser. The existing stdlib acquisition/verification functions enforce
public HTTPS/no redirects, size and SHA256 before execution. Existing bootstrap
and build-tool locks are reused. The new `requirements-p2-test-linux.lock`
contains only cryptography50.0.2/cffi2.1.1/pycparser3.12, with exactly the hashes
already present in that manifest and runtime Linux lock. No sdist is acquired
or compiled for these test dependencies.

Three fresh venvs use `--without-pip`; pip must be absent first. Each is
bootstrapped by executing only the already SHA-verified pip26.3 wheel and
installing `requirements-bootstrap.lock` with `--require-hashes --no-index
--no-deps --only-binary`. The pip wheel is not a network bootstrap script.
Bootstrap alone uses `--ignore-installed`: the executing zip wheel must not be
mistaken for an already installed distribution. This follows an explicit
empty-venv/pip-absent check and targets that venv, never the base interpreter.

| Environment | Exact distributions after setup |
| --- | --- |
| build | pip26.3, setuptools84.2.1, wheel0.48.0, packaging26.3 |
| envelope test | pip26.3, pamolive-vault-envelope0.1.0a1, cryptography50.0.2, cffi2.1.1, pycparser3.12 |
| contracts test | pip26.3, pamolive-vault-contracts0.1.0a1 |

The build environment runs `pip wheel --no-index --no-build-isolation --no-deps`
on private copies of each component. A missing backend dependency fails rather
than being provisioned. Exactly one `py3-none-any` wheel per library is accepted;
native extensions, `.pth`, bytecode, duplicate/unsafe archive entries and budget
overruns are refused. Current-run wheel hashes form separate local install locks;
they are outputs, not fixed expected binary hashes or signed authority.

Only the produced wheel and explicitly locked dependencies are installed into
each test environment. Every interpreter has `include-system-site-packages=false`,
a distinct prefix, no user-site fallback and exact distribution metadata.
Imports of pip/the library must resolve inside that venv. Django, application
packages and provider/database SDKs must not be importable. The job installs no
system compiler or SDK; it does not claim that the hosted runner has none.
All three environments run `pip check`.

## Tests exercise installed code

The25 envelope and17 contract tests are copied unchanged into an isolated test
directory, including the fixed golden files. No `src` directory exists beside
those staged tests. This matters because the contract tests insert that sibling
path: running them in the checkout could otherwise select source code instead
of the installed wheel. The runner prechecks the imported package path, then
runs the real unittest suites, requires the exact counts and refuses skips.
The envelope import subprocess also finds the installed package without
`PYTHONPATH`. No product test or library is changed to make packaging pass.

Build/test subprocesses receive a small environment without GitHub/application
credentials or Python path overrides. Package acquisition is a distinct online
phase; all later pip calls use no-index/no-deps and local hash locks. These flags
control pip's resolver, not the hosted runner's network namespace. The job is
ordinary non-root hosted execution, not an isolation proof against the runner
administrator or a malicious build process. GitHub's runner is part of its TCB.

## N0 review and limits

An external, frozen controller can execute the **same embedded CI controller**
against the exact existing R8-r2 image. It verifies the32 existing local public
materials, selects seven, freezes source/controller hashes, then uses one new
container with UID1000, root read-only, network none, dropped capabilities,
no-new-privileges, CPU1, RAM/swap512MiB, pids128 and a bounded192MiB `/tmp`.
The tmpfs needs executable mappings for the reviewed cryptography/cffi wheels;
`noexec` would prevent their ELF `dlopen`. Source, public wheels and controller
are bind-mounted read-only, with only a new evidence directory writable. No
existing Core venv, product wrapper or service configuration is modified.
The local profile therefore specifies `exec` explicitly:
`/tmp:size=192m,mode=1777,exec,nosuid,nodev`. A kernel mount observation of the
single `/tmp` publishes tmpfs/nosuid/nodev and absence of noexec before the payload;
the first r3 attempt omitted explicit exec and failed at ELF import, not the suites.

The N0 controller and commands are maintained outside the repository under
`C:/Users/Cy24/Documents/PAM/output/`. Preparation is not execution: Docker,
package builds and tests require a separate explicit Root allocation after
review. The local R8-r2 base's global Django/application packages remain on disk;
the isolated test venvs must prove they cannot import them.

The JSON evidence keeps `build_verified=false`, `attestation_verified=false`
and `authority_created=false`. Passing these tests proves installed-library
behavior in the reported profile, not KMS/HSM operation, independent authority,
durable replay protection, P2 service isolation, a signed build, F1 delivery or
production readiness. F1 image scans and their unresolved findings remain gates.

## Local installed-wheel result, 14 November 2026

The frozen inline controller was executed on the R8-r2 local image with the
source snapshot from integration merge `4c9cd2b` and the explicitly hashed CI,
minimal lock and document candidates. This is not execution of the whole GitHub
workflow or its network acquisition phase, and does not qualify a new image.

The first run, `p2-installed-n0-20261114-r3`, built and installed both wheels and
passed three `pip check` calls, then failed to map cryptography's native library
from the temporary filesystem. No library tests ran and none are counted as
passing. That failed run and its stopped container remain retained.

The new one-use run `p2-installed-n0-20261114-r4` adds an explicit `exec` mount
option in the external test controller. Before the unchanged CI payload starts,
a kernel mountinfo observation confirms one `/tmp` tmpfs, `rw,nosuid,nodev`,
192 MiB and no `noexec`. The product runtime configuration is unchanged.
Both libraries then pass their unchanged installed-wheel suites: **25 + 17
tests, zero skips**. All three environments have the exact distribution sets
listed above, pass `pip check` and reject global application/SDK imports.
The container exits zero, is stopped, reports no OOM and preserves other resources.

A separate local check audits all seven explicit material versions with strict
no-deps/disable-pip: seven packages, zero reported advisories. Bandit on the two
source directories returns zero findings and zero errors at the existing
medium/high threshold. These are bounded checks, not exhaustive dependency or
service qualification. The full updated workflow and candidate still require CI.

References: [GitHub job permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions),
[job/container execution](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container),
[pip wheel options](https://pip.pypa.io/en/stable/cli/pip_wheel/).
