# Isolated installed public verifier check — integrated-source candidate

This controller targets the selected components/pam-trust-verifier tree, not
an external prototype. source_payload checks a pinned PAYLOAD-MANIFEST.json
closing every component file; there is no lookup/fallback for FREEZE.json,
MANIFEST.json, a sibling output directory, Django, app or source imports.
The source library, installed runner, process helper and public lock inputs
retain their reviewed origins. See the external candidate AST-DELTA and review
freeze for the explicit controller/source-document differences.

## Two separate explicit phases

acquire_materials.py uses only the pinned existing deploy/python_materials.py
from this checkout, its closed Linux manifest and lock checks, and exactly the
13 entries in materials-plan.json. It calls the maintained public HTTPS opener,
download and verify_file functions, then the adapter ZIP/RECORD checker. It does
not acquire 32 unrelated inputs, install anything, use credentials/proxies,
retry, fall back to an index or execute acquired wheel code. Each phase needs
its own reviewed plan hash. The output is a fresh external directory and a
reduced success/failure report; errors remain failures. No acquisition occurred
during this candidate preparation. A future CI must acquire its own inputs.

qualify_installed.py runs separately in a Linux environment whose network is
disabled externally. --no-index itself is not a network sandbox. It creates two
fresh --without-pip venvs, bootstraps hash-pinned pip26.3 in each, installs four
build/tooling distributions or nine runtime wheels plus pip, builds one own wheel
with --no-index --no-build-isolation --no-deps, verifies sources/licences/RECORD,
and installs that hash-locked wheel in the verifier venv. pip check is required
in both. Expected distribution totals are 4 build and 11 verifier.

Tests and fixtures are staged as siblings with no src. The unchanged r2 child
installs IO/import counters before package import, verifies installed origins
and exact six source files, then requires 30 methods with zero skips/errors/
failures and 20 current case matches. Its filesystem guard remains unchanged and allows only the
single exact exclusive report create in its final block. Swallowed forbidden
IO still fails through counters. These Python hooks do not prove native/OS
confinement. The old seven-wheel/two-package job is unchanged and supplies no
installed evidence for this package.

Target: nonroot Linux amd64 CPython3.12.16, regular ABI, glibc>=2.34. Linux cp312
materials do not qualify Windows or 3.13. A separate reviewed outer execution
profile must impose network none, RO source/controller/materials/root, caps0,
NNP, 1 CPU/512MiB and bounded private work permitting dlopen of hash-pinned
native wheels. This Python controller does not enforce that external profile.
Its reviewed IO helper retains at most 1MiB stdout/256KiB stderr per owned
child, with 120s after spawn and 900s total; failures and bounded prefixes remain.

Thirty existing adapter tests and twelve child-diagnostic tests form the exact
42-method pure gate, with zero skips and external attempts required. They
import no verifier/Django and run
no controller main, wheel backend, venv or pip. Popen/run/socket/DNS/HTTP are
prohibited in that suite; acquisition is exercised only with mocks. This new DAG requires Root and independent mapping review before integration
or a future installed CI attempt. Prior failed CI runs stay failed; no
installed success is transferred to this source mapping. Neither source nor installed results supply full
P0 acceptance, human independence, MFA/possession, action permission, release,
service or build-attestation authority. The selected CLI plans are
`acquisition-plan.json` and `adapter-plan.json`, in this directory. The external
development plan is not a runtime dependency. See
[ADR-023](../../docs/adr-023-public-pam-material-verifier.md) for the accepted
library scope and project fixture-notice decision.

From the checkout root, the separate public acquisition phase is:

```sh
python -I -B qualification/pam_trust_verifier/acquire_materials.py acquire \
  --plan-sha256 bc65c92ffc630e302515f7abc2dae60617231dfbb134fd6d58a39f26e781f36e \
  --repository "$PWD" --destination "$RUNNER_TEMP/public-verifier-thirteen-new"
```

After a separately reviewed outer runner imposes the profile above, the command
inside that allocation is:

```sh
/usr/local/bin/python3 -I -B /controller/qualify_installed.py run \
  --plan-sha256 46b9bc5562fc33a9c4081293ff5a6f002eca3714e0e209bbcd9b359e5832ccf1 \
  --source /source --materials /materials --work /work/public-verifier-selected-n0r1
```

These commands do not themselves create the outer allocation or export its
tmpfs evidence. Their presence is not a completed qualification or an execution
authorization from a plan field. Preserve failed runs; never reuse the work leaf.

## Bounded failed-child diagnostic r2

A reaped and fully drained probe-build or probe-verifier exit1 can retain
only a strict bounded typed child failure report at its fixed report path.
The parent still raises the original owned_process_failed error. Huge integer
elapsed_seconds values are range-checked before math.isfinite; diagnostics
cannot replace the original failure with OverflowError. No raw exception
message/log, unknown field or success-shaped failure is admitted. Existing
success validators, file guards and external counters are unchanged.

Run the pure gate from the checkout root, before acquisition:

```sh
python -I -B qualification/pam_trust_verifier/run_pure.py
```

This runs the 30 historical adapter methods plus 12 diagnostic methods,
not the 30 installed public-verifier methods. The latter require the
separate externally confined Linux execution; its cause of failure on
the ef1285 CI subject remains unobserved at preparation time.
