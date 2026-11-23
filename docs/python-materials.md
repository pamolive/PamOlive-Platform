# Linux Python materials (ADR021 partial integration)

This profile pins Python input **bytes** for CPython 3.12.16, regular cp312,
Linux amd64/x86_64 and glibc 2.41. It preserves the existing package versions,
including libpq 17.12 and Pillow 13.0.0. It does not change the development
`requirements.lock`, its Windows markers, or the existing host/build locks.
Those declarations remain covered by consistency tests.

The reviewed public manifest is `deploy/python-materials.linux-amd64.json`.
It is an input to the reviewed recipe, not an independent authority. Both its
`build_verified` and `attestation_verified` fields are false. This change grants
no vulnerability exception, production qualification, reproducibility claim,
or expansion of the four Kerberos ELF deltas permitted by the existing policy.

## Closed input sets

| File / role | Materials | Destination |
| --- | --- | --- |
| `requirements-python-runtime-linux.lock` | 26 upstream application wheels | runtime |
| Existing `requirements-bootstrap.lock` | pip 26.3 wheel | builder and runtime |
| `requirements-python-build-tools-linux.lock` | setuptools 84.2.1, wheel 0.48.0, packaging 26.3 | builder |
| `requirements-python-native-sources-linux.lock` | psycopg-c 3.2.10 and python-ldap 3.4.8 sdists | builder |
| `requirements-python-native-test-linux.lock` | Pillow 13.0.0 wheel | native-test only |

There are 32 unique public files: 30 wheels (including Pillow) and two sdists.
`packaging` is one of the 26 existing runtime dependencies and also a build
tool; its single reviewed file serves both roles. `setuptools` and `wheel`
inputs, source archives and Pillow wheel bytes are never copied into a runtime
image layer. The runtime receives exactly 27 upstream wheel files (26 plus pip)
and two locally produced C wheels. Proof JSON and lock declarations can name
builder inputs without containing or installing their artifacts.

These counts describe unique input files. The later [ensurepip overlay](ensurepip-bundle.md)
also copies the same approved pip wheel to the runtime bootstrap bundle; it
adds no new unique input and preserves the base's historical layers.

Input locks contain only named version pins and SHA256 hashes, with no direct
URLs or environment-dependent resolution. The manifest closes names, versions,
roles, file kinds, target and source inventory paths. Official public wheel tags
were reviewed for the explicit Linux target; the Windows host's tags are not
used. The helper also checks target interpreter, platform, glibc, debug/GIL ABI
before acquisition and capture in the builder. Pip enforces wheel compatibility
again during the offline install. A future target change requires review of the
profile, not automatic host-dependent selection.

Pillow's selected upstream file is
`pillow-13.0.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`,
7,144,542 bytes, SHA256
`42d63be3af4f9b951b199b0a9d23365d37ab14687e6d77b74940432c8515c4ca`.
The primary release metadata is [PyPI Pillow 13.0.0](https://pypi.org/pypi/Pillow/13.0.0/json).
The other 31 files derive from the independently reviewed ADR021 material
candidate of 2026-11-14. Dependency metadata for that explicit target closed all
28 existing runtime distributions; wheels may contain further bundled native
code, for which this profile makes no exhaustive SBOM coverage claim.

## Acquisition and budgets

The `directory-builder` first provisions its existing LDAP/SASL/compiler/libpq
SDK packages. Only then does `python_materials.py acquire` fetch the public files.
It uses stdlib HTTPS with hostname and certificate verification, no ambient
proxy or authentication handler, no Authorization/Cookie, and only the exact
`files.pythonhosted.org` origin. URLs must be canonical ASCII HTTPS paths with
the approved filename, without userinfo, port, query, fragment, percent escapes,
whitespace or traversal. Redirects are refused before a second request, and the
returned origin/status are checked as well. No backend or downloaded module is
imported or executed, and no archive is extracted during acquisition.

Budgets are: 256 KiB JSON, exactly 32 distinct public inputs, at most 32 MiB per
input and 64 MiB total reviewed compressed input bytes. Reads use at most 64 KiB
chunks; HTTP Content-Length (when present), exact byte count and SHA256 must all
agree before use. The opener timeout is at most 30 seconds and the remaining
budget. Each file shares one five-minute monotonic budget across all attempts;
the full acquisition shares a thirty-minute budget. Checks occur before opens,
before/after reads and after each download. These are cooperative deadlines:
DNS and an in-progress blocking transport call can overrun before control returns.
There is no hard wall-clock cancellation guarantee.

At most three fresh public GETs are allowed for explicitly typed timeouts,
connection resets/aborts, temporary DNS errors and HTTP 408/429/500/502/503/504.
Backoff is fixed at one then two seconds within the same budget; Retry-After,
redirects, resumed ranges, alternate hosts and credential handlers cannot change
the request. Certificate/TLS verification, changed URLs, encoding, byte count,
hash mismatches, filesystem errors and unknown errors are terminal. Every retry
starts with a fresh exclusive file and a new hash/count. A partial file is removed
only when its original regular-file identity and parent identity still match;
replacement, links or uncertainty stop cleanup/retry and preserve the object.
These guards rely on the trusted build runner, not an atomic hostile-host sandbox.

Source decompression is capped at 64 MiB before tar metadata parsing; source
archives have at most 2,048 visible members, regular files/directories only,
bounded names and no duplicate, absolute, traversal or link entries. Archive
bytes are checked before inspection. The source maps must contain the exact
reviewed C/header/setup/backend/metadata paths: nine for psycopg-c and 24 for
python-ldap, each with its reviewed hash. The complete archive hash binds all
other files too. No `.pyx` file is accepted in these reviewed sdists. The three
pre-generated psycopg C sources (`_psycopg.c`, `pq.c`, `types/numutils.c`) are all
recorded; they produce two extensions. The LDAP C/header set is recorded too.
Decompression uses the same bounded byte buffer whose source hash was checked.

## Qualification des compilations natives Python

Le banc Linux amd64 reconstruit les deux roues depuis les sdists et les outils
épinglés. La compilation hors réseau s'exécute avec l'UID 65534. La sonde
enregistre les fichiers C, les objets, les dépendances d'en-têtes et la carte
du lien GNU. Le vérificateur rapproche les sommes de chaque objet avec les
fichiers source recensés. Pour les trois extensions, la sortie du lien doit
avoir la même empreinte dans la roue et dans l'installation hors réseau.

Les jeux de preuves incluent les versions des SDK Debian, les identités des
outils sélectionnés par GCC, le manifeste des roues et les traces bornées.
Les empreintes d'en-têtes et d'entrées de lien sont relevées après chaque
appel. Le résultat suppose l'intégrité du runner et des backends épinglés.
Le reçu reste une observation du banc avec les SDK Debian d'origine. La
candidate PamOlive doit établir ces mêmes liaisons avec ses SDK reconstruits
et son archive exacte. Le résultat du scan GCC reste soumis à cette validation.
Upstream inspection and additional role copies use their checked buffer too;
generated-wheel inspection uses exactly the buffer hashed in its per-run record.
This avoids a hash/parse mismatch on reopening a path. A compromised runner can
still change files later; offline pip hash checks and the future exact-artifact
and runner verification remain required.

Wheel directories have exact counts and regular, nonlinked files. ZIP inspection
allows at most 4,096 entries, 32 MiB per entry and 64 MiB expanded content, and
rejects duplicate/traversal/link/special paths. Runtime/bootstrap/native-test
upstream wheels and both generated wheels refuse `.pth` or `.pyc` entries with
an error requiring review. The reviewed builder-only setuptools wheel contains
`distutils-precedence.pth`; it is never in the runtime input set. These bounds
limit accepted payloads and retained reads, not the interpreter's total RSS.

## Offline build, install and per-run outputs

The next Dockerfile RUN has `--network=none`. It installs the pinned pip and
three build tools using named locks, `--no-index --no-deps --require-hashes`
and local role-specific directories. It builds only the two pinned sdists with
`--no-build-isolation --check-build-dependencies --no-index --no-deps
--require-hashes`, using those preinstalled tools. There is no fallback index,
backend dependency installer, Cython download, alternate version or extra APT
library. Missing dependencies or build failures abort the build.

`--check-build-dependencies` checks the static build requirements. It is not a
verification of every dynamic backend hook: pip with `--no-build-isolation`
does not provision dynamic hook requirements. The exact psycopg sdist contains
pre-generated C and lacks the `.pyx` trigger for its optional Cython hook;
python-ldap uses setuptools. Both exact source inputs were statically reviewed
without invoking their backends. Those backends execute only in the offline
build RUN. If a hook requires an undeclared tool or attempts provisioning, the
build must fail; the remedy is independent material review, never network
fallback. Network isolation alone does not authenticate the builder.

`capture-derived` then rechecks source archive and source-file hashes and accepts
exactly two output wheels with exact package/version, cp312-cp312-linux_x86_64
filename and WHEEL metadata. Their extension sets must be precisely the two
psycopg extensions and `_ldap`. It checks ELF64/little-endian/current-version,
ET_DYN and x86_64 machine headers. This header check does not prove ABI behavior,
compiler provenance or linkage safety.

It emits two outputs in a fresh evidence directory:

* `requirements-python-derived-linux.lock`: named hashes of the two **current
  run's wheel bytes**, never a universal expected binary hash.
* `derived-manifest.json`: input manifest hash, both archive hashes, all reviewed
  source-file hashes, exact generated wheel names/sizes/hashes, and the hashes
  and sizes of the three ELF files inside those wheels. The verification and
  attestation fields remain false.

The public manifest and all five input locks accompany that evidence under
`/usr/share/pamolive/python-materials` in the runtime. Runtime installation is
another `--network=none` RUN with `--no-index --only-binary=:all: --no-deps
--require-hashes`, named upstream and per-run native locks, followed by
`pip check`. All profile installations use `--no-compile`; existing bytecode in
the pinned Python base remains untouched. Native-test separately installs only
the pinned Pillow wheel under the same offline/hash constraints. The install
files are removed in their installation RUN, but no claim is made that COPYed
wheel bytes disappear from earlier image layers. No source archive or additional
builder wheel is copied to those layers.

The per-run sidecar is not self-referential: a later qualification must bind
its bytes to the exact final image, archive and reviewed recipe, and verify
installed files and runtime behavior. It does not authenticate itself by
asserting its own output hashes. APT signed indices/package closure, compiler
materials, runner provenance, complete filesystem origin coverage and a real
workflow attestation are still missing requirements of the broader ADR021
chain. Existing scans, ELF policies and untriaged High findings remain binding.

## Review commands (no Docker or network required)

```powershell
.\.venv\Scripts\python.exe -B deploy/python_materials.py check-locks --manifest deploy/python-materials.linux-amd64.json
.\.venv\Scripts\python.exe -B -m unittest tests.test_python_materials tests.test_python_materials_resilience
.\.venv\Scripts\python.exe -B -m ruff check --no-cache deploy/python_materials.py tests/test_python_materials.py tests/test_python_materials_resilience.py
.\.venv\Scripts\python.exe -B -m ruff format --check --no-cache deploy/python_materials.py tests/test_python_materials.py tests/test_python_materials_resilience.py
```

The CLI has `acquire`, `capture-derived` and `check-locks` commands; use `--help`
for flags. Acquisition and capture reject a non-target host. Unit tests use
explicit target data, local in-memory archives and mocked HTTP only. No real
build was run to validate this integration before coordinator review. Root must
first commit the reviewed input recipe/context, then run a new exact production
and native-test build, inspect the generated evidence and installed inventories,
and repeat the required native/PAM/P0 and scan gates for that new subject.

The transport-only resilience change follows the measured TLS-handshake timeout
in push CI 43707121106 of `6c17536`; that log does not identify the exact endpoint
or material. The original 18 tests remain byte-identical; 18 new synthetic tests
exercise retries, terminal failures, budgets and file ownership, with seven more
independent counter-tests. No new real download/build success follows from these
mock tests. The security workflow includes the new module. The public-verifier
acquisition's explicit gate pin and its selected-source/assets/workflow pin chain
are refreshed together; material bytes, package versions and locks are unchanged.


## Historical public-digest review decisions

The transport update replaces 18 occurrences of nine public file SHA256 pins.
Their former baseline identities are absent from the corresponding current files.
The strict scanner returned code 3 while removing precisely these stale identities
from its temporary copy; code 3 is not accepted as a CI success. Only these 18
identities are retired from the active baseline. All other 2,541 entries and all
detector/filter settings remain identical. The final scan must include this archive.

The full original baseline remains in commit
[6c17536](https://github.com/pamolive/PamOlive-Platform/blob/6c17536e95974ec8472d537500b46983d1bffb02/.secrets.baseline),
SHA256 `937088320c6a362e6b88180b59b0a7c786d6077dd58f2568baa43d3754ed66b6`.
The following is the explicit archive of the retired decision metadata and its
public preimage. Each row has detector type `Hex High Entropy String`,
`is_secret=false` and `is_verified=false` (no network verification).
The line number refers to the original file in that exact commit. The detector
identifier is SHA1 of the displayed public SHA256, not an authentication secret.
This historical classification does not exempt a future reappearance.

| Filename | Historical line | Detector identifier | Public SHA256 preimage | Hashed public file at 6c17536 |
| --- | --- | --- | --- | --- |
| `.github/workflows/p2-public-verifier.yml` | 17 | `1b33b76db816291cff72045cd8ee6d25441125c8` | `5995e3852d3793609420277abcea65e5d2730f1085acfaaac58bbc1b4660d419` | `qualification/p2_installed_ci/source-checksums.sha256` |
| `.github/workflows/p2-public-verifier.yml` | 18 | `e107e9fda456ccc991c7e72b4060c264919d6ffb` | `4124bff9afa21db723b53c2e3a9467772a553d04b39598fb56d550ee0e9d5d29` | `qualification/p2_installed_ci/assets.json` |
| `qualification/p2_installed_ci/assets.json` | 30 | `1941f8afed3e12ad5ca7cebdd1723b1f62267e70` | `d6213ab785eb41bd3e852583bad2ef764af1bed4d2f26e327da684c2dede46e2` | `qualification/p2_installed_ci/pins.json` |
| `qualification/p2_installed_ci/assets.json` | 34 | `70aefa1289e7ef5359c71f3429ee72464428cff6` | `3ae3ecdb26194afb49c8b7fc61e288b81f5f725656c54ad311227f70ff6427f5` | `qualification/p2_installed_ci/selected-inputs.json` |
| `qualification/p2_installed_ci/pins.json` | 26 | `70aefa1289e7ef5359c71f3429ee72464428cff6` | `3ae3ecdb26194afb49c8b7fc61e288b81f5f725656c54ad311227f70ff6427f5` | `qualification/p2_installed_ci/selected-inputs.json` |
| `qualification/p2_installed_ci/plan.json` | 155 | `1b33b76db816291cff72045cd8ee6d25441125c8` | `5995e3852d3793609420277abcea65e5d2730f1085acfaaac58bbc1b4660d419` | `qualification/p2_installed_ci/source-checksums.sha256` |
| `qualification/p2_installed_ci/plan.json` | 165 | `6134b98f67d64b26fe4c5ac74f697f3cbc7143ca` | `c8cede850d78586bc7e4b9459a90bcb66be81b96ca9da9a7d09854db1c0943c3` | `qualification/p2_installed_ci/workflow-template.yml` |
| `qualification/p2_installed_ci/plan.json` | 132 | `70aefa1289e7ef5359c71f3429ee72464428cff6` | `3ae3ecdb26194afb49c8b7fc61e288b81f5f725656c54ad311227f70ff6427f5` | `qualification/p2_installed_ci/selected-inputs.json` |
| `qualification/p2_installed_ci/plan.json` | 19 | `e107e9fda456ccc991c7e72b4060c264919d6ffb` | `4124bff9afa21db723b53c2e3a9467772a553d04b39598fb56d550ee0e9d5d29` | `qualification/p2_installed_ci/assets.json` |
| `qualification/p2_installed_ci/selected-inputs.json` | 1427 | `63f9eca77af2ada011e8e8076aee8122e5f6285a` | `be36d6e49b0fc34b44e80e26f98427f618e4854aa6dc0be09707799e75720ed2` | `qualification/pam_trust_verifier/README.md` |
| `qualification/p2_installed_ci/selected-inputs.json` | 1435 | `6b0c7023df6709cda8447878021ea7c145f4bd00` | `bc65c92ffc630e302515f7abc2dae60617231dfbb134fd6d58a39f26e781f36e` | `qualification/pam_trust_verifier/acquisition-plan.json` |
| `qualification/p2_installed_ci/selected-inputs.json` | 1431 | `ab62af4a591bd3a939bc1b48d0ac4d8649355438` | `3ca08b0f4366de38e0bd278ddab6ec31cb1a378f98f8a7161ee335f5eb05d262` | `qualification/pam_trust_verifier/acquire_materials.py` |
| `qualification/p2_installed_ci/selected-inputs.json` | 1489 | `ecdfb1bd9fd8e74f92328bb4fd70d970720c95a6` | `13bb617e396ed5eaf62eb163dc653764668563013f21a1cb4d1eff5de0bf1d12` | `deploy/python_materials.py` |
| `qualification/p2_installed_ci/workflow-template.yml` | 17 | `1b33b76db816291cff72045cd8ee6d25441125c8` | `5995e3852d3793609420277abcea65e5d2730f1085acfaaac58bbc1b4660d419` | `qualification/p2_installed_ci/source-checksums.sha256` |
| `qualification/p2_installed_ci/workflow-template.yml` | 18 | `e107e9fda456ccc991c7e72b4060c264919d6ffb` | `4124bff9afa21db723b53c2e3a9467772a553d04b39598fb56d550ee0e9d5d29` | `qualification/p2_installed_ci/assets.json` |
| `qualification/pam_trust_verifier/acquire_materials.py` | 16 | `ecdfb1bd9fd8e74f92328bb4fd70d970720c95a6` | `13bb617e396ed5eaf62eb163dc653764668563013f21a1cb4d1eff5de0bf1d12` | `deploy/python_materials.py` |
| `qualification/pam_trust_verifier/acquisition-plan.json` | 15 | `ab62af4a591bd3a939bc1b48d0ac4d8649355438` | `3ca08b0f4366de38e0bd278ddab6ec31cb1a378f98f8a7161ee335f5eb05d262` | `qualification/pam_trust_verifier/acquire_materials.py` |
| `qualification/pam_trust_verifier/acquisition-plan.json` | 10 | `ecdfb1bd9fd8e74f92328bb4fd70d970720c95a6` | `13bb617e396ed5eaf62eb163dc653764668563013f21a1cb4d1eff5de0bf1d12` | `deploy/python_materials.py` |
