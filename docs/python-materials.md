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
agree before use. Each socket operation has a 30-second timeout; each file has
a five-minute deadline checked between reads, and acquisition has a 30-minute
deadline checked between files. Socket blocking may extend a deadline by at
most the current socket timeout. Output directories must be fresh; files use
exclusive creation, and failures do not delete preexisting files.

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
.\.venv\Scripts\python.exe -B -m unittest tests.test_python_materials
.\.venv\Scripts\python.exe -m ruff check deploy/python_materials.py tests/test_python_materials.py
.\.venv\Scripts\python.exe -m ruff format --check deploy/python_materials.py tests/test_python_materials.py
```

The CLI has `acquire`, `capture-derived` and `check-locks` commands; use `--help`
for flags. Acquisition and capture reject a non-target host. Unit tests use
explicit target data, local in-memory archives and mocked HTTP only. No real
build was run to validate this integration before coordinator review. Root must
first commit the reviewed input recipe/context, then run a new exact production
and native-test build, inspect the generated evidence and installed inventories,
and repeat the required native/PAM/P0 and scan gates for that new subject.
