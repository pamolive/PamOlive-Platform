#!/bin/sh
# Build-only harness. No runtime library/headers are installed by this script.
set -eu
exec python - "$@" <<'PY'
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import sys
import tempfile

PATCH = "e676f3727b3c984aa5a7baaafdb39394c8774c913ace0c3ce302e9b81aaa19ee"
p = argparse.ArgumentParser(description="Actual MIT ASN.1 object regression harness, build only")
p.add_argument("--source", type=Path, required=True)
p.add_argument("--build", type=Path, required=True)
p.add_argument("--phase", choices=("baseline", "patched"), required=True)
p.add_argument("--output", type=Path, required=True)
p.add_argument("--harness", type=Path, default=Path("/build-fixtures/krb5_asn1_regression.c"))
args = p.parse_args()
fd = None
stage = "structural"
diagnostic = {}

def require(value):
    if not value:
        raise ValueError("check_failed")

def sha(path):
    require(path.is_file() and path.stat().st_size <= 64 * 1024 * 1024)
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def limits(cpu, memory):
    def apply():
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def process(command, *, env, work, label, timeout, cpu, memory):
    """Bound subprocess output on disk as well as the diagnostic we publish."""
    global diagnostic
    diagnostic = {}
    output, errors = work / (label + ".stdout"), work / (label + ".stderr")
    timed_out = False
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        try:
            result = subprocess.run(command, env=env, stdout=stdout, stderr=stderr,
                                    timeout=timeout, preexec_fn=limits(cpu, memory))
            code = result.returncode
        except subprocess.TimeoutExpired:
            code, timed_out = None, True
    stderr_bytes = errors.stat().st_size
    with errors.open("rb") as stream:
        text = stream.read(4096).decode("utf-8", errors="replace")
    # Only trusted, synthetic builder inputs are supported. Keep qualification
    # roots out of diagnostics even when an operator chooses a different path.
    for path, replacement in ((work, "<scratch>"), (harness, "<harness>"),
                              (source, "<source>"), (build, "<build>")):
        text = text.replace(str(path), replacement)
    text = text[:4096]
    diagnostic = dict(returncode=code, timed_out=timed_out,
                      stdout_bytes=output.stat().st_size, stderr_bytes=stderr_bytes,
                      stderr_prefix=text, stderr_truncated=stderr_bytes > 4096)
    require(not timed_out and code == 0)
    return output, errors

try:
    require(sys.platform == "linux")
    fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    source = args.source.resolve(strict=True)
    build = args.build.resolve(strict=True)
    harness = args.harness.resolve(strict=True)
    diagnostic = {"check": "source_build_headers"}
    require(source.is_dir() and build.is_dir() and not args.harness.is_symlink())
    encode_source = source / "lib/krb5/asn.1/asn1_encode.c"
    # --source is the configured MIT src/ directory, not its archive parent.
    require((source / "include/k5-int.h").is_file() and (build / "include/autoconf.h").is_file())
    objects = []
    for name in ("asn1_encode", "asn1_k_encode"):
        paths = [build / "lib/krb5/asn.1" / (name + suffix) for suffix in (".o", ".so")]
        present = [path for path in paths if path.is_file()]
        diagnostic = {"check": "object_candidates", "object": name,
                      "candidates": [{"name": path.name, "size": path.stat().st_size}
                                     for path in present]}
        require(present)
        path = present[0].resolve(strict=True)
        require(path.is_relative_to(build) and path.stat().st_size <= 64 * 1024 * 1024)
        with path.open("rb") as f:
            header = f.read(64)
        diagnostic.update(check="object_header", selected=path.name,
                          header_prefix_hex=header[:20].hex())
        # MIT's .so suffix denotes PIC object on Linux, not necessarily a DSO.
        require(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01" and
                struct.unpack_from("<HH", header, 16) == (1, 62))
        objects.append(path)
    with tempfile.TemporaryDirectory(prefix="pamolive-asn1-build-") as scratch:
        work = Path(scratch)
        binary = work / "asn1-regression"
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
               "LD_LIBRARY_PATH": str(build / "lib"), "HOME": str(work)}
        command = ["/usr/bin/cc", "-std=c99", "-O1", "-Wall", "-Wextra", "-Werror",
                   "-fno-builtin", "-fno-lto", "-isystem", str(build / "include"),
                   "-isystem", str(source / "include"), "-isystem", str(source / "lib/krb5/asn.1"),
                   str(harness), *map(str, objects), "-L" + str(build / "lib"),
                   "-lkrb5", "-lk5crypto", "-lcom_err", "-lkrb5support",
                   "-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free",
                   "-o", str(binary)]
        stage = "compile"
        process(command, env=env, work=work, label="compile", timeout=60,
                cpu=30, memory=512 * 1024 * 1024)
        stage = "run"
        stdout, stderr = process([str(binary), args.phase], env=env, work=work,
                                 label="run", timeout=12, cpu=5, memory=256 * 1024 * 1024)
        stage = "validate"
        require(stderr.stat().st_size == 0 and stdout.stat().st_size <= 65536)
        with stdout.open("rb") as stream:
            raw_result = stream.read(65537)
        require(len(raw_result) <= 65536)
        result = json.loads(raw_result)
        require(result["phase"] == args.phase and result["case_count"] == 6 and
                set(result["cases"]) == {"long_valid", "empty", "bad_tag", "truncated",
                                         "allocation_failure", "partial_cleanup"})
        require(all(case["status"] == "passed" and
                    case["live_allocations_after_cleanup"] == 0
                    for case in result["cases"].values()))
        result.update(schema="pamolive.krb5-asn1-regression.v1", verified=True,
                      patch_sha256=PATCH, source_file_sha256=sha(encode_source),
                      harness_sha256=sha(harness), executable_sha256=sha(binary),
                      objects=[dict(name=path.name, sha256=sha(path)) for path in objects],
                      upstream_make_check_replaced=False,
                      coverage="Build-only real MIT decoder objects; no network or installed runtime mutation")
        raw = json.dumps(result, indent=2, sort_keys=True)
        require(len(raw) <= 65536)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            f.write(raw + "\n")
except Exception:
    if fd is not None:
        os.close(fd)
    print(json.dumps({"verified": False, "error": "krb5_asn1_regression_failed",
                      "phase": args.phase, "stage": stage, "diagnostic": diagnostic}),
          file=sys.stderr)
    raise SystemExit(1)
print(json.dumps({"verified": True, "phase": args.phase, "case_count": 6}))
PY
