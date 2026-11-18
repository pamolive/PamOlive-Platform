"""Future Linux acquisition/authentication/build. Never executed during DATA preparation.

Default trust pin is absent and patch plan contains an unresolved QUIC conflict.
Changing either requires a reviewed source revision, not a receipt boolean.
"""

import argparse
import importlib
import lzma
import os
import re
import shutil
import socket
import stat
import sys
import time
from pathlib import Path

from acquisition_io import BASE_URL, remaining
from acquisition_io import acquire_blob as bounded_acquire_blob
from acquisition_owner import SECONDS, runtime_role, snapshot, supervise
from patch_contracts import apply_bound
from source_data import (
    BASE_VERSION,
    DSC,
    LOCAL_VERSION,
    RUNTIME,
    SDK,
    check_policy,
    dsc_control,
    fields,
    json_value,
    need,
    patch_contract,
    release_index,
    safe_name,
    sha,
    signature_status,
    source_record,
)

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "future_support"))
_common = importlib.import_module("common")
ENV, command, read, record, write_new = (
    _common.ENV,
    _common.command,
    _common.read,
    _common.record,
    _common.write_new,
)

BUILD_ENV = ENV | {
    "DEB_BUILD_MAINT_OPTIONS": "hardening=+all",
    "QUILT_PATCHES": "debian/patches",
    "QUILT_PATCH_OPTS": "--fuzz=0",
    "DEBFULLNAME": "PamOlive source build",
    "DEBEMAIL": "build@pamolive.invalid",
}


def linux():
    need(
        sys.platform == "linux" and os.name == "posix",
        "LINUX_ONLY_NO_WINDOWS_NATIVE_EXECUTION",
    )


def offline():
    linux()
    need({n for _, n in socket.if_nameindex()} == {"lo"}, "BUILD_NETWORK_MUST_BE_NONE")


def policy(config):
    pin = config.get("trust_policy_sha256")
    # Missing commissioning fails before reading any authority artifact.
    need(
        type(pin) is str and re.fullmatch("[a-f0-9]{64}", pin),
        "trust_policy_pin_missing",
    )
    return check_policy(read(HERE / "trust-policy.json", 65536), pin)


def run(args, cwd, log, trust, seconds=60, cap=2 * 1024**2, env=None, deadline=None):
    linux()
    tool = args[0]
    check_deadline(deadline)
    need(
        tool in trust["tools"]
        and sha(read(Path(tool).resolve(strict=True), 64 * 1024**2)) == trust["tools"][tool],
        "pinned_tool_identity",
    )
    if deadline is not None:
        seconds = min(seconds, remaining(deadline))
    return command(
        args,
        cwd,
        log,
        seconds=seconds,
        cap=cap,
        env=BUILD_ENV if env is None else env,
        deadline=deadline,
        owned_session=deadline is None,
    )


def check_deadline(deadline):
    if deadline is not None:
        remaining(deadline)


def acquire_blob(url, path, maximum, expected=None, *, deadline):
    """One body under the worker's shared absolute owner horizon."""
    linux()
    return bounded_acquire_blob(url, path, maximum, expected, deadline=deadline)


def verified_release(materials, work, trust, deadline=None):
    """Actual gpgv is mandatory; stored signature booleans are ignored."""
    linux()
    check_deadline(deadline)
    key = read(materials / "debian-archive-keyring.gpg", 8 * 1024**2)
    need(sha(key) == trust["keyring_sha256"], "archive_keyring_pin")
    signed = read(materials / "InRelease", 2 * 1024**2)
    from reused_signature_data import cleartext_envelope

    cleartext_envelope(signed)
    check_deadline(deadline)
    write_new(work / "keyring.gpg", key, 0o444)
    check_deadline(deadline)
    write_new(work / "InRelease", signed, 0o444)
    status = run(
        [
            "/usr/bin/gpgv",
            "--keyring",
            str(work / "keyring.gpg"),
            "--status-fd",
            "1",
            "--output",
            str(work / "Release"),
            str(work / "InRelease"),
        ],
        work,
        work / "gpgv",
        trust,
        deadline=deadline,
    )
    check_deadline(deadline)
    signers = signature_status(status, trust, int(time.time()))
    release = read(work / "Release", 2 * 1024**2)
    expected = release_index(release, time.time())
    check_deadline(deadline)
    return expected, {
        "actual_gpgv_invoked": True,
        "signers": signers,
        "release_sha256": sha(release),
        "index": {"bytes": expected[0], "sha256": expected[1]},
    }


def expanded_sources(raw, expected):
    linux()
    need((len(raw), sha(raw)) == tuple(expected), "Sources_compressed_binding")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024**2)
    plain = decoder.decompress(raw, max_length=128 * 1024**2 + 1)
    need(
        len(plain) <= 128 * 1024**2 and decoder.eof and not decoder.unused_data,
        "Sources_expansion",
    )
    return plain


def verify_source(materials, work, trust, deadline=None):
    linux()
    check_deadline(deadline)
    work.mkdir(mode=0o700)
    expected, release = verified_release(materials, work, trust, deadline=deadline)
    rows = source_record(expanded_sources(read(materials / "Sources.xz", 32 * 1024**2), expected))
    dsc_control(read(materials / DSC, 1024**2), rows[DSC])
    check_deadline(deadline)
    for name, (size, digest) in rows.items():
        check_deadline(deadline)
        safe_name(name)
        raw = read(materials / name, 64 * 1024**2)
        need((len(raw), sha(raw)) == (size, digest), "authenticated_source_bytes")
        check_deadline(deadline)
        write_new(work / name, raw, 0o444)
        check_deadline(deadline)
    value = {
        "schema": "pamolive.openssl-source-chain.v1",
        "source": "openssl",
        "version": BASE_VERSION,
        "archive_signature": release,
        "source_record_files": {n: {"bytes": v[0], "sha256": v[1]} for n, v in rows.items()},
        "APT_chain_authenticated": True,
        "uploader_signature_verified": False,
        "upstream_detached_signature_verified": False,
        "archive_extracted": False,
        "build_verified": False,
        "operational_GO": False,
    }
    check_deadline(deadline)
    record(work / "source-authentication.json", value)
    check_deadline(deadline)
    return work


def acquire_sequence(materials, work, trust, *, deadline):
    linux()
    remaining(deadline)
    materials.mkdir(mode=0o700)
    remaining(deadline)
    work.mkdir(mode=0o700)
    key = read(HERE / "trusted-input/debian-archive-keyring.gpg", 8 * 1024**2)
    need(sha(key) == trust["keyring_sha256"], "archive_keyring_pin")
    remaining(deadline)
    write_new(materials / "debian-archive-keyring.gpg", key, 0o444)
    remaining(deadline)
    acquire_blob(
        BASE_URL + "dists/trixie-security/InRelease",
        materials / "InRelease",
        2 * 1024**2,
        deadline=deadline,
    )
    expected, _ = verified_release(materials, work, trust, deadline=deadline)
    acquire_blob(
        BASE_URL + "dists/trixie-security/main/source/by-hash/SHA256/" + expected[1],
        materials / "Sources.xz",
        32 * 1024**2,
        expected,
        deadline=deadline,
    )
    remaining(deadline)
    release_index(read(work / "Release", 2 * 1024**2), time.time())
    rows = source_record(expanded_sources(read(materials / "Sources.xz", 32 * 1024**2), expected))
    remaining(deadline)
    for name, expected_file in rows.items():
        remaining(deadline)
        safe_name(name)
        acquire_blob(
            BASE_URL + "pool/updates/main/o/openssl/" + name,
            materials / name,
            64 * 1024**2,
            expected_file,
            deadline=deadline,
        )
    remaining(deadline)
    result = verify_source(materials, work / "complete-source", trust, deadline=deadline)
    remaining(deadline)
    return result


def acquisition_worker(payload):
    linux()
    deadline = payload["deadline"]
    remaining(deadline)
    trust = payload["trust"]
    role = trust["acquisition_runtime"]
    runtime_role(role, read, deadline)
    need(
        snapshot(HERE, role, read, deadline) == payload["sources"],
        "acquisition_source_changed",
    )
    acquire_sequence(Path(payload["materials"]), Path(payload["work"]), trust, deadline=deadline)
    runtime_role(role, read, deadline)
    need(
        snapshot(HERE, role, read, deadline) == payload["sources"],
        "acquisition_source_changed",
    )
    remaining(deadline)


def acquire(materials, work, trust):
    linux()
    deadline = time.monotonic() + SECONDS
    return supervise(HERE, materials, work, trust, read, command, record, deadline=deadline)


def dependencies(trust, work):
    linux()
    raw = read(HERE / "build-dependencies.lock.json", 2 * 1024**2)
    need(sha(raw) == trust["dependency_lock_sha256"], "dependency_lock_pin")
    lock = json_value(raw)
    need(
        set(lock) == {"schema", "packages"}
        and lock["schema"] == "pamolive.Debian-installed-build-closure.v1",
        "dependency_lock_shape",
    )
    expected = lock["packages"]
    need(type(expected) is list and 20 <= len(expected) <= 5000, "dependency_lock_size")
    need(
        all(
            type(r) is list
            and len(r) == 3
            and all(
                type(v) is str and 0 < len(v) < 256 and "\n" not in v and "\t" not in v for v in r
            )
            for r in expected
        ),
        "dependency_lock_rows",
    )
    need(
        expected == sorted(expected) and len({r[0] for r in expected}) == len(expected),
        "dependency_lock_duplicates",
    )
    required = {
        "build-essential",
        "binutils",
        "make",
        "gcc",
        "g++",
        "dpkg-dev",
        "debhelper",
        "libzstd-dev",
        "zlib1g-dev",
        "perl",
        "quilt",
        "devscripts",
        "gpgv",
        "debian-archive-keyring",
    }
    need(
        required <= {r[0].split(":", 1)[0] for r in expected},
        "dependency_lock_incomplete",
    )
    observed = (
        run(
            [
                "/usr/bin/dpkg-query",
                "--show",
                "--showformat=${binary:Package}\t${Version}\t${Architecture}\n",
            ],
            work,
            work / "installed-dependencies",
            trust,
        )
        .decode()
        .splitlines()
    )
    actual = sorted(r.split("\t") for r in observed)
    need(actual == expected, "installed_dependency_closure_changed")
    return {"lock_sha256": sha(raw), "packages": len(actual)}


def checked_plan(config):
    pin = config.get("exact_debian_patch_plan_sha256")
    need(
        type(pin) is str and re.fullmatch("[a-f0-9]{64}", pin),
        "exact_debian_patch_plan_pin_missing",
    )
    raw = read(HERE / "exact-debian-patch-plan.json", 2 * 1024**2)
    need(sha(raw) == pin, "exact_debian_patch_plan_pin")
    plan = json_value(raw)
    rows = patch_contract(plan)
    patches = {
        r["proposed_patch"]: read(HERE / safe_name(r["proposed_patch"]), 2 * 1024**2) for r in rows
    }
    patch_contract(plan, patches)
    return plan


def source_text(source, name):
    """FD-anchored regular existing text; no linked path component or hardlink."""
    from patch_contracts import target

    target(name)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    root = os.open(source, flags | os.O_DIRECTORY)
    descriptor = root
    try:
        pieces = name.split("/")
        for component in pieces[:-1]:
            child = os.open(component, flags | os.O_DIRECTORY, dir_fd=descriptor)
            if descriptor != root:
                os.close(descriptor)
            descriptor = child
        fd = os.open(pieces[-1], flags | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            row = os.fstat(fd)
            need(
                stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and 0 <= row.st_size <= 2 * 1024**2,
                "patch_target_regular",
            )
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(2 * 1024**2 + 1)
            need(len(raw) == row.st_size and len(raw) <= 2 * 1024**2, "patch_target_size")
            raw.decode("utf-8", "strict")
            need(b"\0" not in raw, "patch_target_text")
            return raw
        finally:
            os.close(fd)
    finally:
        if descriptor != root:
            os.close(descriptor)
        os.close(root)


def patch_tree(source, plan, work, trust):
    """Validate the entire closed patch set before source writes or any quilt command."""
    offline()
    rows = patch_contract(plan)
    patches = {
        r["proposed_patch"]: read(HERE / safe_name(r["proposed_patch"]), 2 * 1024**2) for r in rows
    }
    patch_contract(plan, patches)
    names = {n for r in rows for n in r["before"]}
    simulated = {name: source_text(source, name) for name in names}
    for r in rows:
        simulated = apply_bound(simulated, r, patches[r["proposed_patch"]])
    for r in rows:
        for name, digest in r["before"].items():
            need(sha(source_text(source, name)) == digest, "debian_patch_preimage")
        patch_path = work / (r["cve"] + ".patch")
        write_new(patch_path, patches[r["proposed_patch"]], 0o444)
        run(
            [
                "/usr/bin/quilt",
                "import",
                "-P",
                "pamolive-" + r["cve"] + ".patch",
                str(patch_path),
            ],
            source,
            work / (r["cve"] + "-import"),
            trust,
        )
        output = run(["/usr/bin/quilt", "push"], source, work / (r["cve"] + "-push"), trust)
        need(not re.search(rb"offset|fuzz", output, re.I), "quilt_offset_or_fuzz")
        for name, digest in r["after"].items():
            need(sha(source_text(source, name)) == digest, "debian_patch_postimage")


def build(materials, work, trust, config):
    offline()
    plan = checked_plan(config)  # Refuse unresolved context before extraction or any compiler.
    work.mkdir(mode=0o700)
    deps = dependencies(trust, work)
    captured = verify_source(materials, work / "source-captured", trust)
    baseline = work / "baseline"
    run(
        ["/usr/bin/dpkg-source", "-x", str(captured / DSC), str(baseline)],
        work,
        work / "source-extraction",
        trust,
        seconds=180,
    )
    candidate = work / "candidate"
    shutil.copytree(baseline, candidate, symlinks=True)
    for phase, source in [("baseline", baseline), ("candidate", candidate)]:
        phase_work = work / (phase + "-proof")
        phase_work.mkdir(mode=0o700)
        if phase == "candidate":
            patch_tree(source, plan, phase_work, trust)
            run(
                [
                    "/usr/bin/dch",
                    "--newversion",
                    LOCAL_VERSION,
                    "--distribution",
                    "trixie-security",
                    "Backport four reviewed OpenSSL3.5 security fixes; "
                    "retain upstream3.5.7 source identity and Debian ABI.",
                ],
                source,
                phase_work / "changelog",
                trust,
            )
        run(
            ["/usr/bin/dpkg-checkbuilddeps"],
            source,
            phase_work / "build-dependencies",
            trust,
        )
        run(
            ["/usr/bin/dpkg-buildpackage", "-B", "-us", "-uc", "-j1"],
            source,
            phase_work / "dpkg-buildpackage",
            trust,
            seconds=3600,
            cap=8 * 1024**2,
        )
        # Do not infer a test count from RC0. Retain Debian logs and .buildinfo.
        if phase == "candidate":
            for package in (*RUNTIME, *SDK):
                path = work / (package + "_" + LOCAL_VERSION + "_amd64.deb")
                need(path.is_file(), "expected_package_missing")
                meta = run(
                    [
                        "/usr/bin/dpkg-deb",
                        "--field",
                        str(path),
                        "Package",
                        "Version",
                        "Architecture",
                    ],
                    source,
                    phase_work / (package + "-metadata"),
                    trust,
                )
                values = fields(meta.decode().strip())
                need(
                    values.get("Package") == package
                    and values.get("Version") == LOCAL_VERSION
                    and values.get("Architecture") == "amd64",
                    "package_identity",
                )
    record(
        work / "BUILD-DATA.json",
        {
            "schema": "pamolive.openssl-dpkg-build.DATA.v1",
            "source_version": BASE_VERSION,
            "local_version": LOCAL_VERSION,
            "dependencies": deps,
            "dpkg_processes_returned_zero": True,
            "regression_counts_verified": False,
            "ABI_verified": False,
            "consumers_verified": False,
            "build_verified": False,
            "operational_GO": False,
            "wheel_OpenSSL4_0_3_corrected": False,
        },
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["acquire", "verify", "build"])
    parser.add_argument("--materials", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    linux()
    config = json_value(read(HERE / "recipe-inputs.json", 65536))
    trust = policy(config)
    args.materials = args.materials.resolve()
    args.work = args.work.resolve()
    need(
        not args.work.exists() and not args.work.is_relative_to(args.materials),
        "new_isolated_work_required",
    )
    if args.operation == "acquire":
        need(not args.materials.exists(), "new_materials_required")
        acquire(args.materials, args.work, trust)
    elif args.operation == "verify":
        verify_source(args.materials, args.work, trust)
    else:
        build(args.materials, args.work, trust, config)


if __name__ == "__main__":
    main()
