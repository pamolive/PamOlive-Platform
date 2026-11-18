"""Exact Google package bootstrap for one disposable CI; never admit the old Chrome."""

import argparse
import email.utils
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import time
from datetime import timedelta
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TARGET = Path("/opt/google/chrome/chrome")
PIN_PATH = "qualification/p1g_headless/chrome-bootstrap-pins.json"
ROOT_INTERPRETER = "/usr/bin/python3.12"
ROOT_CACHE_BASENAME = "google-chrome-stable_157.0.8103.78-1_amd64.deb"
ROOT_INTERPRETER_SCHEMA = "pamolive.chrome-root-interpreter/1"
INSTALLED_SCHEMA = "pamolive.chrome-bootstrap/2"
TAR_HELPER_SHA = "46ab045267bf6d8a71d5730426a9ce89b64b23d8e7a42235f5917e7fed4b44e0"
ROOT_FLAGS = {
    "isolated": 1,
    "ignore_environment": 1,
    "no_user_site": 1,
    "no_site": 1,
    "dont_write_bytecode": 1,
    "optimize": 0,
    "safe_path": True,
}
SOURCE_PATHS = {
    "qualification/p1g_headless/chrome_bootstrap.py",
    "qualification/p1g_headless/chrome_bundle.py",
    "qualification/p1g_headless/chrome-bundle-profile.json",
    "qualification/p1g_headless/chrome_phase_a.py",
    "qualification/p1g_headless/chrome-stage-only-profile.json",
    "qualification/p1g_headless/chrome_gpg.py",
    "qualification/p1g_headless/chrome_key_scope.py",
    "qualification/p1g_headless/chrome_key_scope_native.py",
    "qualification/p1g_headless/lab_support.py",
    "deploy/expat-remediation/bounded_io.py",
    *{
        "qualification/p1g_headless/gpg_fixture/" + name
        for name in (
            "fixture_owner.py",
            "fixture_contract.py",
            "agent_exec.py",
            "bounded_io.py",
            "crypto_guard.py",
            "public_packets.py",
        )
    },
}
TEST_PATHS = {
    "qualification/p1g_headless/test_chrome_phase_a.py",
    "qualification/p1g_headless/chrome-stage-inventory.DATA.json",
    "qualification/p1g_headless/test_chrome_bundle.py",
    "qualification/p1g_headless/test_chrome_bootstrap.py",
    "qualification/p1g_headless/test_chrome_key_scope.py",
    "qualification/p1g_headless/chrome_scope_native_fixtures.json",
    "qualification/p1g_headless/chrome_scope_fixtures/primary-expired.asc",
    "qualification/p1g_headless/chrome_scope_fixtures/primary-revoked.pgp",
    "qualification/p1g_headless/run_chrome_pure.py",
    "qualification/p1g_headless/gpg_fixture/test_fixture.py",
    "qualification/p1g_headless/gpg_fixture/source-pins.json",
}
MATERIALS = {"google-key.asc", "Release", "Release.gpg", "Packages"}
BASE_URL = "https://dl.google.com/linux/chrome/deb/"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
DIAGNOSTICS = {
    "bundle_FD_close_unknown",
    "phase_a_root_only",
    "phase_a_profile_pin",
    "phase_a_profile_unadmitted",
    "phase_a_reserved_path",
    "phase_a_cycle_binding",
    "phase_a_ownership",
    "phase_a_ledger",
    "phase_a_identity_drift",
    "phase_a_unexpected_entry",
    "phase_a_resource_drift",
    "phase_a_partial_drift",
    "phase_a_cleanup_unknown",
    "phase_a_cycle_unknown",
    "phase_a_prefix_still_present",
    "phase_a_result_budget",
    "phase_a_result_binding",
    "phase_a_result_identity",
    "phase_a_result_counts",
    "bundle_tar_extensions_refused_PAX",
    "bundle_tar_extensions_refused_GLOBAL",
    "bundle_tar_extensions_refused_GNU_LONGNAME",
    "bundle_tar_extensions_refused_GNU_LONGLINK",
    "bundle_tar_extensions_refused_GNU_SPARSE",
    "bundle_tar_physical_budget",
    "bundle_tar_read_budget",
    "bundle_tar_read_shape",
    "bundle_tar_seek",
    "bundle_tar_truncated",
    "bundle_tar_terminator",
    "bundle_tar_trailing_data",
    "bundle_tar_header_budget",
    "bundle_tar_header",
    "bundle_tar_header_changed",
    "bundle_tar_collision",
    "bundle_tar_member_budget",
    "bundle_tar_nonfile_payload",
    "bundle_tar_padding",
    "bundle_tar_path_type",
    "bundle_tar_type",
    "bundle_root_runtime_checker",
    "payload_tar_helper_pin",
    "bundle_profile_uncommissioned",
    "bundle_profile_pin",
    "bundle_profile_tree",
    "bundle_unsupported_entry",
    "bundle_privileged_roles",
    "bundle_deadline",
    "bundle_payload_changed",
    "bundle_root_parent",
    "bundle_root_race",
    "bundle_parent_race",
    "bundle_resource_changed",
    "bundle_resource_missing",
    "bundle_unexpected_entry",
    "apt_cache_path",
    "apt_cache_metadata",
    "apt_cache_changed",
    "apt_cache_package",
    "bootstrap_deadline",
    "command_UNKNOWN",
    "consumer_key_state_changed",
    "consumer_native_key_times",
    "consumer_native_sub_r",
    "consumer_positive_RSA_SHA256",
    "dependencies_not_already_satisfied",
    "fixture_unknown",
    "installed_package_identity",
    "installed_payload_mismatch",
    "key_bundle_ambiguity",
    "key_duplicate",
    "key_expired",
    "key_fields",
    "key_fingerprint",
    "key_future",
    "key_primary",
    "key_unusable",
    "matrix_expired_other_not_observed",
    "matrix_expiry_precondition",
    "matrix_kind",
    "matrix_original_keyset",
    "matrix_unexpected_guard",
    "native_crosscert_fixture",
    "native_fixture_fields",
    "native_fixture_pin",
    "native_fixture_schema",
    "native_fixture_state",
    "native_import_not_certificate_refusal",
    "native_lifecycle_not_refused",
    "native_lifecycle_wrong_guard",
    "native_mutation_kind",
    "native_negative_H1_unknown",
    "native_negative_accepted",
    "native_negative_not_cryptographic_refusal",
    "native_negative_tool_changed",
    "native_positive_certificate_changed",
    "native_producer_source_not_reviewed",
    "native_receipt_budget",
    "native_selfsig_fixture",
    "native_status_budget",
    "native_status_bytes",
    "native_subpacket",
    "native_unexpected_FAILURE",
    "native_verify_unknown",
    "package_bytes",
    "package_changed",
    "package_control",
    "package_exact_stanza",
    "package_path_budget",
    "payload_budget",
    "payload_path",
    "payload_target_ELF",
    "payload_target_missing",
    "payload_target_size",
    "payload_target_type_owner_mode",
    "producer_H1",
    "producer_H1_bytes",
    "producer_TEST_identity",
    "producer_buffer_binding",
    "producer_external_source_pin",
    "producer_lineage",
    "producer_message",
    "producer_not_admitted",
    "producer_public_budget",
    "producer_public_facts_budget",
    "producer_public_fields",
    "producer_public_names",
    "producer_python_binding",
    "producer_requested_times",
    "producer_tool_binding",
    "release_Packages_binding",
    "release_SHA256_shape",
    "release_UTC",
    "release_freshness",
    "release_identity",
    "root_receipt",
    "root_interpreter_changed",
    "root_interpreter_identity",
    "root_interpreter_receipt",
    "root_interpreter_runtime",
    "scope_armor",
    "scope_armor_crc",
    "scope_bytes",
    "scope_duplicate_subkey",
    "scope_exact_keys",
    "scope_indeterminate_length",
    "scope_key_body_pin",
    "scope_mode",
    "scope_multiple_primaries",
    "scope_native_preflight_incomplete",
    "scope_original_keyset",
    "scope_original_pin",
    "scope_packet_budget",
    "scope_packet_header",
    "scope_packet_length",
    "scope_packet_order",
    "scope_packet_size",
    "scope_partial_length",
    "scope_primary_block_changed",
    "scope_primary_first",
    "scope_primary_signature_type",
    "scope_purpose",
    "scope_secret_or_unknown_tag",
    "scope_selected_state_changed",
    "scope_signature_lengths",
    "scope_signer_block_changed",
    "scope_subkey_signature_type",
    "scope_v4_RSA_key",
    "scope_v4_fingerprint",
    "scope_v4_signature",
    "signature_after_key_expiry",
    "signature_ambiguity",
    "signature_authority",
    "signature_before_key",
    "signature_expired",
    "signature_fields",
    "signature_future",
    "signature_hash",
    "signer_not_in_purpose_certificate",
    "signing_capability_missing",
    "status_bad",
    "status_framing",
    "sudo_changed",
    "sudo_role",
    "temporal_VALID_count",
    "temporal_actual_signature",
    "temporal_expired_state",
    "temporal_future_state",
    "tool_alias_refused",
    "tool_byte_budget",
    "tool_changed",
    "tool_changed_or_not_ELF",
    "tool_fd_identity",
    "tool_parent_writable_or_alias",
    "tool_type_owner_mode",
}


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(rows):
    value = {}
    for key, item in rows:
        need(key not in value, "duplicate_JSON")
        value[key] = item
    return value


def read(path, cap):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap, "input_regular_budget")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(cap + 1)
        after = path.lstat()
    need(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        and len(raw) == before.st_size
        and before.st_ctime_ns == after.st_ctime_ns,
        "input_changed",
    )
    return raw


def interpreter_identity(row):
    fields = ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
    values = [getattr(row, "st_" + name) for name in fields]
    need(
        all(type(value) is int and 0 <= value < 2**64 for value in values)
        and stat.S_ISREG(values[2])
        and not values[2] & 0o6022
        and values[3] == 0
        and values[5] == 1
        and 0 < values[6] <= 512 * 1024**2,
        "root_interpreter_identity",
    )
    return values


def cache_identity(row):
    values = tuple(
        getattr(row, "st_" + key)
        for key in ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
    )
    need(all(type(value) is int and 0 <= value < 2**64 for value in values), "apt_cache_metadata")
    return values


def root_cache_paths(private):
    need(
        private.is_absolute()
        and private.parent.as_posix() == "/var/tmp"
        and re.fullmatch(r"pamolive-chrome-bootstrap-[0-9]+-[0-9]+", private.name),
        "apt_cache_path",
    )
    cache = private / "apt-archives"
    return cache, cache / ROOT_CACHE_BASENAME


def root_apt_argv(private, *, action):
    need(type(action) is str and action in ("--simulate", "--assume-yes"), "apt_cache_path")
    cache, package = root_cache_paths(private)
    return [
        *APT,
        "-o",
        "Dir::Cache::Archives=" + cache.as_posix() + "/",
        action,
        "install",
        package.as_posix(),
    ]


def cache_directory(path, expected=None):
    row = path.lstat()
    need(
        stat.S_ISDIR(row.st_mode)
        and row.st_uid == row.st_gid == 0
        and stat.S_IMODE(row.st_mode) == 0o700,
        "apt_cache_metadata",
    )
    # APT may create partial/auxfiles/lock; directory mtime/nlink may change.
    identity = (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid)
    need(expected is None or identity == expected, "apt_cache_changed")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for observed in (os.fstat(fd), path.lstat()):
            need(
                (
                    observed.st_dev,
                    observed.st_ino,
                    observed.st_mode,
                    observed.st_uid,
                    observed.st_gid,
                )
                == identity,
                "apt_cache_changed",
            )
    finally:
        os.close(fd)
    return identity


def cache_file(path, expected, *, uid, gid=None, identity=None, retain=False):
    row = path.lstat()
    need(
        stat.S_ISREG(row.st_mode)
        and row.st_uid == uid
        and (gid is None or row.st_gid == gid)
        and row.st_nlink == 1
        and stat.S_IMODE(row.st_mode) == 0o400
        and row.st_size == int(expected["Size"])
        and 0 < row.st_size <= 256 * 1024**2,
        "apt_cache_metadata",
    )
    before = cache_identity(row)
    need(identity is None or before == identity, "apt_cache_changed")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    total, digest, chunks = 0, hashlib.sha256(), []
    with os.fdopen(fd, "rb", buffering=0) as stream:
        need(cache_identity(os.fstat(fd)) == before, "apt_cache_changed")
        while block := stream.read(65536):
            total += len(block)
            need(total <= row.st_size, "apt_cache_changed")
            digest.update(block)
            if retain:
                chunks.append(block)
        need(
            total == row.st_size
            and digest.hexdigest() == expected["SHA256"]
            and cache_identity(os.fstat(fd)) == before
            and cache_identity(path.lstat()) == before,
            "apt_cache_changed",
        )
    return before, b"".join(chunks) if retain else None


def root_cache_copy(private, source, expected):
    need(
        os.getuid() == os.geteuid() == 0
        and expected["Package"] == "google-chrome-stable"
        and expected["Version"] == "157.0.8103.78-1"
        and expected["Architecture"] == "amd64"
        and expected["Filename"] == "pool/main/g/google-chrome-stable/" + ROOT_CACHE_BASENAME
        and expected["Size"] == "147497676"
        and expected["SHA256"]
        == "4d740636b5c96f687798602c5aad6a5a270f44dd02e48db0638ae77aa4867b1b",
        "apt_cache_package",
    )
    cache, package = root_cache_paths(private)
    parent = cache_directory(private)
    source_uid = os.environ.get("SUDO_UID", "")
    need(re.fullmatch(r"[1-9][0-9]*", source_uid), "apt_cache_metadata")
    _, raw = cache_file(source, expected, uid=int(source_uid), retain=True)
    cache.mkdir(mode=0o700)  # Exclusive; never adopt or repair an existing directory.
    directory = cache_directory(cache)
    fd = os.open(
        package, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(fd, "wb", buffering=0) as target:
        need(target.write(raw) == len(raw), "apt_cache_changed")
        os.fsync(fd)
        os.fchmod(fd, 0o400)
        row = os.fstat(fd)
        need(
            stat.S_ISREG(row.st_mode)
            and row.st_uid == row.st_gid == 0
            and row.st_nlink == 1
            and stat.S_IMODE(row.st_mode) == 0o400
            and row.st_size == len(raw),
            "apt_cache_metadata",
        )
        identity = cache_identity(row)
        need(cache_identity(package.lstat()) == identity, "apt_cache_changed")
    del raw
    cache_directory(private, parent)
    cache_directory(cache, directory)
    cache_file(package, expected, uid=0, gid=0, identity=identity)
    return package, (parent, directory, identity)


def root_cache_check(private, binding, expected):
    cache, package = root_cache_paths(private)
    parent, directory, identity = binding
    cache_directory(private, parent)
    cache_directory(cache, directory)
    cache_file(package, expected, uid=0, gid=0, identity=identity)
    cache_directory(cache, directory)
    cache_directory(private, parent)


def root_interpreter_pin(support):
    # Select this role directly; never resolve/adopt the frontend or a PATH alias.
    path = Path(ROOT_INTERPRETER)
    before = interpreter_identity(path.lstat())
    pin = support.tool_pin(path)  # Original UID/parents/FD/ELF/hash guard, unchanged.
    need(
        type(pin) is dict
        and set(pin) == {"sha256", "bytes", "uid", "mode"}
        and type(pin["sha256"]) is str
        and re.fullmatch(r"[a-f0-9]{64}", pin["sha256"])
        and type(pin["bytes"]) is int
        and pin["bytes"] == before[6]
        and type(pin["uid"]) is int
        and pin["uid"] == 0
        and type(pin["mode"]) is int
        and pin["mode"] == stat.S_IMODE(before[2])
        and interpreter_identity(path.lstat()) == before,
        "root_interpreter_changed",
    )
    return {"path": ROOT_INTERPRETER, "pin": pin, "identity": before}


def check_root_interpreter(facts, role, *, context_sha, pins_sha, source_sha, revision):
    need(
        type(facts) is dict
        and set(facts)
        == {
            "schema",
            "role",
            "path",
            "pin",
            "identity",
            "running_identity",
            "real_uid",
            "effective_uid",
            "version",
            "implementation",
            "flags",
            "revision",
            "context_receipt_sha256",
            "pins_manifest_sha256",
            "bootstrap_source_sha256",
            "stdlib_loader_hermeticity_verified",
        }
        and facts["schema"] == ROOT_INTERPRETER_SCHEMA
        and facts["role"] == "privileged-stdlib-supervisor"
        and facts["path"] == ROOT_INTERPRETER == role["path"]
        and facts["pin"] == role["pin"]
        and facts["identity"] == facts["running_identity"] == role["identity"]
        and all(
            type(facts[name]) is int and facts[name] == 0 for name in ("real_uid", "effective_uid")
        )
        and facts["revision"] == revision
        and facts["context_receipt_sha256"] == context_sha
        and facts["pins_manifest_sha256"] == pins_sha
        and facts["bootstrap_source_sha256"] == source_sha
        and facts["stdlib_loader_hermeticity_verified"] is False,
        "root_interpreter_receipt",
    )
    # Equality alone would accept bools in numeric fields of a forged old receipt.
    for name in ("identity", "running_identity"):
        need(
            type(facts[name]) is list
            and len(facts[name]) == 9
            and all(type(value) is int and 0 <= value < 2**64 for value in facts[name]),
            "root_interpreter_receipt",
        )
    pin = facts["pin"]
    need(
        type(pin) is dict
        and set(pin) == {"sha256", "bytes", "uid", "mode"}
        and type(pin["sha256"]) is str
        and re.fullmatch(r"[a-f0-9]{64}", pin["sha256"])
        and all(type(pin[name]) is int for name in ("bytes", "uid", "mode")),
        "root_interpreter_receipt",
    )
    version = facts["version"]
    need(
        type(version) is dict
        and set(version) == {"major", "minor", "micro", "releaselevel", "serial"}
        and all(type(version[name]) is int for name in ("major", "minor", "micro", "serial"))
        and version["major"] == 3
        and version["minor"] == 12
        and 0 <= version["micro"] <= 999
        and version["releaselevel"] == "final"
        and version["serial"] == 0
        and facts["implementation"] == {"name": "cpython", "cache_tag": "cpython-312"}
        and type(facts["implementation"]) is dict
        and type(facts["flags"]) is dict
        and set(facts["flags"]) == set(ROOT_FLAGS)
        and all(
            type(facts["flags"][name]) is type(value) and facts["flags"][name] == value
            for name, value in ROOT_FLAGS.items()
        ),
        "root_interpreter_receipt",
    )


def root_interpreter_runtime(support, *, context_sha, pins_sha, source_sha, revision):
    need(
        type(os.getuid()) is int
        and os.getuid() == 0
        and type(os.geteuid()) is int
        and os.geteuid() == 0
        and sys.executable == ROOT_INTERPRETER
        and sys.platform == "linux",
        "root_interpreter_runtime",
    )
    role = root_interpreter_pin(support)
    running = interpreter_identity(os.stat("/proc/self/exe"))
    version = sys.version_info
    facts = {
        "schema": ROOT_INTERPRETER_SCHEMA,
        "role": "privileged-stdlib-supervisor",
        **role,
        "running_identity": running,
        "real_uid": os.getuid(),
        "effective_uid": os.geteuid(),
        "version": {
            name: getattr(version, name)
            for name in ("major", "minor", "micro", "releaselevel", "serial")
        },
        "implementation": {
            "name": sys.implementation.name,
            "cache_tag": sys.implementation.cache_tag,
        },
        "flags": {name: getattr(sys.flags, name) for name in ROOT_FLAGS},
        "revision": revision,
        "context_receipt_sha256": context_sha,
        "pins_manifest_sha256": pins_sha,
        "bootstrap_source_sha256": source_sha,
        "stdlib_loader_hermeticity_verified": False,
    }
    check_root_interpreter(
        facts,
        role,
        context_sha=context_sha,
        pins_sha=pins_sha,
        source_sha=source_sha,
        revision=revision,
    )
    return facts


def root_supervisor(
    commands, support, public, pins, pins_sha, target, scope_proof, source_sha, signature
):
    role = root_interpreter_pin(support)
    context_sha = sha(read(Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json", 4 * 1024**2))
    commands.run(
        [
            "/usr/bin/sudo",
            "-n",
            "--preserve-env=" + PRESERVE,
            "--",
            ROOT_INTERPRETER,
            "-I",
            "-B",
            "-S",
            str(HERE / "chrome_bootstrap.py"),
            "--pins-sha",
            pins_sha,
            "--root-install",
            "--native-scope-preflight-required",
        ],
        seconds=480,
        sudo=True,
    )
    need(root_interpreter_pin(support) == role, "root_interpreter_changed")
    result = json.loads(read(public / "installed.json", 32768), object_pairs_hook=unique)
    need(
        type(result) is dict
        and set(result)
        == {
            "schema",
            "state",
            "package_sha256",
            "package_version",
            "revision",
            "pins_manifest_sha256",
            "context_receipt_sha256",
            "target",
            "signature",
            "key_scope",
            "root_interpreter",
            "all_OS_descendants_released",
            "browser_executed",
            "operational_GO",
        }
        and result["schema"] == INSTALLED_SCHEMA
        and result["state"] == "INSTALLED_AUTHENTICATED_PACKAGE_ONLY"
        and result["target"] == target
        and result["package_sha256"] == pins["package"]["SHA256"]
        and result["package_version"] == pins["package"]["Version"]
        and result["pins_manifest_sha256"] == pins_sha
        and result["revision"] == os.environ["GITHUB_SHA"]
        and result["context_receipt_sha256"] == context_sha
        and result["key_scope"] == scope_proof
        and result["signature"] == signature
        and all(
            result[name] is False
            for name in ("all_OS_descendants_released", "browser_executed", "operational_GO")
        ),
        "root_receipt",
    )
    check_root_interpreter(
        result["root_interpreter"],
        role,
        context_sha=context_sha,
        pins_sha=pins_sha,
        source_sha=source_sha,
        revision=os.environ["GITHUB_SHA"],
    )
    need(time.monotonic() < commands.until, "bootstrap_deadline")
    return result


def fields(raw):
    result, previous = {}, None
    for line in raw.decode("utf8", "strict").splitlines():
        if line.startswith((" ", "\t")):
            need(previous is not None, "field_continuation")
            result[previous] += " " + line.strip()
            continue
        key, separator, value = line.partition(":")
        need(
            separator and key not in result and re.fullmatch(r"[A-Za-z0-9-]+", key),
            "field_duplicate_shape",
        )
        result[key], previous = value.strip(), key
    return result


def release_check(raw, packages, now):
    row = fields(raw)
    need(
        row.get("Origin") == "Google LLC" and row.get("Suite") == row.get("Codename") == "stable",
        "release_identity",
    )
    date = email.utils.parsedate_to_datetime(row["Date"])
    need(date.tzinfo is not None and date.utcoffset() == timedelta(0), "release_UTC")
    timestamp = int(date.timestamp())
    need(now - 7 * 86400 <= timestamp <= now + 300, "release_freshness")
    # fields unfolds continuations; Release SHA256 entries have fixed three-word tuples.
    tokens = row["SHA256"].split()
    need(len(tokens) % 3 == 0, "release_SHA256_shape")
    entries = [tokens[index : index + 3] for index in range(0, len(tokens), 3)]
    selected = [item for item in entries if item[2] == "main/binary-amd64/Packages"]
    need(
        selected == [[sha(packages), str(len(packages)), "main/binary-amd64/Packages"]],
        "release_Packages_binding",
    )
    return timestamp


def package_check(raw, expected):
    matches = [fields(part) for part in raw.split(b"\n\n") if part.strip()]
    matches = [
        row
        for row in matches
        if row.get("Package") == "google-chrome-stable" and row.get("Architecture") == "amd64"
    ]
    need(
        len(matches) == 1 and all(matches[0].get(key) == value for key, value in expected.items()),
        "package_exact_stanza",
    )
    version = expected["Version"]
    need(
        re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+", version)
        and expected["Filename"]
        == "pool/main/g/google-chrome-stable/" + "google-chrome-stable_" + version + "_amd64.deb"
        and expected["Size"].isdigit()
        and 0 < int(expected["Size"]) <= 256 * 1024**2
        and re.fullmatch(r"[a-f0-9]{64}", expected["SHA256"]),
        "package_path_budget",
    )


def control_check(raw, expected):
    row = fields(raw)
    need(
        set(row) == {"Package", "Version", "Architecture", "Depends"}
        and all(" ".join(row[key].split()) == " ".join(expected[key].split()) for key in row),
        "package_control",
    )


def apt_plan(raw):
    lines = raw.decode("utf8", "strict").splitlines()
    actions = [line.split() for line in lines if line.startswith(("Inst ", "Conf ", "Remv "))]
    need(
        len(actions) == 2
        and [row[0] for row in actions] == ["Inst", "Conf"]
        and all(len(row) >= 2 and row[1] == "google-chrome-stable" for row in actions),
        "dependencies_not_already_satisfied",
    )


def payload_archive(stream, *, until=None):
    """Use the same pinned pre-parse physical/IO bounds in the legacy reader."""
    until = time.monotonic() + 60 if until is None else until
    need(time.monotonic() < until, "bootstrap_deadline")
    path = HERE / "chrome_bundle.py"
    body = read(path, 131072)
    need(sha(body) == TAR_HELPER_SHA, "payload_tar_helper_pin")
    helper = load("p1g_pinned_payload_tar", body, path)
    return helper.checked_tar(stream, until=until)


def payload_target(stream, *, until=None):
    target, count, total = None, 0, 0
    with payload_archive(stream, until=until) as archive:
        for member in archive:
            count, total = count + 1, total + member.size
            need(
                count <= 20000
                and 0 <= member.size <= 512 * 1024**2
                and total <= 1024**3
                and len(member.name) <= 1024,
                "payload_budget",
            )
            name = member.name.removeprefix("./")
            need(
                not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts,
                "payload_path",
            )
            if name != TARGET.as_posix().removeprefix("/"):
                continue
            need(
                target is None
                and member.isfile()
                and not member.sparse
                and member.uid == member.gid == 0
                and member.mode == 0o755
                and 0 < member.size <= 512 * 1024**2,
                "payload_target_type_owner_mode",
            )
            result, size, magic = hashlib.sha256(), 0, b""
            with archive.extractfile(member) as source:
                while block := source.read(65536):
                    size += len(block)
                    need(size <= member.size, "payload_target_size")
                    magic = magic or block[:4]
                    result.update(block)
            need(size == member.size and magic == b"\x7fELF", "payload_target_ELF")
            target = {"sha256": result.hexdigest(), "bytes": size, "uid": 0, "mode": 0o755}
    need(target is not None, "payload_target_missing")
    return target


def context(root, receipt_path, pins_sha, revision):
    raw = read(root / PIN_PATH, 131072)
    need(sha(raw) == pins_sha, "external_manifest_pin")
    pins = json.loads(raw, object_pairs_hook=unique)
    receipt = json.loads(read(receipt_path, 4 * 1024**2), object_pairs_hook=unique)
    need(
        receipt.get("schema") == "pamolive.committed-build-context.v1"
        and receipt.get("revision") == revision
        and receipt["files"].get(PIN_PATH) == pins_sha,
        "committed_context_pin",
    )
    need(
        pins["schema"] == "pamolive.chrome-bootstrap-pins/1"
        and set(pins["source_files"]) == SOURCE_PATHS
        and set(pins["test_files"]) == TEST_PATHS
        and set(pins["files"]) == MATERIALS
        and pins["Release_max_age_seconds"] == 604800
        and pins["future_tolerance_seconds"] == 300
        and pins["purpose"] == "google-release-selected-signer-certificate-v1"
        and pins["primary"] == "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796"
        and pins["signer"] == "0E225917414670F4442C250DFD533C07C264648F"
        and pins["PGP_validity_still_required_in_CI"] is True,
        "finite_manifest",
    )
    captured = {}
    for name, expected in (pins["source_files"] | pins["test_files"]).items():
        body = read(root / name, 131072)
        need(sha(body) == expected == receipt["files"].get(name), "source_context_drift")
        captured[name] = body
    for name, expected in pins["files"].items():
        path = "qualification/p1g_headless/chrome_materials/" + name
        body = read(root / path, 131072)
        need(
            sha(body) == expected["sha256"] == receipt["files"].get(path)
            and len(body) == expected["bytes"],
            "material_context_drift",
        )
        captured[name] = body
    return pins, captured


def load(name, raw, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def public_journal_directory(path):
    """Only typed public journals: private creation, then explicit readable mode."""
    path.mkdir(mode=0o700)
    created = path.lstat()
    need(
        stat.S_ISDIR(created.st_mode)
        and created.st_uid == os.geteuid()
        and not created.st_mode & 0o022,
        "public_journal_directory",
    )
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        named = path.lstat()
        need(
            stat.S_ISDIR(before.st_mode)
            and before.st_uid == os.geteuid()
            and not before.st_mode & 0o022
            and (created.st_dev, created.st_ino)
            == (before.st_dev, before.st_ino)
            == (named.st_dev, named.st_ino),
            "public_journal_directory",
        )
        os.fchmod(fd, 0o755)
        after = os.fstat(fd)
        named = path.lstat()
        need(
            stat.S_ISDIR(after.st_mode)
            and stat.S_IMODE(after.st_mode) == 0o755
            and after.st_uid == before.st_uid
            and (before.st_dev, before.st_ino)
            == (after.st_dev, after.st_ino)
            == (named.st_dev, named.st_ino),
            "public_journal_directory",
        )
    finally:
        os.close(fd)


def apt_line_projection(body):
    """Exact raw LF lines, no decoding or normalization; caller gates complete H1."""
    need(type(body) is bytes and len(body) <= 262144, "command_UNKNOWN")
    offset, count, rows = 0, 0, []
    while offset < len(body):
        stop = body.find(b"\n", offset)
        end = len(body) if stop < 0 else stop + 1
        count += 1
        if count <= 16:
            line = body[offset:end]
            severity = next(
                (
                    label
                    for prefix, label in ((b"E:", "E"), (b"W:", "W"), (b"N:", "N"))
                    if line.startswith(prefix)
                ),
                "OTHER",
            )
            rows.append({"bytes": len(line), "sha256": sha(line), "severity_enum": severity})
        offset = end
    need(count <= 262144, "command_UNKNOWN")
    return {"total_lines": count, "truncated": count > 16, "lines": rows}


def apt_failure_diagnostic(result):
    """Marker observations from the same bounded buffers; never an APT success predicate."""
    boolean_names = (
        "spawn_attempted",
        "owned_child_reaped",
        "drains_complete",
        "killed_owned_child",
    )
    facts = {
        name: value if type(value := getattr(result, name, None)) is bool else None
        for name in boolean_names
    }
    rc = getattr(result, "returncode", None)
    facts["returncode"] = rc if type(rc) is int and -(2**31) <= rc < 2**31 else None
    reason = getattr(result, "reason", None)
    reasons = {
        "nonzero_exit",
        "timeout",
        "deadline_before_spawn",
        "absolute_deadline_exceeded",
        "stdout_overflow",
        "stderr_overflow",
        "combined_overflow",
        "stdout_read_contract",
        "stderr_read_contract",
        "stdout_drain_error",
        "stderr_drain_error",
        "reap_error",
        "drain_incomplete",
        "group_cleanup_error",
        "pipe_close_error",
        "spawn_error",
        "controller_error",
    }
    facts["reason"] = reason if type(reason) is str and reason in reasons else "unknown"
    facts["exception_present"] = getattr(result, "exception_type", None) is not None
    facts["cleanup_exception_present"] = getattr(result, "cleanup_exception_type", None) is not None
    pid = getattr(result, "pid", None)
    normal = (
        result.ok is False
        and facts["spawn_attempted"] is True
        and type(pid) is int
        and pid > 0
        and type(rc) is int
        and rc == 100
        and type(reason) is str
        and reason == "nonzero_exit"
        and facts["owned_child_reaped"] is True
        and facts["drains_complete"] is True
        and facts["killed_owned_child"] is False
        and not facts["exception_present"]
        and not facts["cleanup_exception_present"]
    )
    streams = {}
    bodies = []
    for name in ("stdout", "stderr"):
        body = getattr(result, name, None)
        valid = type(body) is bytes and len(body) <= 262144
        streams[name] = {
            "buffer_valid": valid,
            "bytes": len(body) if valid else None,
            "sha256": sha(body) if valid else None,
        }
        if valid:
            bodies.append(body)
    examined = normal and len(bodies) == 2
    # LC_ALL=C is unchanged. These finite upstream-message fragments never leave here.
    markers = {
        "no-download": (b"Unable to fetch some archives", b"it cannot be downloaded."),
        "cache": (
            b"The package lists or status file could not be parsed or opened.",
            b"Archives directory ",
        ),
        "localaccess": (
            b"Could not open file ",
            b"Unsupported file ",
            b"couldn't be accessed by user",
        ),
        "missingdeps": (
            b"Unmet dependencies.",
            b"Broken packages",
            b"Unable to correct dependencies",
        ),
        "downgrade": (b"Packages were downgraded and -y was used",),
        "dpkg-lock": (b"Unable to acquire the dpkg frontend lock", b"Could not open lock file "),
        "dpkg-maintainer": (b"script subprocess returned error exit status",),
        "interrupted": (b"dpkg was interrupted, you must manually",),
        "authconsent": (
            b"There were unauthenticated packages and -y was used without --allow-unauthenticated",
            b"Some packages could not be authenticated",
        ),
        "heldconsent": (
            b"Held packages were changed and -y was used without --allow-change-held-packages.",
        ),
        "essentialconsent": (
            b"Essential packages were removed and -y was used without --allow-remove-essential.",
        ),
        "sourcewarnings": (
            b"Unable to read ",
            b"Malformed entry ",
        ),
        "internal-install": (
            b"Internal error, InstallPackages was called with broken packages!",
            b"Internal error, Ordering didn't finish",
        ),
        "internal-source": (
            b"Internal Error, No file name for ",
            b"Internal ordering error",
        ),
        "archivesnofile": (b"No file name for ",),
        "space": (
            b"You don't have enough free space in ",
            b"Couldn't determine free space in ",
        ),
        "exec-hooks": (
            b"Problem executing scripts ",
            b"Failed to exec compressor ",
        ),
        "size-hash": (
            b"Hash Sum mismatch",
            b"Size mismatch",
        ),
        "errno-site": (
            b"Failed to create subprocess IPC",
            b"Failed to fork",
            b"Failed to create IPC pipe to subprocess",
            b"Failed to setgroups",
            b"Failed to set new user ids",
            b"Failed to set new group ids",
        ),
        "acquire-failed": (
            b"Failed to fetch ",
            b"Some files failed to download",
        ),
        "configured-state": (
            b"Internal error, packages left unconfigured.",
            b"Could not configure ",
        ),
    }
    counts = {
        kind: sum(body.count(marker) for body in bodies for marker in fragments) if examined else 0
        for kind, fragments in markers.items()
    }
    counts["unknown"] = int(not examined or not any(counts.values()))
    return {
        "schema": "pamolive.chrome-apt-failure-DATA/2",
        "diagnostic_only": True,
        "line_projection": {
            "state": "AVAILABLE" if examined else "UNAVAILABLE",
            "format": "raw-LF-including-terminator/1",
            **{
                name: apt_line_projection(getattr(result, name))
                if examined
                else {"total_lines": None, "truncated": None, "lines": []}
                for name in ("stdout", "stderr")
            },
        },
        "role": "root-local-exact-install",
        "phase": "install_local_exact",
        "state": "UNKNOWN",
        "completion": "NORMAL_NONZERO100" if normal else "UNKNOWN",
        "H1": facts,
        "streams": streams,
        "markers_examined": examined,
        "marker_counts": counts,
        "root_cause": "UNKNOWN",
        "tool_postcheck_observed": False,
        "installation_verified": False,
        "operational_GO": False,
    }


class Commands:
    def __init__(self, support, bounded, private, public, *, horizon=870):
        self.support, self.io, self.private, self.public = support, bounded, private, public
        self.number, self.unknown = 0, False
        self.until = time.monotonic() + horizon

    def run(self, argv, *, seconds=30, cap=262144, sink=None, sudo=False, diagnostic_role=None):
        need(
            diagnostic_role is None
            or (
                type(diagnostic_role) is str
                and diagnostic_role == "root-local-exact-install"
                and type(argv) is list
                and argv == root_apt_argv(self.private, action="--assume-yes")
                and type(seconds) is int
                and seconds == 180
                and type(cap) is int
                and cap == 262144
                and sink is None
                and sudo is False
                and type(os.getuid()) is int
                and os.getuid() == 0
                and type(os.geteuid()) is int
                and os.geteuid() == 0
            ),
            "command_UNKNOWN",
        )
        need(not self.unknown, "previous_UNKNOWN")
        need(time.monotonic() + seconds + 10 < self.until, "bootstrap_deadline")
        self.number += 1
        journal = self.public / ("command-" + str(self.number))
        public_journal_directory(journal)
        tool = Path(argv[0])
        if sudo:
            info = tool.lstat()

            def role_identity(row):
                return (
                    row.st_dev,
                    row.st_ino,
                    row.st_mode,
                    row.st_uid,
                    row.st_gid,
                    row.st_nlink,
                    row.st_size,
                    row.st_mtime_ns,
                    row.st_ctime_ns,
                )

            need(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and info.st_gid == 0
                and info.st_nlink == 1
                and tool.resolve(strict=True) == tool
                and stat.S_IMODE(info.st_mode) == 0o4755,
                "sudo_role",
            )
            for parent in tool.parents:
                row = parent.lstat()
                need(
                    stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022,
                    "sudo_role",
                )
            pin = {"sha256": sha(read(tool, 16 * 1024**2)), "bytes": info.st_size}
        else:
            pin = self.support.tool_pin(tool)
        self.support.fresh_write(
            journal / "intent.json",
            json.dumps({"state": "PENDING", "tool": pin, "seconds": seconds}).encode(),
            mode=0o444,
        )
        try:
            env = ENV | {"HOME": str(self.private)}
            if sudo:
                env.update(
                    {key: os.environ[key] for key in PRESERVE.split(",") if key in os.environ}
                )
            result = self.io.run_capped(
                argv,
                env=env,
                cwd=str(self.private),
                timeout=seconds + 10,
                work_timeout=seconds,
                stdout_cap=cap,
                stderr_cap=262144,
                total_cap=cap + 262144,
                stdout_sink=sink,
                owned_session=True,
                deadline=self.until,
                on_spawn=lambda pid: self.support.fresh_write(
                    journal / "pid.json", json.dumps({"pid": pid}).encode(), mode=0o444
                ),
            )
            if diagnostic_role is not None and result.ok is not True:
                # Same result buffers, before strict refusal. Publication cannot replace it.
                try:
                    diagnostic = json.dumps(apt_failure_diagnostic(result)).encode()
                    need(len(diagnostic) <= 8192, "command_UNKNOWN")
                    self.support.fresh_write(journal / "apt-failure.json", diagnostic, mode=0o444)
                except BaseException:
                    pass  # Refusal below remains primary, even if the public destination failed.
            try:
                self.support.fresh_write(
                    journal / "process.json", json.dumps(result.facts()).encode(), mode=0o444
                )
            except BaseException:
                if diagnostic_role is None or result.ok is True:
                    raise
                # The failed root APT result still reaches its strict refusal below.
            need(
                result.ok
                and result.spawn_attempted is True
                and type(result.pid) is int
                and result.pid > 0
                and type(result.returncode) is int
                and result.returncode == 0
                and result.reason is None
                and result.owned_child_reaped is True
                and result.drains_complete is True
                and result.killed_owned_child is False
                and result.exception_type is result.cleanup_exception_type is None,
                "command_UNKNOWN",
            )
            if sudo:
                need(
                    sha(read(tool, 16 * 1024**2)) == pin["sha256"]
                    and role_identity(tool.lstat()) == role_identity(info),
                    "sudo_changed",
                )
            else:
                need(self.support.tool_pin(tool) == pin, "tool_changed")
            # Raw output is private; the sole caller parses bounded public metadata only.
            self.support.fresh_write(self.private / ("stderr-" + str(self.number)), result.stderr)
            return result.stdout
        except BaseException:
            self.unknown = True
            try:
                self.support.fresh_write(
                    journal / "UNKNOWN.json", b'{"state":"UNKNOWN"}\n', mode=0o444
                )
            except BaseException:
                pass  # Preserve the original refusal; UNKNOWN is already sticky in memory.
            raise


PRESERVE = (
    "GITHUB_ACTIONS,GITHUB_REPOSITORY,GITHUB_EVENT_NAME,GITHUB_REF,GITHUB_HEAD_REF,"
    "GITHUB_SHA,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT,RUNNER_TEMP,P1G_HEAD_REPOSITORY,"
    "PAMOLIVE_P1G_DISPOSABLE,PAMOLIVE_TEST_DATABASE_NAME,DATABASE_URL"
)
APT = [
    "/usr/bin/apt-get",
    "--no-download",
    "--no-remove",
    "--no-install-recommends",
    "--reinstall",
    "-o",
    "Dir::Etc::sourcelist=/dev/null",
    "-o",
    "Dir::Etc::sourceparts=-",
]


def gpg_status_diagnostic(status, listing, primary, signer, now):
    """Bounded metadata only. Never an authentication predicate or key attribution."""
    bad_names = {
        "BADSIG",
        "ERRSIG",
        "EXPSIG",
        "EXPKEYSIG",
        "REVKEYSIG",
        "NO_PUBKEY",
        "NODATA",
        "FAILURE",
        "ERROR",
        "KEYEXPIRED",
        "SIGEXPIRED",
        "KEYREVOKED",
        "BADARMOR",
    }
    benign_names = {
        "NEWSIG",
        "KEY_CONSIDERED",
        "SIG_ID",
        "GOODSIG",
        "VALIDSIG",
        "TRUST_UNDEFINED",
        "TRUST_NEVER",
        "TRUST_MARGINAL",
        "TRUST_FULLY",
        "TRUST_ULTIMATE",
        "POLICY_URL",
        "NOTATION_NAME",
        "NOTATION_DATA",
    }

    def blank_key():
        return {
            "seen": False,
            "unambiguous": False,
            "validity": "unknown",
            "created": None,
            "expires": None,
            "times_well_formed": False,
            "signing_capability": None,
        }

    result = {
        "schema": "pamolive.chrome-gpg-status-diagnostic/1",
        "diagnostic_only": True,
        "operational_GO": False,
        "status_budget_ok": type(status) is bytes and len(status) <= 16384,
        "status_rows_ok": False,
        "status_framing_ok": False,
        "status_parse_complete": False,
        "unknown_status_present": True,
        "bad_names": [],
        "GOODSIG_count": None,
        "VALIDSIG_count": None,
        "listing_budget_ok": type(listing) is bytes and len(listing) <= 16384,
        "listing_rows_ok": False,
        "listing_parse_complete": False,
        "expected_keys": {"primary": blank_key(), "signer": blank_key()},
        "other_keys": {"observed": None, "expired": None, "unusable": None, "unclassified": None},
        "KEYEXPIRED_attributed_to_specific_key": False,
    }
    if result["status_budget_ok"]:
        try:
            lines = status.decode("ascii", "strict").splitlines()
        except UnicodeError:
            lines = None
        if lines is not None and len(lines) <= 1024:
            result["status_rows_ok"] = True
            framed = bool(lines) and all(line.startswith("[GNUPG:] ") for line in lines)
            result["status_framing_ok"] = framed
            if framed:
                rows = [line[9:].split() for line in lines]
                names = [row[0] for row in rows if row]
                complete = len(names) == len(rows)
                result.update(
                    {
                        "status_parse_complete": complete,
                        "unknown_status_present": not complete
                        or any(name not in bad_names | benign_names for name in names),
                        "bad_names": sorted(set(names) & bad_names),
                        "GOODSIG_count": names.count("GOODSIG"),
                        "VALIDSIG_count": names.count("VALIDSIG"),
                    }
                )
    if not result["listing_budget_ok"]:
        return result
    try:
        lines = listing.decode("utf-8", "strict").splitlines()
    except UnicodeError:
        return result
    if len(lines) > 1024:
        return result
    result["listing_rows_ok"] = True
    expected_valid = all(
        type(value) is str and re.fullmatch(r"[0-9A-F]{40}", value) for value in (primary, signer)
    )
    if not expected_valid or type(now) is not int or not 0 <= now <= 253402300799:
        return result
    rows, matches, complete = [line.split(":") for line in lines], {primary: [], signer: []}, True
    others = {"observed": 0, "expired": 0, "unusable": 0, "unclassified": 0}
    other_fingerprints = set()

    def timestamp(value, *, empty=False):
        if value == "" and empty:
            return None, True
        if value.isascii() and value.isdigit() and len(value) <= 12:
            number = int(value)
            if number <= 253402300799:
                return number, True
        return None, False

    for index, row in enumerate(rows):
        if not row or row[0] not in {"pub", "sub"}:
            if not row or row[0] not in {"fpr", "uid", "uat", "tru", "grp"}:
                complete = False
            continue  # UID/trust arguments are never projected.
        if len(row) < 12 or index + 1 >= len(rows):
            complete = False
            others["unclassified"] += 1
            continue
        fpr = rows[index + 1]
        if len(fpr) < 10 or fpr[0] != "fpr" or not re.fullmatch(r"[0-9A-F]{40}", fpr[9]):
            complete = False
            others["unclassified"] += 1
            continue
        created, created_ok = timestamp(row[5])
        expires, expires_ok = timestamp(row[6], empty=True)
        validity = (
            row[1]
            if row[1] in {"-", "q", "n", "m", "f", "u", "r", "e", "d", "i", "o", "w", "s"}
            else "unknown"
        )
        caps_ok = len(row[11]) <= 32 and all(c in "escaESCA?D" for c in row[11])
        state = {
            "seen": True,
            "unambiguous": True,
            "validity": validity,
            "created": created,
            "expires": expires,
            "times_well_formed": created_ok and expires_ok,
            "signing_capability": "s" in row[11] if caps_ok else None,
        }
        complete &= created_ok and expires_ok and caps_ok and validity != "unknown"
        if fpr[9] in matches:
            matches[fpr[9]].append(state)
        else:
            if fpr[9] in other_fingerprints:
                complete = False
                continue
            other_fingerprints.add(fpr[9])
            others["observed"] += 1
            others["expired"] += int(
                validity == "e" or (expires_ok and expires not in {None, 0} and expires <= now)
            )
            others["unusable"] += int(validity in {"r", "e", "d", "i"} or "D" in row[11])
    for label, fingerprint in (("primary", primary), ("signer", signer)):
        found = matches[fingerprint]
        if len(found) == 1:
            result["expected_keys"][label] = found[0]
        elif found:
            state = blank_key()
            state["seen"] = True
            result["expected_keys"][label] = state
            complete = False
    complete &= bool(matches[primary]) and bool(matches[signer])
    result["other_keys"] = others
    result["listing_parse_complete"] = complete
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--pins-sha", required=True)
    parser.add_argument("--native-scope-preflight-required", action="store_true", required=True)
    parser.add_argument("--scope-native-only", action="store_true")
    parser.add_argument("--root-install", action="store_true")
    bundle_modes = parser.add_mutually_exclusive_group()
    bundle_modes.add_argument("--test-bundle", action="store_true")
    bundle_modes.add_argument("--bundle-inventory-only", action="store_true")
    bundle_modes.add_argument("--stage-cleanup-only", action="store_true")
    args = parser.parse_args(argv)
    need(
        not (args.root_install and args.bundle_inventory_only)
        and not (
            args.scope_native_only
            and (args.test_bundle or args.bundle_inventory_only or args.stage_cleanup_only)
        ),
        "bundle_mode",
    )
    need(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true", "CI_Linux_only")
    os.umask(0o077)
    root = ROOT
    need(root == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True) / "p1g-source", "source_root")
    pins, captured = context(
        root,
        Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json",
        args.pins_sha,
        os.environ["GITHUB_SHA"],
    )
    support = load(
        "p1g_chrome_support",
        captured["qualification/p1g_headless/lab_support.py"],
        root / "qualification/p1g_headless/lab_support.py",
    )
    gpg = load(
        "p1g_chrome_gpg",
        captured["qualification/p1g_headless/chrome_gpg.py"],
        root / "qualification/p1g_headless/chrome_gpg.py",
    )
    scope = load(
        "p1g_chrome_key_scope",
        captured["qualification/p1g_headless/chrome_key_scope.py"],
        root / "qualification/p1g_headless/chrome_key_scope.py",
    )
    need(pins["purpose"] == scope.PURPOSE, "scope_purpose")
    need(not (args.root_install and args.scope_native_only), "scope_mode")
    support.guard(os.environ, uid=int(os.environ["SUDO_UID"]) if args.root_install else os.getuid())
    support.source_binding(
        root, Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json", os.environ["GITHUB_SHA"]
    )
    base = Path(os.environ["RUNNER_TEMP"])
    name = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    private = base / ("p1g-chrome-private-" + name)
    public = base / ("p1g-headless-" + name + "-chrome")
    package = private / "chrome.deb"
    if not args.root_install:
        need(os.getuid() > 0, "nonroot_frontend")
        private.mkdir(mode=0o700)
        public.mkdir(mode=0o700)
    else:
        need(os.getuid() == 0, "root_installer_only")
        private = Path("/var/tmp") / ("pamolive-chrome-bootstrap-" + name)
        private.mkdir(mode=0o700)
    command_public = public / ("root" if args.root_install else "frontend")
    public_journal_directory(command_public)
    commands = Commands(
        support,
        support.bounded(root),
        private,
        command_public,
        horizon=450 if args.root_install else 870,
    )
    phase = "authenticate"
    try:
        root_runtime = None
        if args.root_install:
            phase = "root_interpreter"
            root_runtime = root_interpreter_runtime(
                support,
                context_sha=sha(read(base / "p1g-source.json", 4 * 1024**2)),
                pins_sha=args.pins_sha,
                source_sha=sha(captured["qualification/p1g_headless/chrome_bootstrap.py"]),
                revision=os.environ["GITHUB_SHA"],
            )
            need(time.monotonic() < commands.until, "bootstrap_deadline")
            # Observation only: installed/2 and its post-install proof remain mandatory.
            support.fresh_write(
                command_public / "root-interpreter-observation.json",
                json.dumps(root_runtime).encode(),
                mode=0o444,
            )
            phase = "authenticate"
        support.fresh_write(
            command_public / "resources.json",
            json.dumps(support.resources(private)).encode(),
            mode=0o444,
        )
        # Both frontend and privileged supervisor verify the same frozen inputs.
        release_check(captured["Release"], captured["Packages"], int(time.time()))
        package_check(captured["Packages"], pins["package"])
        staged = private / "materials"
        staged.mkdir(mode=0o700)
        for name, body in captured.items():
            if name in MATERIALS:
                support.fresh_write(staged / name, body, mode=0o400)
        valid, scope_proof, positive_status, positive_listing = scope.authenticate(
            commands,
            support,
            staged,
            private,
            gpg,
            captured["google-key.asc"],
            diagnostic_sink=lambda status, listed, now: support.fresh_write(
                command_public / "gpg-status-diagnostic.json",
                json.dumps(
                    gpg_status_diagnostic(status, listed, pins["primary"], pins["signer"], now)
                ).encode(),
                mode=0o444,
            ),
        )
        native_path = public / "scope-native-preflight.json"
        native = load(
            "p1g_chrome_key_scope_native",
            captured["qualification/p1g_headless/chrome_key_scope_native.py"],
            root / "qualification/p1g_headless/chrome_key_scope_native.py",
        )
        if not args.root_install:
            phase = "scope_native_preflight"
            original_listing = commands.run(
                scope.options(private / "gnupg-original")
                + [
                    "--with-colons",
                    "--fixed-list-mode",
                    "--fingerprint",
                    "--with-subkey-fingerprint",
                    "--list-keys",
                ],
                seconds=10,
                cap=16384,
            )
            fixture_prefix = "qualification/p1g_headless/gpg_fixture/"
            need(
                sha(captured[fixture_prefix + "source-pins.json"])
                == native.PRODUCER_CONTRACT["source_pin"],
                "producer_external_source_pin",
            )
            owner_module = load(
                "p1g_TEST_fixture_owner",
                captured[fixture_prefix + "fixture_owner.py"],
                root / (fixture_prefix + "fixture_owner.py"),
            )
            loaded, fixture_sources = owner_module.modules(native.PRODUCER_CONTRACT["source_pin"])
            fixture_context = loaded["fixture_contract"].ci_context(os.environ)

            def produce():
                return owner_module.Owner(
                    loaded,
                    fixture_sources,
                    command_public / "TEST-fixture-generator",
                    until=commands.until,
                    context=os.environ,
                ).run()

            def publish_fixture(buffers, facts):
                destination = command_public / "TEST-fixture-public"
                destination.mkdir(mode=0o700)
                need(
                    set(buffers) == set(native.PRODUCER_CONTRACT["public_names"]),
                    "producer_public_names",
                )
                for name in native.PRODUCER_CONTRACT["public_names"]:
                    support.fresh_write(destination / name, buffers[name], mode=0o444)
                raw = json.dumps(facts).encode()
                need(len(raw) <= 65536, "producer_public_facts_budget")
                support.fresh_write(destination / "fixture-facts.json", raw, mode=0o444)

            def lane_factory(label):
                local = private / ("native-" + label)
                local.mkdir(mode=0o700)
                journal = command_public / ("native-" + label)
                journal.mkdir(mode=0o700)
                lane = Commands(support, commands.io, local, journal)
                lane.until = commands.until
                return lane, local

            try:
                tested = native.exercise(
                    scope,
                    gpg,
                    support,
                    read,
                    captured,
                    private,
                    lane_factory,
                    expected_scoped_sha256=scope_proof["scoped_sha256"],
                    positive_proof=scope_proof,
                    positive_status=positive_status,
                    positive_listing=positive_listing,
                    original_listing=original_listing,
                    producer=produce,
                    producer_context=fixture_context,
                    publish_fixture=publish_fixture,
                )
            except BaseException:
                support.fresh_write(
                    native_path,
                    json.dumps(
                        {
                            "schema": native.RECEIPT_SCHEMA,
                            "state": "INCOMPLETE",
                            "cases": {},
                            "missing": sorted(native.REQUIRED),
                            "purpose": scope.PURPOSE,
                            "operational_GO": False,
                            "native_case_failed_or_UNKNOWN": True,
                            "matrix_required": sorted(native.MATRIX_REQUIRED),
                            "matrix_completed": [],
                            "matrix_missing": sorted(native.MATRIX_REQUIRED),
                            "source_unimplemented": sorted(
                                native.MATRIX_REQUIRED - native.SOURCE_MATRIX_IMPLEMENTED
                            ),
                            "ADR_evidence_matrix_complete": False,
                            "all_rows_are_native_crypto": False,
                        }
                    ).encode(),
                    mode=0o444,
                )
                raise
            tested.update(
                revision=os.environ["GITHUB_SHA"],
                pins_manifest_sha256=args.pins_sha,
                run=os.environ["GITHUB_RUN_ID"],
                attempt=os.environ["GITHUB_RUN_ATTEMPT"],
                scoped_sha256=scope_proof["scoped_sha256"],
            )
            native_raw = json.dumps(tested).encode()
            need(len(native_raw) <= 16384, "native_receipt_budget")
            support.fresh_write(native_path, native_raw, mode=0o444)
        else:
            tested = json.loads(read(native_path, 16384), object_pairs_hook=unique)
        need(
            native.MATRIX_REQUIRED <= native.SOURCE_MATRIX_IMPLEMENTED
            and tested["schema"] == native.RECEIPT_SCHEMA
            and tested["ADR_evidence_matrix_complete"] is True
            and tested["all_rows_are_native_crypto"] is False
            and tested["producer_contract"] == native.PRODUCER_CONTRACT["purpose"]
            and tested["producer_source_connected"] is True
            and set(tested["matrix_required"]) == native.MATRIX_REQUIRED
            and set(tested["matrix_completed"]) == native.MATRIX_REQUIRED
            and tested["matrix_missing"] == []
            and tested["source_unimplemented"] == []
            and tested["other_expired_keys_freshly_observed"] > 0
            and tested["state"] == "COMPLETE"
            and tested["missing"] == []
            and set(tested["cases"]) == native.REQUIRED
            and set(
                json.loads(
                    captured["qualification/p1g_headless/chrome_scope_native_fixtures.json"],
                    object_pairs_hook=unique,
                )["cases"]
            )
            == set(native.LIFECYCLE)
            and all(
                r["refused"] is True and r["complete_H1"] is True for r in tested["cases"].values()
            )
            and tested["purpose"] == scope.PURPOSE
            and tested["operational_GO"] is False
            and tested["revision"] == os.environ["GITHUB_SHA"]
            and tested["pins_manifest_sha256"] == args.pins_sha
            and tested["run"] == os.environ["GITHUB_RUN_ID"]
            and tested["attempt"] == os.environ["GITHUB_RUN_ATTEMPT"]
            and tested["scoped_sha256"] == scope_proof["scoped_sha256"],
            "scope_native_preflight_incomplete",
        )
        if args.scope_native_only:
            return 0
        now = int(time.time())
        # Metadata is parsed again AFTER actual GPG authentication, before DEB processing.
        release_check(captured["Release"], captured["Packages"], now)
        phase = "package_bytes"
        if not args.root_install:
            with package.open("xb") as sink:
                commands.run(
                    [
                        "/usr/bin/curl",
                        "-q",
                        "--proto",
                        "=https",
                        "--tlsv1.2",
                        "--fail",
                        "--silent",
                        "--show-error",
                        "--noproxy",
                        "*",
                        "--max-time",
                        "120",
                        "--max-filesize",
                        pins["package"]["Size"],
                        BASE_URL + pins["package"]["Filename"],
                    ],
                    seconds=130,
                    cap=int(pins["package"]["Size"]),
                    sink=sink,
                )
            package.chmod(0o400)
        if args.root_install:
            package, cache_binding = root_cache_copy(private, package, pins["package"])
        else:
            need(
                package.stat().st_size == int(pins["package"]["Size"])
                and sha(read(package, 256 * 1024**2)) == pins["package"]["SHA256"],
                "package_bytes",
            )
        control_check(
            commands.run(
                [
                    "/usr/bin/dpkg-deb",
                    "--field",
                    str(package),
                    "Package",
                    "Version",
                    "Architecture",
                    "Depends",
                ],
                seconds=10,
            ),
            pins["package"],
        )
        phase = "payload_inspection"
        payload = private / "payload.tar"
        with payload.open("xb+") as stream:
            commands.run(
                ["/usr/bin/dpkg-deb", "--fsys-tarfile", str(package)],
                seconds=60,
                cap=1024**3,
                sink=stream,
            )
            target = payload_target(stream, until=commands.until - 10)
            if args.test_bundle or args.bundle_inventory_only or args.stage_cleanup_only:
                bundle = load(
                    "p1g_authenticated_bundle",
                    captured["qualification/p1g_headless/chrome_bundle.py"],
                    root / "qualification/p1g_headless/chrome_bundle.py",
                )
                profile_raw = captured["qualification/p1g_headless/chrome-bundle-profile.json"]
                tree = bundle.inventory(
                    stream, pins["package"]["SHA256"], until=commands.until - 10
                )
                support.fresh_write(
                    command_public / "bundle-inventory.json", bundle.canonical(tree), mode=0o444
                )
                if args.bundle_inventory_only:
                    return 0
                if args.stage_cleanup_only:
                    phase = "private_stage_admission"
                    stage_only = load(
                        "p1g_private_phase_a",
                        captured["qualification/p1g_headless/chrome_phase_a.py"],
                        root / "qualification/p1g_headless/chrome_phase_a.py",
                    )
                    profile_raw = captured[
                        "qualification/p1g_headless/chrome-stage-only-profile.json"
                    ]
                    stage_only.admit(bundle, tree, profile_raw, stage_only.PROFILE_SHA)
                else:
                    phase = "test_bundle_admission"
                    bundle.admit(tree, profile_raw, bundle.PROFILE_SHA)
        phase = "dependencies"
        if args.root_install:
            root_cache_check(private, cache_binding, pins["package"])
            apt_plan(commands.run(root_apt_argv(private, action="--simulate"), seconds=30))
            root_cache_check(private, cache_binding, pins["package"])
        else:
            apt_plan(commands.run([*APT, "--simulate", "install", str(package)], seconds=30))
        if args.stage_cleanup_only:
            phase = "private_stage_cleanup_only"
            bindings = {
                "revision": os.environ["GITHUB_SHA"],
                "pins_manifest_sha256": args.pins_sha,
                "context_receipt_sha256": sha(read(base / "p1g-source.json", 4 * 1024**2)),
                "package_version": pins["package"]["Version"],
                "signature": valid,
                "key_scope": scope_proof,
                "root_interpreter": root_runtime,
            }
            source_sha = sha(captured["qualification/p1g_headless/chrome_bootstrap.py"])
            if args.root_install:
                result = private_stage_root(commands, support, bundle, stage_only, tree,
                                            profile_raw, bindings, private, cache_binding,
                                            pins, payload, source_sha, root_runtime)
                # DATA response from the exact, normally completed Root command.
                # It cannot authorize v3/UI and the prefix is already absent.
                print(bundle.canonical(result).decode("utf-8"), end="", flush=True)
            else:
                result = private_stage_supervisor(commands, support, bundle, stage_only, tree,
                                                  bindings, args.pins_sha, source_sha)
            support.fresh_write(
                public / ("root-private-stage.json" if args.root_install else "private-stage.json"),
                bundle.canonical(result), mode=0o444,
            )
            return 0
        if args.test_bundle:
            phase = "test_bundle_stage"
            bindings = {
                "revision": os.environ["GITHUB_SHA"],
                "pins_manifest_sha256": args.pins_sha,
                "context_receipt_sha256": sha(read(base / "p1g-source.json", 4 * 1024**2)),
                "package_version": pins["package"]["Version"],
                "signature": valid,
                "key_scope": scope_proof,
                "root_interpreter": root_runtime,
            }
            if not args.root_install:
                root_bundle_supervisor(
                    commands,
                    support,
                    bundle,
                    profile_raw,
                    bindings,
                    args.pins_sha,
                    sha(captured["qualification/p1g_headless/chrome_bootstrap.py"]),
                )
            else:
                bundle_receipt = stage_bundle_root(
                    commands,
                    support,
                    bundle,
                    profile_raw,
                    bindings,
                    pins,
                    args,
                    captured,
                    private,
                    cache_binding,
                    payload,
                    tree,
                    root_runtime,
                )
                support.fresh_write(
                    public / "test-bundle.json", bundle.canonical(bundle_receipt), mode=0o444
                )
            return 0
        if not args.root_install:
            phase = "root_supervisor"
            root_supervisor(
                commands,
                support,
                public,
                pins,
                args.pins_sha,
                target,
                scope_proof,
                sha(captured["qualification/p1g_headless/chrome_bootstrap.py"]),
                valid,
            )
        else:
            phase = "install_local_exact"
            release_check(captured["Release"], captured["Packages"], int(time.time()))
            # No remote source, dependency fetching/fix, downgrade consent or mode repair.
            root_cache_check(private, cache_binding, pins["package"])
            commands.run(
                root_apt_argv(private, action="--assume-yes"),
                seconds=180,
                diagnostic_role="root-local-exact-install",
            )
            root_cache_check(private, cache_binding, pins["package"])
            phase = "unchanged_Chrome_guard"
            installed = commands.run(
                [
                    "/usr/bin/dpkg-query",
                    "--show",
                    "--showformat=${Package}\n${Version}\n${Architecture}\n${Status}\n",
                    "google-chrome-stable",
                ],
                seconds=10,
            )
            need(
                installed
                == (
                    "google-chrome-stable\n"
                    + pins["package"]["Version"]
                    + "\namd64\ninstall ok installed\n"
                ).encode(),
                "installed_package_identity",
            )
            need(
                support.tool_pin(TARGET) == target and TARGET.lstat().st_gid == 0,
                "installed_payload_mismatch",
            )
            need(time.monotonic() < commands.until, "bootstrap_deadline")
            need(
                root_interpreter_runtime(
                    support,
                    context_sha=sha(read(base / "p1g-source.json", 4 * 1024**2)),
                    pins_sha=args.pins_sha,
                    source_sha=sha(captured["qualification/p1g_headless/chrome_bootstrap.py"]),
                    revision=os.environ["GITHUB_SHA"],
                )
                == root_runtime,
                "root_interpreter_changed",
            )
            need(time.monotonic() < commands.until, "bootstrap_deadline")
            support.fresh_write(
                public / "installed.json",
                json.dumps(
                    {
                        "schema": INSTALLED_SCHEMA,
                        "state": "INSTALLED_AUTHENTICATED_PACKAGE_ONLY",
                        "package_sha256": pins["package"]["SHA256"],
                        "package_version": pins["package"]["Version"],
                        "revision": os.environ["GITHUB_SHA"],
                        "pins_manifest_sha256": args.pins_sha,
                        "context_receipt_sha256": sha(
                            read(Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json", 4 * 1024**2)
                        ),
                        "target": target,
                        "signature": valid,
                        "key_scope": scope_proof,
                        "root_interpreter": root_runtime,
                        "all_OS_descendants_released": False,
                        "browser_executed": False,
                        "operational_GO": False,
                    }
                ).encode(),
                mode=0o444,
            )
        return 0
    except BaseException as error:
        code = (
            error.args[0]
            if (
                type(error) is ValueError
                and len(error.args) == 1
                and type(error.args[0]) is str
                and error.args[0] in DIAGNOSTICS
            )
            else "unknown"
        )
        support.fresh_write(
            public / ("root-UNKNOWN.json" if args.root_install else "UNKNOWN.json"),
            json.dumps(
                {
                    "state": "UNKNOWN",
                    "phase": phase,
                    "code": code,
                    "error_class": type(error).__name__,
                    "all_OS_descendants_released": False,
                    "operational_GO": False,
                }
            ).encode(),
            mode=0o444,
        )
        return 42


def stage_bundle_root(
    commands,
    support,
    bundle,
    profile_raw,
    bindings,
    pins,
    args,
    captured,
    private,
    cache_binding,
    payload,
    tree,
    root_runtime,
):
    root_cache_check(private, cache_binding, pins["package"])
    with payload.open("rb") as stream:
        bundle_receipt = bundle.stage(
            stream,
            tree,
            profile_raw,
            bundle.PROFILE_SHA,
            os.environ,
            bindings,
            until=commands.until - 10,
        )
    bundle.verify(os.environ, bindings, profile_raw, bundle.PROFILE_SHA, until=commands.until - 10)
    root_cache_check(private, cache_binding, pins["package"])
    need(
        root_interpreter_runtime(
            support,
            context_sha=bindings["context_receipt_sha256"],
            pins_sha=args.pins_sha,
            source_sha=sha(captured["qualification/p1g_headless/chrome_bootstrap.py"]),
            revision=os.environ["GITHUB_SHA"],
        )
        == root_runtime,
        "root_interpreter_changed",
    )
    return bundle_receipt


def root_bundle_supervisor(commands, support, bundle, profile_raw, bindings, pins_sha, source_sha):
    """Explicit new contract; no fallback from a refused legacy installation."""
    role = root_interpreter_pin(support)
    commands.run(
        [
            "/usr/bin/sudo",
            "-n",
            "--preserve-env=" + PRESERVE,
            "--",
            ROOT_INTERPRETER,
            "-I",
            "-B",
            "-S",
            str(HERE / "chrome_bootstrap.py"),
            "--pins-sha",
            pins_sha,
            "--root-install",
            "--test-bundle",
            "--native-scope-preflight-required",
        ],
        seconds=480,
        sudo=True,
    )
    need(root_interpreter_pin(support) == role, "root_interpreter_changed")
    expected = {key: value for key, value in bindings.items() if key != "root_interpreter"}

    def runtime_check(facts):
        check_root_interpreter(
            facts,
            role,
            context_sha=bindings["context_receipt_sha256"],
            pins_sha=pins_sha,
            source_sha=source_sha,
            revision=bindings["revision"],
        )

    bundle.verify(
        os.environ,
        expected,
        profile_raw,
        bundle.PROFILE_SHA,
        until=commands.until - 10,
        runtime_check=runtime_check,
    )
    need(root_interpreter_pin(support) == role, "root_interpreter_changed")
    need(time.monotonic() < commands.until, "bootstrap_deadline")


def private_stage_root(commands, support, bundle, stage_only, tree, profile_raw, bindings,
                       private, cache_binding, pins, payload, source_sha, root_runtime):
    root_cache_check(private, cache_binding, pins["package"])
    with payload.open("rb") as stream:
        result = stage_only.run(bundle, stream, tree, profile_raw, stage_only.PROFILE_SHA,
                                os.environ, bindings, until=commands.until - 10)
    root_cache_check(private, cache_binding, pins["package"])
    need(root_interpreter_runtime(support, context_sha=bindings["context_receipt_sha256"],
         pins_sha=bindings["pins_manifest_sha256"], source_sha=source_sha,
         revision=bindings["revision"]) == root_runtime, "root_interpreter_changed")
    need(time.monotonic() < commands.until, "bootstrap_deadline")
    return result


def private_stage_supervisor(
    commands, support, bundle, stage_only, tree, bindings, pins_sha, source_sha
):
    """Typed, non-UI Phase A; only normal Root completion plus independent absence."""
    role = root_interpreter_pin(support)
    raw = commands.run(
        ["/usr/bin/sudo", "-n", "--preserve-env=" + PRESERVE, "--", ROOT_INTERPRETER,
         "-I", "-B", "-S", str(HERE / "chrome_bootstrap.py"), "--pins-sha", pins_sha,
         "--root-install", "--stage-cleanup-only", "--native-scope-preflight-required"],
        seconds=480, cap=32768, sudo=True,
    )
    need(root_interpreter_pin(support) == role, "root_interpreter_changed")
    result = stage_only.result_contract(
        bundle, raw, tree, stage_only.PROFILE_SHA, os.environ, bindings
    )
    check_root_interpreter(result["root_interpreter"], role,
                           context_sha=bindings["context_receipt_sha256"], pins_sha=pins_sha,
                           source_sha=source_sha, revision=bindings["revision"])
    stage_only.assert_absent(bundle, os.environ, until=commands.until - 10)
    need(root_interpreter_pin(support) == role, "root_interpreter_changed")
    need(time.monotonic() < commands.until, "bootstrap_deadline")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
