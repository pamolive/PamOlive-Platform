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
import tarfile
import time
from datetime import timedelta
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TARGET = Path("/opt/google/chrome/chrome")
PIN_PATH = "qualification/p1g_headless/chrome-bootstrap-pins.json"
SOURCE_PATHS = {
    "qualification/p1g_headless/chrome_bootstrap.py",
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


def payload_target(stream):
    stream.seek(0)
    target, count, total = None, 0, 0
    with tarfile.open(fileobj=stream, mode="r:") as archive:
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


class Commands:
    def __init__(self, support, bounded, private, public, *, horizon=870):
        self.support, self.io, self.private, self.public = support, bounded, private, public
        self.number, self.unknown = 0, False
        self.until = time.monotonic() + horizon

    def run(self, argv, *, seconds=30, cap=262144, sink=None, sudo=False):
        need(not self.unknown, "previous_UNKNOWN")
        need(time.monotonic() + seconds + 10 < self.until, "bootstrap_deadline")
        self.number += 1
        journal = self.public / ("command-" + str(self.number))
        journal.mkdir(mode=0o755)
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
            self.support.fresh_write(
                journal / "process.json", json.dumps(result.facts()).encode(), mode=0o444
            )
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
            self.support.fresh_write(journal / "UNKNOWN.json", b'{"state":"UNKNOWN"}\n', mode=0o444)
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
    args = parser.parse_args(argv)
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
    command_public.mkdir(mode=0o755)
    commands = Commands(
        support,
        support.bounded(root),
        private,
        command_public,
        horizon=450 if args.root_install else 870,
    )
    phase = "authenticate"
    try:
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
        need(
            package.stat().st_size == int(pins["package"]["Size"])
            and sha(read(package, 256 * 1024**2)) == pins["package"]["SHA256"],
            "package_bytes",
        )
        if args.root_install:
            # Place verified bytes in a fresh root-owned directory before package tools.
            raw = read(package, 256 * 1024**2)
            need(sha(raw) == pins["package"]["SHA256"], "package_changed")
            package = private / "chrome.deb"
            support.fresh_write(package, raw, mode=0o400)
            del raw
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
            target = payload_target(stream)
        phase = "dependencies"
        apt_plan(commands.run([*APT, "--simulate", "install", str(package)], seconds=30))
        if not args.root_install:
            phase = "root_supervisor"
            python = Path(sys.executable).resolve(strict=True)
            support.tool_pin(python)
            commands.run(
                [
                    "/usr/bin/sudo",
                    "-n",
                    "--preserve-env=" + PRESERVE,
                    "--",
                    str(python),
                    "-I",
                    "-B",
                    "-S",
                    str(HERE / "chrome_bootstrap.py"),
                    "--pins-sha",
                    args.pins_sha,
                    "--root-install",
                    "--native-scope-preflight-required",
                ],
                seconds=480,
                sudo=True,
            )
            result = json.loads(read(public / "installed.json", 32768), object_pairs_hook=unique)
            need(
                result["state"] == "INSTALLED_AUTHENTICATED_PACKAGE_ONLY"
                and result["target"] == target
                and result["package_sha256"] == pins["package"]["SHA256"]
                and result["pins_manifest_sha256"] == args.pins_sha
                and result["revision"] == os.environ["GITHUB_SHA"]
                and result["key_scope"] == scope_proof,
                "root_receipt",
            )
        else:
            phase = "install_local_exact"
            release_check(captured["Release"], captured["Packages"], int(time.time()))
            # No remote source, dependency fetching/fix, downgrade consent or mode repair.
            need(sha(read(package, 256 * 1024**2)) == pins["package"]["SHA256"], "package_changed")
            commands.run([*APT, "--assume-yes", "install", str(package)], seconds=180)
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
            support.fresh_write(
                public / "installed.json",
                json.dumps(
                    {
                        "schema": "pamolive.chrome-bootstrap/1",
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


if __name__ == "__main__":
    raise SystemExit(main())
