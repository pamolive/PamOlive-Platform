"""Linux-only native matrix; missing source or native cases never admit installation."""

import json
import re
import time
from pathlib import Path

REQUIRED = {
    "bad_signature",
    "missing_binding",
    "corrupt_crosscert",
    "corrupt_selfsig",
    "historical_expired_signer",
    "primary_expired",
    "primary_revoked",
    "signer_revoked",
}
RECEIPT_SCHEMA = "pamolive.chrome-scope-native-preflight/2"
VENDOR_PURPOSE = "google-release-selected-signer-certificate-v1"
LIFECYCLE = {
    "historical_expired_signer": ("signer", "e"),
    "primary_expired": ("primary", "e"),
    "primary_revoked": ("primary", "r"),
    "signer_revoked": ("signer", "r"),
}
MATRIX_REQUIRED = REQUIRED | {
    "vendor_scoped_positive",
    "wrong_authority",
    "wrong_signer",
    "signature_future",
    "signature_expired",
    "signature_before_key",
    "signature_after_key_expiry",
    "unexpected_key_UID_packet",
    "export_filter_unavailable",
}
CASE_POLICY = {
    **{name: "native_GPG_refusal" for name in REQUIRED - set(LIFECYCLE)},
    **{name: "native_GPG_state_guard" for name in LIFECYCLE},
    "vendor_scoped_positive": "native_GPG_positive_with_other_expired_observed",
    "wrong_authority": "native_output_authority_guard",
    "wrong_signer": "native_output_authority_guard",
    "signature_future": "native_GPG_temporal_refusal",
    "signature_expired": "native_GPG_temporal_refusal",
    "signature_before_key": "modelled_guard_with_native_preconditions",
    "signature_after_key_expiry": "modelled_guard_with_native_preconditions",
    "unexpected_key_UID_packet": "DATA_precrypto_guard",
    "export_filter_unavailable": "mandatory_pure_model_and_current_native_capability",
}
SOURCE_MATRIX_IMPLEMENTED = MATRIX_REQUIRED
PRODUCER_CONTRACT = {
    "purpose": "pamolive.gpg-selected-signer-revoked-fixture/2",
    "source_pin": "7bb5c0565e1a4a0c5ddd5f3b729626680076fba66b88a82729b170b115edbf84",
    "call": "produce() -> (immutable_public_buffers, typed_TEST_facts)",
    "public_names": (
        "certificate-before.pgp",
        "certificate-revoked.pgp",
        "message.bin",
        "signature.sig",
        "signature-future.sig",
        "signature-expired.sig",
    ),
    "reviewed_source_connected": True,
    "requirements": (
        "owned_agent_normal_H1_and_socket_removed",
        "private_secret_home_removed",
        "same_captured_buffers_bound_to_SHA256",
        "consumer_independent_positive_then_sub_r_then_preexport_refusal",
    ),
}
TEST_MESSAGE = b"PamOlive synthetic selected signing subkey revocation fixture v1\n"


def need(ok, code):
    if not ok:
        raise ValueError(code)


def matrix_facts(cases, positive_proof, expected_scoped_sha256, *, evidence=None, expired_others=0):
    """Describe actual completed cases separately from absent source/native coverage."""
    observed = {
        label
        for label, row in cases.items()
        if label in REQUIRED
        and type(row) is dict
        and row.get("refused") is True
        and row.get("complete_H1") is True
    }
    evidence = {} if evidence is None else evidence
    for name, row in evidence.items():
        need(name in CASE_POLICY and row["evidence_kind"] == CASE_POLICY[name], "matrix_kind")
        if row.get("covered") is True:
            observed.add(name)
    if (
        type(positive_proof) is dict
        and positive_proof.get("purpose") == VENDOR_PURPOSE
        and positive_proof.get("crypto_verified") is True
        and positive_proof.get("selected_states_identical") is True
        and positive_proof.get("scoped_sha256") == expected_scoped_sha256
        and type(expired_others) is int
        and expired_others > 0
    ):
        observed.add("vendor_scoped_positive")
    source_missing = sorted(MATRIX_REQUIRED - SOURCE_MATRIX_IMPLEMENTED)
    return {
        "matrix_required": sorted(MATRIX_REQUIRED),
        "matrix_completed": sorted(observed),
        "matrix_missing": sorted(MATRIX_REQUIRED - observed),
        "source_unimplemented": source_missing,
        "ADR_evidence_matrix_complete": not source_missing and observed == MATRIX_REQUIRED,
        "all_rows_are_native_crypto": False,
        "matrix_evidence": evidence,
        "other_expired_keys_freshly_observed": expired_others,
        "producer_contract": PRODUCER_CONTRACT["purpose"],
        "producer_source_connected": PRODUCER_CONTRACT["reviewed_source_connected"],
    }


def expected_refusal(action, code):
    try:
        action()
    except ValueError as error:
        need(error.args == (code,), "matrix_unexpected_guard")
    else:
        raise ValueError("matrix_guard_accepted")


def control_evidence(scope, gpg, status, listing, original_listing, captured, selected, now):
    """Actual GPG output policy, explicit models and DATA guards; no forged signature."""
    gpg.valid_status(status, scope.PRIMARY, scope.SIGNER, now)
    keys = gpg.one_primary(listing, scope.PRIMARY)
    gpg.signing_capability(keys, scope.PRIMARY, scope.SIGNER, now)
    original_keys = gpg.one_primary(original_listing, scope.PRIMARY)
    _, _, original_subs = scope.blocks(captured["google-key.asc"])
    need(set(original_keys) == {scope.PRIMARY, *original_subs}, "matrix_original_keyset")
    expired_others = sum(
        row["validity"] == "e"
        for key, row in original_keys.items()
        if key not in {scope.PRIMARY, scope.SIGNER}
    )
    need(expired_others > 0, "matrix_expired_other_not_observed")
    evidence = {}
    for name, primary, signer in (
        ("wrong_authority", "F" * 40, scope.SIGNER),
        ("wrong_signer", scope.PRIMARY, "F" * 40),
    ):
        expected_refusal(
            lambda: gpg.valid_status(status, primary, signer, now), "signature_authority"
        )
        evidence[name] = {
            "covered": True,
            "evidence_kind": CASE_POLICY[name],
            "guard_code": "signature_authority",
            "native_signature_forged": False,
            "native_status_sha256": scope.sha(status),
            "operational_GO": False,
        }
    expiry = [int(row["expires"]) for row in keys.values() if row["expires"] not in {"", "0"}]
    need(expiry, "matrix_expiry_precondition")
    for name, when in (
        ("signature_before_key", max(int(row["created"]) for row in keys.values()) - 1),
        ("signature_after_key_expiry", min(expiry) + 1),
    ):
        expected_refusal(
            lambda: gpg.signing_capability(keys, scope.PRIMARY, scope.SIGNER, now, when), name
        )
        evidence[name] = {
            "covered": True,
            "evidence_kind": CASE_POLICY[name],
            "guard_code": name,
            "synthetic_guard_input": True,
            "native_exact_crypto_branch": False,
            "native_precondition": "current_selected_keys_usable",
            "operational_GO": False,
        }
    _, prefix, subs = scope.blocks(selected)
    changed = list(prefix)
    index = next(i for i, row in enumerate(changed) if row[0] == 13)
    tag, body, _ = changed[index]
    changed[index] = (tag, body + b" TEST_UNEXPECTED_UID", b"")
    uid_mutation = b"".join(encoded(t, b) for t, b, _ in changed + subs[scope.SIGNER])
    expected_refusal(
        lambda: scope.lineage(captured["google-key.asc"], uid_mutation),
        "scope_primary_block_changed",
    )
    other = next(rows for key, rows in original_subs.items() if key != scope.SIGNER)
    extra_key = selected + b"".join(encoded(t, b) for t, b, _ in other)
    expected_refusal(
        lambda: scope.lineage(captured["google-key.asc"], extra_key), "scope_exact_keys"
    )
    expected_refusal(
        lambda: scope.lineage(captured["google-key.asc"], selected + encoded(60, b"UNEXPECTED")),
        "scope_secret_or_unknown_tag",
    )
    evidence["unexpected_key_UID_packet"] = {
        "covered": True,
        "evidence_kind": CASE_POLICY["unexpected_key_UID_packet"],
        "blocked_variants": ["UID", "extra_key", "unknown_packet"],
        "crypto_calls_for_blocked_inputs": 0,
        "operational_GO": False,
    }
    model_paths = (
        "qualification/p1g_headless/test_chrome_bootstrap.py",
        "qualification/p1g_headless/test_chrome_key_scope.py",
    )
    evidence["export_filter_unavailable"] = {
        "covered": True,
        "evidence_kind": CASE_POLICY["export_filter_unavailable"],
        "model_references": [
            "test_real_command_H1_pending_before_spawn_and_UNKNOWN_sticky",
            "test_R2_export_filter_unavailable_blocks_scoped_import",
        ],
        "model_source_sha256": {path: scope.sha(captured[path]) for path in model_paths},
        "native_current_filter_supported": True,
        "native_unsupported_host_simulated": False,
        "reception_requires_mandatory_pure_step_success": True,
        "operational_GO": False,
    }
    return evidence, expired_others


def encoded(tag, body):
    return bytes([0xC0 | tag, 255]) + len(body).to_bytes(4, "big") + body


def mutate_key(scope, raw, kind):
    """Test DATA mutations only; never used by certificate derivation/installation."""
    _, prefix, subs = scope.blocks(raw)
    sub = list(subs[scope.SIGNER])
    prefix = list(prefix)
    if kind == "missing_binding":
        sub = [r for r in sub if r[0] != 2 or r[1][1] != 0x18]
    elif kind == "corrupt_selfsig":
        indexes = [
            i for i, r in enumerate(prefix) if r[0] == 2 and r[1][1] in {0x10, 0x11, 0x12, 0x13}
        ]
        need(indexes, "native_selfsig_fixture")
        for i in indexes:
            tag, body, _ = prefix[i]
            prefix[i] = (tag, body[:-1] + bytes([body[-1] ^ 1]), b"")
    else:
        need(kind == "corrupt_crosscert", "native_mutation_kind")
        changed = False
        for i, (tag, body, _) in enumerate(sub):
            if tag != 2 or body[1] != 0x18:
                continue
            # Flip the embedded cross-signature's last byte when its signature
            # subpacket32 is present; no resigning or weak flags. If hashed, this
            # also invalidates the outer binding: report does not claim isolation.
            h = int.from_bytes(body[4:6], "big")
            u = int.from_bytes(body[6 + h : 8 + h], "big")
            spans = [(6, 6 + h), (8 + h, 8 + h + u)]
            data = bytearray(body)
            for start, end in spans:
                at = start
                while at < end:
                    size = body[at]
                    at += 1
                    if 192 <= size < 255:
                        need(at < end, "native_subpacket")
                        size = ((size - 192) << 8) + body[at] + 192
                        at += 1
                    elif size == 255:
                        need(at + 4 <= end, "native_subpacket")
                        size = int.from_bytes(body[at : at + 4], "big")
                        at += 4
                    need(size > 0 and at + size <= end, "native_subpacket")
                    if body[at] & 127 == 32:
                        data[at + size - 1] ^= 1
                        changed = True
                    at += size
            sub[i] = (tag, bytes(data), b"")
        need(changed, "native_crosscert_fixture")
    return b"".join(encoded(tag, body) for tag, body, _ in prefix + sub)


def command_status(lane, support, read, argv, case, name):
    """Retain expected normal nonzero in its UNKNOWN lane; never heal a process failure."""
    status_path = case / name
    index = lane.number + 1
    nonzero = False
    with status_path.open("xb") as sink:
        try:
            lane.run(
                argv,
                seconds=10,
                cap=65536,
                sink=sink,
            )
        except ValueError as error:
            need(error.args == ("command_UNKNOWN",), "native_verify_unknown")
            nonzero = True
    journal = lane.public / ("command-" + str(index))
    facts = json.loads(read(journal / "process.json", 16384))
    need(
        facts["returncode"] in {0, 1, 2}
        and type(facts["returncode"]) is int
        and facts["reason"] == ("nonzero_exit" if nonzero else None)
        and (facts["returncode"] != 0) is nonzero
        and facts["spawn_attempted"] is True
        and type(facts["pid"]) is int
        and facts["pid"] > 0
        and facts["owned_child_reaped"] is True
        and facts["drains_complete"] is True
        and facts["killed_owned_child"] is False
        and facts["exception_type"] is facts["cleanup_exception_type"] is None,
        "native_negative_H1_unknown",
    )
    pin = json.loads(read(journal / "intent.json", 16384))["tool"]
    need(support.tool_pin(Path(argv[0])) == pin, "native_negative_tool_changed")
    status = read(status_path, 65536)
    need(
        type(facts["stdout_bytes"]) is int
        and len(status) == facts["stdout_bytes"]
        and len(status) <= 65536,
        "native_status_bytes",
    )
    return status, nonzero, facts


def verify_status(lane, support, read, scope, home, sig, data, case):
    return command_status(
        lane,
        support,
        read,
        scope.options(home) + ["--status-fd", "1", "--verify", str(sig), str(data)],
        case,
        "status",
    )


def status_rows(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 65536, "native_status_budget")
    lines = raw.decode("ascii", "strict").splitlines()
    need(
        len(lines) <= 512 and all(line.startswith("[GNUPG:] ") for line in lines), "status_framing"
    )
    rows = [line[9:].split() for line in lines]
    need(all(rows), "status_framing")
    return rows


def terminal_failure(rows):
    """GnuPG2.4 g10_exit emits GENERAL for normal nonzero; other failures stay closed."""
    failures = [row for row in rows if row[0] == "FAILURE"]
    need(
        not failures or failures == [["FAILURE", "gpg-exit", "33554433"]],
        "native_unexpected_FAILURE",
    )


def verify_refusal(
    lane, support, read, scope, gpg, case, certificate, signature, release, primary, signer
):
    home = case / "home"
    home.mkdir(mode=0o700)
    key, sig, data = (case / n for n in ("key.gpg", "signature.asc", "Release"))
    for path, body in ((key, certificate), (sig, signature), (data, release)):
        support.fresh_write(path, body, mode=0o400)
    imported, import_nonzero, _ = command_status(
        lane,
        support,
        read,
        scope.options(home) + ["--status-fd", "1", "--import", str(key)],
        case,
        "import-status",
    )
    if import_nonzero:
        # DETAILS2.4.7: IMPORT_PROBLEM1 is Invalid Certificate, not a storage error.
        # This is an upstream functional refusal, not a claim about the verify branch.
        rows = status_rows(imported)
        terminal_failure(rows)
        problems = [row for row in rows if row[0] == "IMPORT_PROBLEM"]
        need(
            problems == [["IMPORT_PROBLEM", "1", primary]]
            and not any(row[0] in gpg.BAD - {"FAILURE"} for row in rows),
            "native_import_not_certificate_refusal",
        )
        return {
            "refused": True,
            "complete_H1": True,
            "UNKNOWN_retained": True,
            "refusal_phase": "native_import_invalid_certificate",
            "native_exact_verify_branch": False,
            "operational_GO": False,
        }
    status, nonzero, _ = verify_status(lane, support, read, scope, home, sig, data, case)
    rows = status_rows(status)
    terminal_failure(rows)
    names = {row[0] for row in rows}
    need(
        bool(names & {"BADSIG", "ERRSIG", "NO_PUBKEY"})
        and not names & {"ERROR", "NODATA", "BADARMOR"},
        "native_negative_not_cryptographic_refusal",
    )
    try:
        gpg.valid_status(status, primary, signer, int(time.time()))
    except ValueError as error:
        need(error.args == ("status_bad",), "native_negative_not_cryptographic_refusal")
    else:
        raise ValueError("native_negative_accepted")
    return {
        "refused": True,
        "complete_H1": True,
        "UNKNOWN_retained": nonzero,
        "unfiltered_strict_BAD_refusal": True,
        "refusal_phase": "native_verify_strict_BAD",
        "operational_GO": False,
    }


def producer_inputs(buffers, facts, scope, support, context):
    """A label/time request is never crypto evidence; bind exact immutable public buffers."""
    need(
        type(buffers) is dict and set(buffers) == set(PRODUCER_CONTRACT["public_names"]),
        "producer_public_names",
    )
    need(
        all(type(raw) is bytes and 0 < len(raw) <= 65536 for raw in buffers.values())
        and sum(map(len, buffers.values())) <= 262144,
        "producer_public_budget",
    )
    need(buffers["message.bin"] == TEST_MESSAGE, "producer_message")
    need(
        type(facts) is dict
        and set(facts)
        == {
            "schema",
            "purpose",
            "production_authority",
            "operational_GO",
            "primary",
            "signer",
            "selected_subkey_revocation",
            "cleanup_complete",
            "unknown",
            "adr034_matrix_complete",
            "temporal_signatures",
            "missing_cases",
            "files",
            "context",
            "signature_requests",
            "key_creation_epoch_verified",
            "source_manifest_sha256",
            "tools",
            "python_bootstrap",
            "h1",
        }
        and facts.get("schema") == PRODUCER_CONTRACT["purpose"]
        and facts.get("purpose") == "TEST_ONLY"
        and facts.get("production_authority") is False
        and facts.get("operational_GO") is False
        and facts.get("cleanup_complete") is True
        and facts.get("unknown") is False
        and facts.get("adr034_matrix_complete") is False
        and facts.get("temporal_signatures") == "CREATED_PENDING_INDEPENDENT_NATIVE_CONSUMER"
        and facts.get("source_manifest_sha256") == PRODUCER_CONTRACT["source_pin"]
        and facts.get("context") == context,
        "producer_not_admitted",
    )
    need(
        facts["selected_subkey_revocation"] == "NATIVE_GUARD_REFUSED"
        and facts["missing_cases"]
        == ["primary_revoked_RSA", "signature_future", "signature_expired", "wrong_S2"],
        "producer_public_fields",
    )
    p, s = facts.get("primary"), facts.get("signer")
    need(
        all(type(fp) is str and re.fullmatch("[0-9A-F]{40}", fp) for fp in (p, s))
        and p != s
        and not {p, s} & {scope.PRIMARY, scope.SIGNER},
        "producer_TEST_identity",
    )
    need(
        facts.get("files")
        == {name: {"bytes": len(raw), "sha256": scope.sha(raw)} for name, raw in buffers.items()},
        "producer_buffer_binding",
    )
    request = facts.get("signature_requests")
    need(
        type(request) is dict
        and set(request) == {"anchor", "key", "future", "expired", "signature_duration"}
        and all(type(v) is int for v in request.values()),
        "producer_requested_times",
    )
    anchor = request["anchor"]
    need(
        3600 < anchor < 2**32 - 82800
        and request
        == {
            "anchor": anchor,
            "key": anchor - 3600,
            "future": anchor + 3600,
            "expired": anchor - 600,
            "signature_duration": 60,
        }
        and facts.get("key_creation_epoch_verified") == request["key"],
        "producer_requested_times",
    )
    tools = facts.get("tools")
    need(
        type(tools) is dict
        and set(tools) == {"gpg", "gpg-agent", "gpgconf", "gpg-connect-agent"}
        and all(
            type(row) is dict
            and set(row) == {"sha256", "version"}
            and type(row["sha256"]) is str
            and re.fullmatch("[0-9a-f]{64}", row["sha256"])
            and type(row["version"]) is str
            and re.fullmatch(r"2\.4\.[0-9]{1,3}", row["version"])
            for row in tools.values()
        )
        and tools["gpg"]["sha256"] == support.tool_pin(Path("/usr/bin/gpg"))["sha256"]
        and len({row["version"] for row in tools.values()}) == 1,
        "producer_tool_binding",
    )
    python = facts["python_bootstrap"]
    need(
        type(python) is dict
        and set(python) == {"path", "sha256", "version"}
        and python["path"] == "/usr/bin/python3.12"
        and type(python["sha256"]) is str
        and re.fullmatch("[0-9a-f]{64}", python["sha256"])
        and type(python["version"]) is str
        and re.fullmatch(r"Python 3\.12\.[0-9]{1,3}", python["version"]),
        "producer_python_binding",
    )
    h1 = facts.get("h1")
    need(type(h1) is list and 1 <= len(h1) <= 41, "producer_H1")
    for row in h1:
        need(
            type(row) is dict
            and set(row)
            == {
                "spawn_attempted",
                "pid",
                "returncode",
                "reason",
                "exception_type",
                "killed_owned_child",
                "owned_child_reaped",
                "drains_complete",
                "cleanup_exception_type",
                "stdout_bytes",
                "stderr_bytes",
            }
            and row.get("spawn_attempted") is True
            and type(row.get("pid")) is int
            and row["pid"] > 0
            and type(row.get("returncode")) is int
            and row["returncode"] == 0
            and row.get("reason") is None
            and row.get("owned_child_reaped") is True
            and row.get("drains_complete") is True
            and row.get("killed_owned_child") is False
            and row.get("exception_type") is row.get("cleanup_exception_type") is None,
            "producer_H1",
        )
        need(
            all(
                type(row[name]) is int and 0 <= row[name] <= 262144
                for name in ("stdout_bytes", "stderr_bytes")
            ),
            "producer_H1_bytes",
        )
    # Compare packet content/order/multiplicity; GPG below proves selfsig/revocation validity.
    a, prefix_a, subs_a = scope.blocks(buffers["certificate-before.pgp"])
    b, prefix_b, subs_b = scope.blocks(buffers["certificate-revoked.pgp"])

    def content(rows):
        return [(tag, body) for tag, body, _ in rows]

    need(
        a == b == p
        and set(subs_a) == set(subs_b) == {s}
        and content(prefix_a) == content(prefix_b),
        "producer_lineage",
    )
    old, new = content(subs_a[s]), content(subs_b[s])
    added = [i for i, (tag, body) in enumerate(new) if tag == 2 and body[1] == 0x28]
    need(
        not any(tag == 2 and body[1] == 0x28 for tag, body in old)
        and len(added) == 1
        and len(new) == len(old) + 1
        and new[: added[0]] + new[added[0] + 1 :] == old,
        "producer_lineage",
    )
    return p, s, request


def public_case(lane, case, support, scope, certificate, signature, message):
    home = case / "home"
    home.mkdir(mode=0o700)
    key, sig, data = (case / n for n in ("key.pgp", "signature.sig", "message.bin"))
    for path, raw in ((key, certificate), (sig, signature), (data, message)):
        support.fresh_write(path, raw, mode=0o400)
    lane.run(scope.options(home) + ["--import", str(key)], seconds=10)
    listing = lane.run(
        scope.options(home)
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
    return home, sig, data, listing


def temporal_refusal(raw, gpg, keys, p, s, request, label, now):
    rows = status_rows(raw)
    terminal_failure(rows)
    valid = [row for row in rows if row[0] == "VALIDSIG"]
    need(len(valid) == 1, "temporal_VALID_count")
    row = valid[0]
    need(
        len(row) == 11
        and row[1] == s
        and row[10] == p
        and row[3] == str(request["future" if label == "signature_future" else "expired"])
        and row[5:10] == ["4", "0", "1", "8", "00"],
        "temporal_actual_signature",
    )
    stamp = int(row[3])
    gpg.signing_capability(keys, p, s, now, stamp)
    bad = {r[0] for r in rows if r[0] in gpg.BAD}
    if label == "signature_future":
        need(not bad and row[4] == "0" and stamp > now + 300, "temporal_future_state")
        expected_refusal(lambda: gpg.valid_status(raw, p, s, now), "signature_future")
        code = "signature_future"
    else:
        expiry = stamp + request["signature_duration"]
        need(
            row[4] == str(expiry)
            and expiry < now
            and bad <= {"EXPSIG", "SIGEXPIRED", "FAILURE"}
            and "EXPSIG" in bad,
            "temporal_expired_state",
        )
        # Keep all BAD lines. EXPSIG may precede VALIDSIG; never sanitize then approve.
        expected_refusal(lambda: gpg.valid_status(raw, p, s, now), "status_bad")
        code = "status_bad"
    return {
        "covered": True,
        "evidence_kind": CASE_POLICY[label],
        "guard_code": code,
        "actual_timestamp": stamp,
        "actual_expiry": int(row[4]),
        "native_VALID_identity_bound": True,
        "real_verification_clock": True,
        "operational_GO": False,
    }


def consume_producer(producer, scope, gpg, support, read, lane_factory, context):
    buffers, facts = producer()
    p, s, request = producer_inputs(buffers, facts, scope, support, context)
    evidence = {}
    positive, case = lane_factory("TEST-positive")
    home, sig, data, listed = public_case(
        positive,
        case,
        support,
        scope,
        buffers["certificate-before.pgp"],
        buffers["signature.sig"],
        buffers["message.bin"],
    )
    keys = gpg.one_primary(listed, p)
    need(
        set(keys) == {p, s}
        and all(
            r["created"] == str(request["key"]) and r["expires"] == str(request["key"] + 86400)
            for r in keys.values()
        ),
        "consumer_native_key_times",
    )
    status = positive.run(
        scope.options(home) + ["--status-fd", "1", "--verify", str(sig), str(data)],
        seconds=10,
        cap=16384,
    )
    now = int(time.time())
    actual = gpg.valid_status(status, p, s, now)
    gpg.signing_capability(keys, p, s, now, actual["timestamp"])
    vals = [row for row in status_rows(status) if row[0] == "VALIDSIG"]
    need(vals[0][7:10] == ["1", "8", "00"], "consumer_positive_RSA_SHA256")
    for label, name in (
        ("signature_future", "signature-future.sig"),
        ("signature_expired", "signature-expired.sig"),
    ):
        lane, case = lane_factory(label)
        home, sig, data, temporal_listing = public_case(
            lane,
            case,
            support,
            scope,
            buffers["certificate-before.pgp"],
            buffers[name],
            buffers["message.bin"],
        )
        temporal_keys = gpg.one_primary(temporal_listing, p)
        need(temporal_keys == keys, "consumer_key_state_changed")
        raw, nonzero, _ = verify_status(lane, support, read, scope, home, sig, data, case)
        evidence[label] = temporal_refusal(raw, gpg, keys, p, s, request, label, int(time.time()))
        evidence[label]["complete_H1"] = True
        evidence[label]["UNKNOWN_retained"] = nonzero
    negative, case = lane_factory("signer_revoked")
    _, _, _, listed = public_case(
        negative,
        case,
        support,
        scope,
        buffers["certificate-revoked.pgp"],
        buffers["signature.sig"],
        buffers["message.bin"],
    )
    revoked = gpg.one_primary(listed, p)
    need(set(revoked) == {p, s} and revoked[s]["validity"] == "r", "consumer_native_sub_r")
    expected_refusal(
        lambda: gpg.signing_capability(revoked, p, s, int(time.time())), "key_unusable"
    )
    refusal = {
        "refused": True,
        "complete_H1": True,
        "actual_native_selected_state": "r",
        "refusal_phase": "native_preexport_state_guard",
        "operational_GO": False,
    }
    # Only public immutable buffers and typed TEST facts are returned for narrow export.
    return refusal, evidence, buffers, facts


def exercise(
    scope,
    gpg,
    support,
    read,
    captured,
    private,
    lane_factory,
    *,
    expected_scoped_sha256,
    positive_proof=None,
    producer=None,
    positive_status=None,
    positive_listing=None,
    original_listing=None,
    producer_context=None,
    publish_fixture=None,
):
    """Missing required fixtures refuse completion; never synthesize native passes."""
    cases = {}
    original = captured["google-key.asc"]
    selected = read(private / "selected-public-certificate.gpg", scope.LIMIT)
    need(scope.sha(selected) == expected_scoped_sha256, "native_positive_certificate_changed")
    scope.lineage(original, selected)
    need(callable(producer) and callable(publish_fixture), "native_producer_source_not_reviewed")
    evidence, expired_others = control_evidence(
        scope,
        gpg,
        positive_status,
        positive_listing,
        original_listing,
        captured,
        selected,
        int(time.time()),
    )
    for label in ("bad_signature", "missing_binding", "corrupt_crosscert", "corrupt_selfsig"):
        lane, case = lane_factory(label)
        cert = selected if label == "bad_signature" else mutate_key(scope, selected, label)
        release = captured["Release"] + b"x" if label == "bad_signature" else captured["Release"]
        cases[label] = verify_refusal(
            lane,
            support,
            read,
            scope,
            gpg,
            case,
            cert,
            captured["Release.gpg"],
            release,
            scope.PRIMARY,
            scope.SIGNER,
        )
    # Closed public upstream fixture descriptors will be supplied/pinned by NSS.
    raw = captured["qualification/p1g_headless/chrome_scope_native_fixtures.json"]
    manifest = json.loads(raw)
    need(
        manifest.get("schema") == "pamolive.chrome-scope-public-negative-fixtures/1",
        "native_fixture_schema",
    )
    need(set(manifest) == {"schema", "cases", "status"}, "native_fixture_fields")
    descriptors = manifest["cases"]
    need(type(descriptors) is dict and set(descriptors) <= set(LIFECYCLE), "native_fixture_fields")
    for label in LIFECYCLE:
        if label not in descriptors:
            continue
        row = descriptors[label]
        if label == "signer_revoked":
            need(
                row
                == {
                    "producer_purpose": PRODUCER_CONTRACT["purpose"],
                    "source_pin": PRODUCER_CONTRACT["source_pin"],
                },
                "native_fixture_pin",
            )
            continue
        need(
            set(row) == {"path", "sha256", "primary", "signer", "expected", "role"},
            "native_fixture_fields",
        )
        need(
            (row["role"], row["expected"]) == LIFECYCLE[label]
            and all(
                type(row[k]) is str and re.fullmatch("[0-9A-F]{40}", row[k])
                for k in ("primary", "signer")
            )
            and type(row["path"]) is str
            and row["path"] in captured,
            "native_fixture_pin",
        )
        cert = captured[row["path"]]
        need(scope.sha(cert) == row["sha256"], "native_fixture_pin")
        lane, case = lane_factory(label)
        home = case / "home"
        home.mkdir(mode=0o700)
        key = case / "public.gpg"
        support.fresh_write(key, cert, mode=0o400)
        base = scope.options(home)
        lane.run(base + ["--import", str(key)], seconds=10)
        listed = lane.run(
            base
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
        # one_primary deliberately refuses a revoked/expired primary; the exact
        # native row is checked first without changing the crypto predicate.
        lines = [s.split(":") for s in listed.decode("utf8", "strict").splitlines()]
        fp = row[row["role"]]
        observed = [
            r
            for i, r in enumerate(lines[:-1])
            if r[0] in {"pub", "sub"}
            and lines[i + 1][0] == "fpr"
            and len(lines[i + 1]) > 9
            and lines[i + 1][9] == fp
        ]
        need(len(observed) == 1 and observed[0][1] == row["expected"], "native_fixture_state")
        try:
            keys = gpg.one_primary(listed, row["primary"])
            gpg.signing_capability(keys, row["primary"], row["signer"], int(time.time()))
        except ValueError as error:
            need(error.args == ("key_unusable",), "native_lifecycle_wrong_guard")
        else:
            raise ValueError("native_lifecycle_not_refused")
        cases[label] = {
            "refused": True,
            "complete_H1": True,
            "actual_native_selected_state": row["expected"],
            "operational_GO": False,
        }
    if "signer_revoked" in descriptors:
        refusal, temporal, buffers, facts = consume_producer(
            producer,
            scope,
            gpg,
            support,
            read,
            lane_factory,
            producer_context,
        )
        cases["signer_revoked"] = refusal
        evidence.update(temporal)
        # Publish after independent native consumer admission, never export a secret home.
        publish_fixture(buffers, facts)
    missing = sorted(REQUIRED - set(cases))
    matrix = matrix_facts(
        cases,
        positive_proof,
        expected_scoped_sha256,
        evidence=evidence,
        expired_others=expired_others,
    )
    return {
        "schema": RECEIPT_SCHEMA,
        "state": "COMPLETE"
        if not missing and matrix["ADR_evidence_matrix_complete"]
        else "INCOMPLETE",
        "cases": cases,
        "missing": missing,
        "purpose": scope.PURPOSE,
        "private_keys_generated": "TEST_ONLY_destroyed_before_public_export",
        "GPG_agent_autostart_allowed": False,
        "revocation_completeness_claimed": False,
        "operational_GO": False,
        **matrix,
    }
