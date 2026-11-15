"""Closed installed-Vault reports; no service, SQL or authority format."""

import hashlib
import json
import math
import re

CHILD = "pamolive.vault-runtime-installed-child/3"
PACKET = "pamolive.vault-runtime-installed-ci-packet/1"
MAX_CHILD = 320 * 1024
MAX_PACKET = 480 * 1024
MODULES = {
    "pamolive_vault_runtime": 8,
    "pamolive_vault_contracts": 3,
    "pamolive_pam_trust_verifier": 6,
}
FAILURES = {"NONE", "ENVIRONMENT", "ORIGIN", "FILES", "GUARD", "TESTS", "UNCLASSIFIED"}
ERROR_TYPES = {
    "AssertionError",
    "ValueError",
    "TypeError",
    "RuntimeError",
    "OSError",
    "FileNotFoundError",
    "ModuleNotFoundError",
    "ImportError",
    "ForbiddenIO",
    "Refusal",
    "Other",
}
ATTEMPTS = {
    "import.driver",
    "import.application_or_SDK",
    "socket.constructor",
    "DNS",
    "socket.connect",
    "sqlite3.connect",
    "subprocess.Popen",
    "file.mutation",
    "file.descriptor_open",
    "file.unresolved_path",
    "file.open_arguments",
    "file.write",
    "file.global_site",
    "file.read_outside_roots",
    "external.audit",
}
PROBES = {
    "socket.constructor",
    "DNS",
    "sqlite3.connect",
    "subprocess.Popen",
    "import.driver",
    "file.read_outside_roots",
}


TEST_IDS = frozenset(
    {
        "test_r2_boundaries.H11LifecycleTests.test_original_R1_same_refusal_still_fails_actual_inherited_cleanup",
        "test_r2_boundaries.H11LifecycleTests.test_parser_error_after_bound_TLS_uses_real_H11_and_cleans_up",
        "test_r2_boundaries.H11LifecycleTests.test_refused_TLS_DER_and_error_callbacks_close_without_dispatch_or_leak",
        "test_r2_boundaries.H11LifecycleTests.test_two_connections_keepalive_closures_remain_per_connection_then_reset",
        "test_r2_boundaries.H11LifecycleTests.test_valid_HTTP_parser_is_delegated_and_its_callback_cycle_cleans",
        "test_r2_boundaries.JSONPrebudgetTests.test_escaped_braces_backslashes_quotes_UTF8_and_finite_types_are_data",
        "test_r2_boundaries.JSONPrebudgetTests.test_exact_nodes_and_depth_still_accepted_keys_count_as_nodes",
        "test_r2_boundaries.JSONPrebudgetTests.test_exact_reviewed_27010_byte_9001_list_case_refuses_before_any_decode",
        "test_r2_boundaries.JSONPrebudgetTests.test_original_R1_really_allocates_all_9001_children_then_refuses",
        "test_r2_boundaries.JSONPrebudgetTests.test_stdlib_retains_syntax_duplicate_and_nonfinite_authority",
        "test_r2_boundaries.JSONPrebudgetTests.test_wide_containers_strings_keys_and_primitives_pre_refuse",
        "test_ro_slot.ReadOnlySlotTests.test_fd_replacement_and_late_path_alias_refuse_and_close",
        "test_ro_slot.ReadOnlySlotTests.test_file_link_hardlink_write_owner_type_size_refused_before_open",
        "test_ro_slot.ReadOnlySlotTests.test_growth_or_short_read_refused_with_bounded_read_and_close",
        "test_ro_slot.ReadOnlySlotTests.test_parent_alias_wrong_owner_and_writable_parent_refused_before_open",
        "test_ro_slot.ReadOnlySlotTests.test_same_fd_bytes_then_snapshot_parents",
        "test_runtime.ASGITests.test_bound_endpoint_success_and_unbound_scope_refusal",
        "test_runtime.ASGITests.test_chunk_budget_exact_and_plus_one_before_dispatch",
        "test_runtime.ASGITests.test_forged_headers_and_duplicates_rejected_without_dispatch",
        "test_runtime.ASGITests.test_timeout_keeps_capacity_until_actual_job_finishes",
        "test_runtime.ASGITests.test_unexpected_error_never_exports_exception_or_draft",
        "test_runtime.ASGITests.test_wrong_path_method_query_http_and_body_lengths",
        "test_runtime.AdmissionTests.test_checkpoint_freshness_at_40_seconds_and_slot_closed_by_time",
        "test_runtime.AdmissionTests.test_every_server_expectation_substitution_refuses_before_ledger",
        "test_runtime.AdmissionTests.test_expired_or_revoked_checkpoint_key_is_not_restored_by_valid_old_signature",
        "test_runtime.AdmissionTests.test_keepalive_revalidates_exact_leaf_and_validity_each_request",
        "test_runtime.AdmissionTests.test_modified_server_context_still_fails_real_V1_even_with_matching_draft",
        "test_runtime.AdmissionTests.test_mutated_slot_before_ledger_or_at_recheck_refuses",
        "test_runtime.AdmissionTests.test_no_assembly_algorithm_or_business_approval_is_invented",
        "test_runtime.AdmissionTests.test_principal_instance_certificate_and_claims_do_not_authenticate",
        "test_runtime.AdmissionTests.test_request_type_size_extra_fields_and_invalid_base64_are_closed",
        "test_runtime.AdmissionTests.test_short_checkpoint_expiry_caps_reservation_without_extending",
        "test_runtime.AdmissionTests.test_signatures_chain_checkpoint_and_independent_context_fail_before_sql",
        "test_runtime.AdmissionTests.test_signed_current_materials_enter_pending_only",
        "test_runtime.SQLContractTests.test_all_forbidden_privilege_bits_and_missing_role_refuse",
        "test_runtime.SQLContractTests.test_commit_unknown_is_constant_unavailable_and_not_retried",
        "test_runtime.SQLContractTests.test_each_retry_bound_value_divergence_conflicts_without_mutation",
        "test_runtime.SQLContractTests.test_expired_retry_does_not_renew",
        "test_runtime.SQLContractTests.test_insert_and_audit_same_transaction_and_stable_namespace",
        "test_runtime.SQLContractTests.test_postwrite_expiry_requests_rollback_not_success",
        "test_runtime.SQLContractTests.test_prewrite_refusal_has_no_insert",
        "test_runtime.SQLContractTests.test_quota_and_closed_or_other_incarnation_stop_before_nonce",
        "test_runtime.SQLContractTests.test_retry_returns_original_without_nonce_generation_or_insert",
        "test_runtime.SQLContractTests.test_startup_requires_exact_external_incarnation_and_never_repairs",
        "test_runtime.SlotTests.test_duplicate_nonfinite_unicode_and_float_types",
        "test_runtime.SlotTests.test_duplicate_principal_cert_and_key_and_closed_recovery_refused",
        "test_runtime.SlotTests.test_slot_file_rechecks_same_bytes_and_filesystem_identity",
        "test_runtime.SlotTests.test_strict_config_pin_and_all_closed_fields",
        "test_runtime.TransportTests.test_config_explicit_h11_factory_and_no_proxy_ws_or_autobackend",
        "test_runtime.TransportTests.test_connection_local_closures_and_certrequired_without_global_mutation",
        "test_runtime.TransportTests.test_missing_tls_certnone_missing_der_and_changed_server_version_no_connection",
        "test_runtime.TransportTests.test_n0_binding_is_exact_in_configuration_and_lab_manifest",
    }
)


def need(value):
    if not value:
        raise ValueError("vault_installed_schema_refused")


def digest(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def shape(value):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        need(count <= 8192 and depth <= 12)
        if type(item) is dict:
            need(len(item) <= 256)
            for key, child in item.items():
                need(type(key) is str and 0 < len(key) <= 128)
                pending.append((child, depth + 1))
        elif type(item) is list:
            need(len(item) <= 256)
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            need(len(item) <= 4096)
        elif type(item) is int:
            need(-(2**63) <= item < 2**63)
        elif type(item) is float:
            need(-900 <= item <= 900 and math.isfinite(item))
        else:
            need(item is None or type(item) is bool)


def encode(value, maximum=MAX_CHILD):
    need(type(maximum) is int and 0 < maximum <= MAX_PACKET)
    shape(value)
    parts, size = [], 0
    for part in json.JSONEncoder(allow_nan=False, separators=(",", ":")).iterencode(value):
        raw = part.encode("utf-8")
        need(size + len(raw) + 1 <= maximum)
        parts.append(raw)
        size += len(raw)
    return b"".join(parts) + b"\n"


def parse(raw, maximum=MAX_CHILD):
    need(type(maximum) is int and 0 < maximum <= MAX_PACKET)
    need(type(raw) is bytes and 0 < len(raw) <= maximum)
    # Resource prepass only; stdlib retains syntax/UTF8 authority. Count all
    # string/container/scalar starts before decode/allocation, including keys.
    quoted = escaped = scalar = False
    depth = tokens = 0
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted, scalar = True, False
            tokens += 1
        elif byte in (91, 123):
            depth += 1
            tokens += 1
            scalar = False
        elif byte in (93, 125):
            depth -= 1
            scalar = False
        elif byte in b" \t\r\n,:":
            scalar = False
        elif not scalar:
            scalar = True
            tokens += 1
        need(depth <= 12 and tokens <= 8192)

    def unique(items):
        result = {}
        for key, child in items:
            need(key not in result)
            result[key] = child
        return result

    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=lambda _: need(False)
    )
    shape(value)
    return value


def counters(value, names):
    need(type(value) is dict and set(value) <= names)
    need(all(type(number) is int and 0 < number <= 64 for number in value.values()))


def diagnostics(value):
    need(type(value) is list and len(value) <= 8)
    seen = set()
    for row in value:
        need(type(row) is dict and set(row) == {"test_id", "exception_type"})
        name, kind = row["test_id"], row["exception_type"]
        need(type(name) is str and len(name) <= 256 and name in TEST_IDS and name not in seen)
        need(type(kind) is str and kind in ERROR_TYPES)
        seen.add(name)
    return value


def child(value, expected_distributions):
    shape(value)
    need(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "state",
            "authority",
            "venv",
            "installed",
            "tests",
            "test_errors",
            "attempts",
            "probes",
            "input_sha256",
            "elapsed_seconds",
            "failure_code",
            "exception_type",
        }
    )
    need(value["schema"] == CHILD and value["authority"] is False)
    need(type(value["state"]) is str and value["state"] in {"FAILED", "INSTALLED_RUNTIME_52_PASS"})
    need(digest(value["input_sha256"]))
    elapsed = value["elapsed_seconds"]
    need(type(elapsed) in (int, float) and 0 <= elapsed <= 900 and math.isfinite(elapsed))
    need(type(value["failure_code"]) is str and value["failure_code"] in FAILURES)
    need(
        value["exception_type"] is None
        or type(value["exception_type"]) is str
        and value["exception_type"] in {"ValueError", "ForbiddenIO", "AssertionError", "Other"}
    )
    counters(value["attempts"], ATTEMPTS)
    counters(value["probes"], PROBES)
    if value["venv"] is not None:
        need(type(value["venv"]) is dict and set(value["venv"]) == {"distributions", "origins"})
        need(value["venv"]["distributions"] == expected_distributions)
        origins = value["venv"]["origins"]
        need(type(origins) is dict and set(origins) == set(MODULES))
        for module, path in origins.items():
            need(
                type(path) is str
                and path == "lib/python3.12/site-packages/" + module + "/__init__.py"
            )
    if value["installed"] is not None:
        need(
            type(value["installed"]) is dict
            and set(value["installed"]) == {"modules", "files_matched", "sql_sha256", "site_PTH"}
        )
        need(value["installed"]["modules"] == MODULES)
        need(
            type(value["installed"]["files_matched"]) is int
            and 17 <= value["installed"]["files_matched"] <= 128
        )
        need(digest(value["installed"]["sql_sha256"]))
        need(type(value["installed"]["site_PTH"]) is int and value["installed"]["site_PTH"] == 0)
    if value["tests"] is not None:
        need(
            type(value["tests"]) is dict
            and set(value["tests"]) == {"run", "failures", "errors", "skips"}
        )
        need(all(type(number) is int and 0 <= number <= 52 for number in value["tests"].values()))
    diagnostics(value["test_errors"])
    need(
        len(value["test_errors"]) <= (value["tests"]["errors"] if value["tests"] is not None else 0)
    )
    if value["state"] == "INSTALLED_RUNTIME_52_PASS":
        need(value["failure_code"] == "NONE" and value["exception_type"] is None)
        need(not value["attempts"] and value["probes"] == dict.fromkeys(PROBES, 1))
        need(value["venv"] is not None and value["installed"] is not None)
        need(value["tests"] == {"run": 52, "failures": 0, "errors": 0, "skips": 0})
        need(value["test_errors"] == [])
    else:
        need(value["failure_code"] != "NONE")
    return value


def packet(value, expected_distributions, code, *, expected_input_sha256, expected_sql_sha256):
    need(digest(expected_input_sha256) and digest(expected_sql_sha256))
    need(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "ok",
            "authority",
            "child",
            "child_sha256",
            "child_bytes",
            "source_sha256",
            "attestation_verified",
        }
    )
    need(
        value["schema"] == PACKET
        and value["authority"] is False
        and value["attestation_verified"] is False
    )
    need(
        type(value["ok"]) is bool
        and digest(value["child_sha256"])
        and digest(value["source_sha256"])
    )
    need(type(value["child_bytes"]) is int and 0 < value["child_bytes"] <= MAX_CHILD)
    child(value["child"], expected_distributions)
    canonical = encode(value["child"])
    need(value["child_bytes"] == len(canonical))
    need(value["child_sha256"] == hashlib.sha256(canonical).hexdigest())
    success = value["child"]["state"] == "INSTALLED_RUNTIME_52_PASS"
    if success:
        need(value["child"]["input_sha256"] == expected_input_sha256)
        need(value["child"]["installed"]["sql_sha256"] == expected_sql_sha256)
    need(
        type(code) is int and code in (0, 42) and value["ok"] is success and (code == 0) is success
    )
    return value
