"""Packet/profile functions only; no operational main or hidden workload launch."""

import schema
from support import load, need, sha


def kernel_profile(status, mounts):
    return load("entrypoint.py").profile(status, mounts)


def export_child(
    raw,
    child_code,
    expected_distributions,
    *,
    source_sha256,
    expected_input_sha256,
    expected_sql_sha256,
):
    need(type(child_code) is int and child_code in (0, 1))
    value = schema.parse(raw)
    schema.child(value, expected_distributions)
    canonical = schema.encode(value)
    need(raw == canonical)
    success = value["state"] == "INSTALLED_RUNTIME_52_PASS"
    need((child_code == 0) is success)
    packet = {
        "schema": schema.PACKET,
        "ok": success,
        "authority": False,
        "child": value,
        "child_sha256": sha(raw),
        "child_bytes": len(raw),
        "source_sha256": source_sha256,
        "attestation_verified": False,
    }
    code = 0 if success else 42
    schema.packet(
        packet,
        expected_distributions,
        code,
        expected_input_sha256=expected_input_sha256,
        expected_sql_sha256=expected_sql_sha256,
    )
    return code, schema.encode(packet, schema.MAX_PACKET)
