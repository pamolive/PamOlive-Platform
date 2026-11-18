"""OpenSSL-specific DATA contracts. No networking, commands, archives or C execution."""

import re
from email.utils import parsedate_to_datetime
from pathlib import Path

from patch_contracts import apply_bound, bound_patch, target
from reused_signature_data import BAD, cleartext_envelope, valid_status
from reused_text_helpers import checksums, fields, json_value, need, safe_name, sha

HERE = Path(__file__).resolve().parent
BASE_VERSION = "3.5.7-1~deb13u3"
LOCAL_VERSION = BASE_VERSION + "+pamolive1"
SOURCE_FILES = {
    "openssl_3.5.7.orig.tar.gz": (
        53153930,
        "a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8",
    ),
    "openssl_3.5.7.orig.tar.gz.asc": (
        833,
        "d3d082bee3f658c31db53af625eceecf29d777c7010394bed5787ebcc98abdf2",
    ),
    "openssl_3.5.7-1~deb13u3.debian.tar.xz": (
        147344,
        "0a427fdc3e773f4119a7dd5b36d1f0903a163cf4ea15d812bb823b251ff1cbc5",
    ),
}
DSC = "openssl_" + BASE_VERSION + ".dsc"
CVES = {"CVE-2026-88823", "CVE-2026-107496", "CVE-2026-95692", "CVE-2026-95691"}
RUNTIME = ("libssl3t64", "openssl", "openssl-provider-legacy")
SDK = ("libssl-dev",)


def bounded_text(path, cap=2 * 1024**2):
    path = Path(path)
    need(
        path.is_file() and not path.is_symlink() and path.stat().st_size <= cap,
        "text_type_budget",
    )
    raw = path.read_bytes()
    need(len(raw) <= cap and b"\0" not in raw, "text_budget")
    raw.decode("utf-8", "strict")
    return raw


def control_body(raw):
    cleartext_envelope(raw)
    header, sep, body = raw.partition(b"\n\n")
    need(
        sep and header.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: "),
        "signed_control_envelope",
    )
    body = body.split(b"\n-----BEGIN PGP SIGNATURE-----", 1)[0].rstrip(b"\n")
    return b"\n".join(line[2:] if line.startswith(b"- ") else line for line in body.split(b"\n"))


def check_policy(policy, pin):
    need(
        type(pin) is str and re.fullmatch("[a-f0-9]{64}", pin),
        "trust_policy_pin_missing",
    )
    need(type(policy) is bytes and sha(policy) == pin, "trust_policy_pin")
    value = json_value(policy)
    need(
        set(value)
        == {
            "schema",
            "suite",
            "keyring_sha256",
            "signer_to_primary",
            "allowed_primaries",
            "tools",
            "dependency_lock_sha256",
            "acquisition_runtime",
        },
        "trust_policy_shape",
    )
    need(
        value["schema"] == "pamolive.openssl-source-trust-policy.v2"
        and value["suite"] == "trixie-security",
        "trust_policy_scope",
    )
    need(
        re.fullmatch("[a-f0-9]{64}", str(value["keyring_sha256"]))
        and re.fullmatch("[a-f0-9]{64}", str(value["dependency_lock_sha256"])),
        "policy_hashes",
    )
    mapping = value["signer_to_primary"]
    need(type(mapping) is dict and 1 <= len(mapping) <= 8, "policy_signers_missing")
    need(
        all(
            re.fullmatch("[A-F0-9]{40}", k) and re.fullmatch("[A-F0-9]{40}", v)
            for k, v in mapping.items()
        ),
        "policy_fingerprints",
    )
    need(
        type(value["allowed_primaries"]) is list
        and value["allowed_primaries"]
        and set(mapping.values()) <= set(value["allowed_primaries"]),
        "policy_primary_scope",
    )
    required = {
        "/usr/bin/gpgv",
        "/usr/bin/dpkg-source",
        "/usr/bin/dpkg-buildpackage",
        "/usr/bin/dpkg-deb",
        "/usr/bin/dpkg-checkbuilddeps",
        "/usr/bin/dch",
        "/usr/bin/dpkg-query",
        "/usr/bin/quilt",
    }
    need(
        type(value["tools"]) is dict
        and set(value["tools"]) == required
        and all(re.fullmatch("[a-f0-9]{64}", str(v)) for v in value["tools"].values()),
        "tool_pins_missing",
    )
    from acquisition_owner import runtime_contract

    runtime_contract(value["acquisition_runtime"])
    return value


def signature_status(raw, policy, now):
    lines = raw.decode("ascii", "strict").splitlines()
    need(
        lines and all(x.startswith("[GNUPG:] ") for x in lines),
        "signature_status_frame",
    )
    rows = [x[9:].split() for x in lines]
    need(all(r and r[0] not in BAD for r in rows), "signature_status_bad")
    valid = [r for r in rows if r[0] == "VALIDSIG"]
    good = [r for r in rows if r[0] == "GOODSIG"]
    need(1 <= len(valid) <= 8 and len(good) == len(valid), "signature_status_count")
    need(len({r[1] for r in valid}) == len(valid), "signature_status_duplicate")
    result = []
    for r in valid:
        need(
            len(r) == 11
            and r[1] in policy["signer_to_primary"]
            and policy["signer_to_primary"][r[1]] == r[10]
            and r[10] in policy["allowed_primaries"],
            "signature_signer_scope",
        )
        matching = [g for g in good if len(g) >= 2 and g[1] == r[1][-16:]]
        need(len(matching) == 1, "signature_matching_good")
        frame = ("[GNUPG:] " + " ".join(matching[0]) + "\n[GNUPG:] " + " ".join(r) + "\n").encode()
        result.append(valid_status(frame, r[10], r[1], now))
    return result


def release_index(raw, now):
    r = fields(raw.decode("utf-8", "strict").strip())
    need(
        r.get("Origin") == "Debian"
        and r.get("Codename") == "trixie-security"
        and r.get("Acquire-By-Hash") == "yes",
        "release_scope",
    )
    issued = parsedate_to_datetime(r.get("Date", ""))
    expiry = parsedate_to_datetime(r.get("Valid-Until", ""))
    need(
        issued.tzinfo is not None
        and expiry.tzinfo is not None
        and 0 <= now - issued.timestamp() <= 7 * 86400
        and now < expiry.timestamp() <= issued.timestamp() + 14 * 86400,
        "release_freshness",
    )
    rows = checksums(r.get("SHA256", ""))
    need("main/source/Sources.xz" in rows, "release_sources_missing")
    size, digest = rows["main/source/Sources.xz"]
    need(0 < size <= 32 * 1024**2, "source_index_cap")
    return size, digest


def source_record(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 128 * 1024**2, "Sources_text_cap")
    found = []
    for block in raw.decode("utf-8", "strict").strip().split("\n\n"):
        if not block.startswith("Package: openssl\n"):
            continue
        row = fields(block)
        if row.get("Version") == BASE_VERSION:
            found.append(row)
    need(
        len(found) == 1 and found[0].get("Directory") == "pool/updates/main/o/openssl",
        "source_record_identity",
    )
    rows = checksums(found[0].get("Checksums-Sha256", ""))
    need(set(rows) == {DSC, *SOURCE_FILES}, "source_record_files")
    need(all(rows[n] == v for n, v in SOURCE_FILES.items()), "source_record_payload_pins")
    return rows


def dsc_control(raw, expected_dsc):
    need((len(raw), sha(raw)) == expected_dsc, "dsc_index_binding")
    r = fields(control_body(raw).decode("utf-8"))
    need(
        r.get("Source") == "openssl"
        and r.get("Version") == BASE_VERSION
        and r.get("Format") == "3.0 (quilt)",
        "dsc_identity",
    )
    need(checksums(r["Checksums-Sha256"]) == SOURCE_FILES, "dsc_payload_binding")
    return r


def verify_text_materials():
    received = json_value(bounded_text(HERE / "materials-reception.json"))
    supplementary = json_value(bounded_text(HERE / "supplementary-text-reception.json"))
    rows = received["receipts"] + [r for r in supplementary if r.get("usable_source_text") is True]
    seen = set()
    for r in rows:
        name = safe_name(r["path"])
        need(name not in seen, "material_duplicate")
        seen.add(name)
        raw = bounded_text(HERE / name)
        need((len(raw), sha(raw)) == (r["bytes"], r["sha256"]), "material_bytes_changed")
    need({r["cve"] for r in received["commits"]} == CVES, "CVE_set")
    return len(rows)


def patch_contract(plan, patches=None):
    need(
        type(plan) is dict and plan.get("schema") == "pamolive.openssl-static-source-replay.v1",
        "patch_plan_schema",
    )
    rows = plan.get("rows")
    need(
        type(rows) is list
        and len(rows) == 4
        and all(type(r) is dict for r in rows)
        and {r.get("cve") for r in rows} == CVES,
        "patch_plan_CVE_set",
    )
    need(
        all(r.get("action") == "APPLY_EXACT_AUTHENTICATED_DEBIAN_SOURCE" for r in rows),
        "patch_plan_unresolved_context",
    )
    for r in rows:
        need(
            type(r["before"]) is dict
            and type(r["after"]) is dict
            and r["before"]
            and set(r["before"]) == set(r["after"]),
            "patch_plan_file_set",
        )
        for name in r["before"]:
            target(name)
        need(
            all(
                re.fullmatch("[a-f0-9]{64}", str(x))
                for x in [
                    *r["before"].values(),
                    *r["after"].values(),
                    r["proposed_patch_sha256"],
                ]
            ),
            "patch_plan_hashes",
        )
        safe_name(r["proposed_patch"])
    need(len({r["proposed_patch"] for r in rows}) == 4, "patch_plan_duplicate_patch")
    if patches is not None:
        need(
            type(patches) is dict and set(patches) == {r["proposed_patch"] for r in rows},
            "patch_plan_patch_set",
        )
        for r in rows:
            bound_patch(r, patches[r["proposed_patch"]])
    return rows


def patch_source_buffers(tree, plan, patches):
    # Validate every patch's complete target inventory before transforming even row1.
    rows = patch_contract(plan, patches)
    need(
        type(tree) is dict and all(type(x) is bytes for x in tree.values()),
        "source_tree_buffers",
    )
    result = dict(tree)
    for r in rows:
        patch = patches[r["proposed_patch"]]
        result = apply_bound(result, r, patch)
    return result


def pending():
    json_value(bounded_text(HERE / "recipe-inputs.json"))
    replay = json_value(bounded_text(HERE / "static-source-replay.json"))
    blockers = [
        "TRUST_POLICY_UNCOMMISSIONED",
        "SIGNED_APT_CHAIN_NOT_VERIFIED",
        "EXACT_DEBIAN_SOURCE_FILES_NOT_RECEIVED",
        "BUILD_DEPENDENCIES_NOT_LOCKED",
        "QUIC_SOURCE_CONTEXT_UNRESOLVED",
        "NO_LINUX_COMPILE_OR_TEST_RECEIPT",
    ]
    return {
        "schema": "pamolive.openssl-source-preflight.DATA.v1",
        "text_materials_checked": verify_text_materials(),
        "blockers": blockers,
        "upstream_tag_reference_replays": sum(
            r["action"] == "APPLY_TEXT_ONLY_UPSTREAM_TAG_REFERENCE" for r in replay["rows"]
        ),
        "exact_Debian_applicability_proved": False,
        "build_verified": False,
        "image_qualified": False,
        "operational_GO": False,
        "wheel_OpenSSL_4_0_3_corrected": False,
    }
