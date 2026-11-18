"""Only DATA/manifests/refusal contracts; no compiler/library/network/commands."""

import difflib
import json
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import future_linux
import source_data as data
from reused_text_helpers import json_value, patch_files, sha, transform

HERE = Path(__file__).resolve().parent
NOW = datetime(2026, 11, 17, 12, tzinfo=UTC).timestamp()


def source_fixture():
    dsc = (HERE / "materials/debian" / data.DSC).read_bytes()
    rows = {data.DSC: (len(dsc), sha(dsc)), **data.SOURCE_FILES}
    lines = [
        "Package: openssl",
        "Version: " + data.BASE_VERSION,
        "Directory: pool/updates/main/o/openssl",
        "Checksums-Sha256:",
    ]
    lines += [" " + digest + " " + str(size) + " " + name for name, (size, digest) in rows.items()]
    return ("\n".join(lines) + "\n").encode(), rows


def release_fixture(**overrides):
    fields = {
        "Origin": "Debian",
        "Codename": "trixie-security",
        "Acquire-By-Hash": "yes",
        "Date": "Tue, 17 Nov 2026 10:00:00 UTC",
        "Valid-Until": "Tue, 24 Nov 2026 10:00:00 UTC",
        "SHA256": "\n " + "1" * 64 + " 123 main/source/Sources.xz",
    }
    fields.update(overrides)
    return ("\n".join(k + ": " + v for k, v in fields.items()) + "\n").encode()


class DataContracts(unittest.TestCase):
    def test_received_text_47_files_match_recorded_bytes(self):
        self.assertEqual(data.verify_text_materials(), 47)

    def test_three_fix_declarations_exist_in_tag_reference(self):
        root = HERE / "materials/baseline/upstream-3.5.7"
        header = (root / "providers/implementations/ciphers/cipher_aes_gcm_siv.h").read_text()
        self.assertIn("unsigned int used_enc : 1;", header)
        self.assertIn("unsigned int used_dec : 1;", header)
        self.assertIn("EC_R_INVALID_GROUP_ORDER", (root / "include/openssl/ecerr.h").read_text())
        self.assertIn("PROV_R_INVALID_IV_LENGTH", (root / "include/openssl/proverr.h").read_text())

    def test_default_preflight_never_qualifies(self):
        value = data.pending()
        self.assertEqual(len(value["blockers"]), 6)
        self.assertFalse(value["build_verified"])
        self.assertFalse(value["operational_GO"])
        self.assertFalse(value["wheel_OpenSSL_4_0_3_corrected"])

    def test_no_trust_pin_refuses_before_any_file_or_command(self):
        with self.assertRaisesRegex(ValueError, "trust_policy_pin_missing"):
            future_linux.policy({"trust_policy_sha256": None})

    def test_policy_boolean_is_not_a_digest(self):
        with self.assertRaisesRegex(ValueError, "trust_policy_pin_missing"):
            data.check_policy(b"{}", True)

    def test_wrong_policy_bytes_refused(self):
        with self.assertRaisesRegex(ValueError, "trust_policy_pin"):
            data.check_policy(b"{}", "f" * 64)

    def test_empty_pseudo_authority_has_no_scope(self):
        raw = b"{}"
        with self.assertRaisesRegex(ValueError, "trust_policy_shape"):
            data.check_policy(raw, sha(raw))

    def test_exact_debian_plan_pin_missing_refused(self):
        with self.assertRaisesRegex(ValueError, "exact_debian_patch_plan_pin_missing"):
            future_linux.checked_plan({"exact_debian_patch_plan_sha256": None})

    def test_duplicate_json_is_refused(self):
        with self.assertRaisesRegex(ValueError, "json_duplicate"):
            json_value(b'{"authority":false,"authority":true}')

    def test_nonfinite_json_is_refused(self):
        with self.assertRaisesRegex(ValueError, "json_nonfinite"):
            json_value(b'{"result":NaN}')

    def test_release_freshness_fixture(self):
        self.assertEqual(data.release_index(release_fixture(), NOW), (123, "1" * 64))

    def test_release_wrong_suite_refused(self):
        with self.assertRaisesRegex(ValueError, "release_scope"):
            data.release_index(release_fixture(Codename="sid"), NOW)

    def test_release_expired_refused(self):
        with self.assertRaisesRegex(ValueError, "release_freshness"):
            data.release_index(
                release_fixture(**{"Valid-Until": "Tue, 17 Nov 2026 11:00:00 UTC"}), NOW
            )

    def test_release_future_refused(self):
        with self.assertRaisesRegex(ValueError, "release_freshness"):
            data.release_index(release_fixture(Date="Wed, 18 Nov 2026 10:00:00 UTC"), NOW)

    def test_release_no_by_hash_refused(self):
        with self.assertRaisesRegex(ValueError, "release_scope"):
            data.release_index(release_fixture(**{"Acquire-By-Hash": "no"}), NOW)

    def test_release_duplicate_field_refused(self):
        with self.assertRaisesRegex(ValueError, "control_fields"):
            data.release_index(release_fixture() + b"Origin: Other\n", NOW)

    def test_source_record_text_pins_match_observed_dsc(self):
        raw, expected = source_fixture()
        self.assertEqual(data.source_record(raw), expected)

    def test_source_record_wrong_version_refused(self):
        raw, _ = source_fixture()
        with self.assertRaisesRegex(ValueError, "source_record_identity"):
            data.source_record(raw.replace(data.BASE_VERSION.encode(), b"3.5.9-fake"))

    def test_source_record_duplicate_package_refused(self):
        raw, _ = source_fixture()
        with self.assertRaisesRegex(ValueError, "source_record_identity"):
            data.source_record(raw + b"\n" + raw)

    def test_source_record_tampered_tar_hash_refused(self):
        raw, _ = source_fixture()
        name = "openssl_3.5.7.orig.tar.gz"
        with self.assertRaisesRegex(ValueError, "source_record_payload_pins"):
            data.source_record(raw.replace(data.SOURCE_FILES[name][1].encode(), b"0" * 64))

    def test_dsc_control_parsing_is_not_signature_authentication(self):
        raw = (HERE / "materials/debian" / data.DSC).read_bytes()
        value = data.dsc_control(raw, (len(raw), sha(raw)))
        self.assertEqual(value["Version"], data.BASE_VERSION)
        self.assertNotIn("authenticated", value)

    def test_dsc_wrong_index_binding_refused(self):
        raw = (HERE / "materials/debian" / data.DSC).read_bytes()
        with self.assertRaisesRegex(ValueError, "dsc_index_binding"):
            data.dsc_control(raw, (len(raw), "0" * 64))

    def test_dsc_unsigned_refused(self):
        raw = b"Format: 3.0 (quilt)\nSource: openssl\n"
        with self.assertRaisesRegex(ValueError, "cleartext_envelope"):
            data.dsc_control(raw, (len(raw), sha(raw)))

    def test_dsc_ambiguous_signature_envelope_refused(self):
        raw = (
            HERE / "materials/debian" / data.DSC
        ).read_bytes() + b"\n-----BEGIN PGP SIGNATURE-----\n"
        with self.assertRaises(ValueError):
            data.control_body(raw)

    def test_missing_signature_status_refused(self):
        with self.assertRaisesRegex(ValueError, "signature_status_frame"):
            data.signature_status(b"", {"signer_to_primary": {}, "allowed_primaries": []}, int(NOW))

    def test_bad_signature_status_refused(self):
        with self.assertRaisesRegex(ValueError, "signature_status_bad"):
            data.signature_status(
                b"[GNUPG:] BADSIG 1234 synthetic\n",
                {"signer_to_primary": {}, "allowed_primaries": []},
                int(NOW),
            )

    def test_unsigned_success_text_refused(self):
        with self.assertRaisesRegex(ValueError, "signature_status_frame"):
            data.signature_status(
                b"signature_verified=true\n",
                {"signer_to_primary": {}, "allowed_primaries": []},
                int(NOW),
            )

    def test_all_four_patches_reproduce_exact_upstream_postimages(self):
        received = json.loads((HERE / "materials-reception.json").read_text())
        for row in received["commits"]:
            patch = (HERE / "materials/patches" / (row["cve"] + ".patch")).read_bytes()
            names = [x["name"] for x in patch_files(patch)]
            before = {n: (HERE / "materials/blobs" / row["parent"] / n).read_bytes() for n in names}
            after = transform(before, patch)
            self.assertEqual(
                after,
                {n: (HERE / "materials/blobs" / row["commit"] / n).read_bytes() for n in names},
            )

    def test_three_tag_rebases_are_distinct_from_debian_application(self):
        replay = json.loads((HERE / "static-source-replay.json").read_text())
        self.assertEqual(
            sum(r["action"] == "APPLY_TEXT_ONLY_UPSTREAM_TAG_REFERENCE" for r in replay["rows"]),
            3,
        )
        self.assertTrue(
            all(r["exact_Debian_u3_applicability_proved"] is False for r in replay["rows"])
        )

    def test_QUIC_missing_files_refuses_no_transplant(self):
        replay = json.loads((HERE / "static-source-replay.json").read_text())
        row = next(r for r in replay["rows"] if r["cve"] == "CVE-2026-95691")
        self.assertEqual(row["action"], "REFUSED_SOURCE_CONTEXT_CONFLICT")
        self.assertEqual(len(row["missing_paths"]), 2)
        self.assertIsNone(row["proposed_patch"])

    def test_current_replay_cannot_authorize_a_build(self):
        replay = json.loads((HERE / "static-source-replay.json").read_text())
        with self.assertRaisesRegex(ValueError, "patch_plan_unresolved_context"):
            data.patch_contract(replay)

    def test_missing_CVE_cannot_authorize_a_build(self):
        replay = json.loads((HERE / "static-source-replay.json").read_text())
        replay["rows"].pop()
        with self.assertRaisesRegex(ValueError, "patch_plan_CVE_set"):
            data.patch_contract(replay)

    def test_unsafe_patch_path_refused_in_synthetic_contract(self):
        replay = json.loads((HERE / "static-source-replay.json").read_text())
        rows = []
        for cve in sorted(data.CVES):
            rows.append(
                {
                    "cve": cve,
                    "action": "APPLY_EXACT_AUTHENTICATED_DEBIAN_SOURCE",
                    "before": {"x.txt": "1" * 64},
                    "after": {"x.txt": "2" * 64},
                    "proposed_patch_sha256": "3" * 64,
                    "proposed_patch": "../outside.patch",
                }
            )
        replay["rows"] = rows
        with self.assertRaisesRegex(ValueError, "archive_path"):
            data.patch_contract(replay)

    def test_synthetic_text_patch_contract_checks_preimage(self):
        rows = []
        patches = {}
        tree = {}
        for i, cve in enumerate(sorted(data.CVES)):
            name = f"data{i}.txt"
            a = b"before\n"
            b = b"after\n"
            path = f"patch{i}.patch"
            patch = "".join(
                difflib.unified_diff(
                    a.decode().splitlines(True),
                    b.decode().splitlines(True),
                    fromfile="a/" + name,
                    tofile="b/" + name,
                )
            ).encode()
            tree[name] = a
            patches[path] = patch
            rows.append(
                {
                    "cve": cve,
                    "action": "APPLY_EXACT_AUTHENTICATED_DEBIAN_SOURCE",
                    "before": {name: sha(a)},
                    "after": {name: sha(b)},
                    "proposed_patch_sha256": sha(patch),
                    "proposed_patch": path,
                }
            )
        plan = {"schema": "pamolive.openssl-static-source-replay.v1", "rows": rows}
        self.assertTrue(
            all(v == b"after\n" for v in data.patch_source_buffers(tree, plan, patches).values())
        )
        tree["data0.txt"] = b"changed\n"
        with self.assertRaisesRegex(ValueError, "debian_source_preimage"):
            data.patch_source_buffers(tree, plan, patches)

    def test_linux_guard_rejects_non_linux_model(self):
        with (
            patch.object(future_linux.sys, "platform", "win32"),
            patch.object(
                future_linux, "read", side_effect=AssertionError("IO_before_platform_guard")
            ),
            patch.object(
                future_linux, "run", side_effect=AssertionError("native_before_platform_guard")
            ),
        ):
            with self.assertRaisesRegex(ValueError, "LINUX_ONLY_NO_WINDOWS_NATIVE_EXECUTION"):
                future_linux.linux()


if __name__ == "__main__":
    unittest.main()
