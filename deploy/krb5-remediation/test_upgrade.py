"""N0 public/synthetic models. No GPG, compiler, Docker, KDC or product execution."""

import ast
import copy
import gzip
import io
import json
import lzma
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import abi_data
import acquire
import authenticate_upgrade as auth
import bounded_io
import build_upgrade as build
import check_data_export
import export_evidence
import legacy_auth
import legacy_inventory
import profile_v2
import qualify_candidate
import source_model as model
import tls_oracle
from policy import HERE, MATERIALS, ROOT_PURPOSE, material


def synthetic_elf(soname):
    strings = b"\0" + soname.encode() + b"\0synthetic_export\0SYNTHETIC_1\0"
    chunks = [
        b"",
        strings,
        bytes(24) + struct.pack("<IBBHQQ", strings.index(b"synthetic_export"), 18, 0, 1, 0, 10),
        struct.pack("<qQqQ", 14, 1, 0, 0),
        struct.pack("<HHHHIIIII", 1, 0, 2, 1, 0, 20, 0, strings.index(b"SYNTHETIC_1"), 0),
        struct.pack("<HH", 0, 2),
    ]
    offset, sections = 64 + 64 * len(chunks), []
    for index, chunk in enumerate(chunks):
        kind = [0, 3, 11, 6, 0x6FFFFFFD, 0x6FFFFFFF][index]
        link = 1 if index in (2, 3, 4) else 2 if index == 5 else 0
        sections.append(
            struct.pack(
                "<IIQQQQIIQQ",
                0,
                kind,
                0,
                0,
                offset,
                len(chunk),
                link,
                0,
                1,
                24 if index == 2 else 0,
            )
        )
        offset += len(chunk)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01" + bytes(10),
        3,
        62,
        1,
        0,
        0,
        64,
        0,
        64,
        56,
        0,
        64,
        len(chunks),
        0,
    )
    return header + b"".join(sections) + b"".join(chunks)


def tar(rows):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        for name, kind, raw in rows:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(raw) if kind == tarfile.REGTYPE else 0
            info.linkname = "../outside" if kind == tarfile.SYMTYPE else ""
            archive.addfile(info, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)
    return gzip.compress(stream.getvalue())


def abi_model():
    value = {
        "libraries": {
            p: {
                "soname": names[1],
                "symbols": [["old", 18, 0, "KRB_1", False, None]],
                "abi_sha256": "1" * 64,
                "exported_symbols": 1,
            }
            for p, names in abi_data.LIBRARIES.items()
        }
    }
    for row in value["libraries"].values():
        row["abi_sha256"] = legacy_inventory.digest(
            legacy_inventory.canonical(row["symbols"]).encode()
        )
    return value


class UpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.captured = {name: material(HERE / "materials", name) for name in MATERIALS}
        cls.plan = model.json_value((HERE / "patch-plan.json").read_bytes())
        cls.rebased = {p.name: p.read_bytes() for p in (HERE / "rebased-patches").iterdir()}

    def test_real_five_material_pins_and_DSC_packaging(self):
        self.assertEqual(len(self.captured), 5)
        auth.dsc_packaging(self.captured["krb5_1.22.1-3.dsc"])

    def test_real_sixteen_patch_classifications_and_final_tree(self):
        _, _, tree, required = build.prepared_buffers(self.captured, self.plan, self.rebased)
        self.assertEqual(len(required), 11)  # ten Debian deltas plus exact EPERM compatibility
        self.assertEqual(len(self.plan["series"]), 16)
        text = tree["src/plugins/tls/k5tls/openssl.c"]
        self.assertNotIn(b"r = X509_check_host(x, expected_name, 0, 0, NULL);", text)
        self.assertIn(b"label_match(", text)
        self.assertIn(b"'add_key: Operation not permitted'", tree["src/util/k5test.py"])
        self.assertIn(
            b"header_len < (size_t)(in->ptr - msg_base)",
            tree["src/lib/gssapi/spnego/negoex_util.c"],
        )

    def test_material_mutation_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            name = "krb5-1.22.3.tar.gz.asc"
            (Path(folder) / name).write_bytes(self.captured[name] + b"x")
            with self.assertRaises(ValueError):
                material(folder, name)

    def test_archive_path_link_duplicates_and_parent_file_refused(self):
        cases = [
            [("../outside", tarfile.REGTYPE, b"x")],
            [("alias", tarfile.SYMTYPE, b"")],
            [("same", tarfile.REGTYPE, b"a"), ("same", tarfile.REGTYPE, b"b")],
            [("parent", tarfile.REGTYPE, b"a"), ("parent/child", tarfile.REGTYPE, b"b")],
            [("/absolute", tarfile.REGTYPE, b"a")],
        ]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                model.archive_buffers(tar(rows), "gz")

    def test_archive_expansion_cap_refused(self):
        raw = tar([("synthetic", tarfile.REGTYPE, b"x" * 4096)])
        with patch.object(model, "LIMIT", 1024), self.assertRaisesRegex(ValueError, "expansion"):
            model.archive_buffers(raw, "gz")

    def test_exact_context_refuses_missing_and_ambiguous(self):
        for lines in (["wrong\n"], ["old\n", "old\n"]):
            with self.assertRaisesRegex(ValueError, "context_not_unique"):
                model.exact_context(lines, ["old\n"], ["new\n"])

    def test_mutated_patch_and_unknown_action_refuse(self):
        plan = copy.deepcopy(self.plan)
        plan["series"][0]["action"] = "ignore_error"
        with self.assertRaisesRegex(ValueError, "unknown_action"):
            build.prepared_buffers(self.captured, plan, self.rebased)
        patches = dict(self.rebased)
        name = plan["series"][0]["rebased"]
        patches[name] += b"unreviewed"
        with self.assertRaisesRegex(ValueError, "rebased_patch_pin"):
            build.prepared_buffers(self.captured, self.plan, patches)

    def test_json_duplicate_keys_refused(self):
        with self.assertRaisesRegex(ValueError, "json_duplicate"):
            model.json_value(b'{"admitted":false,"admitted":true}')

    def test_release_freshness_source_identity_and_pinned_index(self):
        text = (
            "Origin: Debian\nCodename: sid\nAcquire-By-Hash: yes\n"
            "Date: Mon, 16 Nov 2026 10:00:00 +0000\n"
            "Valid-Until: Mon, 23 Nov 2026 10:00:00 +0000\n"
            "SHA256:\n " + "1" * 64 + " 10 main/source/Sources.xz\n"
        ).encode()
        now = 1794826800  # 2026-11-16 11:00Z
        self.assertEqual(acquire.release_fields(text, now), (10, "1" * 64))
        for bad in (
            text.replace(b"Codename: sid", b"Codename: trixie"),
            text.replace(b"23 Nov", b"15 Nov"),
            text.replace(b"16 Nov", b"19 Nov"),
        ):
            with self.assertRaises(ValueError):
                acquire.release_fields(bad, now)

    def test_source_record_matches_two_exact_payload_tuples_only(self):
        rows = "".join(
            f" {digest} {size} {name}\n"
            for name, (size, digest) in MATERIALS.items()
            if name.startswith("krb5_")
        )
        text = (
            "Package: krb5\nVersion: 1.22.1-3\nDirectory: pool/main/k/krb5\n"
            "Checksums-Sha256:\n" + rows
        )
        compressed = lzma.compress(text.encode())
        value = acquire.source_record(compressed, (len(compressed), model.sha(compressed)))
        self.assertEqual(value["Version"], "1.22.1-3")
        bad = lzma.compress(text.replace("1.22.1-3\n", "1.22.1-4\n").encode())
        with self.assertRaises(ValueError):
            acquire.source_record(bad, (len(bad), model.sha(bad)))
        with self.assertRaises(ValueError):
            acquire.source_record(compressed, (len(compressed), "0" * 64))

    def test_archive_signature_bad_or_missing_refused(self):
        for raw in (
            b"",
            b"[GNUPG:] BADSIG synthetic\n",
            b"garbage\n",
            b"[GNUPG:] VALIDSIG incomplete\n",
        ):
            with self.assertRaises(ValueError):
                acquire.archive_status(raw)

    def test_MIT_signature_purpose_bad_hash_revocation_and_ambiguity(self):
        fp = model.PRIMARY
        good = (
            f"[GNUPG:] GOODSIG {fp[-16:]} synthetic\n"
            f"[GNUPG:] VALIDSIG {fp} 2026-11-09 1794239672 0 4 0 1 10 00 {fp}\n"
        ).encode()
        self.assertEqual(legacy_auth.valid_status(good, fp, fp, 1794826800)["primary"], fp)
        for raw in (
            good.replace(b" 10 00 ", b" 2 00 "),
            good + good,
            good + b"[GNUPG:] REVKEYSIG synthetic\n",
            good.replace(fp.encode(), b"A" * 40),
        ):
            with self.assertRaises(ValueError):
                legacy_auth.valid_status(raw, fp, fp, 1794826800)

    def test_wrong_Root_purpose_before_command_or_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrong = dict(ROOT_PURPOSE, product_admission=True)
            (root / "Root-purpose.json").write_text(json.dumps(wrong))
            with patch.object(auth, "command") as command, self.assertRaises(ValueError):
                auth.authenticate(root, root / "never")
            command.assert_not_called()
            self.assertFalse((root / "never").exists())

    def test_authentication_failure_never_parses_source_or_runs_compiler(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(build, "authenticate", side_effect=ValueError("synthetic_auth")),
                patch.object(build, "archive_buffers") as archive,
                patch.object(build, "command") as command,
                self.assertRaises(ValueError),
            ):
                build.main(Path(directory), Path(directory) / "new")
            archive.assert_not_called()
            command.assert_not_called()

    def test_ABI_parser_legacy_hash_and_rows_agree(self):
        raw = synthetic_elf("libsynthetic.so.1")
        old = legacy_inventory.elf_abi(raw)
        new = abi_data.elf_exports(raw)
        self.assertEqual({key: new[key] for key in old}, old)
        self.assertEqual(new["symbols"], [["synthetic_export", 18, 0, "SYNTHETIC_1", False, None]])

    def test_ABI_new_exports_are_DATA_not_admission(self):
        before, after = abi_model(), abi_model()
        after["libraries"]["libkrb5-3"]["symbols"].append(["new", 18, 0, "KRB_2", False, None])
        result = abi_data.compare(before, after)
        self.assertTrue(result["all_old_exports_preserved"])
        self.assertFalse(result["candidate_profile_v2_admitted"])
        self.assertEqual(len(result["candidate_additions"]["libkrb5-3"]), 1)

    def test_ABI_every_old_field_must_match(self):
        for index, changed in enumerate(("other", 17, 3, "KRB_2", True, 8)):
            before, after = abi_model(), abi_model()
            after["libraries"]["libkrb5-3"]["symbols"][0][index] = changed
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(ValueError, "old_export_changed"),
            ):
                abi_data.compare(before, after)

    def test_ABI_missing_duplicate_or_SONAME_changed_refuse(self):
        for operation in ("missing", "duplicate", "soname"):
            before, after = abi_model(), abi_model()
            if operation == "missing":
                del after["libraries"]["libkrb5-3"]
            elif operation == "duplicate":
                after["libraries"]["libkrb5-3"]["symbols"] *= 2
            else:
                after["libraries"]["libkrb5-3"]["soname"] = "other.so"
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                abi_data.compare(before, after)

    def test_profile_false_and_unreviewed_extra_refused(self):
        candidate = abi_model()
        profile = json.loads((HERE / "Root-profile-v2.CANDIDATE.json").read_text())
        with self.assertRaisesRegex(ValueError, "not_admitted"):
            profile_v2.admit(profile, candidate)
        profile["admitted"] = True
        profile["libraries"] = copy.deepcopy(candidate["libraries"])
        self.assertTrue(profile_v2.admit(profile, candidate)["product_build_gate"])
        candidate["libraries"]["libkrb5-3"]["symbols"].append(
            ["extra", 18, 0, "KRB_2", False, None]
        )
        row = candidate["libraries"]["libkrb5-3"]
        row["exported_symbols"] = len(row["symbols"])
        row["abi_sha256"] = legacy_inventory.digest(
            legacy_inventory.canonical(sorted(row["symbols"])).encode()
        )
        with self.assertRaisesRegex(ValueError, "unreviewed_exports"):
            profile_v2.admit(profile, candidate)

    def test_no_Sid_binaries_nocheck_or_product_gate_bypass(self):
        docker = (HERE / "Dockerfile.lab").read_text()
        self.assertNotIn("deb http", docker)
        self.assertNotIn("nocheck", docker)
        self.assertIn(
            "RUN --network=none python -I -B -S /opt/krb5-upgrade/build_upgrade.py", docker
        )
        self.assertFalse(ROOT_PURPOSE["product_admission"])

    def test_legacy_v1_auth_H1_and_six_case_harness_byte_exact(self):
        pins = {
            "common.py": "68a0c8f52b430f739b46f02d3b15162de08b850aadffe1d182687bdfb7ab442a",
            "bounded_io.py": "72b778ad6e441744e8bd9ac84ba7f47b1f6b577b7885a2e0daf3b4584cc0150a",
            "legacy_inventory.py": (
                "1aa5b149de5954e2b46ffb378e2fb6ce75161d3e054b8cd223bc06cd52e454e0"
            ),
            "legacy_auth.py": "ee2fa56b745671af2e2349f663220ed16d1b6389f79c376801eed9bedbd1c803",
            "check_krb5_asn1.sh": (
                "cbd5d4c3732025feb5666381e359af605ed1cfa09e263d00f010217f554a8688"
            ),
            "krb5_asn1_regression.c": (
                "1636dc0901e1e62094bc1b00f1215f64a7357a462195c7e16cd8646252ff0275"
            ),
        }
        for name, digest in pins.items():
            self.assertEqual(model.sha((HERE / name).read_bytes()), digest)
        self.assertEqual(legacy_inventory.VERSION, "1.21.3-5+deb13u1+pamolive1")

    def test_ABI_bool_numeric_type_confusion_and_nonfinite_JSON_refused(self):
        for index, bad in ((1, True), (2, False), (4, 0), (5, True)):
            before, after = abi_model(), abi_model()
            after["libraries"]["libkrb5-3"]["symbols"][0][index] = bad
            with self.subTest(index=index), self.assertRaises(ValueError):
                abi_data.compare(before, after)
        with self.assertRaisesRegex(ValueError, "json_nonfinite"):
            model.json_value(b'{"admitted":NaN}')

    def test_expected_nonzero_keyring_requires_complete_H1_and_exact_errno(self):
        stderr = b"add_key: Operation not permitted\n"
        facts = {
            "returncode": 1,
            "reason": "nonzero_exit",
            "exception_type": None,
            "cleanup_exception_type": None,
            "spawn_attempted": True,
            "pid": 123,
            "owned_child_reaped": True,
            "drains_complete": True,
            "killed_owned_child": False,
            "stdout_bytes": 0,
            "stderr_bytes": len(stderr),
        }
        build.keyring_facts(facts, b"", stderr)
        for key, value in (
            ("reason", "work_timeout"),
            ("reason", None),
            ("returncode", True),
            ("pid", 0),
            ("owned_child_reaped", False),
            ("drains_complete", False),
            ("cleanup_exception_type", "OSError"),
            ("killed_owned_child", True),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                build.keyring_facts(dict(facts, **{key: value}), b"", stderr)
        with self.assertRaises(ValueError):
            build.keyring_facts(facts, b"", stderr + b"other diagnostic")

    def test_export_whitelist_and_collision_do_not_walk_source_or_emit_ELF(self):
        self.assertEqual(len(export_evidence.LOGS), 25)
        self.assertEqual(
            set(export_evidence.LEAVES),
            {"intent.json", "pid.json", "result.json", "unknown.json", "stdout", "stderr"},
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "already").mkdir()
            with self.assertRaises(FileExistsError):
                export_evidence.main(root / "source", root / "already")

    def test_signer_key_capability_expiry_and_revocation_are_not_bypassed(self):
        fp = model.PRIMARY
        good = {fp: {"validity": "u", "created": "1389117826", "expires": "0", "caps": "sc"}}
        legacy_auth.signing_capability(good, fp, fp, 1794826800, 1794239672)
        for key, bad in (
            ("validity", "r"),
            ("caps", "c"),
            ("expires", "1790000000"),
            ("created", "1800000000"),
        ):
            keys = copy.deepcopy(good)
            keys[fp][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                legacy_auth.signing_capability(keys, fp, fp, 1794826800, 1794239672)

    def test_MIT_authentication_uses_same_captured_buffers_after_path_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            materials = root / "materials"
            materials.mkdir()
            for name, raw in self.captured.items():
                (materials / name).write_bytes(raw)
            (materials / "Root-purpose.json").write_text(json.dumps(ROOT_PURPOSE))
            fp = model.PRIMARY
            pub = ["pub", "u", "4096", "1", fp[-16:], "1389117826", "0", "", "u", "", "", "sc"]
            listed = (":".join(pub) + "\nfpr:::::::::" + fp + ":\n").encode()
            good = (
                f"[GNUPG:] GOODSIG {fp[-16:]} synthetic\n"
                f"[GNUPG:] VALIDSIG {fp} 2026-11-09 1794239672 0 4 0 1 10 00 {fp}\n"
            ).encode()
            calls = []

            def fake(args, *_positional, **_kwargs):
                calls.append(args)
                if "--list-keys" in args:
                    return listed
                if "--verify" in args:
                    (materials / "krb5-1.22.3.tar.gz").write_bytes(b"mutated after capture")
                    self.assertEqual(
                        Path(args[-1]).read_bytes(), self.captured["krb5-1.22.3.tar.gz"]
                    )
                    return good
                return b""

            with (
                patch.object(auth, "verify_release", return_value=((10, "1" * 64), {})),
                patch.object(auth, "source_record", return_value={}),
                patch.object(auth, "command", side_effect=fake),
                patch.object(auth.time, "time", return_value=1794826800),
            ):
                (materials / "Sources.xz").write_bytes(b"synthetic signed-index model")
                captured, receipt = auth.authenticate(materials, root / "work")
            self.assertEqual(len(calls), 3)
            self.assertEqual(captured, self.captured)
            self.assertFalse(receipt["product_admission"])
            self.assertFalse(receipt["source_payload_extracted"])

    def test_Debian_chain_refusal_precedes_any_MIT_command(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, raw in self.captured.items():
                (root / name).write_bytes(raw)
            (root / "Root-purpose.json").write_text(json.dumps(ROOT_PURPOSE))
            with (
                patch.object(
                    auth, "verify_release", side_effect=ValueError("synthetic_bad_archive")
                ),
                patch.object(auth, "command") as command,
                self.assertRaises(ValueError),
            ):
                auth.authenticate(root, root / "work")
            command.assert_not_called()

    def test_current_old_hostname_bodies_preserved_not_partial_wildcards(self):
        _, _, tree, _ = build.prepared_buffers(self.captured, self.plan, self.rebased)
        old = (HERE / "TLS-old-hostname-contract.DATA.inc").read_bytes()
        self.assertEqual(
            model.sha(old), "4b4670e7c7bb9236babd043f3487c407643ab03114222b7dc873946c030b55b5"
        )
        source = tree["src/plugins/tls/k5tls/openssl.c"]
        tls_oracle.verify_contract(source, old)
        changed = source.replace(b"allow_wildcard && plen == 1", b"allow_wildcard && plen >= 1")
        self.assertNotEqual(changed, source)
        with self.assertRaisesRegex(ValueError, "old_hostname_contract"):
            tls_oracle.verify_contract(changed, old)

    def test_TLS_actual_main_includes_utf8_header_and_preserves_commands_and_receipt(self):
        _, _, tree, _ = build.prepared_buffers(self.captured, self.plan, self.rebased)
        raw = tree["src/plugins/tls/k5tls/openssl.c"]
        old = (HERE / "TLS-old-hostname-contract.DATA.inc").read_bytes()
        helpers = tls_oracle.verify_contract(raw, old)
        outputs = {}
        result = {"cases": 12, "passed": 12, "certificate_chain_verified": False}
        with tempfile.TemporaryDirectory() as directory:
            source, work = Path(directory) / "source", Path(directory) / "work"
            inputs = {
                source / "src/plugins/tls/k5tls/openssl.c": raw,
                HERE / "TLS-old-hostname-contract.DATA.inc": old,
                source / "src/include/k5-utf8.h": tree["src/include/k5-utf8.h"],
                source / "build/include/krb5/krb5.h": (
                    b"/* This file is generated, please don't edit it directly.  */\n"
                    b"#ifndef KRB5_KRB5_H_INCLUDED\n#define KRB5_KRB5_H_INCLUDED\n"
                    b"/* SYNTHETIC public-header buffer; no native preprocessing. */\n"
                ),
            }

            def reader(path, cap):
                self.assertLessEqual(len(inputs[path]), cap)
                return inputs[path]

            with (
                patch.object(tls_oracle, "read", side_effect=reader),
                patch.object(
                    tls_oracle, "write_new", side_effect=lambda p, v: outputs.setdefault(p, v)
                ),
                patch.object(
                    tls_oracle, "command", side_effect=[b"", json.dumps(result).encode()]
                ) as command,
                patch.object(tls_oracle, "record") as record,
            ):
                tls_oracle.main(source, work)
            preamble = (
                b'#include "' + (source / "build/include/krb5/krb5.h").as_posix().encode() + b'"\n'
                b"#include <stddef.h>\n#include <string.h>\n#include <arpa/inet.h>\n"
                b"#include <openssl/x509.h>\n#include <openssl/x509v3.h>\n"
            )
            self.assertEqual(
                outputs,
                {
                    work / "hostname-helpers.inc": preamble
                    + tls_oracle.project_upper(tree["src/include/k5-utf8.h"])
                    + helpers
                },
            )
            self.assertEqual(command.call_count, 2)
            self.assertEqual(
                command.call_args_list[0].args,
                (
                    [
                        "/usr/bin/cc",
                        "-std=c99",
                        "-O2",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-I" + str(source / "src/include"),
                        "-I" + str(source / "build/include"),
                        "-I" + str(work),
                        str(HERE / "tls_hostname_oracle.c"),
                        "-lssl",
                        "-lcrypto",
                        "-o",
                        str(work / "hostname-oracle"),
                    ],
                    work,
                    work / "compile",
                ),
            )
            self.assertEqual(command.call_args_list[0].kwargs, {"seconds": 60})
            self.assertEqual(
                command.call_args_list[1].args,
                ([str(work / "hostname-oracle")], work, work / "run"),
            )
            self.assertEqual(command.call_args_list[1].kwargs, {"seconds": 10})
            record.assert_called_once_with(
                work / "TLS-HOSTNAME-DATA.json",
                {
                    "actual_source_sha256": model.sha(raw),
                    "actual_helper_region_sha256": model.sha(helpers),
                    "old_helper_region_sha256": model.sha(old),
                    "actual_utf8_header_sha256": model.sha(tree["src/include/k5-utf8.h"]),
                    "projected_upper_sha256": model.sha(
                        tls_oracle.project_upper(tree["src/include/k5-utf8.h"])
                    ),
                    "configured_public_header_sha256": model.sha(
                        inputs[source / "build/include/krb5/krb5.h"]
                    ),
                    "matching": result,
                    "certificate_chain_or_AD_interop": "NOT_EXECUTED",
                    "partial_label_wildcards_admitted": False,
                    "operational_GO": False,
                },
            )

    def test_old_product_ABI_anchor_is_not_stock_assumption(self):
        # Consistent SYNTHETIC contract; real old anchors are never rewritten by product code.
        value = abi_model()
        anchors = {
            p: (r["exported_symbols"], r["abi_sha256"]) for p, r in value["libraries"].items()
        }
        with patch.object(abi_data, "OLD_ANCHORS", anchors):
            abi_data.bind_old_product_baseline(value)
            value["libraries"]["libkrb5-3"]["abi_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "old_ABI_record_digest_count"):
                abi_data.bind_old_product_baseline(value)

    def test_R1_forged_baseline_subset_copied_historical_counts_cannot_admit_build(self):
        candidate = abi_model()
        before = copy.deepcopy(candidate)
        for package, row in before["libraries"].items():
            row["exported_symbols"], row["abi_sha256"] = abi_data.OLD_ANCHORS[package]
        compared = abi_data.compare(before, candidate)
        profile = json.loads((HERE / "Root-profile-v2.CANDIDATE.json").read_text())
        profile["admitted"] = True  # future explicitly approved SYNTHETIC model, not Root approval
        profile["libraries"] = copy.deepcopy(candidate["libraries"])
        with tempfile.TemporaryDirectory() as folder:
            for name, value in (
                ("ABI-before.json", before),
                ("ABI-candidate.json", candidate),
                ("ABI-comparison-DATA.json", compared),
            ):
                (Path(folder) / name).write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "old_ABI_record_digest_count"):
                profile_v2.admit_build(profile, Path(folder))
        valid = abi_model()
        for key, bad in (
            ("exported_symbols", True),
            ("exported_symbols", 1.0),
            ("abi_sha256", 123),
            ("symbols", tuple(valid["libraries"]["libkrb5-3"]["symbols"])),
        ):
            changed = copy.deepcopy(valid)
            changed["libraries"]["libkrb5-3"][key] = bad
            with self.subTest(key=key, bad=type(bad).__name__), self.assertRaises(ValueError):
                abi_data.bind_old_product_baseline(changed)

    def test_real_H1_memory_Popen_rc1_keyring_probe_keeps_UNKNOWN_and_false_success(self):
        class MemoryProcess:
            pid = 123

            def __init__(self):
                self.stdout = io.BytesIO(b"")
                self.stderr = io.BytesIO(b"add_key: Operation not permitted\n")

            def poll(self):
                return 1

            def wait(self, timeout=None):
                return 1

            def kill(self):
                raise AssertionError("normal exited fake must never be killed")

        result = bounded_io.run_capped(
            ["/usr/bin/keyctl", "add", "user", "synthetic", "synthetic", "@p"],
            env={},
            cwd=str(HERE),
            timeout=5,
            stdout_cap=4096,
            stderr_cap=4096,
            popen=lambda *args, **kwargs: MemoryProcess(),
        )
        self.assertEqual(result.reason, "nonzero_exit")
        self.assertFalse(result.ok)
        self.assertTrue(result.owned_child_reaped and result.drains_complete)
        build.keyring_facts(result.facts(), result.stdout, result.stderr)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "status").write_bytes(b"Seccomp:\t2\n")
            (root / "net/lo").mkdir(parents=True)

            def command(args, work, log, **kwargs):
                log.mkdir()
                for name, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
                    (log / name).write_bytes(raw)
                (log / "result.json").write_text(json.dumps(result.facts()))
                (log / "unknown.json").write_text('{"state":"UNKNOWN"}')
                raise ValueError("child_failed_or_unknown")

            def mapped(path):
                return {"/proc/self/status": root / "status", "/sys/class/net": root / "net"}.get(
                    str(path), Path(path)
                )

            with (
                patch.object(build, "command", side_effect=command),
                patch.object(build, "Path", side_effect=mapped),
            ):
                value = build.keyring_probe(root)
            self.assertFalse(value["command_success"])
            self.assertTrue(value["UNKNOWN_marker_retained"])
            self.assertEqual(
                json.loads((root / "keyring-probe/unknown.json").read_text()), {"state": "UNKNOWN"}
            )

    def test_v2_profile_never_accepts_old_version_bad_adaptation_or_truthy_flags(self):
        base = json.loads((HERE / "Root-profile-v2.CANDIDATE.json").read_text())
        candidate = abi_model()
        base["admitted"] = True
        base["libraries"] = copy.deepcopy(candidate["libraries"])
        for name, bad in (
            ("version", "1.21.3-5+deb13u1+pamolive1"),
            ("admitted", 1),
            ("operational_GO", True),
            ("patch_plan_sha256", "0" * 64),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                profile_v2.admit(dict(base, **{name: bad}), candidate)
        with self.assertRaises(ValueError):
            profile_v2.admit(dict(base, wildcard="*"), candidate)

    def test_SBOM_v2_graph_contract_model_not_Linux_schema_qualification(self):
        # Isolated function AST only. The real module/validator is NOT imported or bypassed.
        # This checks graph/source bindings; mandatory Linux schema verification stays pending.
        module = ast.parse((HERE / "sbom_v2.py").read_text())
        node = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "export")
        schema_calls = []
        import re
        import uuid
        from urllib.parse import quote

        namespace = {
            "need": model.need,
            "admit": profile_v2.admit,
            "VERSION": model.VERSION,
            "re": re,
            "uuid": uuid,
            "quote": quote,
            "MATERIALS": MATERIALS,
            "LIBRARIES": abi_data.LIBRARIES,
            "PREFIX": "urn:pamolive:krb5-upgrade-v2:",
            "standard": SimpleNamespace(validate_schema=schema_calls.append),
        }
        exec(
            compile(
                ast.Module(body=[node], type_ignores=[]), "<SBOM-function-contract-model>", "exec"
            ),
            namespace,
        )
        abi = abi_model()
        for row in abi["libraries"].values():
            row["file_sha256"] = "2" * 64
        profile = json.loads((HERE / "Root-profile-v2.CANDIDATE.json").read_text())
        profile["admitted"] = True
        profile["libraries"] = {
            p: {k: r[k] for k in ("soname", "abi_sha256", "exported_symbols", "symbols")}
            for p, r in abi["libraries"].items()
        }
        report = {
            "schema": "pamolive.krb5-runtime-verification/2",
            "version": model.VERSION,
            "verified": True,
            "compilation_attestation": False,
            "active_ABI": abi,
            "candidate_ABI": abi,
            "Root_profile": profile,
            "old_ABI_exports_preserved": True,
        }
        value = namespace["export"](report, "sha256:" + "3" * 64, "4" * 64)
        self.assertEqual(len(value["components"]), 6)
        refs = {row["bom-ref"] for row in value["components"]}
        self.assertEqual(len(refs), 6)
        self.assertTrue(
            all(
                row["ref"] in refs and set(row["dependsOn"]) <= refs
                for row in value["dependencies"]
            )
        )
        self.assertNotIn("vulnerabilities", value)
        self.assertEqual(len(schema_calls), 1)  # spy invocation only, NOT actual schema PASS
        report["Root_profile"]["admitted"] = False
        with self.assertRaises(ValueError):
            namespace["export"](report, "sha256:" + "3" * 64, "4" * 64)

    def test_incompatible_ABI_never_installs_or_runs_consumer_but_preserves_DATA(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "ABI-comparison-DATA.json").write_text(
                json.dumps({"all_old_exports_preserved": False})
            )
            with patch.object(qualify_candidate, "command") as command:
                qualify_candidate.main(root, root / "out", root / "runtime", root / "sdk")
            command.assert_not_called()
            value = model.json_value((root / "out/QUALIFICATION-DATA.json").read_bytes())
            self.assertEqual(value["status"], "ABI_PRECONDITION_REFUSED")
            self.assertFalse(value["runtime_or_SDK_installed"])
            export_evidence.main(root / "out", root / "public", consumer=True)
            exported = model.json_value((root / "public/PUBLIC-FILES.json").read_bytes())
            self.assertEqual([r["name"] for r in exported["files"]], ["QUALIFICATION-DATA.json"])

    def test_unknown_install_stops_commands_exports_partialfacts_and_fails_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "ABI-comparison-DATA.json").write_text(
                json.dumps({"all_old_exports_preserved": True})
            )
            with patch.object(
                qualify_candidate, "command", side_effect=ValueError("private-marker")
            ) as command:
                qualify_candidate.main(root, root / "out", root / "runtime", root / "sdk")
            self.assertEqual(command.call_count, 1)
            raw = (root / "out/QUALIFICATION-DATA.json").read_bytes()
            self.assertNotIn(b"private-marker", raw)
            value = model.json_value(raw)
            self.assertEqual(value["status"], "MEASUREMENT_FAILED_OR_UNKNOWN")
            self.assertEqual(value["phase"], "install_candidate")
            self.assertIsNone(value["resources_released"])
            export_evidence.main(root / "out", root / "public", consumer=True)
            source = {
                "schema": "pamolive.krb5-upgrade-build-DATA/1",
                "authentication": {"both_source_chains_authenticated": True},
                "ABI_comparison": {"all_old_exports_preserved": True},
                "tests_enabled": True,
                "candidate_profile_v2_admitted": False,
                "product_admission": False,
                "operational_GO": False,
            }
            with self.assertRaisesRegex(ValueError, "consumer_gate_failed_or_unknown"):
                check_data_export.gate(source, value)

    def test_CI_DATA_gate_never_turns_refusal_or_truthy_scalar_into_green(self):
        source = {
            "schema": "pamolive.krb5-upgrade-build-DATA/1",
            "authentication": {"both_source_chains_authenticated": True},
            "ABI_comparison": {"all_old_exports_preserved": True},
            "tests_enabled": True,
            "candidate_profile_v2_admitted": False,
            "product_admission": False,
            "operational_GO": False,
        }
        consumer = {
            "schema": "pamolive.krb5-candidate-DATA/1",
            "status": "CANDIDATE_MEASUREMENT_COMPLETE",
            "runtime_SDK_same_build": True,
            "product_profile_v2_admitted": False,
            "operational_GO": False,
        }
        check_data_export.gate(source, consumer)
        for status in ("ABI_PRECONDITION_REFUSED", "MEASUREMENT_FAILED_OR_UNKNOWN", "SKIPPED"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                check_data_export.gate(source, dict(consumer, status=status))
        for key in ("runtime_SDK_same_build", "product_profile_v2_admitted", "operational_GO"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_data_export.gate(source, dict(consumer, **{key: 0}))

    def test_actual_DATA_tar_reader_rejects_duplicate_link_and_traversal(self):
        source = {
            "schema": "pamolive.krb5-upgrade-build-DATA/1",
            "authentication": {"both_source_chains_authenticated": True},
            "ABI_comparison": {"all_old_exports_preserved": True},
            "tests_enabled": True,
            "candidate_profile_v2_admitted": False,
            "product_admission": False,
            "operational_GO": False,
        }
        consumer = {
            "schema": "pamolive.krb5-candidate-DATA/1",
            "status": "CANDIDATE_MEASUREMENT_COMPLETE",
            "runtime_SDK_same_build": True,
            "product_profile_v2_admitted": False,
            "operational_GO": False,
        }
        rows = [
            ("source-build/BUILD-DATA.json", tarfile.REGTYPE, json.dumps(source).encode()),
            (
                "candidate-consumer/QUALIFICATION-DATA.json",
                tarfile.REGTYPE,
                json.dumps(consumer).encode(),
            ),
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "public.tar"
            path.write_bytes(gzip.decompress(tar(rows)))
            check_data_export.main(path)
            for extra in (
                rows[0],
                ("source-build/link", tarfile.SYMTYPE, b""),
                ("source-build/../escape", tarfile.REGTYPE, b"x"),
            ):
                path.write_bytes(gzip.decompress(tar(rows + [extra])))
                with self.subTest(extra=extra[0]), self.assertRaises(ValueError):
                    check_data_export.main(path)


class CanonicalArchiveKeyringTests(unittest.TestCase):
    def test_fixed_canonical_path_and_synthetic_regular_capture(self):
        self.assertEqual(
            acquire.KEYRING.as_posix(),
            "/usr/share/keyrings/debian-archive-keyring.pgp",
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic-keyring.pgp"
            raw = b"synthetic-public-keyring-model-only"
            path.write_bytes(raw)
            self.assertEqual(bounded_io.read_regular(path, 8 * 1024**2), raw)
            with self.assertRaisesRegex(ValueError, "regular file type/size budget"):
                bounded_io.read_regular(path, len(raw) - 1)

    def test_alias_hardlink_type_reparse_and_budget_refused_before_open(self):
        base = dict(st_mode=0o100444, st_nlink=1, st_size=12, st_dev=1, st_ino=2)
        cases = [
            ({"st_mode": 0o120777}, True),
            ({"st_mode": 0o040755}, False),
            ({"st_nlink": 2}, False),
            ({"st_file_attributes": 1024}, False),
            ({"st_size": 8 * 1024**2 + 1}, False),
            ({"st_size": -1}, False),
            ({}, True),
        ]
        for delta, alias in cases:
            leaf = SimpleNamespace(
                lstat=lambda d=delta: SimpleNamespace(**(base | d)),
                is_symlink=lambda a=alias: a,
            )
            with self.subTest(delta=delta, alias=alias):
                with patch.object(bounded_io, "Path", return_value=leaf):
                    with self.assertRaisesRegex(ValueError, "regular file type/size budget"):
                        bounded_io.read_regular(acquire.KEYRING, 8 * 1024**2)

    def test_fd_swap_refused_before_read_and_capture_closed(self):
        class Capture(io.BytesIO):
            reads = 0

            def fileno(self):
                return 123

            def read(self, maximum=-1):
                self.reads += 1
                return super().read(maximum)

        base = dict(st_mode=0o100444, st_nlink=1, st_size=3, st_dev=1, st_ino=2)
        for delta in ({"st_ino": 3}, {"st_dev": 2}, {"st_nlink": 2}):
            capture = Capture(b"toy")
            leaf = SimpleNamespace(
                lstat=lambda: SimpleNamespace(**base),
                is_symlink=lambda: False,
                open=lambda mode: capture,
            )
            with self.subTest(delta=delta):
                with (
                    patch.object(bounded_io, "Path", return_value=leaf),
                    patch.object(
                        bounded_io.os, "fstat", return_value=SimpleNamespace(**(base | delta))
                    ),
                ):
                    with self.assertRaisesRegex(ValueError, "file identity/type/size changed"):
                        bounded_io.read_regular(acquire.KEYRING, 8 * 1024**2)
                self.assertEqual(capture.reads, 0)
                self.assertTrue(capture.closed)


class DpkgFailureDiagnosticTests(unittest.TestCase):
    @staticmethod
    def facts(**changes):
        value = dict(
            spawn_attempted=True,
            pid=123,
            returncode=2,
            reason="nonzero_exit",
            killed_owned_child=False,
            owned_child_reaped=True,
            drains_complete=True,
            exception_type=None,
            cleanup_exception_type=None,
            stdout_bytes=3,
            stderr_bytes=4,
        )
        return value | changes

    def test_success_preserves_exact_command_without_diagnostic_reads_or_output(self):
        source, log = Path("source"), Path("log")
        with (
            patch.object(build, "command") as command,
            patch.object(build, "read", side_effect=AssertionError("success must not read")),
            patch("builtins.print") as printed,
        ):
            build.dpkg_build(source, log)
        command.assert_called_once_with(
            ["/usr/bin/dpkg-buildpackage", "-B", "-us", "-uc", "-j1"],
            source,
            log,
            seconds=3000,
            cap=8 * 1024**2,
            env=build.BUILD_ENV,
        )
        printed.assert_not_called()

    def test_failure_typed_H1_hashes_caps_and_original_refusal_without_raw_output(self):
        cases = [
            ({}, "NORMAL_NONZERO"),
            ({"returncode": -9}, "SIGNALLED"),
            ({"reason": "stdout_overflow", "stdout_bytes": 8 * 1024**2}, "OUTPUT_CAP_REFUSED"),
            ({"reason": "timeout", "killed_owned_child": True}, "TIME_BUDGET_REFUSED"),
            ({"owned_child_reaped": False}, "H1_UNKNOWN"),
            ({"drains_complete": False}, "H1_UNKNOWN"),
            ({"exception_type": "PRIVATE_EXCEPTION"}, "H1_UNKNOWN"),
            ({"returncode": 0, "reason": None}, "RC0_CALLER_REFUSAL"),
        ]
        for delta, expected in cases:
            original = ValueError("PRIVATE_ORIGINAL_REFUSAL")
            reads = []
            buffers = {"stdout": b"::error::PRIVATE_KEY_PASSWORD_ENV", "stderr": b"PRIVATE_KDC_RAW"}

            def reader(path, cap):
                reads.append((path.name, cap))
                return (
                    json.dumps(
                        self.facts(
                            **(
                                dict(
                                    stdout_bytes=len(buffers["stdout"]),
                                    stderr_bytes=len(buffers["stderr"]),
                                )
                                | delta
                            )
                        )
                    ).encode()
                    if path.name == "result.json"
                    else buffers[path.name]
                )

            console = io.StringIO()
            with (
                self.subTest(expected=expected),
                patch.object(build, "command", side_effect=original) as command,
                patch.object(build, "read", side_effect=reader),
                patch("sys.stdout", console),
            ):
                with self.assertRaises(ValueError) as caught:
                    build.dpkg_build(Path("source"), Path("log"))
            self.assertIs(caught.exception, original)
            command.assert_called_once()
            text = console.getvalue()
            self.assertLessEqual(len(text.encode()), 8192)
            self.assertNotIn("PRIVATE", text)
            self.assertNotIn("::error::", text)
            result = json.loads(text)
            self.assertEqual(result["classification"], expected)
            self.assertIs(result["operational_GO"], False)
            self.assertIs(result["tool_stability_proved"], False)
            for name, raw in buffers.items():
                self.assertEqual(
                    result[name], {"available": True, "bytes": len(raw), "sha256": model.sha(raw)}
                )
            self.assertEqual(
                reads, [("result.json", 16384), ("stdout", 8 * 1024**2), ("stderr", 8 * 1024**2)]
            )

    def test_injected_missing_malformed_receipts_or_console_failure_never_mask_primary(self):
        variants = [
            self.facts(reason="PRIVATE_UNKNOWN_REASON"),
            self.facts(returncode=True),
            self.facts(pid=True),
            self.facts(stdout_bytes=8 * 1024**2 + 1),
            self.facts(extra="PRIVATE_FREE_FIELD"),
            {"not": "PRIVATE_DATA"},
        ]
        for facts in variants:
            with (
                self.subTest(facts=list(facts)),
                patch.object(
                    build,
                    "read",
                    side_effect=lambda path, cap: json.dumps(facts).encode()
                    if path.name == "result.json"
                    else (_ for _ in ()).throw(ValueError("PRIVATE_READ_REFUSAL")),
                ),
            ):
                packet = build.dpkg_failure_data(Path("log"))
                self.assertFalse(packet["facts_available"])
                self.assertEqual(packet["classification"], "H1_UNKNOWN")
                self.assertFalse(packet["stdout"]["available"])
                self.assertFalse(packet["stderr"]["available"])
                self.assertNotIn("PRIVATE", json.dumps(packet))
        for error in [OSError("PRIVATE"), ValueError("PRIVATE")]:
            original = ValueError("PRIMARY")
            console = io.StringIO()
            console.close()
            with (
                patch.object(build, "command", side_effect=original) as command,
                patch.object(build, "read", side_effect=error),
                patch("sys.stdout", console),
            ):
                with self.assertRaises(ValueError) as caught:
                    build.dpkg_build(Path("source"), Path("log"))
            self.assertIs(caught.exception, original)
            command.assert_called_once()
        for missing in [True, False]:

            def reader(path, cap):
                if path.name == "result.json":
                    return json.dumps(self.facts()).encode()
                if missing:
                    raise OSError("PRIVATE_MISSING_LOG")
                return b"retained bytes disagree with receipt"

            with self.subTest(missing=missing), patch.object(build, "read", side_effect=reader):
                packet = build.dpkg_failure_data(Path("log"))
            self.assertTrue(packet["facts_available"])
            self.assertEqual(packet["classification"], "H1_UNKNOWN")
            self.assertIs(packet["retained_counts_match"], None if missing else False)


class DpkgMarkerTests(unittest.TestCase):
    def test_finite_tools_codes_locations_and_statuses_without_messages(self):
        raw = (
            b"dpkg-checkbuilddeps: error: unmet build dependencies: PRIVATE_DEP\n"
            b"PRIVATE_SOURCE.c:12:7: fatal error: PRIVATE_HEADER: No such file\n"
            b"collect2: error: ld returned 1 exit status\n"
            b"/usr/bin/ld: PRIVATE_OBJECT: undefined reference to PRIVATE_SYMBOL\n"
            b"dh_auto_build: error: PRIVATE_CMD returned exit code 2\n"
            b"dpkg-buildpackage: error: PRIVATE_RULE subprocess returned exit status 2\n"
            b"make[1]: *** [PRIVATE_TARGET: all] Error 2\n"
            b"dpkg-gensymbols: warning: some new symbols appeared in the symbols file: PRIVATE\n"
        )
        result = build.dpkg_failure_markers({"stdout": b"", "stderr": raw})
        self.assertEqual(len(result["events"]), 8)
        self.assertEqual(
            {r["tool_marker"] for r in result["events"]},
            {"checkbuilddeps", "compiler", "linker", "debhelper", "dpkg", "make", "gensymbols"},
        )
        self.assertEqual(result["root_cause"], "UNKNOWN")
        self.assertFalse(result["operational_GO"])
        self.assertNotIn("PRIVATE", json.dumps(result))
        for event in result["events"]:
            start, length = event["byte_offset"], event["line_bytes"]
            self.assertEqual(model.sha(raw[start : start + length]), event["line_sha256"])
        compiler = next(r for r in result["events"] if r["code"] == "COMPILER_ERROR")
        self.assertEqual((compiler["source_line"], compiler["source_column"]), (12, 7))
        self.assertEqual(compiler["source_path_sha256"], model.sha(b"PRIVATE_SOURCE.c"))
        numbers = {
            r["tool_marker"]: r["status_number"]
            for r in result["events"]
            if r["status_number"] is not None
        }
        self.assertEqual(numbers, {"linker": 1, "dpkg": 2, "make": 2})

    def test_make_flood_and_distinct_code_truncation_never_hide_other_tool_families(self):
        raw = b"make[1]: *** [private: all] Error 2\n" * 1000
        raw += (
            b"dpkg-checkbuilddeps: error: unmet build dependencies: private\n"
            b"dpkg-checkbuilddeps: error: unmet build conflicts: private\n"
            b"p.c:1:1: error: private\n"
            b"gcc: error: private\n"
            b"collect2: error: ld returned 1 exit status\n"
            b"ld: private: undefined reference to private\n"
            b"ld: cannot find private\n"
            b"dh_makeshlibs: error: private\n"
            b"dpkg-buildpackage: error: private\n"
            b"dpkg-gensymbols: warning: some new symbols appeared private\n"
            b"dpkg-gensymbols: error: some symbols or patterns disappeared private\n"
            b"dpkg-gensymbols: warning: new libraries appeared private\n"
            b"dpkg-gensymbols: error: some libraries disappeared private\n"
            b"dpkg-gensymbols: warning: private doesn't match completely private\n"
            b"dpkg-gensymbols: error: private\n"
        )
        value = build.dpkg_failure_markers({"stdout": raw, "stderr": b""})
        self.assertEqual(value["counts"]["MAKE_ERROR"], 1000)
        self.assertTrue(all(count > 0 for count in value["counts"].values()))
        self.assertEqual(value["distinct_codes"], 16)
        self.assertEqual(len(value["events"]), 8)
        self.assertTrue(value["events_truncated"])
        self.assertEqual(len({r["tool_marker"] for r in value["events"]}), 7)
        self.assertLessEqual(len(json.dumps(value).encode()), 7000)
        self.assertEqual(value["root_cause"], "UNKNOWN")
        facts = DpkgFailureDiagnosticTests.facts(stdout_bytes=len(raw), stderr_bytes=0)
        with patch.object(
            build,
            "read",
            side_effect=lambda path, cap: json.dumps(facts).encode()
            if path.name == "result.json"
            else raw
            if path.name == "stdout"
            else b"",
        ):
            packet = build.dpkg_failure_data(Path("log"))
        self.assertLessEqual(len(json.dumps(packet).encode()), 8192)
        self.assertIs(packet["retained_counts_match"], True)
        self.assertTrue(packet["failure_markers"]["events_truncated"])

    def test_parser_gated_by_normal_rc2_same_captured_buffers_and_original_refusal(self):
        buffers = {
            "stdout": b"make: *** [private] Error 2\n",
            "stderr": b"dpkg-gensymbols: error: some new symbols appeared private\n",
        }
        for delta, parsed in [
            ({}, True),
            ({"returncode": 1}, False),
            ({"reason": "timeout"}, False),
            ({"owned_child_reaped": False}, False),
        ]:
            calls = []
            facts = DpkgFailureDiagnosticTests.facts(
                **(
                    dict(stdout_bytes=len(buffers["stdout"]), stderr_bytes=len(buffers["stderr"]))
                    | delta
                )
            )

            def reader(path, cap):
                calls.append(path.name)
                self.assertEqual(calls.count(path.name), 1)
                return (
                    json.dumps(facts).encode() if path.name == "result.json" else buffers[path.name]
                )

            original = ValueError("PRIVATE_ORIGINAL")
            console = io.StringIO()
            with (
                self.subTest(delta=delta),
                patch.object(build, "command", side_effect=original),
                patch.object(build, "read", side_effect=reader),
                patch("sys.stdout", console),
            ):
                with self.assertRaises(ValueError) as caught:
                    build.dpkg_build(Path("source"), Path("log"))
            self.assertIs(caught.exception, original)
            value = json.loads(console.getvalue())
            self.assertIs(value["failure_markers"]["parsed"], parsed)
            self.assertEqual(value["failure_markers"]["root_cause"], "UNKNOWN")
            self.assertEqual(calls, ["result.json", "stdout", "stderr"])
            self.assertLessEqual(len(console.getvalue().encode()), 8192)
            for name in buffers:
                self.assertEqual(value[name]["sha256"], model.sha(buffers[name]))

    def test_private_control_unknown_and_line_budgets_remain_non_authority(self):
        raw = (
            b"::error:: PRIVATE\n\x1bgcc: error: PRIVATE\nunknown: PRIVATE\n" + b"x" * 8193 + b"\n"
        )
        value = build.dpkg_failure_markers({"stdout": raw, "stderr": b""})
        self.assertEqual(value["events"], [])
        self.assertEqual(value["long_or_control_lines_skipped"], 2)
        self.assertTrue(value["unrecognized_failure"])
        self.assertNotIn("PRIVATE", json.dumps(value))
        value = build.dpkg_failure_markers(
            {"stdout": b"\n" * 100001, "stderr": b"gcc: error: private\n"}
        )
        self.assertTrue(value["line_budget_exhausted"])
        self.assertEqual(value["counts"]["COMPILER_DRIVER_ERROR"], 1)
        self.assertEqual(value["root_cause"], "UNKNOWN")
        with self.assertRaises(ValueError):
            build.dpkg_failure_markers({"stdout": b"x" * (8 * 1024**2 + 1), "stderr": b""})


class PackagingSymbolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.captured = {name: material(HERE / "materials", name) for name in MATERIALS}
        cls.plan = model.json_value((HERE / "patch-plan.json").read_bytes())
        cls.rebased = {p.name: p.read_bytes() for p in (HERE / "rebased-patches").iterdir()}
        cls.original = model.archive_buffers(cls.captured["krb5_1.22.1-3.debian.tar.xz"], "xz")

    def test_real_packaging_declares_the_actual_new_upstream_export(self):
        _, prepared, tree, _ = build.prepared_buffers(self.captured, self.plan, self.rebased)
        name = "debian/libkrb5-3.symbols"
        line = b" k5_ser_unpack_len@krb5_3_MIT 1.22.3\n"
        self.assertNotIn(line, self.original[name][0])
        self.assertEqual(prepared[name][0].count(line), 1)
        self.assertEqual(prepared[name][0].replace(line, b""), self.original[name][0])
        self.assertEqual(
            model.sha(prepared[name][0]),
            "00b743262a79ae50cd189c488a25576c3d3d52d349d7b98e115c45b95bd97ab1",
        )
        self.assertEqual(
            tree["src/lib/krb5/libkrb5.exports"].splitlines().count(b"k5_ser_unpack_len"), 1
        )
        for path in ("src/include/k5-int.h", "src/lib/krb5/krb/serialize.c"):
            self.assertIn(b"k5_ser_unpack_len(", tree[path])

    def test_adaptation_is_a_copy_with_one_row_and_every_old_symbol_preserved(self):
        original = dict(self.original)
        result = build.packaging_symbols(original)
        self.assertIsNot(result, original)
        self.assertEqual(original, self.original)
        name = "debian/libkrb5-3.symbols"
        self.assertEqual(set(result), set(original))
        self.assertEqual(result[name][1], original[name][1])
        self.assertEqual(
            {k: v for k, v in result.items() if k != name},
            {k: v for k, v in original.items() if k != name},
        )
        self.assertEqual(
            model.sha(original[name][0]),
            "7452b6b13d0a121d7034bc86ea50ad042761be2682319b2513b6f98db338b727",
        )

    def test_mutation_duplicate_already_adapted_wrong_namespace_or_mode_refuse(self):
        name = "debian/libkrb5-3.symbols"
        raw, mode = self.original[name]
        line = b" k5_ser_unpack_len@krb5_3_MIT 1.22.3\n"
        cases = [
            (raw + b"\n", mode),
            (raw + line, mode),
            (raw.replace(b"krb5_3_MIT", b"OTHER_3_MIT", 1), mode),
            (raw, 0o755),
            (raw, float(mode)),
            (bytearray(raw), mode),
        ]
        for row in cases:
            with self.subTest(mode=type(row[1]).__name__), self.assertRaises(ValueError):
                build.packaging_symbols({**self.original, name: row})
        with self.assertRaises(ValueError):
            build.packaging_symbols(build.packaging_symbols(self.original))

    def test_gensymbols_strictness_and_unadmitted_profile_are_not_replaced(self):
        tree = ast.parse((HERE / "build_upgrade.py").read_bytes())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        calls = [n for n in ast.walk(main) if isinstance(n, ast.Call)]
        self.assertTrue(
            any(isinstance(n.func, ast.Name) and n.func.id == "dpkg_build" for n in calls)
        )
        profile = model.json_value((HERE / "Root-profile-v2.CANDIDATE.json").read_bytes())
        self.assertIs(profile["admitted"], False)
        self.assertEqual(profile["libraries"], {})
        prepared = build.packaging_symbols(self.original)
        self.assertEqual(prepared["debian/rules"], self.original["debian/rules"])


class TLSCompileDiagnosticTests(unittest.TestCase):
    def capture(self, stdout=b"", stderr=b"public C: compiler or linker error\n", **delta):
        facts = dict(
            spawn_attempted=True,
            pid=123,
            returncode=1,
            reason="nonzero_exit",
            exception_type=None,
            cleanup_exception_type=None,
            killed_owned_child=False,
            owned_child_reaped=True,
            drains_complete=True,
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
        )
        facts.update(delta)
        buffers = {"result.json": json.dumps(facts).encode(), "stdout": stdout, "stderr": stderr}
        reads = []

        def reader(path, cap):
            reads.append((path.name, cap))
            self.assertEqual(sum(name == path.name for name, _ in reads), 1)
            return buffers[path.name]

        with patch.object(tls_oracle, "read", side_effect=reader):
            packet = tls_oracle.compile_failure_data(Path("/compile"))
        return packet, reads, buffers

    def test_public_compiler_tail_is_actual_same_buffer_and_H1_hash_once(self):
        import base64

        packet, reads, buffers = self.capture()
        self.assertEqual(
            reads, [("result.json", 4096), ("stdout", 2 * 1024**2), ("stderr", 2 * 1024**2)]
        )
        self.assertEqual(packet["classification"], "NORMAL_NONZERO")
        self.assertEqual(packet["stderr"]["sha256"], model.sha(buffers["stderr"]))
        self.assertEqual(base64.b64decode(packet["stderr"]["tail_base64"]), buffers["stderr"])
        self.assertEqual(packet["result.json"]["sha256"], model.sha(buffers["result.json"]))
        self.assertFalse(packet["tool_stability_proved"])
        self.assertEqual(packet["root_cause"], "UNKNOWN")
        self.assertFalse(packet["operational_GO"])

    def test_process_nonzero_timeout_signal_rc0_nondrain_bool_and_tool_uncertainty(self):
        for delta, expected in [
            ({"returncode": 2}, "NORMAL_NONZERO"),
            ({"returncode": True}, "H1_UNKNOWN"),
            ({"reason": "timeout"}, "H1_UNKNOWN"),
            ({"returncode": -9}, "SIGNALLED"),
            ({"returncode": 0, "reason": None}, "RC0_CALLER_REFUSAL"),
            ({"owned_child_reaped": False}, "H1_UNKNOWN"),
            ({"drains_complete": False}, "H1_UNKNOWN"),
            ({"killed_owned_child": True}, "H1_UNKNOWN"),
            ({"exception_type": "PRIVATE"}, "H1_UNKNOWN"),
            ({"pid": True}, "H1_UNKNOWN"),
            ({"reason": "PRIVATE_REASON"}, "H1_UNKNOWN"),
        ]:
            with self.subTest(delta=delta):
                packet, _, _ = self.capture(**delta)
                self.assertEqual(packet["classification"], expected)
                self.assertFalse(packet["tool_stability_proved"])
                self.assertNotIn("PRIVATE", json.dumps(packet))

    def test_receipt_unknown_fields_duplicate_nonfinite_or_count_drift_stay_unknown(self):
        for delta in (
            {"stderr_bytes": 0},
            {"stderr_bytes": True},
            {"stdout_bytes": -1},
            {"argv": "PRIVATE_ENV"},
            {"extra": "PRIVATE_ENV"},
        ):
            packet, _, _ = self.capture(**delta)
            self.assertEqual(packet["classification"], "H1_UNKNOWN")
            self.assertNotIn("PRIVATE", json.dumps(packet))
        for raw in (b"PRIVATE_ENV", b'{"pid":1,"pid":2}', b'{"pid":NaN}'):
            with patch.object(
                tls_oracle,
                "read",
                side_effect=lambda path, cap: raw if path.name == "result.json" else b"",
            ):
                packet = tls_oracle.compile_failure_data(Path("/compile"))
            self.assertEqual(packet["classification"], "H1_UNKNOWN")
            self.assertIsNone(packet["facts"])
            self.assertNotIn("PRIVATE", json.dumps(packet))

    def test_both_public_streams_flood_binary_bytes_stderr_priority_and_16K_total(self):
        import base64

        stdout = b"public stdout" * (2 * 1024**2 // 13)
        stderr = bytes(range(256)) * (2 * 1024**2 // 256)
        packet, _, buffers = self.capture(stdout=stdout, stderr=stderr)
        self.assertEqual(packet["classification"], "NORMAL_NONZERO")
        self.assertEqual(packet["stderr"]["tail_bytes"], 8192)
        self.assertEqual(packet["stdout"]["tail_bytes"], 0)
        self.assertEqual(base64.b64decode(packet["stderr"]["tail_base64"]), stderr[-8192:])
        self.assertEqual(packet["stderr"]["tail_offset"], len(stderr) - 8192)
        self.assertEqual(packet["stderr"]["tail_sha256"], model.sha(stderr[-8192:]))
        self.assertLessEqual(len(json.dumps(packet).encode()), 16384)
        packet, _, _ = self.capture(stdout=b"x" * 8192, stderr=b"actual error")
        self.assertEqual(packet["stdout"]["tail_bytes"] + packet["stderr"]["tail_bytes"], 8192)
        packet, _, _ = self.capture(stderr=b"x" * (2 * 1024**2 + 1))
        self.assertFalse(packet["stderr"]["available"])
        self.assertEqual(packet["classification"], "H1_UNKNOWN")

    def test_failed_compile_prints_one_typed_packet_and_reraises_original_exception(self):
        packet, _, _ = self.capture()
        original = ValueError("child_failed_or_unknown")
        console = io.StringIO()
        with (
            patch.object(tls_oracle, "command", side_effect=original) as command,
            patch.object(tls_oracle, "compile_failure_data", return_value=packet),
            patch("sys.stdout", console),
            self.assertRaises(ValueError) as caught,
        ):
            tls_oracle.compile_checked(["/usr/bin/cc"], Path("/work"), Path("/compile"), seconds=60)
        self.assertIs(caught.exception, original)
        self.assertEqual(json.loads(console.getvalue()), packet)
        command.assert_called_once_with(
            ["/usr/bin/cc"], Path("/work"), Path("/compile"), seconds=60
        )

    def test_missing_capture_read_or_console_failure_never_masks_original_refusal(self):
        with patch.object(tls_oracle, "read", side_effect=OSError("PRIVATE_READ")):
            packet = tls_oracle.compile_failure_data(Path("/compile"))
        self.assertFalse(packet["stderr"]["available"])
        self.assertEqual(packet["classification"], "H1_UNKNOWN")
        for error in (OSError("PRIVATE"), ValueError("PRIVATE")):
            original = ValueError("original_refusal")
            with (
                patch.object(tls_oracle, "command", side_effect=original),
                patch.object(tls_oracle, "compile_failure_data", side_effect=error),
                self.assertRaises(ValueError) as caught,
            ):
                tls_oracle.compile_checked(
                    ["/usr/bin/cc"], Path("/work"), Path("/compile"), seconds=60
                )
            self.assertIs(caught.exception, original)
        original = ValueError("original_refusal")
        with (
            patch.object(tls_oracle, "command", side_effect=original),
            patch.object(tls_oracle, "compile_failure_data", return_value=packet),
            patch("builtins.print", side_effect=OSError("PRIVATE_CONSOLE")),
            self.assertRaises(ValueError) as caught,
        ):
            tls_oracle.compile_checked(["/usr/bin/cc"], Path("/work"), Path("/compile"), seconds=60)
        self.assertIs(caught.exception, original)

    def test_success_compile_wrapper_has_no_capture_IO_or_output_and_same_budget(self):
        with (
            patch.object(tls_oracle, "command", return_value=b"ok") as command,
            patch.object(tls_oracle, "read") as read,
            patch("builtins.print") as printed,
        ):
            self.assertEqual(
                tls_oracle.compile_checked(
                    ["/usr/bin/cc"], Path("/work"), Path("/compile"), seconds=60
                ),
                b"ok",
            )
        command.assert_called_once_with(
            ["/usr/bin/cc"], Path("/work"), Path("/compile"), seconds=60
        )
        read.assert_not_called()
        printed.assert_not_called()

    def test_only_public_C_compile_is_wrapped_without_new_flags_or_GPG_DEB_scope(self):
        tree = ast.parse((HERE / "tls_oracle.py").read_bytes())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        wrapped = [
            n
            for n in ast.walk(main)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "compile_checked"
        ]
        self.assertEqual(len(wrapped), 1)
        self.assertEqual(wrapped[0].args[0].elts[0].value, "/usr/bin/cc")
        self.assertEqual([(k.arg, k.value.value) for k in wrapped[0].keywords], [("seconds", 60)])
        self.assertNotIn("-fdiagnostics", ast.unparse(main))
        calls = [
            n
            for n in ast.walk(main)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "command"
        ]
        self.assertEqual(len(calls), 1)
        self.assertEqual([(k.arg, k.value.value) for k in calls[0].keywords], [("seconds", 10)])


class TLSProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        captured = {name: material(HERE / "materials", name) for name in MATERIALS}
        plan = model.json_value((HERE / "patch-plan.json").read_bytes())
        rebased = {p.name: p.read_bytes() for p in (HERE / "rebased-patches").iterdir()}
        _, _, cls.tree, _ = build.prepared_buffers(captured, plan, rebased)

    def exercise(self, *, utf8=None, generated=None, missing=False, changed=False, reply=None):
        events = SimpleNamespace(calls=[], outputs={}, receipts=[], reads=[], error=None)
        with tempfile.TemporaryDirectory() as directory:
            source, work = Path(directory) / "source", Path(directory) / "work"
            public = source / "build/include/krb5/krb5.h"
            fake = (
                b"/* This file is generated, please don't edit it directly.  */\n"
                b"#ifndef KRB5_KRB5_H_INCLUDED\n#define KRB5_KRB5_H_INCLUDED\n"
                b"/* SYNTHETIC; no preprocessing/native compiler. */\n"
            )
            inputs = {
                source / "src/plugins/tls/k5tls/openssl.c": self.tree[
                    "src/plugins/tls/k5tls/openssl.c"
                ],
                source / "src/include/k5-utf8.h": self.tree["src/include/k5-utf8.h"]
                if utf8 is None
                else utf8,
                HERE / "TLS-old-hostname-contract.DATA.inc": (
                    HERE / "TLS-old-hostname-contract.DATA.inc"
                ).read_bytes(),
                public: fake if generated is None else generated,
            }

            def reader(path, cap):
                events.reads.append(path)
                if path == public:
                    if missing:
                        raise FileNotFoundError("synthetic missing configured header")
                    if changed and events.reads.count(public) > 1:
                        return inputs[path] + b"/* changed */\n"
                self.assertIn(path, inputs)  # No system-header fallback is modeled.
                self.assertLessEqual(len(inputs[path]), cap)
                return inputs[path]

            def command(*args, **kwargs):
                events.calls.append((args, kwargs))
                if len(events.calls) == 1:
                    return b""
                return json.dumps(
                    {"cases": 12, "passed": 12, "certificate_chain_verified": False}
                    if reply is None
                    else reply
                ).encode()

            with (
                patch.object(tls_oracle, "read", side_effect=reader),
                patch.object(tls_oracle, "command", side_effect=command),
                patch.object(
                    tls_oracle,
                    "write_new",
                    side_effect=lambda p, b: events.outputs.setdefault(p, b),
                ),
                patch.object(
                    tls_oracle, "record", side_effect=lambda p, v: events.receipts.append((p, v))
                ),
            ):
                try:
                    tls_oracle.main(source, work)
                except (OSError, ValueError) as error:
                    events.error = error
            events.source, events.public = source, public
        return events

    def test_actual_macro_buffer_and_closed_dependency_preamble(self):
        raw = self.tree["src/include/k5-utf8.h"]
        expected = next(line for line in raw.splitlines(keepends=True) if b"KRB5_UPPER" in line)
        self.assertEqual(tls_oracle.project_upper(raw), expected)
        events = self.exercise()
        self.assertIsNone(events.error)
        self.assertEqual(len(events.calls), 2)
        output = next(iter(events.outputs.values()))
        self.assertIn(b'#include "' + events.public.as_posix().encode() + b'"\n', output)
        self.assertIn(expected, output)
        for unwanted in (b'"k5-int.h"', b'"k5-utf8.h"', b"-isystem", b"#pragma"):
            self.assertNotIn(unwanted, output)
        self.assertEqual(events.reads.count(events.public), 2)
        receipt = events.receipts[0][1]
        self.assertEqual(receipt["actual_utf8_header_sha256"], model.sha(raw))
        self.assertEqual(receipt["projected_upper_sha256"], model.sha(expected))
        self.assertIs(receipt["operational_GO"], False)

    def test_header_mutations_refuse_before_cc(self):
        raw = self.tree["src/include/k5-utf8.h"]
        for mutated in (
            raw.replace(b"'A'", b"'B'"),
            raw.replace(b"#define KRB5_UPPER", b"#define KRB5_OTHER"),
            raw + b"#define KRB5_UPPER(c) 1\n",
            raw.replace(b"#define KRB5_UPPER", b"#ifdef UNKNOWN\n#define KRB5_UPPER"),
            raw.replace(b"((c) >=", b"\\\n((c) >="),
            raw.replace(b"\n", b"\r\n"),
        ):
            with self.subTest(mutation_sha=model.sha(mutated)):
                events = self.exercise(utf8=mutated)
                self.assertIsInstance(events.error, ValueError)
                self.assertEqual(str(events.error), "TLS_utf8_header_preimage")
                self.assertEqual(events.calls, [])
                self.assertEqual(events.outputs, {})

    def test_context_and_uniqueness_still_refuse_if_header_digest_is_recommissioned(self):
        raw = self.tree["src/include/k5-utf8.h"]
        real_sha = tls_oracle.sha
        for mutated, code in (
            (b"KRB5_UPPER" + raw[10:], "TLS_upper_unique"),
            (raw.replace(b"/*\n * these macros", b"/*\n * OTHER macros"), "TLS_upper_context"),
            (raw.replace(b"'A'", b"'B'"), "TLS_upper_definition"),
        ):
            with self.subTest(code=code):
                self.assertEqual(len(mutated), len(raw))
                # Independent guard challenge: weaken only the whole-header gate in memory.
                with patch.object(
                    tls_oracle,
                    "sha",
                    side_effect=lambda b: real_sha(raw) if b is mutated else real_sha(b),
                ):
                    with self.assertRaisesRegex(ValueError, code):
                        tls_oracle.project_upper(mutated)

    def test_missing_or_non_generated_header_has_no_fallback_before_cc(self):
        for options in ({"missing": True}, {"generated": b"/* unrelated system header */\n"}):
            with self.subTest(options=options):
                events = self.exercise(**options)
                self.assertIsNotNone(events.error)
                self.assertEqual(events.calls, [])
                self.assertEqual(events.outputs, {})
                self.assertNotIn(Path("/usr/include/krb5.h"), events.reads)

    def test_configured_header_changed_after_cc_blocks_execution_and_receipt(self):
        events = self.exercise(changed=True)
        self.assertIsInstance(events.error, ValueError)
        self.assertEqual(str(events.error), "TLS_configured_header_changed")
        self.assertEqual(len(events.calls), 1)
        self.assertEqual(events.receipts, [])

    def test_projected_oracle_still_requires_all_twelve_cases(self):
        events = self.exercise(
            reply={"cases": 12, "passed": 11, "certificate_chain_verified": False}
        )
        self.assertIsInstance(events.error, ValueError)
        self.assertEqual(str(events.error), "TLS_matching_result")
        self.assertEqual(len(events.calls), 2)
        self.assertEqual(events.receipts, [])


if __name__ == "__main__":
    unittest.main()
