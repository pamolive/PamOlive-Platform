"""Local copies of independent SOURCE challenges; no old output/review dependency."""

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import acquisition_io as a
import acquisition_owner as owner
import future_linux as f
import source_data as d
import test_data_contracts as supplied
import test_hardening_r2 as hardened

ROOT = SOURCE = Path(__file__).resolve().parent
observations = {}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


sha = digest


class EarlierIndependent(unittest.TestCase):
    def test_default_NULL_trust_precedes_every_artifact_and_command(self):
        config = json.loads((ROOT / "recipe-inputs.json").read_bytes())
        with (
            patch.object(f, "read", side_effect=AssertionError("unexpected_read")),
            patch.object(f, "run", side_effect=AssertionError("unexpected_command")),
        ):
            with self.assertRaisesRegex(ValueError, "trust_policy_pin_missing"):
                f.policy(config)
            with self.assertRaisesRegex(ValueError, "exact_debian_patch_plan_pin_missing"):
                f.checked_plan(config)

    def test_unresolved_plan_precedes_build_dependencies_or_extraction(self):
        plan = json.loads((ROOT / "static-source-replay.json").read_bytes())
        with (
            patch.object(f, "offline"),
            patch.object(f, "checked_plan", side_effect=lambda config: d.patch_contract(plan)),
            patch.object(
                f,
                "dependencies",
                side_effect=AssertionError("dependencies_before_plan"),
            ),
            patch.object(f, "run", side_effect=AssertionError("command_before_plan")),
        ):
            with self.assertRaisesRegex(ValueError, "patch_plan_unresolved_context"):
                f.build(Path("SYNTHETIC"), Path("SYNTHETIC"), {}, {})

    def test_signature_contract_rejects_bad_unknown_duplicate_future(self):
        signer = "A" * 40
        primary = "B" * 40
        now = int(supplied.NOW)
        policy = {
            "signer_to_primary": {signer: primary},
            "allowed_primaries": [primary],
        }

        def frame(stamp=now, expiry=0, actual=signer):
            return (
                f"[GNUPG:] GOODSIG {actual[-16:]} Synthetic\n"
                f"[GNUPG:] VALIDSIG {actual} 2026-11-17 {stamp} {expiry} 4 0 1 8 01 {primary}\n"
            ).encode()

        self.assertEqual(d.signature_status(frame(), policy, now)[0]["signing_key"], signer)
        for raw in (
            frame() + frame(),
            frame(stamp=now + 301),
            frame(expiry=now),
            frame(actual="C" * 40),
            frame() + b"[GNUPG:] REVKEYSIG 1234 x\n",
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                d.signature_status(raw, policy, now)

    def test_DSC_index_tamper_refuses_without_crypto_or_archive(self):
        raw = (ROOT / "materials/debian" / d.DSC).read_bytes()
        self.assertEqual(d.dsc_control(raw, (len(raw), digest(raw)))["Version"], d.BASE_VERSION)
        with self.assertRaisesRegex(ValueError, "dsc_index_binding"):
            d.dsc_control(raw + b" ", (len(raw), digest(raw)))

    def test_baseline_references_are_not_four_patch_Debian_plan(self):
        report = json.loads((ROOT / "source-status.json").read_bytes())
        self.assertFalse(report["full_Debian_source_applicability_proved"])
        self.assertFalse(report["source_authentication"]["APT_Source_chain_verified"])
        self.assertFalse(report["source_authentication"]["GPG_executed"])
        self.assertFalse(report["operational_GO"])
        self.assertFalse(report["cryptography_wheel_OpenSSL4_0_3"]["corrected"])
        replay = json.loads((ROOT / "static-source-replay.json").read_bytes())
        quic = next(row for row in replay["rows"] if row["cve"] == "CVE-2026-95691")
        self.assertEqual(quic["action"], "REFUSED_SOURCE_CONTEXT_CONFLICT")
        self.assertEqual(len(quic["missing_paths"]), 2)


class RecentIndependent(unittest.TestCase):
    def test_02_original_extra_target_reproduction_refuses_all_rows_before_transform(
        self,
    ):
        tree, plan, patches = hardened.make_plan()
        last = plan["rows"][-1]
        extra = hardened.diff("EXTRA.txt", b"before\n", b"after\n")
        patches[last["proposed_patch"]] += extra
        last["proposed_patch_sha256"] = sha(patches[last["proposed_patch"]])
        with patch.object(
            d, "apply_bound", side_effect=AssertionError("TRANSFORM_BEFORE_ALL_PATCHES")
        ):
            with self.assertRaisesRegex(ValueError, "inventory_not_exhaustive"):
                d.patch_source_buffers(tree, plan, patches)
        observations["original_F2"] = "extra target in fourth patch refused before first transform"

    def test_03_original_slow_drip_refuses_before_second_write(self):
        actor = hardened.Actor(chunks=[b"x"] * 4 + [b""], step=29)
        with self.assertRaisesRegex(ValueError, "UNKNOWN_DEADLINE"):
            actor.call()
        self.assertEqual((actor.clock[0], actor.sink.getvalue()), (58, b"x"))
        observations["original_F1"] = {
            "simulated_seconds_at_refusal": 58,
            "written_bytes": 1,
            "actual_network_or_wait": False,
        }

    def test_04_late_response_close_never_returns_success(self):
        class LateResponse(hardened.Actor):
            def __exit__(self, *args):
                super().__exit__(*args)
                self.clock[0] = 31

        actor = LateResponse()
        with self.assertRaisesRegex(ValueError, "UNKNOWN_DEADLINE"):
            actor.call(deadline=30)
        self.assertEqual(actor.sink.getvalue(), b"x")

    def test_05_fourth_postimage_failure_before_first_quilt_write(self):
        tree, plan, patches = hardened.make_plan()
        plan["rows"][-1]["after"] = {next(iter(plan["rows"][-1]["after"])): "f" * 64}

        def read(path, cap):
            return patches[path.name]

        with (
            patch.object(f, "offline"),
            patch.object(f, "read", side_effect=read),
            patch.object(f, "source_text", side_effect=lambda root, name: tree[name]),
            patch.object(
                f,
                "write_new",
                side_effect=AssertionError("MUTATION_BEFORE_ALL_SIMULATION"),
            ),
            patch.object(f, "run", side_effect=AssertionError("QUILT_BEFORE_ALL_SIMULATION")),
        ):
            with self.assertRaisesRegex(ValueError, "debian_source_postimage"):
                f.patch_tree(Path("SYNTHETIC"), plan, Path("WORK"), {})

    def test_06_owner_refuses_postcommand_source_drift(self):
        clock = [0]
        records = []
        role = {"path": "/usr/bin/python3.12", "source_files": {}}
        snapshots = iter([{"captured": "x"}, {"captured": "x"}, {"captured": "CHANGED"}])
        with (
            patch.object(owner, "runtime_contract", return_value=role),
            patch.object(owner, "runtime_role"),
            patch.object(owner, "snapshot", side_effect=lambda *args: next(snapshots)),
            patch.object(owner.Path, "mkdir"),
            patch.object(a.time, "monotonic", side_effect=lambda: clock[0]),
        ):
            with self.assertRaisesRegex(ValueError, "acquisition_source_changed"):
                owner.supervise(
                    Path("S"),
                    Path("M"),
                    Path("W"),
                    {"acquisition_runtime": role},
                    None,
                    lambda *args, **kwargs: b'{"state":"COMPLETE"}\n',
                    lambda path, value: records.append(value),
                    deadline=180,
                )
        self.assertEqual(records[-1]["state"], "UNKNOWN")
        self.assertFalse(any(row["state"] == "COMPLETE" for row in records))

    def test_08_NULL_authority_and_QUIC_still_refuse(self):
        config = json.loads((SOURCE / "recipe-inputs.json").read_bytes())
        self.assertIsNone(config["trust_policy_sha256"])
        with patch.object(
            f, "read", side_effect=AssertionError("AUTHORITY_READ_BEFORE_COMMISSION")
        ):
            with self.assertRaisesRegex(ValueError, "trust_policy_pin_missing"):
                f.policy(config)
        plan = json.loads((SOURCE / "static-source-replay.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "unresolved_context"):
            d.patch_contract(plan)
        report = json.loads((SOURCE / "source-status.json").read_bytes())
        for key in (
            "trust_commissioned",
            "build_verified",
            "image_qualified",
            "operational_GO",
            "Linux_authorized",
            "source_publication_authorized",
        ):
            self.assertIs(report[key], False)
        self.assertEqual(report["CVE_closed"], 0)
