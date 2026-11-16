"""Public packet DATA and orchestration doubles only; no native crypto is executed."""

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from qualification.p1g_headless import chrome_bootstrap as boot
from qualification.p1g_headless import chrome_gpg as gpg
from qualification.p1g_headless import chrome_key_scope as scope
from qualification.p1g_headless import chrome_key_scope_native as native
from qualification.p1g_headless import lab_support
from qualification.p1g_headless.test_chrome_bootstrap import NOW, listing, status

HERE = Path(__file__).resolve().parent
ORIGINAL = (HERE / "chrome_materials/google-key.asc").read_bytes()


def projected():
    _, prefix, subs = scope.blocks(ORIGINAL)
    return b"".join(native.encoded(tag, body) for tag, body, _ in prefix + subs[scope.SIGNER])


def full_listing():
    rows = listing()
    _, _, subs = scope.blocks(ORIGINAL)
    example = listing().decode().splitlines()[2].split(":")
    for fingerprint in subs:
        if fingerprint == scope.SIGNER:
            continue
        row = list(example)
        row[4] = fingerprint[-16:]
        rows += (
            ":".join(row) + "\n" + ":".join(["fpr"] + [""] * 8 + [fingerprint, ""]) + "\n"
        ).encode()
    return rows


class FakeCommands:
    def __init__(self, *, exported=None, narrowed=None, verify=None, original=None):
        self.exported = projected() if exported is None else exported
        self.narrowed = listing() if narrowed is None else narrowed
        self.verify = status() if verify is None else verify
        self.original = full_listing() if original is None else original
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if "--export-filter" in argv:
            return self.exported
        if "--list-keys" in argv:
            return self.original if "gnupg-original" in argv[3] else self.narrowed
        if "--verify" in argv:
            return self.verify
        return b""


class KeyScopeTests(unittest.TestCase):
    def exercise(self, *args, **kwargs):
        # Existing orchestration tests model only their original seam, never native evidence.
        kwargs.update(producer=lambda: None, publish_fixture=lambda *a: None)
        with patch.object(native, "control_evidence", return_value=({}, 0)):
            return native.exercise(*args, **kwargs)

    def authenticate(self, commands, directory, sink=None):
        root = Path(directory)
        staged = root / "materials"
        staged.mkdir()
        with patch.object(scope.time, "time", return_value=NOW):
            return scope.authenticate(
                commands, lab_support, staged, root, gpg, ORIGINAL, diagnostic_sink=sink
            )

    def test_actual_public_packet_pins_and_ordered_lineage_only_DATA(self):
        p, prefix, subs = scope.blocks(ORIGINAL)
        self.assertEqual(p, scope.PRIMARY)
        self.assertEqual(len(subs), 8)
        for fingerprint, body in ((p, prefix[0][1]), (scope.SIGNER, subs[scope.SIGNER][0][1])):
            self.assertEqual(scope.sha(body), scope.KEY_BODY_SHA256[fingerprint])
        facts = scope.lineage(ORIGINAL, projected())
        self.assertTrue(facts["signed_blocks_preserved"])
        self.assertFalse(facts["crypto_verified"])
        self.assertEqual(facts["purpose"], scope.PURPOSE)

    def test_finite_packet_lengths_secret_unknown_and_version_refused(self):
        first = scope.packets(ORIGINAL)[0][2]
        for raw in (
            b"",
            b"x" * 65537,
            b"\xc6\xe0x",
            b"\x9b",
            b"\xc6\xff\x00",
            native.encoded(5, b"secret"),
            native.encoded(7, b"secret"),
            native.encoded(60, b"unknown"),
            first[:-1],
            b"\x00" + first,
            native.encoded(6, b"\x05" + b"\x00" * 20),
        ):
            with self.subTest(raw=raw[:8]), self.assertRaises(ValueError):
                scope.packets(raw)
        primary = scope.packets(ORIGINAL)[0]
        body = bytearray(primary[1])
        body[5] = 17
        with self.assertRaises(ValueError):
            scope.packets(native.encoded(6, bytes(body)))

    def test_packet_count_and_signature_lengths_closed(self):
        first = scope.packets(ORIGINAL)[0][2]
        for raw in (
            first + native.encoded(13, b"uid") * 256,
            first + native.encoded(2, b"\x04\x13\x01\x08\xff\xff" + b"x" * 8),
        ):
            with self.assertRaises(ValueError):
                scope.packets(raw)

    def test_public_armor_crc_strict_and_binary_headers_may_change(self):
        raw = projected()
        armor = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
            + base64.b64encode(raw)
            + b"\n="
            + base64.b64encode(scope.crc24(raw))
            + b"\n-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        # Armor lines themselves have a finite 76-byte bound.
        with self.assertRaises(ValueError):
            scope.binary(armor)
        lines = [
            base64.b64encode(raw)[i : i + 64] for i in range(0, len(base64.b64encode(raw)), 64)
        ]
        armor = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: DATA test\n\n"
            + b"\n".join(lines)
            + b"\n="
            + base64.b64encode(scope.crc24(raw))
            + b"\n-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        self.assertEqual(scope.binary(armor), raw)
        self.assertEqual(scope.lineage(ORIGINAL, armor)["crypto_verified"], False)
        for bad in (
            armor.replace(b"Version:", b"Unknown:"),
            armor.replace(b"PUBLIC", b"PRIVATE"),
            armor.replace(base64.b64encode(scope.crc24(raw)), b"AAAA"),
            armor + b"trailing",
        ):
            with self.assertRaises(ValueError):
                scope.blocks(bad)

    def test_primary_subkey_multiplicity_order_and_signed_body_changes_refused(self):
        _, prefix, subs = scope.blocks(ORIGINAL)
        rows = prefix + subs[scope.SIGNER]
        alternatives = [
            rows + [rows[-1]],
            rows + [prefix[0]],
            rows[:-1],
            prefix + next(v for k, v in subs.items() if k != scope.SIGNER),
            rows + next(v for k, v in subs.items() if k != scope.SIGNER),
        ]
        changed = list(rows)
        tag, body, _ = changed[1]
        changed[1] = (tag, body[:-1] + bytes([body[-1] ^ 1]), b"")
        alternatives += [changed]
        for candidate in alternatives:
            raw = b"".join(native.encoded(tag, body) for tag, body, _ in candidate)
            with self.assertRaises(ValueError):
                scope.lineage(ORIGINAL, raw)
        with self.assertRaisesRegex(ValueError, "scope_original_pin"):
            scope.lineage(ORIGINAL + b"x", projected())

    def test_six_real_orchestrator_calls_and_diagnostic_before_unchanged_guard(self):
        commands = FakeCommands()
        seen = []
        with tempfile.TemporaryDirectory() as directory:
            valid, proof, _, _ = self.authenticate(
                commands, directory, lambda *args: seen.append(args)
            )
        self.assertEqual(len(commands.calls), 6)
        export = commands.calls[2][0]
        self.assertEqual(
            export[-4:],
            ["--export-filter", "drop-subkey=fpr <> " + scope.SIGNER, "--export", scope.PRIMARY],
        )
        for argv, kwargs in commands.calls:
            self.assertEqual(kwargs["seconds"], 10)
            self.assertIn("--no-autostart", argv)
            self.assertIn("--require-cross-certification", argv)
            self.assertNotIn("--export-clean", argv)
        self.assertEqual(valid["signing_key"], scope.SIGNER)
        self.assertTrue(proof["crypto_verified"])
        self.assertTrue(proof["selected_states_identical"])
        self.assertEqual(len(seen), 1)

    def test_changed_selected_state_revoked_expired_or_future_refuses(self):
        for field, value in (
            (1, "r"),
            (1, "e"),
            (5, str(NOW + 301)),
            (6, str(NOW - 1)),
            (11, "c"),
            (11, "sD"),
        ):
            rows = listing().decode().splitlines()
            row = rows[2].split(":")
            row[field] = value
            rows[2] = ":".join(row)
            commands = FakeCommands(narrowed=("\n".join(rows) + "\n").encode())
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                self.authenticate(commands, directory)
            self.assertFalse(any("--verify" in argv for argv, _ in commands.calls))
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            self.authenticate(FakeCommands(original=listing()), directory)

    def test_unfiltered_BAD_wrong_primary_signer_or_malformed_refuses(self):
        for bad in [status() + ("[GNUPG:] " + code + " PRIVATE\n").encode() for code in gpg.BAD] + [
            status().replace(scope.SIGNER.encode(), b"F" * 40),
            status().replace(scope.PRIMARY.encode(), b"F" * 40),
            b"PRIVATE\n",
        ]:
            seen = []
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                self.authenticate(
                    FakeCommands(verify=bad), directory, lambda *args: seen.append(args)
                )
            self.assertEqual(len(seen), 1)

    def test_exported_body_mutation_refuses_before_scoped_import(self):
        for kind in ("missing_binding", "corrupt_crosscert", "corrupt_selfsig"):
            commands = FakeCommands(exported=native.mutate_key(scope, ORIGINAL, kind))
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                self.authenticate(commands, directory)
            self.assertEqual(len(commands.calls), 3)

    def test_command_UNKNOWN_cannot_be_reclassified_as_scope_success(self):
        commands = FakeCommands()
        commands.run = lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("command_UNKNOWN"))
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "command_UNKNOWN"),
        ):
            self.authenticate(commands, directory)

    def test_native_missing_revocation_is_INCOMPLETE_not_install_authority(self):
        captured = {
            "google-key.asc": ORIGINAL,
            "Release": b"data",
            "Release.gpg": b"sig",
            "qualification/p1g_headless/chrome_scope_native_fixtures.json": json.dumps(
                {
                    "schema": "pamolive.chrome-scope-public-negative-fixtures/1",
                    "status": "PENDING",
                    "cases": {},
                }
            ).encode(),
        }
        result = {"refused": True, "complete_H1": True}
        with patch.object(native, "verify_refusal", return_value=result):
            tested = self.exercise(
                scope,
                gpg,
                lab_support,
                lambda *args: projected(),
                captured,
                HERE,
                lambda label: (None, None),
                expected_scoped_sha256=scope.sha(projected()),
            )
        self.assertEqual(tested["state"], "INCOMPLETE")
        self.assertEqual(set(tested["missing"]), set(native.LIFECYCLE))
        self.assertFalse(tested["operational_GO"])
        self.assertFalse(tested["GPG_agent_autostart_allowed"])

    def test_lifecycle_label_cannot_be_replaced_with_an_easier_state(self):
        captured = {"google-key.asc": ORIGINAL, "Release": b"data", "Release.gpg": b"sig"}
        for label, (role, state) in native.LIFECYCLE.items():
            row = {
                "path": "google-key.asc",
                "sha256": scope.ORIGINAL_SHA256,
                "primary": scope.PRIMARY,
                "signer": scope.SIGNER,
                "expected": "r" if state == "e" else "e",
                "role": role,
            }
            captured["qualification/p1g_headless/chrome_scope_native_fixtures.json"] = json.dumps(
                {
                    "schema": "pamolive.chrome-scope-public-negative-fixtures/1",
                    "status": "PENDING",
                    "cases": {label: row},
                }
            ).encode()
            with (
                patch.object(native, "verify_refusal", return_value={}),
                self.assertRaisesRegex(ValueError, "native_fixture_pin"),
            ):
                self.exercise(
                    scope,
                    gpg,
                    lab_support,
                    lambda *args: projected(),
                    captured,
                    HERE,
                    lambda label: (None, None),
                    expected_scoped_sha256=scope.sha(projected()),
                )

    def test_original_predicates_and_vendor_buffers_byte_exact(self):
        self.assertEqual(
            hashlib.sha256((HERE / "chrome_gpg.py").read_bytes()).hexdigest(),
            "001d178e5876df97156bf2061df19a51fc56bbf5b9bfa102098999bc10357512",
        )
        for name, pin in json.loads((HERE / "chrome-bootstrap-pins.json").read_bytes())[
            "files"
        ].items():
            raw = (HERE / "chrome_materials" / name).read_bytes()
            self.assertEqual(
                (len(raw), hashlib.sha256(raw).hexdigest()), (pin["bytes"], pin["sha256"])
            )

    def negative_lane(
        self, directory, *, rc=1, reason="nonzero_exit", changed=None, tool_change=False, raw=None
    ):
        root = Path(directory)
        private, public = root / "private", root / "public"
        private.mkdir()
        public.mkdir()
        verify_status = b"[GNUPG:] BADSIG FAKE_PUBLIC_CASE\n" if raw is None else raw
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            kwargs["on_spawn"](234)
            verifying = "--verify" in argv
            data = dict(
                spawn_attempted=True,
                pid=234,
                returncode=rc if verifying else 0,
                reason=reason if verifying else None,
                owned_child_reaped=True,
                drains_complete=True,
                killed_owned_child=False,
                exception_type=None,
                cleanup_exception_type=None,
                stdout_bytes=len(verify_status) if verifying else len(b"[GNUPG:] IMPORT_RES 1\n"),
                stderr_bytes=0,
            )
            if verifying and changed:
                data.update(changed)
            raw = verify_status if verifying else b"[GNUPG:] IMPORT_RES 1\n"
            if kwargs.get("stdout_sink") is not None:
                kwargs["stdout_sink"].write(raw)
            return SimpleNamespace(
                **data,
                ok=data["returncode"] == 0 and data["reason"] is None,
                stdout=b"" if kwargs.get("stdout_sink") else raw,
                stderr=b"",
                facts=lambda: dict(data),
            )

        count = []

        def pin(path):
            self.assertIsInstance(path, Path)
            count.append(path)
            return {"sha256": ("b" if tool_change and len(count) >= 5 else "a") * 64}

        support = SimpleNamespace(fresh_write=lab_support.fresh_write, tool_pin=pin)
        lane = boot.Commands(support, SimpleNamespace(run_capped=runner), private, public)
        return lane, private, support, calls

    def test_native_normal_nonzero_H1_is_expected_refusal_with_UNKNOWN_still_sticky(self):
        with tempfile.TemporaryDirectory() as directory:
            lane, private, support, calls = self.negative_lane(directory)
            proof = native.verify_refusal(
                lane,
                support,
                boot.read,
                scope,
                gpg,
                private,
                b"public",
                b"signature",
                b"Release",
                scope.PRIMARY,
                scope.SIGNER,
            )
            self.assertTrue(proof["refused"] and proof["complete_H1"] and proof["UNKNOWN_retained"])
            self.assertTrue(lane.unknown)
            self.assertTrue((lane.public / "command-2/UNKNOWN.json").is_file())
            with self.assertRaisesRegex(ValueError, "previous_UNKNOWN"):
                lane.run(["/usr/bin/gpg", "next"])
            self.assertEqual(len(calls), 2)

    def test_native_rc0_BAD_is_refusal_but_signal_timeout_nondrain_and_changed_tool_are_not(self):
        with tempfile.TemporaryDirectory() as directory:
            lane, private, support, _ = self.negative_lane(directory, rc=0, reason=None)
            proof = native.verify_refusal(
                lane,
                support,
                boot.read,
                scope,
                gpg,
                private,
                b"public",
                b"signature",
                b"Release",
                scope.PRIMARY,
                scope.SIGNER,
            )
            self.assertFalse(proof["UNKNOWN_retained"])
        for kwargs in (
            {"rc": -9},
            {"rc": 1, "reason": "timeout"},
            {"changed": {"drains_complete": False}},
            {"changed": {"owned_child_reaped": False}},
            {"changed": {"returncode": True}},
            {"changed": {"killed_owned_child": True}},
            {"tool_change": True},
        ):
            with tempfile.TemporaryDirectory() as directory:
                lane, private, support, _ = self.negative_lane(directory, **kwargs)
                with self.assertRaises(ValueError):
                    native.verify_refusal(
                        lane,
                        support,
                        boot.read,
                        scope,
                        gpg,
                        private,
                        b"public",
                        b"signature",
                        b"Release",
                        scope.PRIMARY,
                        scope.SIGNER,
                    )

    def test_current_fixture_manifest_is_partial_and_contains_no_generated_private_keys(self):
        manifest = json.loads((HERE / "chrome_scope_native_fixtures.json").read_bytes())
        self.assertEqual(set(manifest["cases"]), set(native.LIFECYCLE))
        for label, row in manifest["cases"].items():
            if label == "signer_revoked":
                self.assertEqual(row["source_pin"], native.PRODUCER_CONTRACT["source_pin"])
                self.assertEqual(row["producer_purpose"], native.PRODUCER_CONTRACT["purpose"])
                continue
            self.assertEqual((row["role"], row["expected"]), native.LIFECYCLE[label])
            if row["path"] != "google-key.asc":
                raw = (HERE.parents[1] / row["path"]).read_bytes()
                self.assertEqual(scope.sha(raw), row["sha256"])
                self.assertNotIn(b"PRIVATE KEY", raw)

    def test_native_cases_use_the_actual_positive_scoped_bytes_not_other_expired_subkeys(self):
        captured = {
            "google-key.asc": ORIGINAL,
            "Release": b"data",
            "Release.gpg": b"sig",
            "qualification/p1g_headless/chrome_scope_native_fixtures.json": json.dumps(
                {
                    "schema": "pamolive.chrome-scope-public-negative-fixtures/1",
                    "status": "PENDING",
                    "cases": {},
                }
            ).encode(),
        }
        calls = []

        def refusal(*args):
            calls.append(args[6])
            return {"refused": True, "complete_H1": True}

        with patch.object(native, "verify_refusal", side_effect=refusal):
            self.exercise(
                scope,
                gpg,
                lab_support,
                lambda *args: projected(),
                captured,
                HERE,
                lambda label: (None, None),
                expected_scoped_sha256=scope.sha(projected()),
            )
        self.assertEqual(calls[0], projected())
        for certificate in calls:
            self.assertEqual(set(scope.blocks(certificate)[2]), {scope.SIGNER})
        with self.assertRaisesRegex(ValueError, "native_positive_certificate_changed"):
            self.exercise(
                scope,
                gpg,
                lab_support,
                lambda *args: ORIGINAL,
                captured,
                HERE,
                lambda label: (None, None),
                expected_scoped_sha256=scope.sha(projected()),
            )

    def test_lifecycle_actual_predicates_require_the_observed_native_state(self):
        captured = {"google-key.asc": ORIGINAL, "Release": b"data", "Release.gpg": b"sig"}
        manifest = {
            "schema": "pamolive.chrome-scope-public-negative-fixtures/1",
            "status": "PENDING",
            "cases": {
                "primary_revoked": {
                    "path": "google-key.asc",
                    "sha256": scope.ORIGINAL_SHA256,
                    "primary": scope.PRIMARY,
                    "signer": scope.SIGNER,
                    "role": "primary",
                    "expected": "r",
                }
            },
        }
        captured["qualification/p1g_headless/chrome_scope_native_fixtures.json"] = json.dumps(
            manifest
        ).encode()
        for observed in ("r", "-"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)

                def factory(label):
                    case = root / label
                    case.mkdir()

                    class Lane:
                        def run(self, argv, **kwargs):
                            if "--list-keys" not in argv:
                                return b""
                            rows = listing().decode().splitlines()
                            fields = rows[0].split(":")
                            fields[1] = observed
                            rows[0] = ":".join(fields)
                            return ("\n".join(rows) + "\n").encode()

                    return Lane(), case

                with patch.object(
                    native, "verify_refusal", return_value={"refused": True, "complete_H1": True}
                ):
                    if observed == "r":
                        tested = self.exercise(
                            scope,
                            gpg,
                            lab_support,
                            lambda *args: projected(),
                            captured,
                            root,
                            factory,
                            expected_scoped_sha256=scope.sha(projected()),
                        )
                        self.assertEqual(
                            tested["cases"]["primary_revoked"]["actual_native_selected_state"], "r"
                        )
                        self.assertEqual(tested["state"], "INCOMPLETE")
                    else:
                        with self.assertRaisesRegex(ValueError, "native_fixture_state"):
                            self.exercise(
                                scope,
                                gpg,
                                lab_support,
                                lambda *args: projected(),
                                captured,
                                root,
                                factory,
                                expected_scoped_sha256=scope.sha(projected()),
                            )

    def test_native_BAD_word_in_UID_or_malformed_framing_is_not_crypto_negative(self):
        for raw in (
            status().replace(b"Public Vendor", b"[GNUPG:] BADSIG PRIVATE"),
            b"PRIVATE_UNFRAMED\n[GNUPG:] BADSIG KEY\n",
            b"[GNUPG:] GOODSIG PUBLIC\n",
        ):
            with tempfile.TemporaryDirectory() as directory:
                lane, private, support, _ = self.negative_lane(directory, raw=raw)
                with self.assertRaisesRegex(
                    ValueError,
                    "native_negative_(accepted|not_cryptographic_refusal)|status_framing",
                ):
                    native.verify_refusal(
                        lane,
                        support,
                        boot.read,
                        scope,
                        gpg,
                        private,
                        b"public",
                        b"signature",
                        b"Release",
                        scope.PRIMARY,
                        scope.SIGNER,
                    )


class ConsumerR2Tests(unittest.TestCase):
    def test_R2_export_filter_unavailable_blocks_scoped_import(self):
        commands = FakeCommands()
        original_run = commands.run

        def run(argv, **kwargs):
            if "--export-filter" in argv:
                commands.calls.append((argv, kwargs))
                raise ValueError("command_UNKNOWN")
            return original_run(argv, **kwargs)

        commands.run = run
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "command_UNKNOWN"),
        ):
            KeyScopeTests().authenticate(commands, directory)
        self.assertEqual(len(commands.calls), 3)
        self.assertFalse(any("gnupg-scoped" in argv[3] for argv, _ in commands.calls))

    def test_R2_composed_consumer_real_H1_normal_nonzero_and_revocation_before_publication(self):
        t, buffers, facts, _ = self.setup_fixture()
        support = SimpleNamespace(
            fresh_write=lab_support.fresh_write,
            tool_pin=lambda path: {"sha256": "a" * 64} if isinstance(path, Path) else None,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls, lanes = [], {}

            def factory(label):
                case, public = root / label, root / (label + "-H1")
                case.mkdir()
                public.mkdir()

                def runner(argv, **kw):
                    calls.append((label, argv))
                    kw["on_spawn"](987)
                    output, rc = b"", 0
                    if "--list-keys" in argv:
                        output = t.listing(revoked=label == "signer_revoked")
                    if "--verify" in argv:
                        output = t.valid_status()
                        if label in {"signature_future", "signature_expired"}:
                            future = label == "signature_future"
                            stamp = facts["signature_requests"]["future" if future else "expired"]
                            expiry = 0 if future else stamp + 60
                            prefix = "GOODSIG" if future else "EXPSIG"
                            output = (
                                f"[GNUPG:] {prefix} {t.S[-16:]} TEST_ONLY\n"
                                f"[GNUPG:] VALIDSIG {t.S} 2026-11-16 {stamp} {expiry} "
                                f"4 0 1 8 00 {t.P}\n"
                            ).encode()
                            rc = 0 if future else 1
                            if rc:
                                output += b"[GNUPG:] FAILURE gpg-exit 33554433\n"
                    data = dict(
                        spawn_attempted=True,
                        pid=987,
                        returncode=rc,
                        reason="nonzero_exit" if rc else None,
                        owned_child_reaped=True,
                        drains_complete=True,
                        killed_owned_child=False,
                        exception_type=None,
                        cleanup_exception_type=None,
                        stdout_bytes=len(output),
                        stderr_bytes=0,
                    )
                    if kw.get("stdout_sink") is not None:
                        kw["stdout_sink"].write(output)
                    return SimpleNamespace(
                        **data,
                        ok=rc == 0,
                        stdout=output,
                        stderr=b"",
                        facts=lambda: data,
                    )

                lane = boot.Commands(support, SimpleNamespace(run_capped=runner), case, public)
                lanes[label] = lane
                return lane, case

            with patch.object(native.time, "time", return_value=t.NOW):
                refused, evidence, exported, result = native.consume_producer(
                    lambda: (buffers, facts),
                    scope,
                    gpg,
                    support,
                    boot.read,
                    factory,
                    {"head": "a" * 40},
                )
            self.assertTrue(refused["refused"] and refused["complete_H1"])
            self.assertEqual(refused["actual_native_selected_state"], "r")
            self.assertTrue(evidence["signature_expired"]["UNKNOWN_retained"])
            self.assertTrue(lanes["signature_expired"].unknown)
            self.assertFalse(lanes["signature_future"].unknown)
            self.assertIs(exported, buffers)
            self.assertIs(result, facts)
            self.assertTrue(all("--faked-system-time" not in argv for _, argv in calls))
            self.assertFalse(
                any("--verify" in argv for label, argv in calls if label == "signer_revoked")
            )

    def test_R2_producer_BAD_positive_never_reaches_temporal_or_revocation_consumer(self):
        t, buffers, facts, support = self.setup_fixture()
        calls = []

        class Lane:
            def run(self, argv, **kwargs):
                calls.append(argv)
                if "--list-keys" in argv:
                    return t.listing()
                if "--verify" in argv:
                    return t.valid_status() + b"[GNUPG:] BADSIG TEST_ONLY\n"
                return b""

        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            with (
                patch.object(native.time, "time", return_value=t.NOW),
                self.assertRaisesRegex(ValueError, "status_bad"),
            ):
                native.consume_producer(
                    lambda: (buffers, facts),
                    scope,
                    gpg,
                    SimpleNamespace(tool_pin=support.tool_pin, fresh_write=lab_support.fresh_write),
                    boot.read,
                    lambda label: (Lane(), case),
                    {"head": "a" * 40},
                )
        self.assertEqual(sum("--verify" in argv for argv in calls), 1)

    def setup_fixture(self):
        import test_fixture as t

        from qualification.p1g_headless.gpg_fixture import fixture_contract as c

        buffers = {
            "certificate-before.pgp": t.BEFORE,
            "certificate-revoked.pgp": t.AFTER,
            "message.bin": native.TEST_MESSAGE,
            "signature.sig": b"positive",
            "signature-future.sig": b"future",
            "signature-expired.sig": b"expired",
        }
        # Exercise the actual producer's final contract publication. Its native work
        # is modelled explicitly; these synthetic facts are never native evidence.
        owner = object.__new__(t.o.Owner)
        owner.c, owner.context = c, {"head": "a" * 40}
        owner.prepare = owner.start_agent = owner.shutdown = lambda: None
        owner.fixture = lambda: (buffers, t.P, t.S)
        owner.journal = lambda state: None
        owner.unknown, owner.pending = False, False
        owner.end = native.time.monotonic() + 30
        owner.signature_requests = c.creation_times(t.NOW)
        owner.source_manifest_sha256 = native.PRODUCER_CONTRACT["source_pin"]
        owner.tools = {"/usr/bin/" + name: ("a" * 64, ()) for name in c.TOOLS}
        owner.tools[c.PYTHON] = ("b" * 64, ())
        owner.version, owner.python_version = "2.4.4", "Python 3.12.3"
        owner.records = [t.result().facts()]
        buffers, facts = owner.run()
        support = SimpleNamespace(tool_pin=lambda path: {"sha256": "a" * 64})
        return t, buffers, facts, support

    def test_R2_purpose_same_buffers_cleanup_H1_context_and_pin_required(self):
        import copy

        t, buffers, facts, support = self.setup_fixture()
        self.assertEqual(
            native.producer_inputs(buffers, facts, scope, support, {"head": "a" * 40})[:2],
            (t.P, t.S),
        )
        for key, bad in (
            ("schema", "TEST/1"),
            ("cleanup_complete", False),
            ("unknown", True),
            ("production_authority", True),
            ("source_manifest_sha256", "0" * 64),
            ("context", {}),
            ("primary", scope.PRIMARY),
        ):
            row = copy.deepcopy(facts)
            row[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                native.producer_inputs(buffers, row, scope, support, {"head": "a" * 40})
        for key, bad in (
            ("returncode", True),
            ("returncode", 1),
            ("reason", "timeout"),
            ("drains_complete", False),
            ("owned_child_reaped", False),
            ("killed_owned_child", True),
        ):
            row = copy.deepcopy(facts)
            row["h1"][0][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                native.producer_inputs(buffers, row, scope, support, {"head": "a" * 40})

    def test_R2_six_names_exact_same_bytes_and_aggregate_closed(self):
        t, buffers, facts, support = self.setup_fixture()
        for changed in (
            dict(buffers, extra=b"x"),
            dict(buffers, **{"message.bin": b"other"}),
            dict(buffers, **{"signature.sig": b"different"}),
            dict(buffers, **{"signature.sig": bytearray(b"positive")}),
            dict(buffers, **{"signature.sig": b"x" * 65537}),
        ):
            with self.assertRaises(ValueError):
                native.producer_inputs(changed, facts, scope, support, {"head": "a" * 40})

    def test_R2_public_fact_unknown_secret_keys_and_nested_fields_are_rejected(self):
        import copy

        _, buffers, facts, support = self.setup_fixture()
        variants = []
        row = copy.deepcopy(facts)
        row["SECRET_UID"] = "PRIVATE_CANARY"
        variants.append(row)
        row = copy.deepcopy(facts)
        row["h1"][0]["stderr"] = "PRIVATE_CANARY"
        variants.append(row)
        row = copy.deepcopy(facts)
        row["tools"]["gpg"]["argv"] = "PRIVATE_CANARY"
        variants.append(row)
        row = copy.deepcopy(facts)
        row["python_bootstrap"]["version"] = "PRIVATE_CANARY"
        variants.append(row)
        for row in variants:
            with self.assertRaises(ValueError):
                native.producer_inputs(buffers, row, scope, support, {"head": "a" * 40})

    def test_R2_future_request3600_rejects_old600_and_bool(self):
        import copy

        _, buffers, facts, support = self.setup_fixture()
        for value in (facts["signature_requests"]["anchor"] + 600, True):
            row = copy.deepcopy(facts)
            row["signature_requests"]["future"] = value
            with self.assertRaisesRegex(ValueError, "producer_requested_times"):
                native.producer_inputs(buffers, row, scope, support, {"head": "a" * 40})

    def test_R2_revocation_packet_only_no_substitution_or_duplicate(self):
        _, buffers, facts, support = self.setup_fixture()
        for after in (
            buffers["certificate-before.pgp"],
            buffers["certificate-revoked.pgp"]
            + native.encoded(2, bytes([4, 0x28, 1, 8]) + b"\0" * 6),
        ):
            changed = dict(buffers, **{"certificate-revoked.pgp": after})
            changed_facts = dict(
                facts,
                files={
                    name: {"bytes": len(raw), "sha256": scope.sha(raw)}
                    for name, raw in changed.items()
                },
            )
            with self.assertRaisesRegex(ValueError, "producer_lineage"):
                native.producer_inputs(changed, changed_facts, scope, support, {"head": "a" * 40})

    def temporal(self, label, *, stamp=None, expiry=None, extra=b"", signer=None):
        t, _, facts, _ = self.setup_fixture()
        request = facts["signature_requests"]
        future = label == "signature_future"
        stamp = request["future" if future else "expired"] if stamp is None else stamp
        expiry = (0 if future else stamp + 60) if expiry is None else expiry
        prefix = f"[GNUPG:] {'GOODSIG' if future else 'EXPSIG'} {t.S[-16:]} TEST_ONLY\n"
        raw = (
            prefix
            + f"[GNUPG:] VALIDSIG {signer or t.S} 2026-11-16 {stamp} {expiry} 4 0 1 8 00 {t.P}\n"
        ).encode() + extra
        keys = gpg.one_primary(t.listing(), t.P)
        return native.temporal_refusal(raw, gpg, keys, t.P, t.S, request, label, t.NOW)

    def test_R2_actual_future_status_identity_timestamp_and_unchanged_skew(self):
        proof = self.temporal("signature_future")
        self.assertEqual(proof["guard_code"], "signature_future")
        for kwargs in (
            {"stamp": NOW + 301},
            {"signer": "F" * 40},
            {"expiry": 1},
            {"extra": b"[GNUPG:] BADSIG TEST_ONLY\n"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.temporal("signature_future", **kwargs)

    def test_R2_expired_signature_actual_VALID_required_BAD_never_removed(self):
        proof = self.temporal("signature_expired")
        self.assertEqual(proof["guard_code"], "status_bad")
        self.assertEqual(
            self.temporal("signature_expired", extra=b"[GNUPG:] FAILURE gpg-exit 33554433\n")[
                "guard_code"
            ],
            "status_bad",
        )
        for kwargs in (
            {"expiry": 0},
            {"signer": "F" * 40},
            {"extra": b"[GNUPG:] REVKEYSIG TEST_ONLY\n"},
            {"extra": b"[GNUPG:] NO_PUBKEY TEST_ONLY\n"},
            {"extra": b"[GNUPG:] FAILURE verify 33554433\n"},
            {"extra": b"[GNUPG:] FAILURE gpg-exit 33554434\n"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.temporal("signature_expired", **kwargs)

    def test_R2_evidence_kinds_models_are_not_native_crypto_and_missing_stays_closed(self):
        cases = {k: {"refused": True, "complete_H1": True} for k in native.REQUIRED}
        proof = {
            "purpose": scope.PURPOSE,
            "crypto_verified": True,
            "selected_states_identical": True,
            "scoped_sha256": "a" * 64,
        }
        evidence = {
            k: {"covered": True, "evidence_kind": native.CASE_POLICY[k]}
            for k in native.MATRIX_REQUIRED - native.REQUIRED
        }
        matrix = native.matrix_facts(cases, proof, "a" * 64, evidence=evidence, expired_others=1)
        self.assertTrue(matrix["ADR_evidence_matrix_complete"])
        self.assertFalse(matrix["all_rows_are_native_crypto"])
        del evidence["signature_future"]
        self.assertFalse(
            native.matrix_facts(cases, proof, "a" * 64, evidence=evidence, expired_others=1)[
                "ADR_evidence_matrix_complete"
            ]
        )
        evidence["signature_future"] = {"covered": True, "evidence_kind": "model_only"}
        with self.assertRaisesRegex(ValueError, "matrix_kind"):
            native.matrix_facts(cases, proof, "a" * 64, evidence=evidence, expired_others=1)

    def test_R2_wrong_tuple_models_DATA_and_fresh_original_expired_are_separate(self):
        listed = listing().decode().replace(":0:", f":{NOW + 86400}:").encode()
        original = full_listing().decode().splitlines()
        for i, row in enumerate(original):
            values = row.split(":")
            if values[0] == "sub" and original[i + 1].split(":")[9] != scope.SIGNER:
                values[1] = "e"
                values[6] = str(NOW - 1)
                original[i] = ":".join(values)
        captured = {
            "google-key.asc": ORIGINAL,
            "qualification/p1g_headless/test_chrome_bootstrap.py": b"model source",
            "qualification/p1g_headless/test_chrome_key_scope.py": b"model source",
        }
        evidence, count = native.control_evidence(
            scope,
            gpg,
            status(),
            listed,
            ("\n".join(original) + "\n").encode(),
            captured,
            projected(),
            NOW,
        )
        self.assertEqual(count, 7)
        self.assertFalse(evidence["signature_before_key"]["native_exact_crypto_branch"])
        self.assertEqual(
            evidence["unexpected_key_UID_packet"]["crypto_calls_for_blocked_inputs"], 0
        )
        with self.assertRaisesRegex(ValueError, "matrix_expired_other_not_observed"):
            native.control_evidence(
                scope, gpg, status(), listed, full_listing(), captured, projected(), NOW
            )
