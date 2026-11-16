"""Synthetic metadata/TAR/IO only; never GPG, DEB, sudo, Chrome or SQL."""

import ast
import copy
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from qualification.p1g_headless import chrome_bootstrap as boot
from qualification.p1g_headless import chrome_gpg as gpg
from qualification.p1g_headless import lab_support

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "chrome-bootstrap-pins.json").read_bytes())
NOW = int(datetime(2026, 11, 16, 12, tzinfo=UTC).timestamp())


def listing():
    rows = []
    for kind, fingerprint in (("pub", PINS["primary"]), ("sub", PINS["signer"])):
        values = [
            kind,
            "-",
            "4096",
            "1",
            fingerprint[-16:],
            str(NOW - 1000),
            "0",
            "",
            "",
            "",
            "",
            "sc",
        ]
        rows.append(":".join(values))
        rows.append(":".join(["fpr"] + [""] * 8 + [fingerprint, ""]))
    return ("\n".join(rows) + "\n").encode()


def status():
    return (
        "[GNUPG:] GOODSIG " + PINS["signer"][-16:] + " Public Vendor\n"
        "[GNUPG:] VALIDSIG "
        + PINS["signer"]
        + " 2026-11-16 "
        + str(NOW - 10)
        + " 0 4 0 1 8 00 "
        + PINS["primary"]
        + "\n"
    ).encode()


def tar_payload(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data, mode, uid, kind in entries:
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.uid, item.gid, item.type = len(data), mode, uid, 0, kind
            archive.addfile(item, io.BytesIO(data))
    stream.seek(0)
    return stream


class ChromeBootstrapTests(unittest.TestCase):
    def test_diagnostic_projects_only_known_BAD_names_not_arguments_or_UID(self):
        for code in gpg.BAD:
            raw = status() + ("[GNUPG:] " + code + " PRIVATE_UID_PRIVATE_PAYLOAD\n").encode()
            diagnostic = boot.gpg_status_diagnostic(
                raw, listing(), PINS["primary"], PINS["signer"], NOW
            )
            self.assertEqual(diagnostic["bad_names"], [code])
            self.assertEqual((diagnostic["GOODSIG_count"], diagnostic["VALIDSIG_count"]), (1, 1))
            self.assertTrue(diagnostic["diagnostic_only"])
            self.assertFalse(diagnostic["operational_GO"])
            self.assertNotIn("PRIVATE", json.dumps(diagnostic))
            self.assertNotIn(PINS["primary"], json.dumps(diagnostic))
            with self.assertRaises(ValueError):
                gpg.valid_status(raw, PINS["primary"], PINS["signer"], NOW)

    def test_diagnostic_does_not_attribute_KEYEXPIRED_to_expected_key(self):
        rows = listing().decode().splitlines()
        extra = rows[2].split(":")
        extra[1], extra[6] = "e", str(NOW - 1)
        rows.extend(
            [
                ":".join(extra),
                ":".join(["fpr"] + [""] * 8 + ["F" * 40, ""]),
                "uid:PRIVATE_UID_MUST_NEVER_LEAVE",
            ]
        )
        raw = status() + b"[GNUPG:] KEYEXPIRED 123456 PRIVATE\n"
        diagnostic = boot.gpg_status_diagnostic(
            raw, ("\n".join(rows) + "\n").encode(), PINS["primary"], PINS["signer"], NOW
        )
        self.assertEqual(diagnostic["other_keys"]["observed"], 1)
        self.assertEqual(diagnostic["other_keys"]["expired"], 1)
        self.assertEqual(diagnostic["expected_keys"]["signer"]["expires"], 0)
        self.assertFalse(diagnostic["KEYEXPIRED_attributed_to_specific_key"])
        self.assertNotIn("PRIVATE", json.dumps(diagnostic))
        with self.assertRaises(ValueError):
            gpg.valid_status(raw, PINS["primary"], PINS["signer"], NOW)

    def test_diagnostic_expected_expired_signer_and_duplicate_remain_non_authority(self):
        rows = listing().decode().splitlines()
        key = rows[2].split(":")
        key[1], key[6] = "e", str(NOW - 1)
        rows[2] = ":".join(key)
        raw = ("\n".join(rows) + "\n").encode()
        diagnostic = boot.gpg_status_diagnostic(status(), raw, PINS["primary"], PINS["signer"], NOW)
        self.assertEqual(diagnostic["expected_keys"]["signer"]["validity"], "e")
        self.assertEqual(diagnostic["expected_keys"]["signer"]["expires"], NOW - 1)
        with self.assertRaises(ValueError):
            gpg.signing_capability(
                gpg.one_primary(raw, PINS["primary"]), PINS["primary"], PINS["signer"], NOW
            )
        doubled = listing() + listing()
        diagnostic = boot.gpg_status_diagnostic(
            status(), doubled, PINS["primary"], PINS["signer"], NOW
        )
        self.assertTrue(diagnostic["expected_keys"]["primary"]["seen"])
        self.assertFalse(diagnostic["expected_keys"]["primary"]["unambiguous"])
        self.assertIsNone(diagnostic["expected_keys"]["primary"]["created"])
        with self.assertRaises(ValueError):
            gpg.one_primary(doubled, PINS["primary"])

    def test_diagnostic_malformed_budget_and_unknown_are_bounded_not_success(self):
        for raw in (
            None,
            b"X" * 16385,
            b"\xff",
            b"PRIVATE_UNFRAMED\n",
            b"[GNUPG:] \n",
            b"[GNUPG:] NEW_UNKNOWN PRIVATE\n",
            b"[GNUPG:] X\n" * 1025,
        ):
            diagnostic = boot.gpg_status_diagnostic(
                raw, listing(), PINS["primary"], PINS["signer"], NOW
            )
            self.assertFalse(diagnostic["operational_GO"])
            self.assertTrue(diagnostic["unknown_status_present"])
            self.assertLess(len(json.dumps(diagnostic)), 16384)
            self.assertNotIn("PRIVATE", json.dumps(diagnostic))
        for raw in (None, b"X" * 16385, b"\xff", b"uid:\n" * 1025):
            diagnostic = boot.gpg_status_diagnostic(
                status(), raw, PINS["primary"], PINS["signer"], NOW
            )
            self.assertFalse(diagnostic["listing_parse_complete"])
            self.assertLess(len(json.dumps(diagnostic)), 16384)

    def test_diagnostic_is_written_before_unchanged_guard_in_both_supervisors(self):
        tree = ast.parse((HERE / "chrome_bootstrap.py").read_bytes())
        main = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        diagnostic = next(
            node
            for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "gpg_status_diagnostic"
        )
        scope_tree = ast.parse((HERE / "chrome_key_scope.py").read_bytes())
        authenticate = next(
            n
            for n in scope_tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "authenticate"
        )
        callback = next(
            n
            for n in ast.walk(authenticate)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "diagnostic_sink"
        )
        validation = next(
            n
            for n in ast.walk(authenticate)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "valid_status"
        )
        self.assertLess(callback.lineno, validation.lineno)
        self.assertEqual(
            [n.id for n in validation.args if isinstance(n, ast.Name)],
            ["status", "PRIMARY", "SIGNER", "now"],
        )
        self.assertNotIn("diagnostic[", ast.unparse(main))
        self.assertIn("diagnostic_sink=", ast.unparse(main))
        self.assertIsNotNone(diagnostic)

    def test_actual_controller_bad_signature_or_package_never_reaches_extraction_install(self):
        from qualification.p1g_headless import chrome_key_scope as scope
        from qualification.p1g_headless import chrome_key_scope_native as native
        from qualification.p1g_headless.test_chrome_key_scope import full_listing, projected

        for failure in ("signature", "package", "malformed", "incomplete"):
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                captured = {
                    name: (HERE / "chrome_materials" / name).read_bytes() for name in boot.MATERIALS
                }
                captured.update(
                    {name: b"synthetic source not executed" for name in boot.SOURCE_PATHS}
                )
                captured["qualification/p1g_headless/gpg_fixture/source-pins.json"] = b"model"
                calls = []

                def runner(argv, **kwargs):
                    calls.append(argv)
                    kwargs["on_spawn"](123)
                    output = b""
                    if "--list-keys" in argv:
                        output = full_listing() if "gnupg-original" in argv[3] else listing()
                    if "--export-filter" in argv:
                        output = projected()
                    if "--verify" in argv:
                        output = status() + (
                            b"[GNUPG:] BADSIG PRIVATE\n" if failure == "signature" else b""
                        )
                    if "--verify" in argv and failure == "malformed":
                        output = b"UNFRAMED PRIVATE UID OUTPUT\n"
                    if argv[0] == "/usr/bin/curl":
                        kwargs["stdout_sink"].write(b"SYNTHETIC_INVALID_PACKAGE_BYTES")
                    return SimpleNamespace(
                        ok=True,
                        spawn_attempted=True,
                        pid=123,
                        returncode=0,
                        reason=None,
                        owned_child_reaped=True,
                        drains_complete=True,
                        killed_owned_child=False,
                        exception_type=None,
                        cleanup_exception_type=None,
                        stdout=output,
                        stderr=b"PRIVATE_OUTPUT_NOT_EXPORTED",
                        facts=lambda: {"pid": 123, "returncode": 0},
                    )

                support = SimpleNamespace(
                    guard=lambda *args, **kwargs: None,
                    resources=lambda path: {},
                    source_binding=lambda *args: {},
                    bounded=lambda root: SimpleNamespace(run_capped=runner),
                    tool_pin=lambda path: {"sha256": "a" * 64},
                    fresh_write=lab_support.fresh_write,
                )
                captured["qualification/p1g_headless/chrome_scope_native_fixtures.json"] = (
                    json.dumps({"cases": {label: {} for label in native.LIFECYCLE}}).encode()
                )
                native_model = SimpleNamespace(
                    LIFECYCLE=native.LIFECYCLE,
                    PRODUCER_CONTRACT={
                        **native.PRODUCER_CONTRACT,
                        "source_pin": boot.sha(b"model"),
                    },
                    REQUIRED=native.REQUIRED,
                    RECEIPT_SCHEMA=native.RECEIPT_SCHEMA,
                    MATRIX_REQUIRED=native.MATRIX_REQUIRED,
                    SOURCE_MATRIX_IMPLEMENTED=native.MATRIX_REQUIRED,
                    exercise=lambda *args, **kwargs: {
                        "schema": native.RECEIPT_SCHEMA,
                        "matrix_required": sorted(native.MATRIX_REQUIRED),
                        "matrix_completed": sorted(native.MATRIX_REQUIRED),
                        "matrix_missing": [],
                        "source_unimplemented": [],
                        "ADR_evidence_matrix_complete": True,
                        "all_rows_are_native_crypto": False,
                        "producer_contract": native.PRODUCER_CONTRACT["purpose"],
                        "producer_source_connected": True,
                        "other_expired_keys_freshly_observed": 5,
                        "state": "COMPLETE",
                        "missing": ["signer_revoked"] if failure == "incomplete" else [],
                        "cases": {
                            k: {"refused": True, "complete_H1": True} for k in native.REQUIRED
                        },
                        "purpose": scope.PURPOSE,
                        "operational_GO": False,
                    },
                )
                env = {
                    "GITHUB_ACTIONS": "true",
                    "RUNNER_TEMP": str(base),
                    "GITHUB_SHA": "a" * 40,
                    "GITHUB_RUN_ID": "123",
                    "GITHUB_RUN_ATTEMPT": "1",
                }
                with (
                    patch.object(boot.sys, "platform", "linux"),
                    patch.object(boot, "ROOT", base / "p1g-source"),
                    patch.object(boot.os, "getuid", return_value=1001, create=True),
                    patch.object(boot.os, "umask", return_value=0),
                    patch.dict(boot.os.environ, env),
                    patch.object(boot.time, "time", return_value=NOW),
                    patch.object(scope.time, "time", return_value=NOW),
                    patch.object(boot, "context", return_value=(PINS, captured)),
                    patch.object(
                        boot,
                        "load",
                        side_effect=[
                            support,
                            gpg,
                            scope,
                            native_model,
                            SimpleNamespace(
                                modules=lambda pin: (
                                    {
                                        "fixture_contract": SimpleNamespace(
                                            ci_context=lambda env: {}
                                        )
                                    },
                                    {},
                                )
                            ),
                        ],
                    ),
                ):
                    self.assertEqual(
                        boot.main(["--pins-sha", "f" * 64, "--native-scope-preflight-required"]), 42
                    )
                packet = json.loads((base / "p1g-headless-123-1-chrome/UNKNOWN.json").read_bytes())
                self.assertEqual(
                    packet["code"],
                    {
                        "signature": "status_bad",
                        "package": "package_bytes",
                        "malformed": "status_framing",
                        "incomplete": "scope_native_preflight_incomplete",
                    }[failure],
                )
                self.assertTrue(
                    all(
                        "dpkg" not in argv[0] and "apt-get" not in argv[0] and "sudo" not in argv[0]
                        for argv in calls
                    )
                )
                diagnostic_path = (
                    base / "p1g-headless-123-1-chrome/frontend/gpg-status-diagnostic.json"
                )
                diagnostic = json.loads(diagnostic_path.read_bytes())
                self.assertTrue(diagnostic["diagnostic_only"])
                self.assertFalse(diagnostic["operational_GO"])
                self.assertNotIn("PRIVATE", json.dumps(diagnostic))
                if failure in {"signature", "malformed", "incomplete"}:
                    self.assertTrue(all(argv[0] != "/usr/bin/curl" for argv in calls))
                self.assertNotIn("PRIVATE", json.dumps(packet))

    def test_received_metadata_has_exact_stanza_and_seven_day_freshness(self):
        release = (HERE / "chrome_materials/Release").read_bytes()
        packages = (HERE / "chrome_materials/Packages").read_bytes()
        timestamp = boot.release_check(release, packages, NOW)
        boot.package_check(packages, PINS["package"])
        self.assertEqual(boot.release_check(release, packages, timestamp + 604800), timestamp)
        self.assertEqual(boot.release_check(release, packages, timestamp - 300), timestamp)
        for now in (timestamp + 604801, timestamp - 301):
            with self.assertRaisesRegex(ValueError, "freshness"):
                boot.release_check(release, packages, now)
        with self.assertRaises(ValueError):
            boot.release_check(release, b"changed", NOW)

    def test_wrong_or_duplicate_package_path_version_arch_refuses(self):
        raw = (HERE / "chrome_materials/Packages").read_bytes()
        expected = PINS["package"]
        for field, wrong in (
            ("Version", "current"),
            ("Architecture", "arm64"),
            ("Filename", "../private.deb"),
            ("Size", "0"),
            ("SHA256", "f" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                boot.package_check(raw, {**expected, field: wrong})
        with self.assertRaises(ValueError):
            boot.package_check(raw + b"\n\n" + raw, expected)
        with self.assertRaises(ValueError):
            boot.fields(b"Package: a\nPackage: b\n")

    def test_strict_primary_signer_status_and_bad_flags(self):
        verified = gpg.valid_status(status(), PINS["primary"], PINS["signer"], NOW)
        keys = gpg.one_primary(listing(), PINS["primary"])
        gpg.signing_capability(keys, PINS["primary"], PINS["signer"], NOW, verified["timestamp"])
        for raw in (
            status().replace(PINS["primary"].encode(), b"F" * 40),
            status().replace(PINS["signer"].encode(), b"F" * 40),
            status() + status(),
        ):
            with self.assertRaises(ValueError):
                gpg.valid_status(raw, PINS["primary"], PINS["signer"], NOW)
        for code in gpg.BAD:
            with self.subTest(code=code), self.assertRaises(ValueError):
                gpg.valid_status(
                    status() + ("[GNUPG:] " + code + " PRIVATE\n").encode(),
                    PINS["primary"],
                    PINS["signer"],
                    NOW,
                )

    def test_revoked_expired_future_unsigned_binding_and_wrong_primary_refuse(self):
        keys = gpg.one_primary(listing(), PINS["primary"])
        for field, wrong in (
            ("validity", "r"),
            ("validity", "e"),
            ("caps", "c"),
            ("caps", "sD"),
            ("expires", str(NOW - 1)),
            ("created", str(NOW + 301)),
        ):
            bad = copy.deepcopy(keys)
            bad[PINS["signer"]][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                gpg.signing_capability(bad, PINS["primary"], PINS["signer"], NOW)
        with self.assertRaises(ValueError):
            gpg.one_primary(listing(), "F" * 40)
        with self.assertRaises(ValueError):
            gpg.one_primary(listing() + listing(), PINS["primary"])

    def test_payload_regular_root_0755_exact_ELF_and_duplicate_refuse(self):
        entry = ("./opt/google/chrome/chrome", b"\x7fELFsynthetic-only", 0o755, 0, tarfile.REGTYPE)
        result = boot.payload_target(tar_payload([entry]))
        self.assertEqual(result["sha256"], hashlib.sha256(entry[1]).hexdigest())
        for bad in (
            [entry, entry],
            [(entry[0], entry[1], 0o777, 0, tarfile.REGTYPE)],
            [(entry[0], entry[1], 0o755, 1000, tarfile.REGTYPE)],
            [(entry[0], b"text", 0o755, 0, tarfile.REGTYPE)],
            [("../escape", b"x", 0o755, 0, tarfile.REGTYPE)],
            [(entry[0], b"", 0o755, 0, tarfile.SYMTYPE)],
        ):
            with self.assertRaises(ValueError):
                boot.payload_target(tar_payload(bad))

    def test_control_and_APT_plan_require_no_dependency_or_removal_actions(self):
        expected = PINS["package"]
        raw = "\n".join(
            key + ": " + expected[key] for key in ("Package", "Version", "Architecture", "Depends")
        ).encode()
        boot.control_check(raw, expected)
        with self.assertRaises(ValueError):
            boot.control_check(
                raw.replace(b"Architecture: amd64", b"Architecture: arm64"), expected
            )
        good = (
            b"Inst google-chrome-stable [old] (pinned local [amd64])\n"
            b"Conf google-chrome-stable (pinned local [amd64])\n"
        )
        boot.apt_plan(good)
        for bad in (
            good + b"Inst dependency (new)\n",
            good + b"Remv other\n",
            b"Conf google-chrome-stable\n",
        ):
            with self.assertRaises(ValueError):
                boot.apt_plan(bad)
        self.assertTrue({"--no-download", "--no-remove", "--reinstall"} <= set(boot.APT))
        self.assertNotIn("--fix-broken", boot.APT)

    def test_source_manifest_receipt_external_pin_precedes_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pins = copy.deepcopy(PINS)
            files = {}
            for name in boot.SOURCE_PATHS | boot.TEST_PATHS:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic source not executed")
                selected = pins["source_files"] if name in boot.SOURCE_PATHS else pins["test_files"]
                selected[name] = files[name] = boot.sha(path.read_bytes())
            for name, item in pins["files"].items():
                relative = "qualification/p1g_headless/chrome_materials/" + name
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((HERE / "chrome_materials" / name).read_bytes())
                files[relative] = item["sha256"]
            path = root / boot.PIN_PATH
            raw = json.dumps(pins).encode()
            path.write_bytes(raw)
            digest = files[boot.PIN_PATH] = boot.sha(raw)
            receipt = root / "receipt.json"
            receipt.write_text(
                json.dumps(
                    {
                        "schema": "pamolive.committed-build-context.v1",
                        "revision": "a" * 40,
                        "files": files,
                    }
                ),
                encoding="utf8",
            )
            boot.context(root, receipt, digest, "a" * 40)
            path.write_bytes(b" " + raw)
            with self.assertRaisesRegex(ValueError, "external_manifest_pin"):
                boot.context(root, receipt, digest, "a" * 40)

    def test_real_command_H1_pending_before_spawn_and_UNKNOWN_sticky(self):
        for field, bad in (
            (None, None),
            ("returncode", 2),
            ("returncode", False),
            ("drains_complete", False),
            ("owned_child_reaped", False),
            ("killed_owned_child", True),
            ("cleanup_exception_type", "OSError"),
        ):
            with tempfile.TemporaryDirectory() as directory:
                private, public = Path(directory) / "private", Path(directory) / "public"
                private.mkdir()
                public.mkdir()
                data = dict(
                    ok=True,
                    spawn_attempted=True,
                    pid=123,
                    returncode=0,
                    reason=None,
                    owned_child_reaped=True,
                    drains_complete=True,
                    killed_owned_child=False,
                    exception_type=None,
                    cleanup_exception_type=None,
                    stdout=b"public",
                    stderr=b"PRIVATE",
                    facts=lambda: {"pid": 123, "returncode": 0},
                )
                if field:
                    data[field] = bad

                def runner(argv, **kwargs):
                    self.assertEqual(
                        json.loads((public / "command-1/intent.json").read_bytes())["state"],
                        "PENDING",
                    )
                    self.assertEqual(kwargs["env"]["HOME"], str(private))
                    self.assertTrue(kwargs["owned_session"])
                    self.assertEqual(kwargs["timeout"] - kwargs["work_timeout"], 10)
                    kwargs["on_spawn"](123)
                    return SimpleNamespace(**data)

                with patch.object(lab_support, "tool_pin", return_value={"sha256": "a" * 64}):
                    commands = boot.Commands(
                        lab_support, SimpleNamespace(run_capped=runner), private, public
                    )
                    if field:
                        with self.assertRaises(ValueError):
                            commands.run(["/usr/bin/gpg", "synthetic"])
                        self.assertTrue(commands.unknown)
                        with self.assertRaisesRegex(ValueError, "previous_UNKNOWN"):
                            commands.run(["/usr/bin/gpg", "next"])
                    else:
                        self.assertEqual(commands.run(["/usr/bin/gpg", "synthetic"]), b"public")
                        self.assertNotIn(
                            b"PRIVATE",
                            b"".join(path.read_bytes() for path in public.rglob("*.json")),
                        )

    def test_controller_authentication_precedes_package_tools_and_no_guard_changes(self):
        tree = ast.parse((HERE / "chrome_bootstrap.py").read_bytes())
        main = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        statuses = [
            node.lineno
            for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "authenticate"
        ]
        extractions = [
            node.lineno
            for node in ast.walk(main)
            if isinstance(node, ast.Constant) and node.value == "--fsys-tarfile"
        ]
        installs = [
            node.lineno
            for node in ast.walk(main)
            if isinstance(node, ast.Constant) and node.value == "--assume-yes"
        ]
        self.assertTrue(statuses and min(statuses) < min(extractions) < min(installs))
        body = ast.unparse(tree)
        for prohibited in (
            "--no-sandbox",
            "--fix-broken",
            "--allow-downgrades",
            "ignore_https_errors",
            "--location",
            "--keyserver",
        ):
            self.assertNotIn(prohibited, body)
        self.assertNotIn("TARGET.chmod", body)
        self.assertIn("support.tool_pin(TARGET)", body)


if __name__ == "__main__":
    unittest.main()
