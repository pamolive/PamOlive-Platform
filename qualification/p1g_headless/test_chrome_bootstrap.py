"""Synthetic metadata/TAR/IO only; never GPG, DEB, sudo, Chrome or SQL."""

import ast
import copy
import hashlib
import io
import json
import stat
import tarfile
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

from qualification.p1g_headless import chrome_bootstrap as boot
from qualification.p1g_headless import chrome_gpg as gpg
from qualification.p1g_headless import lab_support

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "chrome-bootstrap-pins.json").read_bytes())
NOW = int(datetime(2026, 11, 16, 12, tzinfo=UTC).timestamp())
OBSERVED_METADATA_TIME = int(datetime(2026, 11, 23, 12, tzinfo=UTC).timestamp())


class PublicJournalTests(unittest.TestCase):
    def scenario(self, mask=0o077, *, swap=False, owner=0, chmod_error=False):
        state = {"mode": 0, "uid": owner, "ino": 2, "closed": [], "chmods": []}

        def row():
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | state["mode"],
                st_uid=state["uid"],
                st_dev=1,
                st_ino=state["ino"],
            )

        def mkdir(*, mode):
            state["mode"] = mode & ~mask

        def fchmod(fd, mode):
            state["chmods"].append((fd, mode))
            if chmod_error:
                raise PermissionError("synthetic")
            state["mode"] = mode

        def opened(path, flags):
            self.assertEqual(flags, 1 | 2 | 4 | 8)
            if swap:
                state["ino"] = 3
            return 10

        path = SimpleNamespace(mkdir=mkdir, lstat=row)
        ops = SimpleNamespace(
            O_RDONLY=1,
            O_DIRECTORY=2,
            O_NOFOLLOW=4,
            O_CLOEXEC=8,
            open=opened,
            fstat=lambda fd: row(),
            fchmod=fchmod,
            close=lambda fd: state["closed"].append(fd),
            geteuid=lambda: 0,
        )
        with patch.object(boot, "os", ops):
            boot.public_journal_directory(path)
        return state

    def test_public_directory_explicit_mode_overcomes_private_umask(self):
        for mask in (0o077, 0o027, 0o000):
            state = self.scenario(mask)
            self.assertEqual(state["mode"], 0o755)
            self.assertEqual(state["closed"], [10])
            self.assertEqual(state["chmods"], [(10, 0o755)])

    def test_alias_owner_and_chmod_failure_refuse(self):
        for options in ({"swap": True}, {"owner": 1000}, {"chmod_error": True}):
            with self.subTest(options=options), self.assertRaises((ValueError, PermissionError)):
                self.scenario(**options)
        path = SimpleNamespace(mkdir=lambda **kw: (_ for _ in ()).throw(FileExistsError()))
        with patch.object(boot.os, "open") as opened, self.assertRaises(FileExistsError):
            boot.public_journal_directory(path)
        opened.assert_not_called()

    def test_only_two_public_journal_sites_use_the_mode_helper(self):
        tree = ast.parse((HERE / "chrome_bootstrap.py").read_bytes())
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "public_journal_directory"
        ]
        self.assertEqual(
            sorted(ast.unparse(node.args[0]) for node in calls), ["command_public", "journal"]
        )
        main = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        self.assertNotIn("chmod(0o755)", ast.unparse(main))


class RootInterpreterTests(unittest.TestCase):
    """The system interpreter is modeled; never executed/read on this host."""

    def setUp(self):
        self.values = (1, 22, 0o100755, 0, 0, 1, 4096, 23, 24)
        self.context = b"synthetic source context only"
        self.bindings = {
            "context_sha": boot.sha(self.context),
            "pins_sha": "b" * 64,
            "source_sha": "c" * 64,
            "revision": "d" * 40,
        }
        self.support = SimpleNamespace(tool_pin=lambda path: self.tool(path))

    def row(self, values=None):
        return SimpleNamespace(
            **dict(
                zip(
                    (
                        "st_dev",
                        "st_ino",
                        "st_mode",
                        "st_uid",
                        "st_gid",
                        "st_nlink",
                        "st_size",
                        "st_mtime_ns",
                        "st_ctime_ns",
                    ),
                    self.values if values is None else values,
                    strict=True,
                )
            )
        )

    def tool(self, path):
        self.assertEqual(path.as_posix(), boot.ROOT_INTERPRETER)
        return {"sha256": "a" * 64, "bytes": 4096, "uid": 0, "mode": 0o755}

    def role(self):
        return {
            "path": boot.ROOT_INTERPRETER,
            "pin": self.tool(Path(boot.ROOT_INTERPRETER)),
            "identity": list(self.values),
        }

    def runtime(self, *, sys_changes=None, uid=0, euid=0, running=None):
        proxy = SimpleNamespace(
            executable=boot.ROOT_INTERPRETER,
            platform="linux",
            version_info=SimpleNamespace(
                major=3, minor=12, micro=3, releaselevel="final", serial=0
            ),
            implementation=SimpleNamespace(name="cpython", cache_tag="cpython-312"),
            flags=SimpleNamespace(**boot.ROOT_FLAGS),
        )
        for name, value in (sys_changes or {}).items():
            setattr(proxy, name, value)
        os_proxy = SimpleNamespace(
            getuid=lambda: uid, geteuid=lambda: euid, stat=lambda path: self.proc(path, running)
        )
        with (
            patch.object(boot, "sys", proxy),
            patch.object(boot, "os", os_proxy),
            patch.object(boot.Path, "lstat", return_value=self.row()),
        ):
            return boot.root_interpreter_runtime(self.support, **self.bindings)

    def proc(self, path, values):
        self.assertEqual(path, "/proc/self/exe")
        if isinstance(values, BaseException):
            raise values
        return self.row(values)

    def receipt(self):
        return {
            "schema": boot.INSTALLED_SCHEMA,
            "state": "INSTALLED_AUTHENTICATED_PACKAGE_ONLY",
            "package_sha256": PINS["package"]["SHA256"],
            "package_version": PINS["package"]["Version"],
            "revision": self.bindings["revision"],
            "pins_manifest_sha256": self.bindings["pins_sha"],
            "context_receipt_sha256": self.bindings["context_sha"],
            "target": {"sha256": "e" * 64},
            "signature": {},
            "key_scope": {"scope": "model"},
            "root_interpreter": self.runtime(),
            "all_OS_descendants_released": False,
            "browser_executed": False,
            "operational_GO": False,
        }

    def handoff(self, receipt, *, roles=None, until=1000):
        trace = []
        role_values = iter(roles or [self.role(), self.role()])

        def pin(support):
            self.assertIs(support, self.support)
            trace.append("python_pin")
            value = next(role_values)
            if isinstance(value, BaseException):
                raise value
            return value

        def read(path, cap):
            if path.name == "p1g-source.json":
                self.assertEqual(cap, 4 * 1024**2)
                trace.append("context")
                return self.context
            self.assertEqual(path.name, "installed.json")
            self.assertEqual(cap, 32768)
            trace.append("receipt")
            return json.dumps(receipt).encode()

        def run(argv, **kwargs):
            trace.append("sudo")
            self.assertEqual(
                argv,
                [
                    "/usr/bin/sudo",
                    "-n",
                    "--preserve-env=" + boot.PRESERVE,
                    "--",
                    "/usr/bin/python3.12",
                    "-I",
                    "-B",
                    "-S",
                    str(boot.HERE / "chrome_bootstrap.py"),
                    "--pins-sha",
                    self.bindings["pins_sha"],
                    "--root-install",
                    "--native-scope-preflight-required",
                ],
            )
            self.assertEqual(kwargs, {"seconds": 480, "sudo": True})
            return b"public output is not receipt authority"

        commands = SimpleNamespace(run=run, until=until)
        with (
            patch.object(boot, "root_interpreter_pin", pin),
            patch.object(boot, "read", read),
            patch.object(
                boot.os, "environ", {"RUNNER_TEMP": "/tmp", "GITHUB_SHA": self.bindings["revision"]}
            ),
            patch.object(boot.sys, "executable", "/frontend-venv/python"),
            patch.object(boot.time, "monotonic", return_value=100),
        ):
            result = boot.root_supervisor(
                commands,
                self.support,
                Path("/public"),
                PINS,
                self.bindings["pins_sha"],
                {"sha256": "e" * 64},
                {"scope": "model"},
                self.bindings["source_sha"],
                {},
            )
        return result, trace

    def test_R6_fixed_role_passes_unchanged_guard_without_resolving_frontend(self):
        with (
            patch.object(boot.Path, "lstat", return_value=self.row()),
            patch.object(boot.Path, "resolve", side_effect=AssertionError("no caller resolve")),
            patch.object(boot.sys, "executable", "/untrusted/venv/python"),
        ):
            self.assertEqual(boot.root_interpreter_pin(self.support), self.role())

    def test_R6_original_guard_alias_permission_missing_refusals_propagate(self):
        for error in (
            ValueError("tool_alias_refused"),
            PermissionError(13, "PRIVATE"),
            FileNotFoundError("PRIVATE"),
        ):
            with self.subTest(error=type(error).__name__):
                guard = unittest.mock.Mock(side_effect=error)
                with patch.object(boot.Path, "lstat", return_value=self.row()):
                    with self.assertRaises(type(error)):
                        boot.root_interpreter_pin(SimpleNamespace(tool_pin=guard))
                self.assertEqual(guard.call_args.args[0].as_posix(), boot.ROOT_INTERPRETER)
                self.assertEqual(guard.call_args.kwargs, {})

    def test_R6_root_leaf_identity_and_pin_values_are_strict(self):
        for index, value in (
            (2, 0o120777),
            (2, 0o100777),
            (2, 0o104755),
            (3, 1001),
            (5, 2),
            (6, 0),
            (1, True),
        ):
            values = list(self.values)
            values[index] = value
            with (
                self.subTest(index=index, value=value),
                patch.object(boot.Path, "lstat", return_value=self.row(values)),
            ):
                with self.assertRaises(ValueError):
                    boot.root_interpreter_pin(self.support)
        for field, value in (
            ("sha256", "not hash"),
            ("bytes", 4097),
            ("bytes", True),
            ("mode", 0o777),
            ("uid", False),
        ):
            pin = self.tool(Path(boot.ROOT_INTERPRETER)) | {field: value}
            with (
                self.subTest(field=field),
                patch.object(boot.Path, "lstat", return_value=self.row()),
            ):
                with self.assertRaises(ValueError):
                    boot.root_interpreter_pin(SimpleNamespace(tool_pin=lambda path: pin))

    def test_R6_leaf_changed_during_original_hash_cannot_be_a_pin(self):
        changed = list(self.values)
        changed[1] += 1
        with patch.object(boot.Path, "lstat", side_effect=[self.row(), self.row(changed)]):
            with self.assertRaisesRegex(ValueError, "changed"):
                boot.root_interpreter_pin(self.support)

    def test_R6_system_micro_is_observed_not_frontend_31216(self):
        for micro in (3, 16, 17):
            facts = self.runtime(
                sys_changes={
                    "version_info": SimpleNamespace(
                        major=3, minor=12, micro=micro, releaselevel="final", serial=0
                    )
                }
            )
            self.assertEqual(facts["version"]["micro"], micro)
            self.assertEqual(facts["path"], "/usr/bin/python3.12")
            self.assertFalse(facts["stdlib_loader_hermeticity_verified"])

    def test_R6_real_effective_UID_and_exact_running_path_precede_tool_access(self):
        for uid, euid, executable in (
            (1001, 0, boot.ROOT_INTERPRETER),
            (0, 1001, boot.ROOT_INTERPRETER),
            (False, 0, boot.ROOT_INTERPRETER),
            (0, 0, "/usr/bin/python3"),
            (0, 0, "/venv/python"),
        ):
            with self.subTest(uid=uid, euid=euid, executable=executable):
                with self.assertRaisesRegex(ValueError, "runtime"):
                    self.runtime(sys_changes={"executable": executable}, uid=uid, euid=euid)

    def test_R6_real_process_image_stat_mismatch_or_failure_is_not_attested(self):
        changed = list(self.values)
        changed[1] += 1
        for running in (changed, PermissionError(13, "PRIVATE"), FileNotFoundError("PRIVATE")):
            with self.subTest(running=type(running).__name__):
                with self.assertRaises((ValueError, OSError)):
                    self.runtime(running=running)

    def test_R6_runtime_wrong_version_implementation_and_isolation_refuse(self):
        cases = [
            {
                "version_info": SimpleNamespace(
                    major=3, minor=14, micro=0, releaselevel="final", serial=0
                )
            },
            {
                "version_info": SimpleNamespace(
                    major=3, minor=12, micro=True, releaselevel="final", serial=0
                )
            },
            {
                "version_info": SimpleNamespace(
                    major=3, minor=12, micro=3, releaselevel="candidate", serial=1
                )
            },
            {"implementation": SimpleNamespace(name="pypy", cache_tag="pypy-312")},
            {"flags": SimpleNamespace(**(boot.ROOT_FLAGS | {"no_site": 0}))},
            {"flags": SimpleNamespace(**(boot.ROOT_FLAGS | {"isolated": True}))},
            {"flags": SimpleNamespace(**(boot.ROOT_FLAGS | {"safe_path": 1}))},
        ]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.runtime(sys_changes=change)

    def test_R6_real_parent_handoff_selects_system_role_and_checks_before_after(self):
        receipt = self.receipt()
        actual, trace = self.handoff(receipt)
        self.assertEqual(actual, receipt)
        self.assertEqual(trace, ["python_pin", "context", "sudo", "python_pin", "receipt"])

    def test_R6_before_pin_refusal_never_launches_sudo(self):
        receipt = self.receipt()
        with self.assertRaisesRegex(ValueError, "tool_alias"):
            self.handoff(receipt, roles=[ValueError("tool_alias_refused")])

    def test_R6_after_success_pin_hash_or_inode_change_is_not_healed(self):
        receipt = self.receipt()
        for field in ("hash", "inode"):
            changed = self.role()
            if field == "hash":
                changed["pin"]["sha256"] = "f" * 64
            else:
                changed["identity"][1] += 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "changed"):
                self.handoff(receipt, roles=[self.role(), changed])

    def test_R6_old_optional_missing_extra_and_false_authority_receipts_refuse(self):
        receipt = self.receipt()
        cases = [
            receipt | {"schema": "pamolive.chrome-bootstrap/1"},
            {key: value for key, value in receipt.items() if key != "root_interpreter"},
            receipt | {"root_interpreter": None},
            receipt | {"extra": "PRIVATE"},
            receipt | {"operational_GO": True},
            receipt | {"context_receipt_sha256": "f" * 64},
        ]
        for value in cases:
            with self.subTest(keys=list(value)), self.assertRaises((ValueError, TypeError)):
                self.handoff(value)

    def test_R6_proof_version_source_flags_metadata_and_nested_fields_are_closed(self):
        receipt = self.receipt()
        for name, value in (
            ("schema", "old/1"),
            ("path", "/usr/bin/python3"),
            ("context_receipt_sha256", "f" * 64),
            ("bootstrap_source_sha256", "f" * 64),
            ("pins_manifest_sha256", "f" * 64),
            ("revision", "f" * 40),
            ("real_uid", False),
            ("effective_uid", 1001),
            ("flags", boot.ROOT_FLAGS | {"site_loaded": False}),
            ("stdlib_loader_hermeticity_verified", True),
        ):
            value_receipt = copy.deepcopy(receipt)
            value_receipt["root_interpreter"][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.handoff(value_receipt)
        for name in ("identity", "running_identity"):
            value = copy.deepcopy(receipt)
            value["root_interpreter"][name][0] = True
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.handoff(value)

    def test_R6_parent_deadline_is_not_extended_by_role_checks(self):
        with self.assertRaisesRegex(ValueError, "deadline"):
            self.handoff(self.receipt(), until=99)

    def test_R6_main_checks_runtime_before_authentication_and_after_install_before_receipt(self):
        tree = ast.parse((HERE / "chrome_bootstrap.py").read_bytes())
        main = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        runtime_calls = sorted(
            node.lineno
            for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "root_interpreter_runtime"
        )
        authenticate = next(
            node.lineno
            for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "authenticate"
        )
        self.assertEqual(len(runtime_calls), 2)
        self.assertLess(runtime_calls[0], authenticate)
        writer = max(
            node.lineno
            for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "fresh_write"
        )
        self.assertLess(runtime_calls[1], writer)
        self.assertNotIn("Path(sys.executable)", ast.unparse(main))


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
    def setUp(self):
        # Filesystem permission semantics are exercised by PublicJournalTests.
        # These crypto/H1 cases keep their existing synthetic filesystem seam.
        self.enterContext(
            patch.object(
                boot, "public_journal_directory", side_effect=lambda path: path.mkdir(mode=0o700)
            )
        )

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
                    patch.object(boot.time, "time", return_value=OBSERVED_METADATA_TIME),
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
        timestamp = boot.release_check(release, packages, OBSERVED_METADATA_TIME)
        boot.package_check(packages, PINS["package"])
        self.assertEqual(boot.release_check(release, packages, timestamp + 604800), timestamp)
        self.assertEqual(boot.release_check(release, packages, timestamp - 300), timestamp)
        for now in (timestamp + 604801, timestamp - 301):
            with self.assertRaisesRegex(ValueError, "freshness"):
                boot.release_check(release, packages, now)
        with self.assertRaises(ValueError):
            boot.release_check(release, b"changed", OBSERVED_METADATA_TIME)

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


class AptFailureDiagnosticTests(unittest.TestCase):
    def result(self, **changes):
        row = dict(
            ok=False,
            spawn_attempted=True,
            pid=123,
            returncode=100,
            reason="nonzero_exit",
            owned_child_reaped=True,
            drains_complete=True,
            killed_owned_child=False,
            exception_type=None,
            cleanup_exception_type=None,
            stdout=b"PRIVATE stdout",
            stderr=b"PRIVATE stderr",
            facts=lambda: {"returncode": 100, "reason": "nonzero_exit"},
        )
        row.update(changes)
        return SimpleNamespace(**row)

    def command(self, result, *, failures=(), role="root-local-exact-install", argv=None):
        writes, calls = [], []
        private = PurePosixPath("/var/tmp/pamolive-chrome-bootstrap-123-1")
        public = Path("public-synthetic")

        def write(path, body, **kwargs):
            writes.append((path.name, body, kwargs.get("mode")))
            if path.name in failures:
                raise PermissionError("PRIVATE SECONDARY WRITE")

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return result

        support = SimpleNamespace(tool_pin=lambda path: {"sha256": "a" * 64}, fresh_write=write)
        args = argv if argv is not None else boot.root_apt_argv(private, action="--assume-yes")
        with (
            patch.object(boot, "public_journal_directory"),
            patch.object(boot.os, "getuid", return_value=0, create=True),
            patch.object(boot.os, "geteuid", return_value=0, create=True),
        ):
            command = boot.Commands(support, SimpleNamespace(run_capped=runner), private, public)
            try:
                command.run(args, seconds=180, diagnostic_role=role)
            except BaseException as error:
                caught = error
            else:
                caught = None
            return command, caught, writes, calls

    def test_R8_finite_markers_counts_hashes_never_export_private_bytes(self):
        samples = {
            "no-download": b"Unable to fetch some archives",
            "cache": b"The package lists or status file could not be parsed or opened.",
            "localaccess": b"Could not open file PRIVATE/path",
            "missingdeps": b"Unmet dependencies.",
            "downgrade": b"Packages were downgraded and -y was used",
            "dpkg-lock": b"Unable to acquire the dpkg frontend lock PRIVATE",
            "dpkg-maintainer": b"script subprocess returned error exit status 1",
            "interrupted": b"dpkg was interrupted, you must manually",
        }
        for kind, sample in samples.items():
            with self.subTest(kind=kind):
                data = sample + b" PRIVATE ::error::token=secret\x00\xff\n"
                packet = boot.apt_failure_diagnostic(self.result(stderr=data))
                self.assertEqual(packet["completion"], "NORMAL_NONZERO100")
                self.assertEqual(packet["marker_counts"][kind], 1)
                self.assertEqual(packet["streams"]["stderr"]["sha256"], boot.sha(data))
                self.assertEqual(packet["streams"]["stderr"]["bytes"], len(data))
                self.assertEqual(packet["root_cause"], "UNKNOWN")
                self.assertFalse(packet["installation_verified"])
                self.assertNotIn("PRIVATE", json.dumps(packet))
                self.assertNotIn("::error::", json.dumps(packet))
                self.assertFalse(packet["operational_GO"])

    def test_R8_unknown_H1_and_typed_buffer_limits_never_classify_as_normal(self):
        for changes in (
            {"returncode": True},
            {"pid": True},
            {"reason": "PRIVATE"},
            {"reason": "timeout"},
            {"owned_child_reaped": False},
            {"drains_complete": False},
            {"killed_owned_child": True},
            {"exception_type": "PRIVATE"},
            {"cleanup_exception_type": "PRIVATE"},
            {"ok": True},
            {"spawn_attempted": 1},
        ):
            with self.subTest(changes=changes):
                packet = boot.apt_failure_diagnostic(self.result(**changes))
                self.assertEqual(packet["completion"], "UNKNOWN")
                self.assertFalse(packet["markers_examined"])
                self.assertEqual(packet["marker_counts"]["unknown"], 1)
                self.assertNotIn("PRIVATE", json.dumps(packet))
        for body in (bytearray(b"PRIVATE"), "PRIVATE", b"a" * 262145):
            packet = boot.apt_failure_diagnostic(self.result(stderr=body))
            self.assertFalse(packet["streams"]["stderr"]["buffer_valid"])
            self.assertIsNone(packet["streams"]["stderr"]["sha256"])
            self.assertFalse(packet["markers_examined"])
        self.assertTrue(
            boot.apt_failure_diagnostic(self.result(stderr=b"x" * 262144))["streams"]["stderr"][
                "buffer_valid"
            ]
        )

    def test_R8_real_command_projects_same_buffers_then_sticky_refusal(self):
        result = self.result(stderr=b"Unable to fetch some archives PRIVATE")
        command, caught, writes, calls = self.command(result)
        self.assertIs(type(caught), ValueError)
        self.assertEqual(caught.args, ("command_UNKNOWN",))
        self.assertTrue(command.unknown)
        self.assertEqual(len(calls), 1)
        packet = json.loads(next(body for name, body, _ in writes if name == "apt-failure.json"))
        self.assertEqual(packet["streams"]["stderr"]["sha256"], boot.sha(result.stderr))
        self.assertEqual(
            [name for name, _, _ in writes],
            ["intent.json", "apt-failure.json", "process.json", "UNKNOWN.json"],
        )
        self.assertTrue(all(mode == 0o444 for _, _, mode in writes))
        self.assertNotIn(b"PRIVATE", b"".join(body for _, body, _ in writes))
        with self.assertRaisesRegex(ValueError, "previous_UNKNOWN"):
            command.run(["/usr/bin/gpg", "next"])
        self.assertEqual(len(calls), 1)
        options = calls[0][1]
        self.assertEqual((options["timeout"], options["work_timeout"]), (190, 180))
        self.assertEqual(
            (options["stdout_cap"], options["stderr_cap"], options["total_cap"]),
            (262144, 262144, 524288),
        )

    def test_R8_secondary_publication_failures_preserve_original_refusal(self):
        for failures in (
            ("apt-failure.json",),
            ("UNKNOWN.json",),
            ("process.json",),
            ("apt-failure.json", "process.json", "UNKNOWN.json"),
        ):
            command, caught, _, calls = self.command(self.result(), failures=failures)
            self.assertIs(type(caught), ValueError)
            self.assertEqual(caught.args, ("command_UNKNOWN",))
            self.assertTrue(command.unknown)
            self.assertEqual(len(calls), 1)

    def test_R8_role_closed_to_exact_APT_install_no_extra_tool_or_success_diagnostic(self):
        for role, argv in (
            ("PRIVATE", None),
            (True, None),
            ("root-local-exact-install", ["/usr/bin/gpg", "PRIVATE"]),
            ("root-local-exact-install", [*boot.APT, "--assume-yes", "install", "x", "extra"]),
        ):
            _, caught, _, calls = self.command(self.result(), role=role, argv=argv)
            self.assertIs(type(caught), ValueError)
            self.assertFalse(calls)
        result = self.result(ok=True, returncode=0, reason=None, stdout=b"ok")
        command, caught, writes, calls = self.command(result)
        self.assertIsNone(caught)
        self.assertFalse(command.unknown)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("apt-failure.json", [name for name, _, _ in writes])

    def test_R8_projection_exception_never_masks_refusal_or_emits_private_exception(self):
        original = ValueError("PRIVATE projection exception")
        with patch.object(boot, "apt_failure_diagnostic", side_effect=original):
            command, caught, writes, calls = self.command(self.result())
        self.assertIs(type(caught), ValueError)
        self.assertEqual(caught.args, ("command_UNKNOWN",))
        self.assertIsNot(caught, original)
        self.assertTrue(command.unknown)
        self.assertEqual(len(calls), 1)
        self.assertNotIn(b"PRIVATE", b"".join(body for _, body, _ in writes))
        self.assertNotIn("apt-failure.json", [name for name, _, _ in writes])

    def test_R8_missing_markers_are_unknown_and_counters_are_bounded_no_text(self):
        packet = boot.apt_failure_diagnostic(self.result())
        self.assertTrue(packet["markers_examined"])
        self.assertEqual(packet["marker_counts"]["unknown"], 1)
        self.assertEqual(sum(packet["marker_counts"].values()), 1)
        packet = boot.apt_failure_diagnostic(
            self.result(stdout=b"Broken packages " * 1000, stderr=b"Broken packages " * 1000)
        )
        self.assertEqual(packet["marker_counts"]["missingdeps"], 2000)
        self.assertEqual(packet["marker_counts"]["unknown"], 0)
        self.assertLess(len(json.dumps(packet).encode()), 8192)

    def test_R8_source_observation_before_auth_install_installed2_still_required(self):
        tree = ast.parse((HERE / "chrome_bootstrap.py").read_bytes())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        observe = next(
            n
            for n in ast.walk(main)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "fresh_write"
            and "root-interpreter-observation.json" in ast.unparse(n)
        )
        self.assertEqual(ast.unparse(observe.args[1]), "json.dumps(root_runtime).encode()")
        self.assertEqual(next(k.value.value for k in observe.keywords if k.arg == "mode"), 0o444)
        first_runtime = min(
            n.lineno
            for n in ast.walk(main)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "root_interpreter_runtime"
        )
        first_auth = min(
            n.lineno
            for n in ast.walk(main)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "authenticate"
        )
        self.assertLess(first_runtime, observe.lineno)
        self.assertLess(observe.lineno, first_auth)
        role_calls = [
            n
            for n in ast.walk(main)
            if isinstance(n, ast.Call) and any(k.arg == "diagnostic_role" for k in n.keywords)
        ]
        self.assertEqual(len(role_calls), 1)
        self.assertIn("--assume-yes", ast.unparse(role_calls[0]))
        self.assertEqual(boot.INSTALLED_SCHEMA, "pamolive.chrome-bootstrap/2")
        parent = next(
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "root_supervisor"
        )
        self.assertIn("result['schema'] == INSTALLED_SCHEMA", ast.unparse(parent))


if __name__ == "__main__":
    unittest.main()


class AptProjection2Tests(unittest.TestCase):
    result = AptFailureDiagnosticTests.result

    def test_raw_LF_CRLF_final_segment_empty_and_severity_are_not_normalized(self):
        cases = [
            (b"", []),
            (b"E: one\n", [b"E: one\n"]),
            (b"W: two\r\nN: three", [b"W: two\r\n", b"N: three"]),
            (b"\n\xff\x00\r", [b"\n", b"\xff\x00\r"]),
        ]
        for raw, lines in cases:
            with self.subTest(raw=raw):
                packet = boot.apt_failure_diagnostic(self.result(stdout=b"", stderr=raw))
                self.assertEqual(packet["schema"], "pamolive.chrome-apt-failure-DATA/2")
                projection = packet["line_projection"]["stderr"]
                self.assertEqual(projection["total_lines"], len(lines))
                self.assertFalse(projection["truncated"])
                self.assertEqual([r["bytes"] for r in projection["lines"]], [len(r) for r in lines])
                self.assertEqual(
                    [r["sha256"] for r in projection["lines"]], [boot.sha(r) for r in lines]
                )
                for row, line in zip(projection["lines"], lines):
                    expected = chr(line[0]) if line.startswith((b"E:", b"W:", b"N:")) else "OTHER"
                    self.assertEqual(row["severity_enum"], expected)

    def test_sixteen_first_lines_exact_total_and_absolute_byte_cap(self):
        for raw, count in (
            (b"X\n" * 16, 16),
            (b"X\n" * 17, 17),
            (b"\n" * 262144, 262144),
            (b"X" * 262144, 1),
        ):
            packet = boot.apt_failure_diagnostic(self.result(stdout=raw, stderr=raw))
            for name in ("stdout", "stderr"):
                value = packet["line_projection"][name]
                self.assertEqual(value["total_lines"], count)
                self.assertEqual(len(value["lines"]), min(16, count))
                self.assertEqual(value["truncated"], count > 16)
            self.assertLessEqual(len(json.dumps(packet).encode()), 8192)

    def test_unknown_H1_or_one_invalid_buffer_never_hashes_partial_lines(self):
        cases = (
            {"reason": "timeout"},
            {"returncode": True},
            {"owned_child_reaped": False},
            {"drains_complete": False},
            {"killed_owned_child": True},
            {"stderr": b"X" * 262145},
            {"stderr": "PRIVATE"},
            {"stdout": bytearray(b"PRIVATE")},
        )
        for changes in cases:
            with (
                self.subTest(changes=list(changes)),
                patch.object(
                    boot,
                    "apt_line_projection",
                    side_effect=AssertionError("no partial line projection"),
                ),
            ):
                packet = boot.apt_failure_diagnostic(self.result(**changes))
                self.assertEqual(packet["line_projection"]["state"], "UNAVAILABLE")
                for name in ("stdout", "stderr"):
                    self.assertEqual(
                        packet["line_projection"][name],
                        {"total_lines": None, "truncated": None, "lines": []},
                    )
                self.assertEqual(packet["root_cause"], "UNKNOWN")

    def test_new_primary_fragment_observations_never_become_consent_or_cause(self):
        samples = {
            "authconsent": (
                b"There were unauthenticated packages and -y was used "
                b"without --allow-unauthenticated"
            ),
            "heldconsent": (
                b"Held packages were changed and -y was used without --allow-change-held-packages."
            ),
            "essentialconsent": (
                b"Essential packages were removed and -y was used without --allow-remove-essential."
            ),
            "sourcewarnings": b"Unable to read ",
            "internal-install": b"Internal error, Ordering didn't finish",
            "internal-source": b"Internal ordering error",
            "archivesnofile": b"No file name for ",
            "space": b"You don't have enough free space in ",
            "exec-hooks": b"Problem executing scripts ",
            "size-hash": b"Hash Sum mismatch",
            "errno-site": b"Failed to fork",
            "acquire-failed": b"Failed to fetch ",
            "configured-state": b"Could not configure ",
        }
        for kind, fragment in samples.items():
            with self.subTest(kind=kind):
                packet = boot.apt_failure_diagnostic(
                    self.result(stderr=b"E: " + fragment + b"PRIVATE\n")
                )
                self.assertGreater(packet["marker_counts"][kind], 0)
                self.assertEqual(packet["root_cause"], "UNKNOWN")
                self.assertEqual(packet["state"], "UNKNOWN")
                self.assertFalse(packet["installation_verified"])
                self.assertFalse(packet["operational_GO"])
                self.assertNotIn("PRIVATE", json.dumps(packet))

    def test_private_control_bytes_and_terminal_sequences_never_leave_projection(self):
        secret = b"PRIVATE ::error:: token=synthetic-secret UID=nominal /private/path"
        raw = b"E: " + secret + b"\x00\xff\x1b[31m\r\nN: " + secret
        packet = boot.apt_failure_diagnostic(self.result(stdout=raw, stderr=raw))
        encoded = json.dumps(packet).encode()
        for private in (
            b"PRIVATE",
            b"::error::",
            b"synthetic-secret",
            b"nominal",
            b"/private/path",
            b"31m",
        ):
            self.assertNotIn(private, encoded)
        self.assertEqual(packet["streams"]["stdout"]["sha256"], boot.sha(raw))
        self.assertEqual(
            packet["line_projection"]["stdout"]["lines"][0]["bytes"], len(raw.split(b"\n")[0]) + 1
        )

    def test_composed_failed_APT_command_still_refuses_after_projection2_sink_failure(self):
        old = AptFailureDiagnosticTests()
        command, error, writes, calls = old.command(
            self.result(stderr=b"E: Some packages could not be authenticated\n")
        )
        self.assertIsInstance(error, ValueError)
        self.assertTrue(command.unknown)
        packet = json.loads(next(raw for name, raw, _ in writes if name == "apt-failure.json"))
        self.assertEqual(packet["schema"], "pamolive.chrome-apt-failure-DATA/2")
        self.assertEqual(packet["line_projection"]["stderr"]["lines"][0]["severity_enum"], "E")
        command, error, _, _ = old.command(self.result(), failures=("apt-failure.json",))
        self.assertIsInstance(error, ValueError)
        self.assertTrue(command.unknown)
        self.assertEqual(len(calls), 1)


class CacheMemory:
    """POSIX operations are memory doubles, never Windows syscalls."""

    def __init__(self):
        self.nodes, self.fds, self.events = {}, {}, []
        self.serial = 10
        self.after_read = None
        model = self

        class MP(PurePosixPath):
            def lstat(self):
                return SimpleNamespace(**model.nodes[str(self)][0])

            def mkdir(self, *, mode):
                if str(self) in model.nodes:
                    raise FileExistsError("public collision")
                model.add(str(self), stat.S_IFDIR | mode)

        self.Path = MP
        self.private = MP("/var/tmp/pamolive-chrome-bootstrap-123-1")
        self.source = MP("/public-input/chrome.deb")
        self.add(str(self.private), stat.S_IFDIR | 0o700)
        self.raw = b"PUBLIC_SYNTHETIC_DEB_BYTES_NOT_A_REAL_DEB"
        self.add(str(self.source), stat.S_IFREG | 0o400, self.raw, uid=1001, gid=1001)

    def add(self, name, mode, raw=b"", *, uid=0, gid=0):
        self.serial += 1
        self.nodes[name] = [
            dict(
                st_dev=1,
                st_ino=self.serial,
                st_mode=mode,
                st_uid=uid,
                st_gid=gid,
                st_nlink=2 if stat.S_ISDIR(mode) else 1,
                st_size=len(raw),
                st_mtime_ns=3,
                st_ctime_ns=4,
            ),
            raw,
        ]

    def open(self, path, flags, mode=None):
        name = str(path)
        self.events.append(("open", name, flags))
        assert flags & 8, "NOFOLLOW required"
        if flags & 64:
            assert flags & 128 and mode == 0o600
            if name in self.nodes:
                raise FileExistsError("public leaf collision")
            self.add(name, stat.S_IFREG | mode)
        self.serial += 1
        self.fds[self.serial] = name
        return self.serial

    def fdopen(self, fd, mode, *, buffering):
        name = self.fds[fd]
        model = self

        class Stream(io.BytesIO):
            def write(self, raw):
                count = super().write(raw)
                model.nodes[name][1] = self.getvalue()
                model.nodes[name][0]["st_size"] = len(self.getvalue())
                return count

            def read(self, count):
                model.events.append(("read", name, count))
                raw = super().read(count)
                if model.after_read:
                    callback, model.after_read = model.after_read, None
                    callback(model.nodes[name][0])
                return raw

            def close(self):
                model.events.append(("close", name))
                super().close()

        return Stream(b"" if "w" in mode else self.nodes[name][1])

    def ops(self):
        def fchmod(fd, mode):
            self.nodes[self.fds[fd]][0]["st_mode"] = stat.S_IFREG | mode
            self.events.append(("fchmod", self.fds[fd], mode))

        return SimpleNamespace(
            O_RDONLY=1,
            O_WRONLY=2,
            O_DIRECTORY=4,
            O_NOFOLLOW=8,
            O_CLOEXEC=16,
            O_NONBLOCK=32,
            O_CREAT=64,
            O_EXCL=128,
            open=self.open,
            fdopen=self.fdopen,
            getuid=lambda: 0,
            geteuid=lambda: 0,
            environ={"SUDO_UID": "1001"},
            fstat=lambda fd: SimpleNamespace(**self.nodes[self.fds[fd]][0]),
            close=lambda fd: self.events.append(("close-dir", self.fds[fd])),
            fchmod=fchmod,
            fsync=lambda fd: self.events.append(("fsync", self.fds[fd])),
        )


class RootAptCacheTests(unittest.TestCase):
    def tiny_expected(self, model):
        return {"Size": str(len(model.raw)), "SHA256": boot.sha(model.raw)}

    def copy(self, model):
        real = boot.cache_file

        def synthetic_bytes(path, expected, **kwargs):
            # The role pins remain the real package pins; only DATA bodies in this
            # writer model are tiny. Actual cache_file is independently exercised.
            self.assertEqual(expected, PINS["package"])
            return real(path, self.tiny_expected(model), **kwargs)

        with (
            patch.object(boot, "os", model.ops()),
            patch.object(boot, "cache_file", synthetic_bytes),
        ):
            return boot.root_cache_copy(model.private, model.source, PINS["package"])

    def test_R10_closed_absolute_cache_argv_preserves_all_original_flags(self):
        model = CacheMemory()
        for action in ("--simulate", "--assume-yes"):
            argv = boot.root_apt_argv(model.private, action=action)
            self.assertEqual(argv[: len(boot.APT)], boot.APT)
            self.assertEqual(
                argv[len(boot.APT) : -2],
                ["-o", "Dir::Cache::Archives=" + str(model.private / "apt-archives") + "/", action],
            )
            self.assertEqual(
                argv[-2:],
                ["install", str(model.private / "apt-archives" / boot.ROOT_CACHE_BASENAME)],
            )
        for private in (
            PurePosixPath("relative"),
            PurePosixPath("/tmp/other"),
            PurePosixPath("/var/tmp/pamolive-chrome-bootstrap-../1"),
        ):
            with self.assertRaises(ValueError):
                boot.root_apt_argv(private, action="--assume-yes")
        for action in (True, "--fix-broken", "install"):
            with self.assertRaises(ValueError):
                boot.root_apt_argv(model.private, action=action)

    def test_R10_known_file_metadata_precedes_any_content_read(self):
        for changes in (
            {"st_mode": stat.S_IFLNK | 0o777},
            {"st_uid": 0},
            {"st_nlink": 2},
            {"st_mode": stat.S_IFREG | 0o644},
            {"st_size": 1},
        ):
            model = CacheMemory()
            model.nodes[str(model.source)][0].update(changes)
            with patch.object(boot, "os", model.ops()):
                with self.assertRaises(ValueError):
                    boot.cache_file(model.source, self.tiny_expected(model), uid=1001)
            self.assertFalse(model.events)

    def test_R10_real_file_FD_hash_and_post_read_identity_are_both_required(self):
        model = CacheMemory()
        with patch.object(boot, "os", model.ops()):
            identity, raw = boot.cache_file(
                model.source, self.tiny_expected(model), uid=1001, retain=True
            )
            self.assertEqual(raw, model.raw)
            self.assertEqual(identity, boot.cache_identity(model.source.lstat()))
            model.after_read = lambda row: row.update(st_ino=999)
            with self.assertRaisesRegex(ValueError, "apt_cache_changed"):
                boot.cache_file(model.source, self.tiny_expected(model), uid=1001)
        model = CacheMemory()
        wrong = {**self.tiny_expected(model), "SHA256": "f" * 64}
        with patch.object(boot, "os", model.ops()):
            with self.assertRaisesRegex(ValueError, "apt_cache_changed"):
                boot.cache_file(model.source, wrong, uid=1001)
        model = CacheMemory()
        ops = model.ops()
        real_stat = ops.fstat

        def changed_fd(fd):
            row = real_stat(fd)
            row.st_ino += 1
            return row

        ops.fstat = changed_fd
        with patch.object(boot, "os", ops):
            with self.assertRaisesRegex(ValueError, "apt_cache_changed"):
                boot.cache_file(model.source, self.tiny_expected(model), uid=1001)
        self.assertFalse(any(e[0] == "read" for e in model.events))

    def test_R10_exclusive_copy_uses_known_bytes_fsync_sameFD_0400_and_binding(self):
        model = CacheMemory()
        package, binding = self.copy(model)
        self.assertEqual(model.nodes[str(package)][1], model.raw)
        self.assertEqual(package.name, boot.ROOT_CACHE_BASENAME)
        self.assertEqual(model.nodes[str(package)][0]["st_nlink"], 1)
        self.assertEqual(model.nodes[str(package)][0]["st_mode"], stat.S_IFREG | 0o400)
        events = [e[0] for e in model.events]
        self.assertLess(events.index("fsync"), events.index("fchmod"))
        with patch.object(boot, "os", model.ops()):
            boot.root_cache_check(model.private, binding, self.tiny_expected(model))
            model.nodes[str(package)][0]["st_nlink"] = 2
            before_reads = len([e for e in model.events if e[0] == "read"])
            with self.assertRaises(ValueError):
                boot.root_cache_check(model.private, binding, self.tiny_expected(model))
            self.assertEqual(before_reads, len([e for e in model.events if e[0] == "read"]))

    def test_R10_collision_or_wrong_parent_is_not_adopted_or_repaired(self):
        model = CacheMemory()
        cache, _ = boot.root_cache_paths(model.private)
        model.add(str(cache), stat.S_IFLNK | 0o777, b"UNKNOWN_NEVER_READ")
        with self.assertRaises(FileExistsError):
            self.copy(model)
        self.assertEqual(model.nodes[str(cache)][1], b"UNKNOWN_NEVER_READ")
        self.assertFalse(any(e[:2] == ("read", str(cache)) for e in model.events))
        model = CacheMemory()
        model.nodes[str(model.private)][0]["st_mode"] = stat.S_IFDIR | 0o755
        with self.assertRaises(ValueError):
            self.copy(model)
        self.assertFalse(any(e[0] == "read" for e in model.events))

    def test_R10_no_other_package_version_sha_size_or_missing_frontend_owner(self):
        model = CacheMemory()
        for field, wrong in (
            ("Package", "other"),
            ("Version", "158.0.0.0-1"),
            ("Architecture", "arm64"),
            ("Filename", "../foreign.deb"),
            ("Size", "1"),
            ("SHA256", "f" * 64),
        ):
            with patch.object(boot, "os", model.ops()):
                with self.assertRaisesRegex(ValueError, "apt_cache_package"):
                    boot.root_cache_copy(
                        model.private, model.source, {**PINS["package"], field: wrong}
                    )
        self.assertFalse(model.events)
        ops = model.ops()
        ops.environ = {}
        with patch.object(boot, "os", ops):
            with self.assertRaisesRegex(ValueError, "apt_cache_metadata"):
                boot.root_cache_copy(model.private, model.source, PINS["package"])

    def test_R10_directory_auxiliary_changes_do_not_relax_parent_or_DEB(self):
        model = CacheMemory()
        package, binding = self.copy(model)
        cache, _ = boot.root_cache_paths(model.private)
        model.nodes[str(cache)][0].update(st_nlink=4, st_mtime_ns=20, st_ctime_ns=20)
        with patch.object(boot, "os", model.ops()):
            boot.root_cache_check(model.private, binding, self.tiny_expected(model))
            model.nodes[str(cache)][0]["st_uid"] = 1001
            with self.assertRaises(ValueError):
                boot.root_cache_check(model.private, binding, self.tiny_expected(model))
        self.assertEqual(model.nodes[str(package)][0]["st_uid"], 0)

    def test_R10_upstream_model_reproduces_basename_then_binds_existing_absolute_cache(self):
        model = CacheMemory()
        cache, package = boot.root_cache_paths(model.private)

        def getarchives(existing_size):
            # Explicit model of source branches, never a claim of executing APT C++.
            stored = boot.ROOT_CACHE_BASENAME
            if existing_size == 123:
                return str(package), True, True
            return stored, False, True  # LocalOnly queued but Done not received.

        for size in (None, 122):
            stored, complete, local = getarchives(size)
            self.assertTrue(local)  # no-download's Local skip does not run Done.
            self.assertFalse(complete)
            self.assertFalse(PurePosixPath(stored).is_absolute())
        stored, complete, local = getarchives(123)
        self.assertTrue(complete and local)
        self.assertEqual(stored, str(cache / boot.ROOT_CACHE_BASENAME))
        self.assertTrue(PurePosixPath(stored).is_absolute())

    def controller(self, failure=None):
        events, writes = [], {}
        required = {"synthetic-row"}
        native = SimpleNamespace(
            MATRIX_REQUIRED=required,
            SOURCE_MATRIX_IMPLEMENTED=required,
            REQUIRED=required,
            LIFECYCLE=required,
            RECEIPT_SCHEMA="SYNTHETIC",
            PRODUCER_CONTRACT={"purpose": "TEST"},
        )
        tested = dict(
            schema="SYNTHETIC",
            ADR_evidence_matrix_complete=True,
            all_rows_are_native_crypto=False,
            producer_contract="TEST",
            producer_source_connected=True,
            matrix_required=list(required),
            matrix_completed=list(required),
            matrix_missing=[],
            source_unimplemented=[],
            other_expired_keys_freshly_observed=5,
            state="COMPLETE",
            missing=[],
            cases={"synthetic-row": {"refused": True, "complete_H1": True}},
            purpose=PINS["purpose"],
            operational_GO=False,
            revision="a" * 40,
            pins_manifest_sha256="f" * 64,
            run="123",
            attempt="1",
            scoped_sha256="b" * 64,
        )
        captured = {name: b"SYNTHETIC_SOURCE_NOT_EXECUTED" for name in boot.SOURCE_PATHS}
        captured.update(
            {name: (HERE / "chrome_materials" / name).read_bytes() for name in boot.MATERIALS}
        )
        captured["qualification/p1g_headless/chrome_scope_native_fixtures.json"] = json.dumps(
            {"cases": {"synthetic-row": {}}}
        ).encode()
        created = set()

        class MP(PurePosixPath):
            def resolve(self, **kwargs):
                return self

            def mkdir(self, **kwargs):
                if str(self) in created:
                    raise FileExistsError("synthetic")
                created.add(str(self))

            def open(self, *args, **kwargs):
                return io.BytesIO()

            def lstat(self):
                return SimpleNamespace(st_gid=0)

        def authenticate(*args, **kwargs):
            events.append("auth")
            return {}, {"scoped_sha256": "b" * 64}, b"", b""

        target = {"sha256": "c" * 64, "bytes": 4, "uid": 0, "mode": 0o755}
        support = SimpleNamespace(
            guard=lambda *a, **k: None,
            source_binding=lambda *a: {},
            resources=lambda p: {},
            bounded=lambda p: None,
            tool_pin=lambda p: target,
            fresh_write=lambda p, raw, **kw: writes.update({str(p): raw}),
        )
        scope_model = SimpleNamespace(PURPOSE=PINS["purpose"], authenticate=authenticate)

        class Commands:
            def __init__(self, *args, **kwargs):
                self.until = 1000

            def run(self, argv, **kwargs):
                if argv[0] == "/usr/bin/dpkg-deb":
                    events.append(argv[1])
                    if argv[1] == "--field":
                        return "".join(
                            k + ": " + PINS["package"][k] + "\n"
                            for k in ("Package", "Version", "Architecture", "Depends")
                        ).encode()
                    return b""
                if argv[0] == "/usr/bin/apt-get":
                    events.append(tuple(argv))
                    self_action = "--simulate" if "--simulate" in argv else "--assume-yes"
                    if self_action == "--simulate":
                        if failure == "simulation":
                            raise ValueError("command_UNKNOWN")
                        version = PINS["package"]["Version"]
                        return (
                            f"Inst google-chrome-stable ({version})\n"
                            f"Conf google-chrome-stable ({version})\n"
                        ).encode()
                    return b""
                events.append("query")
                version = PINS["package"]["Version"]
                return f"google-chrome-stable\n{version}\namd64\ninstall ok installed\n".encode()

        def copy(private, source, expected):
            events.append("copy")
            self.assertIn("auth", events)
            self.assertEqual(str(source), "/runner/p1g-chrome-private-123-1/chrome.deb")
            if failure == "copy":
                raise ValueError("apt_cache_changed")
            return boot.root_cache_paths(private)[1], ("SYNTHETIC_BINDING",)

        def check(*args):
            events.append("cache-check")
            if failure == "post_install" and events.count("cache-check") == 4:
                raise ValueError("apt_cache_changed")

        def read(path, cap):
            return (
                json.dumps(tested).encode()
                if path.name == "scope-native-preflight.json"
                else b"CONTEXT"
            )

        env = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_TEMP": "/runner",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "SUDO_UID": "1001",
            "GITHUB_REF": "",
            "GITHUB_HEAD_REF": "",
        }
        with (
            patch.object(boot, "Path", MP),
            patch.object(boot, "ROOT", MP("/runner/p1g-source")),
            patch.object(boot, "TARGET", MP("/opt/google/chrome/chrome")),
            patch.object(boot.sys, "platform", "linux"),
            patch.dict(boot.os.environ, env),
            patch.object(boot.os, "getuid", return_value=0, create=True),
            patch.object(boot.os, "umask", return_value=0),
            patch.object(boot.time, "time", return_value=OBSERVED_METADATA_TIME),
            patch.object(boot.time, "monotonic", return_value=0),
            patch.object(boot, "context", return_value=(PINS, captured)),
            patch.object(boot, "load", side_effect=[support, gpg, scope_model, native]),
            patch.object(boot, "read", read),
            patch.object(boot, "Commands", Commands),
            patch.object(boot, "public_journal_directory"),
            patch.object(boot, "root_interpreter_runtime", return_value={"SYNTHETIC": True}),
            patch.object(boot, "root_cache_copy", copy),
            patch.object(boot, "root_cache_check", check),
            patch.object(boot, "payload_target", return_value=target),
        ):
            rc = boot.main(
                ["--pins-sha", "f" * 64, "--root-install", "--native-scope-preflight-required"]
            )
        return rc, events, writes

    def test_R10_actual_root_main_wires_same_cache_after_auth_control_payload_and_before_receipt(
        self,
    ):
        rc, events, writes = self.controller()
        self.assertEqual(rc, 0)
        apt = [e for e in events if isinstance(e, tuple)]
        private = PurePosixPath("/var/tmp/pamolive-chrome-bootstrap-123-1")
        self.assertEqual(
            apt,
            [
                tuple(boot.root_apt_argv(private, action=action))
                for action in ("--simulate", "--assume-yes")
            ],
        )
        self.assertLess(events.index("auth"), events.index("copy"))
        self.assertLess(events.index("copy"), events.index("--field"))
        self.assertLess(events.index("--fsys-tarfile"), events.index(apt[0]))
        self.assertEqual(events.count("cache-check"), 4)
        receipt = json.loads(writes["/runner/p1g-headless-123-1-chrome/installed.json"])
        self.assertEqual(receipt["schema"], boot.INSTALLED_SCHEMA)
        self.assertIs(receipt["operational_GO"], False)

    def test_R10_actual_main_failure_never_makes_installed_or_undoes_late_install(self):
        for failure in ("copy", "simulation", "post_install"):
            rc, events, writes = self.controller(failure)
            self.assertEqual(rc, 42)
            self.assertNotIn("/runner/p1g-headless-123-1-chrome/installed.json", writes)
            self.assertIn("/runner/p1g-headless-123-1-chrome/root-UNKNOWN.json", writes)
            apt = [e for e in events if isinstance(e, tuple)]
            self.assertEqual(len(apt), {"copy": 0, "simulation": 1, "post_install": 2}[failure])

    def test_R10_real_workflow_recipe_keeps_negative_first_closed_tools_and_public_leaf(self):
        workflow = (HERE.parents[1] / ".github/workflows/ci.yml").read_text(encoding="utf8")
        step = workflow.split("      - name: Probe absolute local APT cache", 1)[1]
        step = step.split("      - name: Authenticate scoped certificate", 1)[0]
        self.assertIn("timeout-minutes: 3", step)
        self.assertIn("/usr/bin/python3.12 -I -B -S -", step)
        script = step.split("<<'PY'\n", 1)[1].rsplit("          PY\n", 1)[0]
        script = "".join(line[10:] + "\n" for line in script.splitlines())
        tree = ast.parse(script)  # No module/native recipe execution.
        self.assertLess(script.index("rc=100"), script.index("cache.mkdir(mode=0o700)"))
        self.assertIn("assert exact_error in negative.splitlines(keepends=True)", script)
        self.assertIn(
            'support.guard(os.environ, uid=int(os.environ["SUDO_UID"]), stage_only=True)',
            script,
        )
        self.assertIn("== status_before", script)
        self.assertIn('"--simulate"', script)
        self.assertIn('"--assume-yes"', script)
        self.assertIn("assert normal", script)
        self.assertIn('"complete": False', script)
        self.assertIn('"all_OS_descendants_released": False', script)
        self.assertNotIn('"/usr/bin/dpkg"', script)
        self.assertNotIn('"--fix-broken"', script)
        self.assertIn(
            "p1g-apt-cache-probe-${{ github.run_id }}-${{ github.run_attempt }}.json", workflow
        )
        # Exercise the real existing guard through the workflow's sudo whitelist.
        preserved = set(step.split("--preserve-env=", 1)[1].split()[0].split(","))
        self.assertTrue({"DATABASE_URL", "PAMOLIVE_TEST_DATABASE_NAME"} <= preserved)
        url_line = next(
            line for line in step.splitlines() if line.startswith("          DATABASE_URL: ")
        )
        name_line = next(
            line
            for line in step.splitlines()
            if line.startswith("          PAMOLIVE_TEST_DATABASE_NAME: ")
        )
        database_url = url_line.split(": ", 1)[1].replace(
            "${{ job.services.postgres.ports[5432] }}", "55432"
        )
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "pamolive/PamOlive-Platform",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + lab_support.STAGE_BRANCH,
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "PAMOLIVE_P1G_DISPOSABLE": "1",
            "DATABASE_URL": database_url,
            "PAMOLIVE_TEST_DATABASE_NAME": name_line.split(": ", 1)[1],
        }
        handed_off = {key: value for key, value in environment.items() if key in preserved}
        support = boot.load(
            "r10_existing_guard_regression",
            (HERE / "lab_support.py").read_bytes(),
            HERE / "lab_support.py",
        )
        support.guard(handed_off, platform="linux", uid=1001, stage_only=True)
        for key, code in (
            ("DATABASE_URL", "loopback_disposable_database_required"),
            ("PAMOLIVE_TEST_DATABASE_NAME", "fresh_test_database_required"),
        ):
            missing = dict(handed_off)
            del missing[key]
            with self.assertRaisesRegex(ValueError, code):
                support.guard(missing, platform="linux", uid=1001, stage_only=True)
        # Execute only the isolated DATA reader with memory OS/FD doubles.
        reader = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "read")
        model = CacheMemory()
        namespace = {"os": model.ops(), "stat": stat}
        exec(
            compile(ast.Module(body=[reader], type_ignores=[]), "<public-read-memory>", "exec"),
            namespace,
        )
        self.assertEqual(namespace["read"](model.source, 128), model.raw)
        model.after_read = lambda row: row.update(st_ino=999)
        with self.assertRaises(AssertionError):
            namespace["read"](model.source, 128)
        model = CacheMemory()
        ops = model.ops()
        original_stat = ops.fstat

        def swapped(fd):
            row = original_stat(fd)
            row.st_ino += 1
            return row

        ops.fstat = swapped
        namespace["os"] = ops
        with self.assertRaises(AssertionError):
            namespace["read"](model.source, 128)
        self.assertFalse(any(e[0] == "read" for e in model.events))
        model.nodes[str(model.source)][0]["st_mode"] = stat.S_IFIFO | 0o600
        before = len(model.events)
        with self.assertRaises(AssertionError):
            namespace["read"](model.source, 128)
        self.assertEqual(len(model.events), before)
