"""Synthetic child JSON/IO facts only; no installed runner, venv, pip or package."""

import ast
import copy
import json
import os
import stat
import tempfile
import time
import unittest
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import test_adapter_pure as original

PARENT, CHILD = original.PARENT, original.CHILD


def report(code="minimal_distributions", exception="ValueError"):
    return {
        "schema": "pamolive.public-pam-verifier-installed-child/1",
        "operation": "probe",
        "state": "FAILED",
        "authority": False,
        "exception_type": exception,
        "failure_code": code,
        "forbidden_attempts": {},
        "intentional_guard_probes": {
            "socket.constructor": 1,
            "DNS": 1,
            "sqlite3.connect": 1,
            "subprocess.Popen": 1,
            "import.django": 1,
            "file.read_outside_roots": 1,
        },
        "elapsed_seconds": 0.25,
        "installed_wheel_only": True,
        "OS_network_sandbox_claimed": False,
        "full_P0_acceptance": False,
        "build_attestation": False,
    }


class ChildFailureDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.io = PARENT.load_io()
        material, _ = PARENT.document(PARENT.ROOT / "materials-plan.json", PARENT.MATERIALS_HASH)
        rows = material["selected_materials"]
        self.expected = {
            "build": {
                "pip": rows["pip"]["version"],
                **{key: rows[key]["version"] for key in PARENT.BUILD_NAMES},
            },
            "verifier": {
                "pip": rows["pip"]["version"],
                PARENT.DISTRIBUTION: PARENT.VERSION,
                **{key: rows[key]["version"] for key in PARENT.RUNTIME_NAMES},
            },
        }

    def process(self, **changes):
        return self.io.Result(
            **{
                "spawn_attempted": True,
                "pid": 123,
                "returncode": 1,
                "reason": "nonzero_exit",
                "owned_child_reaped": True,
                "drains_complete": True,
                **changes,
            }
        )

    def failed_call(self, raw, *, name="build", process=None):
        process = process or self.process()
        with tempfile.TemporaryDirectory(prefix="child-failure-mock-") as temporary:
            work = Path(temporary)
            (work / "reports").mkdir()
            (work / "logs").mkdir()
            probe_path = work / "reports" / ("probe-" + name + ".json")
            probe_path.write_bytes(raw)
            # Parent target() is Linux-only. Windows lstat/fstat expose differing
            # ctime semantics on these host fixtures; model a stable Linux file.
            # Type/alias/pre-read/post-read race tests below mutate that boundary.
            metadata = probe_path.lstat()
            original_lstat = Path.lstat

            def stable_lstat(item, *args, **kwargs):
                return metadata if item == probe_path else original_lstat(item, *args, **kwargs)

            value = {"processes": [], "venvs": {}}
            namespace = {
                "time": time,
                "started": time.monotonic(),
                "work": work,
                "env": {},
                "IO": SimpleNamespace(run_capped=Mock(return_value=process)),
                "Path": Path,
                "report": value,
                "require": PARENT.require,
                "expected": self.expected,
                "failed_probe_report": PARENT.failed_probe_report,
            }
            call = original.AdapterPureTests().extracted(
                "qualify_installed.py", "run", "call", namespace
            )
            self.last_refusals = []
            original_require = PARENT.require

            def observed_require(condition, code):
                if not condition:
                    self.last_refusals.append(code)
                return original_require(condition, code)

            with (
                patch.object(PARENT, "require", side_effect=observed_require),
                patch.object(Path, "lstat", stable_lstat),
                patch.object(os, "fstat", return_value=metadata),
            ):
                with self.assertRaisesRegex(ValueError, "owned_process_failed"):
                    call("probe-" + name, ["never-executed"], probe_name=name)
            self.assertEqual(value["processes"], [{"phase": "probe-" + name, **process.facts()}])
            return value

    def test_real_parent_call_retains_failure_in_both_probe_slots_and_still_raises(self):
        for name in ("build", "verifier"):
            with self.subTest(name=name):
                child = report()
                value = self.failed_call(json.dumps(child).encode(), name=name)
                self.assertEqual(value["venvs"], {name: child})
                self.assertEqual(value["processes"][0]["returncode"], 1)
                self.assertEqual(value["processes"][0]["reason"], "nonzero_exit")

    def test_forbiddenIO_and_masked_attempt_counters_remain_public_constant_codes(self):
        for code, exception in (
            ("FORBIDDEN_IO", "ForbiddenIO"),
            ("minimal_distributions", "ValueError"),
        ):
            child = report(code, exception)
            child["forbidden_attempts"] = {"file.read_outside_roots": 1}
            value = self.failed_call(json.dumps(child).encode())
            self.assertIn("build", value["venvs"], self.last_refusals)
            self.assertEqual(
                value["venvs"]["build"]["forbidden_attempts"], child["forbidden_attempts"]
            )
            self.assertEqual(value["venvs"]["build"]["failure_code"], code)

    def test_failure_code_enum_never_coerces_or_exports_exception_messages(self):
        self.assertEqual(
            CHILD.failure_code(ValueError("minimal_distributions")), "minimal_distributions"
        )
        self.assertEqual(CHILD.failure_code(CHILD.ForbiddenIO("PRIVATE_PATH")), "FORBIDDEN_IO")
        for error in (
            ValueError("PRIVATE_MESSAGE"),
            RuntimeError("PRIVATE_MESSAGE"),
            ValueError("a", "b"),
        ):
            self.assertEqual(CHILD.failure_code(error), "UNCLASSIFIED_FAILURE")

        class NoString:
            def __str__(self):
                raise AssertionError("message was coerced")

        self.assertEqual(CHILD.failure_code(ValueError(NoString())), "UNCLASSIFIED_FAILURE")
        self.assertEqual(CHILD.REQUIRE_FAILURE_CODES, PARENT.PROBE_REQUIRE_CODES)

    def test_wrong_phase_or_unconfirmed_process_is_refused_before_any_read(self):
        for options in (
            {"returncode": 0},
            {"returncode": 2},
            {"returncode": True},
            {"reason": "timeout"},
            {"reason": "stdout_overflow"},
            {"owned_child_reaped": False},
            {"drains_complete": False},
            {"killed_owned_child": True},
            {"cleanup_exception_type": "OSError"},
            {"exception_type": "OSError"},
            {"spawn_attempted": False},
            {"pid": None},
            {"stdout_bytes": 1},
            {"stderr_bytes": 1},
        ):
            with (
                self.subTest(options=tuple(options)),
                patch.object(Path, "lstat", side_effect=AssertionError("read reached")),
            ):
                with self.assertRaisesRegex(ValueError, "probe_process_unconfirmed"):
                    PARENT.failed_probe_report(
                        Path("/owned"),
                        "probe-build",
                        "build",
                        self.process(**options),
                        self.expected["build"],
                    )
        for phase, name in (
            ("run-installed-30", "build"),
            ("probe-build", "verifier"),
            ("probe-other", "../other"),
        ):
            with patch.object(Path, "lstat", side_effect=AssertionError("path reached")):
                with self.assertRaisesRegex(ValueError, "probe_phase"):
                    PARENT.failed_probe_report(Path("/owned"), phase, name, self.process(), {})

    def test_success_state_unknown_keys_raw_logs_bad_counter_and_failure_codes_refuse(self):
        for fields in (
            {"state": "INSTALLED_ONLY_PROBE_PASS"},
            {"operation": "tests"},
            {"stdout": "PRIVATE"},
            {"logs": "PRIVATE"},
            {"unknown": 1},
            {"authority": True},
            {"failure_code": "PRIVATE_MESSAGE"},
            {"exception_type": "PRIVATE_MESSAGE"},
            {"failure_code": "FORBIDDEN_IO"},
            {"forbidden_attempts": {"PRIVATE_PATH": 1}},
            {"intentional_guard_probes": {"DNS": True}},
            {"venv": {"logs": "PRIVATE"}},
            {"installed_files": {"logs": "PRIVATE"}},
        ):
            with self.subTest(fields=tuple(fields)):
                value = self.failed_call(json.dumps({**report(), **fields}).encode())
                self.assertEqual(value["venvs"], {})

    def test_duplicate_nonfinite_depth_utf8_and_oversize_JSON_never_replace_process_failure(self):
        raw = json.dumps(report()).encode()
        for bad in (
            b"[]",
            b"{}",
            b"\xff",
            b"raw-log\n" + raw,
            raw + b"raw-log",
            raw.replace(b'"authority": false', b'"authority": false,"\\u0061uthority": false'),
            raw.replace(b'"elapsed_seconds": 0.25', b'"elapsed_seconds": NaN'),
            b"[" * 9 + b"]" * 9,
            b"x" * 32769,
        ):
            with self.subTest(size=len(bad)):
                self.assertEqual(self.failed_call(bad)["venvs"], {})

    def test_partial_verifier_and_build_structures_are_closed_and_role_bound(self):
        for name in ("build", "verifier"):
            child = report("installed_file_hash")
            child["venv"] = {
                "distributions": self.expected[name],
                "origins_within_venv": {
                    module: "lib/python3.12/site-packages/" + module + "/__init__.py"
                    for module in (("pip",) if name == "build" else ("pip", PARENT.PACKAGE))
                },
                "global_site_fallback": False,
                "application_or_SDK_importable": False,
            }
            if name == "verifier":
                child["installed_files"] = {
                    "wheel_files_sha256_matched": 12,
                    "package_files_closed": 6,
                    "site_PTH": 0,
                }
            self.assertEqual(
                self.failed_call(json.dumps(child).encode(), name=name)["venvs"][name], child
            )
            for mutation in ("wrong_distribution", "unknown", "raw_origin"):
                bad = copy.deepcopy(child)
                if mutation == "wrong_distribution":
                    bad["venv"]["distributions"]["Django"] = "PRIVATE"
                elif mutation == "unknown":
                    bad["venv"]["stdout"] = "PRIVATE"
                else:
                    bad["venv"]["origins_within_venv"]["pip"] = "PRIVATE_MESSAGE"
                self.assertEqual(self.failed_call(json.dumps(bad).encode(), name=name)["venvs"], {})

    def test_file_type_hardlink_alias_and_size_are_checked_before_open(self):
        with tempfile.TemporaryDirectory(prefix="probe-file-pure-") as temporary:
            work = Path(temporary)
            (work / "reports").mkdir()
            path = work / "reports/probe-build.json"
            path.write_text(json.dumps(report()))
            original_stat = Path.lstat
            actual = path.stat()
            values = {
                field: getattr(actual, field)
                for field in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            }
            for fields in (
                {"st_mode": stat.S_IFDIR},
                {"st_mode": stat.S_IFLNK},
                {"st_nlink": 2},
                {"st_size": 32769},
                {"st_size": 0},
                {"st_file_attributes": 1024},
            ):

                def fake_stat(item, *args, **kwargs):
                    return (
                        SimpleNamespace(**{**values, **fields})
                        if item == path
                        else original_stat(item, *args, **kwargs)
                    )

                with (
                    patch.object(Path, "lstat", fake_stat),
                    patch.object(Path, "open", side_effect=AssertionError("open reached")),
                ):
                    with self.assertRaises(ValueError):
                        PARENT.failed_probe_report(
                            work, "probe-build", "build", self.process(), self.expected["build"]
                        )
            with (
                patch.object(Path, "is_symlink", side_effect=lambda: True),
                patch.object(Path, "open", side_effect=AssertionError("open reached")),
            ):
                with self.assertRaises(ValueError):
                    PARENT.failed_probe_report(
                        work, "probe-build", "build", self.process(), self.expected["build"]
                    )

    def test_open_and_postread_identity_races_refuse(self):
        with tempfile.TemporaryDirectory(prefix="probe-race-pure-") as temporary:
            work = Path(temporary)
            (work / "reports").mkdir()
            path = work / "reports/probe-build.json"
            path.write_text(json.dumps(report()))
            actual = path.stat()
            values = {
                field: getattr(actual, field)
                for field in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            }
            for field in ("st_ino", "st_ctime_ns"):
                for after in (False, True):
                    counter = []

                    def fstat(_fd):
                        counter.append(1)
                        return SimpleNamespace(
                            **{
                                **values,
                                **(
                                    {field: values[field] + 1}
                                    if len(counter) > (1 if after else 0)
                                    else {}
                                ),
                            }
                        )

                    with patch.object(os, "fstat", side_effect=fstat):
                        with self.assertRaisesRegex(ValueError, "probe_(post|open)_identity"):
                            PARENT.failed_probe_report(
                                work, "probe-build", "build", self.process(), self.expected["build"]
                            )

    def test_guarded_distribution_probe_can_fail_two_ways_without_real_metadata_scan(self):
        prefix = Path("/synthetic/venv")
        with (
            patch.object(CHILD.sys, "prefix", str(prefix)),
            patch.object(CHILD.sys, "base_prefix", "/synthetic/base"),
            patch.object(CHILD.site, "ENABLE_USER_SITE", False),
            patch.object(
                CHILD, "bounded_read", return_value=b"include-system-site-packages = false"
            ),
            patch.object(CHILD.importlib.metadata, "distributions", return_value=[]),
        ):
            with self.assertRaisesRegex(ValueError, "minimal_distributions"):
                CHILD.distribution_probe({"pip": "26.3"}, "")
        guard = CHILD.Guards()
        with (
            patch.object(CHILD.sys, "prefix", str(prefix)),
            patch.object(CHILD.sys, "base_prefix", "/synthetic/base"),
            patch.object(CHILD.site, "ENABLE_USER_SITE", False),
            patch.object(
                CHILD, "bounded_read", return_value=b"include-system-site-packages = false"
            ),
            patch.object(
                CHILD.importlib.metadata,
                "distributions",
                side_effect=guard.blocked("file.read_outside_roots"),
            ),
        ):
            with self.assertRaises(CHILD.ForbiddenIO) as caught:
                CHILD.distribution_probe({"pip": "26.3"}, "")
        self.assertEqual(CHILD.failure_code(caught.exception), "FORBIDDEN_IO")
        self.assertEqual(dict(guard.attempts), {"file.read_outside_roots": 1})
        # These are controlled alternatives, not the observed Linux cause.

    def test_maintained_metadata_children_can_mask_refusals_while_counters_keep_them(self):
        # Source-only extraction. No metadata discovery or real directory/zip read.
        source = Path(CHILD.importlib.metadata.__file__).read_bytes()
        tree = ast.parse(source)
        fast_path = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "FastPath"
        )
        children = next(
            node
            for node in fast_path.body
            if isinstance(node, ast.FunctionDef) and node.name == "children"
        )
        guard = CHILD.Guards()
        namespace = {
            "suppress": suppress,
            "os": SimpleNamespace(listdir=guard.blocked("file.read_outside_roots")),
        }
        exec(
            compile(
                ast.Module(body=[children], type_ignores=[]),
                "metadata-children-public-source",
                "exec",
            ),
            namespace,
        )
        synthetic = SimpleNamespace(
            root="/synthetic/base/python312.zip",
            zip_children=guard.blocked("file.read_outside_roots"),
        )
        self.assertEqual(namespace["children"](synthetic), [])
        self.assertEqual(dict(guard.attempts), {"file.read_outside_roots": 2})
        with self.assertRaises(CHILD.ForbiddenIO) as caught:
            guard.require_clean()
        self.assertEqual(CHILD.failure_code(caught.exception), "FORBIDDEN_IO")

    def test_elapsed_prebounds_preserve_exact_original_error_and_phase_facts(self):
        invalid = (
            10**400,
            -(10**400),
            float("inf"),
            float("-inf"),
            float("nan"),
            -1,
            901,
            True,
            False,
        )
        valid = (0, 0.25, 900)
        for name in ("build", "verifier"):
            for accepted, values in ((False, invalid), (True, valid)):
                for elapsed in values:
                    with (
                        self.subTest(role=name, accepted=accepted, type=type(elapsed).__name__),
                        tempfile.TemporaryDirectory(prefix="elapsed-bound-pure-") as temporary,
                    ):
                        work = Path(temporary)
                        (work / "reports").mkdir()
                        (work / "logs").mkdir()
                        path = work / "reports" / ("probe-" + name + ".json")
                        child = {**report(), "elapsed_seconds": elapsed}
                        path.write_text(json.dumps(child))
                        metadata, real_lstat = path.lstat(), Path.lstat
                        value = {"processes": [], "venvs": {}}
                        process = self.process()
                        original_error = ValueError("owned_process_failed")

                        def require_original(condition, code):
                            if not condition and code == "owned_process_failed":
                                raise original_error
                            return PARENT.require(condition, code)

                        def stable_lstat(item, *args, **kwargs):
                            return metadata if item == path else real_lstat(item, *args, **kwargs)

                        namespace = {
                            "time": time,
                            "started": time.monotonic(),
                            "work": work,
                            "env": {},
                            "IO": SimpleNamespace(run_capped=Mock(return_value=process)),
                            "Path": Path,
                            "report": value,
                            "require": require_original,
                            "expected": self.expected,
                            "failed_probe_report": PARENT.failed_probe_report,
                        }
                        call = original.AdapterPureTests().extracted(
                            "qualify_installed.py", "run", "call", namespace
                        )
                        real_isfinite = PARENT.math.isfinite
                        with (
                            patch.object(Path, "lstat", stable_lstat),
                            patch.object(os, "fstat", return_value=metadata),
                            patch.object(PARENT.math, "isfinite", wraps=real_isfinite) as isfinite,
                        ):
                            with self.assertRaises(ValueError) as caught:
                                call("probe-" + name, ["never-executed"], probe_name=name)
                        self.assertIs(caught.exception, original_error)
                        self.assertEqual(
                            value["processes"], [{"phase": "probe-" + name, **process.facts()}]
                        )
                        self.assertEqual(value["venvs"], {name: child} if accepted else {})
                        self.assertEqual(isfinite.call_count, 1 if accepted else 0)
