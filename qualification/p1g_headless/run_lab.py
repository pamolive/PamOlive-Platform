"""Explicit disposable CI owner; public typed facts only, private logs never uploaded."""

import argparse
import io
import json
import os
import re
import secrets
import stat
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from qualification.p1g_headless import lab_support as support  # noqa: E402


def paths():
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    name = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    return root / ("p1g-private-" + name), root / ("p1g-headless-" + name)


def worker(private):
    need = support.need
    row = private.lstat()
    need(
        stat.S_ISDIR(row.st_mode)
        and stat.S_IMODE(row.st_mode) == 0o700
        and row.st_uid == os.getuid()
        and private.resolve(strict=True) == private,
        "private_worker_directory",
    )
    value = {
        "schema": "pamolive.p1g-browser-worker/1",
        "state": "FAILED_OR_UNKNOWN",
        "phase": "TLS_setup",
        "tests": 0,
        "failures": 0,
        "errors": 0,
        "skips": 0,
        "full_P1G_qualified": False,
        "OS_or_VM_resources_released": False,
    }
    result = None
    try:
        value["phase"] = "source_binding"
        value["source"] = support.source_binding(
            REPO, Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json", os.environ["GITHUB_SHA"]
        )
        value["phase"] = "resource_preflight"
        value["resources_before_browser"] = support.resources(private)
        value["phase"] = "chrome_tool_preflight"
        chrome_preflight = support.tool_pin(Path("/opt/google/chrome/chrome"))
        value["phase"] = "TLS_setup"
        tls = support.prepare_tls(private, REPO)
        tls["browser_binary_pin"] = chrome_preflight
        os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
        import django

        django.setup()
        from django.db import connections
        from django.test.runner import DiscoverRunner

        from qualification.p1g_headless import browser_case

        browser_case.TLS.update(tls)
        value["phase"] = "fresh_PostgreSQL_precondition"
        connection = connections["default"]

        def database_state():
            with connection.cursor() as cursor:
                cursor.execute("SHOW server_version_num")
                version = cursor.fetchone()[0]
                cursor.execute("SELECT oid FROM pg_database WHERE datname = %s", ["pamolive_p1g"])
                original = cursor.fetchone()
                cursor.execute(
                    "SELECT oid FROM pg_database WHERE datname = %s", ["test_pamolive_p1g_browser"]
                )
                exists = cursor.fetchone()
            return version, original, exists

        before = database_state()
        need(
            before[0] == "170012" and before[1] is not None and before[2] is None,
            "fresh_database_or_version_refused",
        )
        connection.close()

        class PrivateRunner(unittest.TextTestRunner):
            def __init__(self, **kwargs):
                kwargs["stream"] = io.StringIO()
                super().__init__(**kwargs)

            def run(self, suite):
                nonlocal result
                result = super().run(suite)
                return result

        runner = DiscoverRunner(verbosity=0, interactive=False, keepdb=False)
        runner.test_runner = PrivateRunner
        value["phase"] = "browser_increment"
        failed = runner.run_tests(["qualification.p1g_headless.browser_case.P1GBrowser"])
        value.update(browser_case.FACTS)
        value["tests"], value["failures"], value["errors"], value["skips"] = (
            result.testsRun,
            len(result.failures),
            len(result.errors),
            len(result.skipped),
        )
        value["failure_source_lines"] = sorted(
            {
                int(line)
                for _, text in result.failures + result.errors
                for line in re.findall(r'browser_case\.py["\x27], line ([0-9]{1,5})', text)
            }
        )
        after = database_state()
        value["fresh_test_database_absent_after_runner"] = after[2] is None
        value["base_database_OID_preserved"] = before[1] == after[1]
        value["TLS"] = {"CA_DER_SHA256": tls["CA_DER_SHA256"], "NSS_commands": tls["NSS_commands"]}
        value["live_server_thread_closed"] = not browser_case.P1GBrowser.server_thread.is_alive()
        need(
            failed == 0
            and value["tests"] == 1
            and not value["skips"]
            and value["SDK_cleanup_completed"] is True
            and value["browser_E2E_executed"] is True
            and value["live_server_thread_closed"] is True
            and value["fresh_test_database_absent_after_runner"] is True
            and value["base_database_OID_preserved"] is True,
            "increment_not_complete",
        )
        value["state"] = "OBSERVED_SYNTHETIC_INCREMENT_ONLY"
    except BaseException as error:
        value["error_class"] = type(error).__name__
        diagnostic = support.chrome_tool_diagnostic(error, phase=value["phase"])
        if diagnostic is not None:
            value["chrome_tool_diagnostic"] = diagnostic
        # No exception text/DOM/traceback/password/TOTP/private key or signed proof is public.
        existing = sys.modules.get("qualification.p1g_headless.browser_case")
        if existing is not None and existing.FACTS["phase"] != "not_started":
            value.update(existing.FACTS)
    support.fresh_write(private / "worker-report.json", json.dumps(value, indent=2).encode())
    return 0 if value["state"] == "OBSERVED_SYNTHETIC_INCREMENT_ONLY" else 42


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    support.guard(os.environ)
    os.umask(0o077)
    private, public = paths()
    support.need(
        REPO == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True) / "p1g-source",
        "committed_source_directory_required",
    )
    if args.worker:
        return worker(private)
    private.mkdir(mode=0o700)
    public.mkdir(mode=0o700)
    worker_home = private / "worker-home"
    worker_home.mkdir(mode=0o700)
    io_helper = support.bounded(REPO)
    keys = {
        "GITHUB_ACTIONS",
        "GITHUB_REPOSITORY",
        "GITHUB_EVENT_NAME",
        "GITHUB_REF",
        "GITHUB_HEAD_REF",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "P1G_HEAD_REPOSITORY",
        "PAMOLIVE_P1G_DISPOSABLE",
        "PAMOLIVE_TEST_DATABASE_NAME",
        "DATABASE_URL",
        "RUNNER_TEMP",
    }
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env.update(
        PATH="/usr/bin:/bin",
        LANG="C.UTF-8",
        LC_ALL="C.UTF-8",
        HOME=str(worker_home),
        SECRET_KEY=secrets.token_urlsafe(48),
        PAMOLIVE_ENCRYPTION_KEY=secrets.token_urlsafe(48),
    )
    support.fresh_write(
        public / "intent.json",
        json.dumps(
            {
                "state": "PENDING",
                "revision": env["GITHUB_SHA"],
                "work_seconds": 600,
                "cleanup_reserve_seconds": 60,
                "scope": "one_synthetic_UI_increment_not_full_P1G",
            }
        ).encode(),
    )
    try:
        outcome = io_helper.run_capped(
            [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker"],
            env=env,
            cwd=str(REPO),
            timeout=660,
            work_timeout=600,
            stdout_cap=262144,
            stderr_cap=262144,
            total_cap=524288,
            owned_session=True,
            on_spawn=lambda pid: support.fresh_write(
                public / "pid.json", json.dumps({"pid": pid}).encode()
            ),
        )
        support.fresh_write(private / "stdout.private", outcome.stdout)
        support.fresh_write(private / "stderr.private", outcome.stderr)
        facts = outcome.facts()
        support.fresh_write(public / "process.json", json.dumps(facts, indent=2).encode())
        # Failure diagnostics must be captured before outcome.ok refuses them.
        worker_path = private / "worker-report.json"
        if worker_path.exists():
            raw = io_helper.read_regular(worker_path, 65536)
            packet = json.loads(raw)
            support.need(
                packet.get("schema") == "pamolive.p1g-browser-worker/1"
                and packet.get("state")
                in {"FAILED_OR_UNKNOWN", "OBSERVED_SYNTHETIC_INCREMENT_ONLY"},
                "worker_diagnostic_shape",
            )
            support.fresh_write(public / "worker-data.json", raw)
        support.need(
            outcome.ok
            and outcome.spawn_attempted
            and not outcome.killed_owned_child
            and outcome.exception_type is None
            and outcome.cleanup_exception_type is None,
            "worker_failed_or_unknown",
        )
        raw = io_helper.read_regular(private / "worker-report.json", 65536)
        report = json.loads(raw)
        support.need(
            report.get("schema") == "pamolive.p1g-browser-worker/1"
            and report.get("state") == "OBSERVED_SYNTHETIC_INCREMENT_ONLY"
            and report.get("tests") == 1
            and report.get("full_P1G_qualified") is False,
            "worker_packet_refused",
        )
        support.fresh_write(public / "report.json", raw)
        return 0
    except BaseException as error:
        support.fresh_write(
            public / "UNKNOWN.json",
            json.dumps(
                {
                    "state": "FAILED_OR_UNKNOWN",
                    "error_class": type(error).__name__,
                    "all_descendants_closed": False,
                    "full_P1G_qualified": False,
                    "VM_teardown_is_not_cleanup_evidence": True,
                }
            ).encode(),
        )
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
