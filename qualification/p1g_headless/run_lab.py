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

NATIVE_INPUTS = (
    "qualification/p1g_headless/browser_case.py",
    "qualification/p1g_headless/native_browser_case.py",
    "qualification/p1g_headless/run_lab.py",
    "qualification/p1g_headless/lab_support.py",
    "tests/fixtures/asgi.py",
    "tests/fixtures/guacd.py",
    "tests/fixtures/ssh.py",
    "config/asgi.py",
    "platform_modules/pam/broker.py",
    "platform_modules/pam/context.py",
    "platform_modules/pam/recordings.py",
    "platform_modules/pam/sessions.py",
    "platform_modules/pam/views.py",
    "platform_core/static/platform_core/pam.js",
    "platform_core/static/platform_core/vendor/guacamole-1.6.0.min.js",
    "templates/governance/pam.html",
    "templates/pam/detail.html",
    "templates/pam/session.html",
)
ISOLATED_INPUTS = (
    "qualification/p1g_headless/native_lab.py",
    "qualification/p1g_headless/chrome_sandbox_probe.py",
    "qualification/p1g_headless/postgres_namespace.py",
    "qualification/p1g_headless/guacd_namespace.py",
)
RDP_INPUTS = (
    "qualification/p1g_headless/rdp_peer.py",
    "qualification/p1g_headless/rdp_namespace.py",
    "tests/fixtures/rdp.py",
    "tests/fixtures/rdp_fixture.c",
)
STOP_PHASE = "same_relay_stop_WSS_SSH_and_verified_partial_capture"
RDP_STOP_PHASE = "same_relay_stop_WSS_RDP_and_verified_partial_capture"


def paths():
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    name = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    return root / ("p1g-private-" + name), root / ("p1g-headless-" + name)


def worker(private, *, native_protocol=None, isolated=False):
    need = support.need
    need(native_protocol in (None, "ssh", "rdp") and (
        isolated or native_protocol != "rdp"
    ) and (not isolated or native_protocol is not None), "isolated_worker_requires_native_case")
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
        "case": "native_" + native_protocol if native_protocol else "portal",
    }
    result = None
    try:
        value["phase"] = "source_binding"
        additional = NATIVE_INPUTS if native_protocol else ()
        if isolated:
            additional += ISOLATED_INPUTS
        if native_protocol == "rdp":
            additional += RDP_INPUTS
        value["source"] = support.source_binding(
            REPO, Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json", os.environ["GITHUB_SHA"],
            additional=additional,
        )
        value["phase"] = "resource_preflight"
        value["resources_before_browser"] = support.resources(private)
        value["phase"] = "chrome_tool_preflight"
        if isolated:
            from qualification.p1g_headless import chrome_sandbox_probe as admitted_chrome
            from qualification.p1g_headless.guacd_namespace import PORT

            chrome = private / "chrome/chrome"
            chrome_preflight = support.tool_pin(chrome, root_owner=False)
            need(
                chrome_preflight["sha256"] == admitted_chrome.CHROME_SHA
                and chrome_preflight["bytes"] == admitted_chrome.CHROME_BYTES,
                "isolated_chrome_pin",
            )
        else:
            _, chrome_preflight = support.chrome_target(REPO)
        if native_protocol == "ssh" and not isolated:
            value["phase"] = "guacd_tool_preflight"
            from tests.fixtures.guacd import BINARY

            value["guacd_tool"] = support.tool_pin(BINARY)
        value["phase"] = "TLS_setup"
        tls = support.prepare_tls(private, REPO)
        tls["browser_binary_pin"] = chrome_preflight
        tls["browser_mode"] = os.environ.get("P1G_CHROME_MODE", "legacy-installed-v2")
        if isolated:
            tls.update(
                isolated_chrome=chrome, isolated_chrome_version=admitted_chrome.BROWSER_VERSION,
                isolated_guacd_port=PORT,
            )
            if native_protocol == "rdp":
                tls["isolated_rdp_state"] = private / "rdp-state"
        os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
        import django

        django.setup()
        from django.db import connections
        from django.test.runner import DiscoverRunner

        from qualification.p1g_headless import browser_case

        selected = browser_case.P1GBrowser
        if native_protocol:
            from qualification.p1g_headless.native_browser_case import (
                NativeRDPBrowser,
                NativeSSHBrowser,
            )

            selected = NativeRDPBrowser if native_protocol == "rdp" else NativeSSHBrowser
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

        class PrivateResult(unittest.TextTestResult):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.exception_types = set()

            def addError(self, test, err):
                self.exception_types.add(err[0].__name__)
                super().addError(test, err)

            def addFailure(self, test, err):
                self.exception_types.add(err[0].__name__)
                super().addFailure(test, err)

        class PrivateRunner(unittest.TextTestRunner):
            def __init__(self, **kwargs):
                kwargs["stream"] = io.StringIO()
                kwargs["resultclass"] = PrivateResult
                super().__init__(**kwargs)

            def run(self, suite):
                nonlocal result
                result = super().run(suite)
                return result

        runner = DiscoverRunner(verbosity=0, interactive=False, keepdb=False)
        runner.test_runner = PrivateRunner
        value["phase"] = "browser_increment"
        failed = runner.run_tests([selected.__module__ + "." + selected.__name__])
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
        value["test_exception_types"] = sorted(
            name for name in result.exception_types
            if re.fullmatch(r"[A-Z][A-Za-z0-9_]{1,62}", name)
        )[:8]
        after = database_state()
        value["fresh_test_database_absent_after_runner"] = after[2] is None
        value["base_database_OID_preserved"] = before[1] == after[1]
        value["TLS"] = {"CA_DER_SHA256": tls["CA_DER_SHA256"], "NSS_commands": tls["NSS_commands"]}
        server = getattr(selected, "server_thread", None)
        value["live_server_thread_closed"] = server is not None and not server.is_alive()
        need(
            failed == 0
            and value["tests"] == 1
            and not value["skips"]
            and value["SDK_cleanup_completed"] is True
            and value["browser_E2E_executed"] is True
            and support.sandbox_receipt(value["browser_sandbox"])
            and value["live_server_thread_closed"] is True
            and value["fresh_test_database_absent_after_runner"] is True
            and value["base_database_OID_preserved"] is True,
            "increment_not_complete",
        )
        if native_protocol:
            phase = RDP_STOP_PHASE if native_protocol == "rdp" else STOP_PHASE
            need(
                value["native_PAM_transport_observed"] is True
                and phase in value["observed_UI_phases"]
                and (
                    native_protocol != "rdp" or value["native_RDP_display_and_NLA_observed"] is True
                )
                and (isolated or value["guacd_tool"] == support.tool_pin(BINARY)),
                "native_transport_incomplete",
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
    parser.add_argument("--native-ssh", action="store_true")
    args = parser.parse_args()
    support.guard(os.environ)
    os.umask(0o077)
    private, public = paths()
    support.need(
        REPO == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True) / "p1g-source",
        "committed_source_directory_required",
    )
    if args.worker:
        return worker(private, native_protocol="ssh" if args.native_ssh else None)
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
        "P1G_CHROME_MODE",
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
        command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker"]
        if args.native_ssh:
            command.append("--native-ssh")
        outcome = io_helper.run_capped(
            command,
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
            if packet["state"] == "FAILED_OR_UNKNOWN":
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
            and report.get("case") == ("native_ssh" if args.native_ssh else "portal")
            and support.sandbox_receipt(report.get("browser_sandbox"))
            and report.get("full_P1G_qualified") is False,
            "worker_packet_refused",
        )
        support.fresh_write(public / "worker-data.json", raw)
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
