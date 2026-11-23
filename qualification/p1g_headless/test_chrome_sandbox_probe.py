"""Source and synthetic contracts for the relocated sandbox measurement."""

import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from qualification.p1g_headless import chrome_sandbox_probe as probe
from qualification.p1g_headless import lab_support

ENV = {
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "GITHUB_REPOSITORY": "pamolive/PamOlive-Platform",
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_REF": probe.BRANCH,
    "GITHUB_SHA": "a" * 40,
    "GITHUB_RUN_ID": "25",
    "GITHUB_RUN_ATTEMPT": "1",
}
STATUS = b"NoNewPrivs:\t1\nUid:\t1001\t1001\t1001\t1001\nGroups:\t\n" + b"".join(
    f"{cap}:\t0000000000000000\n".encode() for cap in sorted(probe.CAP_FIELDS)
)
SUCCESS = {
    "state": "SANDBOX_OBSERVED",
    "layer_one": "Namespace",
    "version": "158.0.8127.36",
    "ip_network_isolated": True,
    "renderer_evidence": {
        "schema": "pamolive.p1g-active-sandbox/1",
        "browser_apparmor": "unconfined",
        "renderer_apparmor": ["unconfined"],
        "renderers_checked": 1,
    },
}


class SandboxProbeTests(unittest.TestCase):
    def test_scope_refuses_other_runners_forks_and_branches(self):
        self.assertEqual(
            probe.run_identity(ENV), {"revision": "a" * 40, "run": "25", "attempt": "1"}
        )
        for key, value in {
            "RUNNER_ENVIRONMENT": "self-hosted",
            "GITHUB_REPOSITORY": "fork/PamOlive-Platform",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "main",
        }.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.run_identity({**ENV, key: value})

    def test_isolation_requires_fresh_network_namespace_and_unprivileged_status(self):
        arguments = (STATUS, [(1, "lo")], 23, 27, [], 1001)
        probe.check_isolation(*arguments)
        for index, invalid in (
            (0, STATUS.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0")),
            (0, STATUS.replace(b"Groups:\t\n", b"Groups:\t110\n")),
            (0, STATUS.replace(b"CapBnd:\t0000000000000000", b"CapBnd:\t0000000000000001")),
            (0, STATUS + b"NoNewPrivs:\t1\n"),
            (1, [(1, "lo"), (2, "eth0")]),
            (3, 23),
            (4, [2]),
            (5, 0),
        ):
            options = list(arguments)
            options[index] = invalid
            with self.subTest(index=index), self.assertRaises(ValueError):
                probe.check_isolation(*options)

    def test_abandon_privileges_before_entering_python(self):
        with (
            patch.object(probe.os, "getuid", return_value=1001, create=True),
            patch.object(probe.os, "getgid", return_value=101, create=True),
        ):
            command = probe.worker_command(
                Path("/scratch/work"),
                Path("/scratch"),
                {
                    "revision": "a" * 40,
                    "run": "25",
                    "attempt": "2",
                },
                123,
            )
        self.assertEqual(
            command[:8],
            [
                "/usr/bin/sudo",
                "-n",
                "--",
                "/usr/bin/unshare",
                "--net",
                "--",
                "/usr/bin/setpriv",
                "--reuid",
            ],
        )
        self.assertIn("--no-new-privs", command)
        self.assertIn("--bounding-set=-all", command)
        self.assertIn("--clear-groups", command)
        self.assertLess(command.index("--ambient-caps=-all"), command.index("/usr/bin/env"))
        self.assertEqual(
            command[-4:], ["--worker", str(Path("/scratch/work")), "--host-net", "123"]
        )

    def test_synthetic_probe_cannot_accept_suid_or_ambiguous_results(self):
        self.assertTrue(probe.valid_worker_result(SUCCESS))
        self.assertTrue(
            probe.valid_worker_result(
                {
                    "state": "REFUSED",
                    "phase": "launch",
                    "ip_network_isolated": True,
                    "code": "namespace_startup_refused",
                }
            )
        )
        for update in (
            {"layer_one": "SUID"},
            {"version": "157.0.8103.78"},
            {"ip_network_isolated": False},
            {"operational_GO": True},
            {"renderer_evidence": {}},
        ):
            with self.subTest(update=update):
                self.assertFalse(probe.valid_worker_result({**SUCCESS, **update}))

    def test_launch_diagnostic_exports_only_a_closed_code(self):
        self.assertEqual(
            probe.failure_code("launch", RuntimeError("No usable sandbox")),
            "namespace_startup_refused",
        )
        self.assertEqual(
            probe.failure_code("launch", RuntimeError("unclassified error details")),
            "browser_measurement_refused",
        )

    def test_shared_browser_observer_refuses_suid_before_renderer_proof_in_probe(self):
        browser = Mock()
        context = browser.new_context.return_value
        context.new_page.return_value.url = lab_support.SANDBOX_URL
        with (
            patch.object(lab_support.os, "getuid", return_value=1001, create=True),
            patch.object(lab_support, "sandbox_diagnostic", return_value="SUID"),
            self.assertRaisesRegex(ValueError, "sandbox_namespace_required"),
        ):
            lab_support.observe_browser_sandbox(browser, Path("synthetic"), namespace_only=True)
        browser.new_browser_cdp_session.assert_not_called()
        context.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
