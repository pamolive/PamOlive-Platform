"""Source and synthetic contracts for the relocated sandbox measurement."""

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, mock_open, patch

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
    "P1G_SANDBOX_RUNNER": "ubuntu-24.04",
}
STATUS = b"NoNewPrivs:\t1\nUid:\t1001\t1001\t1001\t1001\nGroups:\t\n" + b"".join(
    f"{cap}:\t0000000000000000\n".encode() for cap in sorted(probe.CAP_FIELDS)
)
SUCCESS = {
    "state": "SANDBOX_OBSERVED",
    "layer_one": "Namespace",
    "version": "158.0.8127.36",
    "ip_network_isolated": True,
    "namespace_control": {
        "create_user_namespace": "created",
        "sysctls": dict.fromkeys(probe.NAMESPACE_SYSCTLS, "absent"),
    },
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
            probe.run_identity(ENV),
            {"revision": "a" * 40, "run": "25", "attempt": "1", "runner": "ubuntu-24.04"},
        )
        for key, value in {
            "RUNNER_ENVIRONMENT": "self-hosted",
            "GITHUB_REPOSITORY": "fork/PamOlive-Platform",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "main",
            "P1G_SANDBOX_RUNNER": "ubuntu-latest",
        }.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.run_identity({**ENV, key: value})

    def test_host_version_and_machine_are_measured_separately_from_label(self):
        release = b'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\n'
        uname = SimpleNamespace(machine="x86_64", release="6.8.0-azure")
        with (
            patch("builtins.open", mock_open(read_data=release)),
            patch.object(probe.os, "uname", return_value=uname, create=True),
        ):
            self.assertEqual(probe.runner_facts("ubuntu-22.04")["kernel"], uname.release)
            with self.assertRaisesRegex(ValueError, "runner_os_mismatch"):
                probe.runner_facts("ubuntu-24.04")
            uname.machine = "aarch64"
            with self.assertRaisesRegex(ValueError, "runner_kernel"):
                probe.runner_facts("ubuntu-22.04")

    def test_namespace_control_records_without_writing_sysctls_or_elevating(self):
        failed = SimpleNamespace(returncode=1)
        with (
            patch("builtins.open", mock_open(read_data=b"1\n")) as read,
            patch.object(probe.subprocess, "run", return_value=failed) as run,
        ):
            result = probe.namespace_control()
        self.assertEqual(result, {"create_user_namespace": "command_failed",
                                  "sysctls": dict.fromkeys(probe.NAMESPACE_SYSCTLS, 1)})
        self.assertTrue(all(call.args[1] == "rb" for call in read.call_args_list))
        command = ["/usr/bin/unshare", "--user", "--", "/usr/bin/true"]
        self.assertEqual(run.call_args.args[0], command)
        self.assertEqual(run.call_args.kwargs["timeout"], 4)

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
                    "runner": "ubuntu-24.04",
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
        self.assertIn("P1G_SANDBOX_RUNNER=ubuntu-24.04", command)
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
                    "namespace_control": SUCCESS["namespace_control"],
                }
            )
        )
        for update in (
            {"layer_one": "SUID"},
            {"version": "157.0.8103.78"},
            {"ip_network_isolated": False},
            {"operational_GO": True},
            {"renderer_evidence": {}},
            {"namespace_control": {}},
            {"namespace_control": {
                "create_user_namespace": "created",
                "sysctls": {**SUCCESS["namespace_control"]["sysctls"],
                            "max_user_namespaces": True},
            }},
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
        self.assertEqual(
            probe.failure_code("launch", RuntimeError("version `GLIBC_2.39' not found")),
            "browser_dependencies_unavailable",
        )

    def test_resolute_selects_only_a_recognized_canonical_sudo_role(self):
        with patch.object(Path, "resolve", return_value=Path("/usr/bin/sudo-rs")) as resolve:
            self.assertEqual(probe.sudo_executable("ubuntu-26.04"), "/usr/bin/sudo-rs")
            self.assertEqual(probe.sudo_executable("ubuntu-24.04"), "/usr/bin/sudo")
        resolve.assert_called_once_with(strict=True)
        with patch.object(Path, "resolve", return_value=Path("/tmp/unreviewed")):
            with self.assertRaisesRegex(ValueError, "sudo_provider_refused"):
                probe.sudo_executable("ubuntu-26.04")

    def test_launcher_reports_only_component_from_the_same_refusal(self):
        for stderr, expected in (
            (b"setpriv: diagnostic details\n", "setpriv_refused"),
            (b"unshare: diagnostic details\n", "unshare_refused"),
            (b"sudo-rs: diagnostic details\n", "sudo_refused"),
            (b"Traceback (most recent call last):\n", "worker_exception"),
            (b"other diagnostic details\n", "launcher_unknown"),
        ):
            with self.subTest(expected=expected):
                result = SimpleNamespace(ok=False, stderr=stderr)
                io = Mock()
                io.run_capped.return_value = result
                observer = probe.LauncherObservation(io)
                self.assertIs(observer.run_capped(["synthetic"]), result)
                self.assertEqual(observer.failure, expected)

    def test_invalid_isolation_produces_refusal_without_loading_browser(self):
        with (
            patch.object(
                probe,
                "isolated_worker_status",
                side_effect=ValueError("sandbox_probe_network_namespace"),
            ),
            patch.object(probe, "browser_probe") as browser,
            patch.object(probe, "namespace_control") as control,
        ):
            refusal = probe.worker(Path("synthetic"), 35)
        browser.assert_not_called()
        control.assert_not_called()
        self.assertEqual(refusal["code"], "sandbox_probe_network_namespace")
        self.assertTrue(probe.valid_worker_result(refusal))
        self.assertFalse(probe.valid_worker_result({**refusal, "ip_network_isolated": True}))

    def test_node_pin_accepts_only_the_locked_linux_wheel_driver(self):
        node = Path("synthetic")
        pin = {
            "bytes": lab_support.SDK_NODE_BYTES,
            "sha256": lab_support.SDK_NODE_SHA,
        }
        with patch.object(lab_support, "tool_pin", return_value=pin) as reader:
            self.assertEqual(lab_support.playwright_node_pin(node), pin)
        reader.assert_called_once_with(node, root_owner=False, cap=lab_support.SDK_NODE_BYTES)
        with patch.object(lab_support, "tool_pin", return_value={**pin, "sha256": "0" * 64}):
            with self.assertRaisesRegex(ValueError, "playwright_driver_identity"):
                lab_support.playwright_node_pin(node)

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
