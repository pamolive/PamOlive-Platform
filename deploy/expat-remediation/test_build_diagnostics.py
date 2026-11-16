"""Public build failure diagnostics preserve failure and execute no process."""

import base64
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import build_debian


class BuildDiagnosticTests(unittest.TestCase):
    def test_narrow_and_wide_commands_keep_limits_and_failure_identity(self):
        for tree in ("build", "buildw"):
            for failed in (False, True):
                with self.subTest(tree=tree, failed=failed):
                    error = ValueError("child_failed_or_unknown")
                    output = io.StringIO()
                    with (
                        mock.patch.object(
                            build_debian,
                            "command",
                            side_effect=error if failed else None,
                        ) as command,
                        mock.patch.object(
                            build_debian, "read", return_value=b"public test log"
                        ) as read,
                        redirect_stdout(output),
                    ):
                        if failed:
                            with self.assertRaises(ValueError) as caught:
                                build_debian.check_tree(Path("/source"), Path("/output"), tree)
                            self.assertIs(caught.exception, error)
                        else:
                            build_debian.check_tree(Path("/source"), Path("/output"), tree)
                    command.assert_called_once_with(
                        ["/usr/bin/make", "-j1", "-C", tree, "check"],
                        Path("/source"),
                        Path("/output") / (tree + "-check"),
                        seconds=300,
                        cap=8 * 1024**2,
                    )
                    if failed:
                        packet = json.loads(output.getvalue())
                        self.assertEqual(packet["stage"], "make-" + tree + "-check")
                        self.assertEqual(packet["state"], "FAILED_OR_UNKNOWN")
                    else:
                        read.assert_not_called()
                        self.assertEqual(output.getvalue(), "")

    def test_unknown_test_tree_and_diagnostic_stage_are_refused_before_io(self):
        with (
            mock.patch.object(build_debian, "command") as command,
            mock.patch.object(build_debian, "read") as read,
        ):
            for tree in ("../foreign", "build/other", "BUILD", "", None):
                with self.subTest(tree=tree), self.assertRaises(ValueError):
                    build_debian.check_tree(Path("/source"), Path("/output"), tree)
            with self.assertRaises(ValueError):
                build_debian.publish_build_failure(Path("/log"), stage="private-authentication")
        command.assert_not_called()
        read.assert_not_called()

    def test_success_keeps_command_limits_and_does_not_publish_logs(self):
        output = io.StringIO()
        with (
            mock.patch.object(build_debian, "command", return_value=b"ok") as command,
            mock.patch.object(build_debian, "read") as read,
            redirect_stdout(output),
        ):
            build_debian.build_package(Path("/source"), Path("/log"))
        command.assert_called_once_with(
            ["/usr/bin/dpkg-buildpackage", "-us", "-uc", "-b", "-aamd64"],
            Path("/source"),
            Path("/log"),
            seconds=900,
            cap=8 * 1024**2,
            env=build_debian.ENV | {"DEB_BUILD_PROFILES": "noudeb"},
        )
        read.assert_not_called()
        self.assertEqual(output.getvalue(), "")

    def test_failure_tails_are_bounded_encoded_and_same_exception_is_raised(self):
        error = ValueError("child_failed_or_unknown")
        sentinel = b"::error::SYNTHETIC_BUILD_MARKER\x1b[31m\n"
        payload = b"x" * 9000 + sentinel
        receipt = b'{"owned_child_reaped":false,"returncode":null}'
        output = io.StringIO()
        with (
            mock.patch.object(build_debian, "command", side_effect=error) as command,
            mock.patch.object(
                build_debian,
                "read",
                side_effect=lambda path, cap: receipt if path.name == "result.json" else payload,
            ) as read,
            redirect_stdout(output),
            self.assertRaises(ValueError) as caught,
        ):
            build_debian.build_package(Path("/source"), Path("/log"))
        self.assertIs(caught.exception, error)
        command.assert_called_once()
        self.assertEqual(
            read.call_args_list,
            [
                mock.call(Path("/log") / "stdout", 8 * 1024**2),
                mock.call(Path("/log") / "stderr", 8 * 1024**2),
                mock.call(Path("/log") / "result.json", 4096),
            ],
        )
        raw = output.getvalue()
        self.assertNotIn("SYNTHETIC_BUILD_MARKER", raw)
        self.assertNotIn("::error::", raw)
        self.assertNotIn("\x1b", raw)
        packet = json.loads(raw)
        self.assertEqual(packet["state"], "FAILED_OR_UNKNOWN")
        self.assertTrue(packet["diagnostic_only"])
        self.assertLess(len(raw), 30000)
        self.assertEqual(
            base64.b64decode(packet["process_receipt"]["receipt_base64"], validate=True),
            receipt,
        )
        for stream in packet["streams"].values():
            self.assertEqual(stream["tail_bytes"], 8192)
            self.assertEqual(
                base64.b64decode(stream["tail_base64"], validate=True), payload[-8192:]
            )

    def test_unreadable_logs_do_not_turn_unknown_into_success_or_run_again(self):
        error = ValueError("child_failed_or_unknown")
        output = io.StringIO()
        with (
            mock.patch.object(build_debian, "command", side_effect=error) as command,
            mock.patch.object(build_debian, "read", side_effect=ValueError("regular file refused")),
            redirect_stdout(output),
            self.assertRaises(ValueError) as caught,
        ):
            build_debian.build_package(Path("/source"), Path("/log"))
        self.assertIs(caught.exception, error)
        command.assert_called_once()
        packet = json.loads(output.getvalue())
        self.assertEqual(
            packet["streams"],
            {
                "stdout": {"available": False},
                "stderr": {"available": False},
            },
        )
        self.assertEqual(packet["state"], "FAILED_OR_UNKNOWN")
        self.assertEqual(packet["process_receipt"], {"available": False})
        closed = io.StringIO()
        closed.close()
        with (
            mock.patch.object(build_debian, "command", side_effect=error) as command,
            mock.patch.object(build_debian, "read", return_value=b"public build output"),
            redirect_stdout(closed),
            self.assertRaises(ValueError) as caught,
        ):
            build_debian.build_package(Path("/source"), Path("/log"))
        self.assertIs(caught.exception, error)
        command.assert_called_once()
