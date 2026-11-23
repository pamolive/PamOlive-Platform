"""Synthetic metadata contracts without network, GPG or browser execution."""

import email.utils
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from qualification.p1g_headless import chrome_metadata as metadata

SOURCE = Path(__file__).resolve().parent / "chrome_materials"


class MetadataTests(unittest.TestCase):
    def test_scope_requires_the_repository_restricted_push_and_typed_run_ids(self):
        env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": metadata.REPOSITORY,
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": metadata.BRANCH,
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "1",
            "GITHUB_RUN_ATTEMPT": "2",
        }
        self.assertEqual(metadata.run_identity(env)["revision"], "a" * 40)
        for changed, reason in (
            ({"GITHUB_REPOSITORY": "synthetic/fork"}, "scope"),
            ({"GITHUB_EVENT_NAME": "pull_request"}, "scope"),
            ({"GITHUB_REF": "refs/heads/main"}, "scope"),
            ({"GITHUB_RUN_ID": "../unsafe"}, "identity"),
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, reason):
                metadata.run_identity({**env, **changed})

    def test_only_the_three_fixed_https_metadata_paths_are_fetched(self):
        commands = Mock()
        commands.run.side_effect = [b"release\n200", b"signature\n200", b"index\n200"]
        self.assertEqual(
            metadata.fetch_indexes(commands),
            {
                "Release": b"release",
                "Release.gpg": b"signature",
                "Packages": b"index",
            },
        )
        urls = [call.args[0][-1] for call in commands.run.call_args_list]
        self.assertEqual(
            urls,
            [
                "https://dl.google.com/linux/chrome/deb/dists/stable/Release",
                "https://dl.google.com/linux/chrome/deb/dists/stable/Release.gpg",
                "https://dl.google.com/linux/chrome/deb/dists/stable/main/binary-amd64/Packages",
            ],
        )
        commands.reset_mock(side_effect=True)
        commands.run.return_value = b"unexpected\n301"
        with self.assertRaisesRegex(ValueError, "metadata_http_response"):
            metadata.fetch_indexes(commands)
        self.assertEqual(commands.run.call_count, 1)

    def test_valid_signature_precedes_release_and_package_checks(self):
        raw = {name: (SOURCE / name).read_bytes() for name in metadata.INDEX_FILES}
        key = (SOURCE / "google-key.asc").read_bytes()
        previous = metadata.package_record(raw["Packages"])
        date = metadata.bootstrap.fields(raw["Release"])["Date"]
        now = int(email.utils.parsedate_to_datetime(date).timestamp()) + 60
        for signature_valid, index in (
            (False, raw["Packages"]),
            (True, raw["Packages"] + b"changed"),
            (True, raw["Packages"]),
        ):
            with (
                tempfile.TemporaryDirectory() as temporary,
                patch.object(metadata, "fetch_indexes", return_value={**raw, "Packages": index}),
                patch.object(metadata.time, "time", return_value=now),
                patch.object(metadata.chrome_key_scope, "authenticate") as authenticate,
            ):
                directory = Path(temporary)
                authenticate.return_value = (
                    {"primary": "synthetic"},
                    {"scoped_sha256": "synthetic"},
                    None,
                    None,
                )
                if not signature_valid:
                    authenticate.side_effect = ValueError("signature_refused")
                    with (
                        patch.object(metadata.bootstrap, "release_check") as release,
                        self.assertRaisesRegex(ValueError, "signature_refused"),
                    ):
                        metadata.acquire(Mock(), directory, directory, key, previous)
                    release.assert_not_called()
                elif index != raw["Packages"]:
                    with self.assertRaisesRegex(ValueError, "release_Packages_binding"):
                        metadata.acquire(Mock(), directory, directory, key, previous)
                else:
                    _, record = metadata.acquire(
                        Mock(),
                        directory,
                        directory,
                        key,
                        {**previous, "Version": "1.2.3.4-1"},
                    )
                    self.assertFalse(record["same_package_as_previous_pin"])
                    self.assertEqual(record["package"], previous)
                authenticate.assert_called_once()

    def test_package_inventory_refuses_altered_record_before_any_download(self):
        package = metadata.package_record((SOURCE / "Packages").read_bytes())
        commands = Mock()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "inventory_package_pin"):
                metadata.inspect_package(commands, Path(temporary), package, {})
            self.assertEqual(list(Path(temporary).iterdir()), [])
        commands.run.assert_not_called()

    def test_package_inventory_authenticates_bytes_before_dpkg(self):
        package = metadata.package_record((SOURCE / "Packages").read_bytes())
        binary = b"synthetic package bytes"
        package.update(Size=str(len(binary)), SHA256=metadata.bootstrap.sha(binary))
        pin = metadata.bootstrap.sha(
            json.dumps(
                package,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
        commands = Mock()
        commands.until = 500

        def run(argv, *, sink=None, **_kwargs):
            if argv[0] == "/usr/bin/curl":
                sink.write(binary.upper())
                return b""
            raise AssertionError("A bad package reached a native archive tool")

        commands.run.side_effect = run
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(metadata, "INVENTORY_PACKAGE_RECORD", pin),
            self.assertRaisesRegex(ValueError, "inventory_package_bytes"),
        ):
            receipt = {}
            metadata.inspect_package(commands, Path(temporary), package, receipt)
        self.assertTrue(receipt["browser_package_download_attempted"])
        self.assertTrue(receipt["browser_package_downloaded"])
        self.assertEqual(commands.run.call_count, 1)
