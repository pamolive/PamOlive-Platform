import os
import runpy
import subprocess
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured

ROOT = Path(__file__).resolve().parents[1]
SIGNING_KEY = "synthetic-signing-key-for-configuration-tests-only"
# Exactly 40 characters, including spaces that must survive validation.
ENCRYPTION_KEY = " " + "synthetic-encryption-configuration-key" + " "
INVALID_KEYS = ("", " " * 40, "x" * 39, "x" * 40 + "\n")


class ChildLaunchAttempted(Exception):
    """Stop the supervisor at the first child without starting any service."""


class KeyConfigurationTests(TestCase):
    def test_settings_refuse_invalid_encryption_keys(self):
        for value in INVALID_KEYS:
            with (
                self.subTest(length=len(value)),
                patch.dict(
                    os.environ,
                    {"SECRET_KEY": SIGNING_KEY, "PAMOLIVE_ENCRYPTION_KEY": value},
                    clear=True,
                ),
                self.assertRaisesRegex(ImproperlyConfigured, "PAMOLIVE_ENCRYPTION_KEY"),
            ):
                runpy.run_path(str(ROOT / "config/settings.py"))

    def test_supervisor_refuses_invalid_encryption_keys_before_starting_children(self):
        for value in INVALID_KEYS:
            with (
                self.subTest(length=len(value)),
                patch.dict(
                    os.environ,
                    {
                        "SECRET_KEY": SIGNING_KEY,
                        "PAMOLIVE_ENCRYPTION_KEY": value,
                        "DATABASE_URL": "postgresql://fixture@127.0.0.1/fixture",
                    },
                    clear=True,
                ),
                patch.object(os, "geteuid", return_value=0, create=True),
                patch("signal.signal"),
                patch.object(subprocess, "Popen", side_effect=ChildLaunchAttempted) as launch,
                self.assertRaisesRegex(SystemExit, "PAMOLIVE_ENCRYPTION_KEY"),
            ):
                runpy.run_path(str(ROOT / "deploy/runtime.py"))
            launch.assert_not_called()

    def test_explicitly_blank_signing_key_is_rejected_even_with_an_encryption_key(self):
        for value in ("", " " * 40):
            with (
                self.subTest(length=len(value)),
                patch.dict(
                    os.environ,
                    {"SECRET_KEY": value, "PAMOLIVE_ENCRYPTION_KEY": ENCRYPTION_KEY},
                    clear=True,
                ),
                self.assertRaisesRegex(ImproperlyConfigured, "SECRET_KEY"),
            ):
                runpy.run_path(str(ROOT / "config/settings.py"))

    def test_absent_encryption_key_uses_unchanged_signing_key(self):
        with patch.dict(os.environ, {"SECRET_KEY": SIGNING_KEY}, clear=True):
            config = runpy.run_path(str(ROOT / "config/settings.py"))
        self.assertEqual(config["PAMOLIVE_ENCRYPTION_KEY"], SIGNING_KEY)

    def test_valid_explicit_key_is_preserved_exactly(self):
        self.assertEqual(len(ENCRYPTION_KEY), 40)
        with patch.dict(
            os.environ,
            {"SECRET_KEY": SIGNING_KEY, "PAMOLIVE_ENCRYPTION_KEY": ENCRYPTION_KEY},
            clear=True,
        ):
            config = runpy.run_path(str(ROOT / "config/settings.py"))
        self.assertEqual(config["PAMOLIVE_ENCRYPTION_KEY"], ENCRYPTION_KEY)

    def test_build_can_load_settings_without_either_key(self):
        with patch.dict(os.environ, {}, clear=True):
            config = runpy.run_path(str(ROOT / "config/settings.py"))
        self.assertEqual(config["PAMOLIVE_ENCRYPTION_KEY"], config["SECRET_KEY"])

    def test_supervisor_accepts_absent_and_valid_encryption_keys(self):
        for key_env in ({}, {"PAMOLIVE_ENCRYPTION_KEY": ENCRYPTION_KEY}):
            with (
                self.subTest(explicit=bool(key_env)),
                patch.dict(
                    os.environ,
                    {
                        "SECRET_KEY": SIGNING_KEY,
                        "DATABASE_URL": "postgresql://fixture@127.0.0.1/fixture",
                        **key_env,
                    },
                    clear=True,
                ),
                patch.object(os, "geteuid", return_value=0, create=True),
                patch("signal.signal"),
                patch.object(subprocess, "Popen", side_effect=ChildLaunchAttempted) as launch,
                self.assertRaises(ChildLaunchAttempted),
            ):
                runpy.run_path(str(ROOT / "deploy/runtime.py"))
            launch.assert_called_once()
