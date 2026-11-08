import copy
import importlib
import importlib.metadata
import io
import json
import os
import sys
import tempfile
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from platform_core.extensions.manifest import BUILTIN_VERSIONS, ExtensionError, ModuleManifest
from platform_core.extensions.release import main as release_main
from platform_core.extensions.release import sign_payload
from platform_core.extensions.releases import (
    inspect_wheel,
    load_catalog,
    load_trust_keys,
    read_json,
    verify_installed,
    verify_payload,
    verify_wheelhouse,
)
from platform_core.registry import get_module

from .extension_fixtures import SOURCE, build_wheel, signed_fixture


class ExtensionReleaseTests(SimpleTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="pamolive-extension-unit-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.wheel, self.manifest, self.key, self.envelope, self.trust, self.catalog = (
            signed_fixture(self.directory)
        )

    def signed(self, payload):
        return sign_payload(payload, self.key, "test-publisher")

    def installed(self):
        target = self.directory / "installed"
        target.mkdir()
        with zipfile.ZipFile(self.wheel) as archive:
            archive.extractall(target)
        distribution = importlib.metadata.PathDistribution(
            target / "pamolive_example_notes-1.0.0.dist-info"
        )
        patched = patch(
            "platform_core.extensions.releases.importlib.metadata.distribution",
            return_value=distribution,
        )
        patched.start()
        self.addCleanup(patched.stop)
        sys.path.insert(0, str(target))
        self.addCleanup(sys.path.remove, str(target))
        importlib.invalidate_caches()
        return target

    def test_manifest_is_immutable_and_matches_builtin_version_contract(self):
        self.assertEqual(ModuleManifest.from_dict(self.manifest.to_dict()), self.manifest)
        for key, version in BUILTIN_VERSIONS.items():
            self.assertEqual(get_module(key).version, version)
        with self.assertRaises(AttributeError):
            self.manifest.key = "tamper"

    def test_offline_cli_generates_protected_keys_signs_and_locks_a_release(self):
        private = self.directory / "cli-private.pem"
        public = self.directory / "cli-public.json"
        release = self.directory / "cli-release.json"
        catalog = self.directory / "cli-catalog.json"
        lock = self.directory / "cli-requirements.lock"
        output = io.StringIO()
        password = "fixture-passphrase-only"
        commands = [
            [
                "keygen",
                "--private-key",
                str(private),
                "--public-keys",
                str(public),
                "--key-id",
                "cli-test",
            ],
            [
                "sign",
                "--wheel",
                str(self.wheel),
                "--manifest",
                str(SOURCE / "pamolive_ext_notes" / "manifest.json"),
                "--private-key",
                str(private),
                "--key-id",
                "cli-test",
                "--output",
                str(release),
            ],
            [
                "catalog",
                "--release",
                str(release),
                "--public-keys",
                str(public),
                "--output",
                str(catalog),
                "--lock-output",
                str(lock),
            ],
            [
                "verify-catalog-wheels",
                "--catalog",
                str(catalog),
                "--wheelhouse",
                str(self.directory),
                "--public-keys",
                str(public),
                "--requirements-lock",
                str(lock),
            ],
        ]
        with redirect_stdout(output), patch("getpass.getpass", return_value=password):
            for command in commands:
                with patch.object(sys, "argv", ["release", *command]):
                    release_main()
        self.assertIn(b"ENCRYPTED PRIVATE KEY", private.read_bytes())
        if os.name != "nt":
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(password, output.getvalue())
        verify_wheelhouse(
            read_json(catalog.read_bytes()), read_json(public.read_bytes()), self.directory, lock
        )

    def test_release_cli_does_not_overwrite_an_existing_key(self):
        private = self.directory / "existing-private.pem"
        private.write_bytes(b"preserve-existing-key")
        with (
            patch.object(
                sys,
                "argv",
                [
                    "release",
                    "keygen",
                    "--private-key",
                    str(private),
                    "--public-keys",
                    str(self.directory / "public.json"),
                    "--key-id",
                    "test",
                ],
            ),
            patch("getpass.getpass") as prompt,
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                release_main()
        prompt.assert_not_called()
        self.assertEqual(private.read_bytes(), b"preserve-existing-key")

    def test_wheel_and_signature_can_be_verified_without_importing_code(self):
        self.assertEqual(verify_payload(self.envelope, self.trust)[0], self.manifest)
        self.assertEqual(inspect_wheel(self.wheel, self.manifest), self.envelope["payload"])
        self.assertNotIn(self.manifest.package, sys.modules)

    def test_unknown_publisher_and_wrong_signature_are_rejected(self):
        with self.assertRaises(ExtensionError):
            verify_payload(self.envelope, {})
        forged = copy.deepcopy(self.envelope)
        forged["payload"]["manifest"]["name"] = "forged"
        with self.assertRaises(ExtensionError):
            verify_payload(forged, self.trust)

    def test_duplicate_json_keys_are_not_a_signature_ambiguity(self):
        with self.assertRaises(ExtensionError):
            read_json(b'{"schema":"one","schema":"two"}')

    def test_signed_path_traversal_cannot_read_outside_package(self):
        payload = copy.deepcopy(self.envelope["payload"])
        payload["files"]["../secret"] = "0" * 64
        with self.assertRaises(ExtensionError):
            verify_payload(self.signed(payload), self.trust)

    def test_reserved_keys_routes_and_undeclared_permissions_are_rejected(self):
        changes = [
            {"key": "identity"},
            {"core_spec": ">=9"},
            {"api_version": "99"},
            {"license_kind": "commercial"},
            {"package": "platform_core"},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ExtensionError):
                ModuleManifest.from_dict(self.manifest.to_dict() | change)
        for path in ["../admin/", "/admin/", "<path:everything>", "<uuid:id>/../../admin/"]:
            data = self.manifest.to_dict()
            data["routes"][1]["path"] = path
            with self.subTest(path=path), self.assertRaises(ExtensionError):
                ModuleManifest.from_dict(data)
        data = self.manifest.to_dict()
        data["routes"][1]["permission"] = "other.secret.reveal"
        with self.assertRaises(ExtensionError):
            ModuleManifest.from_dict(data)

    def test_post_requires_a_sensitive_permission(self):
        data = self.manifest.to_dict()
        data["permissions"][1]["sensitive"] = False
        with self.assertRaises(ExtensionError):
            ModuleManifest.from_dict(data)

    def test_route_guard_does_not_inherit_a_csrf_exemption(self):
        from platform_core.extensions.urls import guarded_view

        def view(request):
            return None

        view.csrf_exempt = True
        wrapped = guarded_view(view, self.manifest.routes[1], self.manifest)
        self.assertIs(wrapped.csrf_exempt, False)

    def test_installer_lock_cannot_add_an_unapproved_url_or_wheel(self):
        lock = self.directory / "requirements.lock"
        payload = self.envelope["payload"]
        expected = (
            f"{payload['distribution']}=={payload['version']} "
            f"--hash=sha256:{payload['wheel_sha256']}\n"
        )
        lock.write_text(expected, encoding="utf8")
        catalog = {"schema": "pamolive.extension-catalog.v1", "releases": [self.envelope]}
        verify_wheelhouse(catalog, self.trust, self.directory, lock)
        for addition in (
            "https://unapproved.example/code.whl\n",
            "--extra-index-url https://unapproved.example\n",
        ):
            lock.write_text(expected + addition, encoding="utf8")
            with self.assertRaises(ExtensionError):
                verify_wheelhouse(catalog, self.trust, self.directory, lock)

    def test_wheel_cannot_overwrite_core_or_install_startup_hooks(self):
        for name in [
            "platform_core/backdoor.py",
            "startup.pth",
            "pamolive_ext_notes/code.pyc",
            "pamolive_ext_notes/__pycache__/views.cpython-312.pyc",
        ]:
            with self.subTest(name=name):
                wheel = build_wheel(self.directory, {name: b"tamper"})
                with self.assertRaises(ExtensionError):
                    inspect_wheel(wheel, self.manifest)

    def test_installed_inventory_matches_signed_release_before_import(self):
        self.installed()
        release = verify_installed(self.envelope, self.trust)
        self.assertEqual(release.manifest, self.manifest)
        self.assertEqual(load_catalog(self.catalog, self.trust), (release,))
        self.assertNotIn(self.manifest.package, sys.modules)

    def test_tampered_python_is_rejected_without_running_its_initializer(self):
        target = self.installed()
        marker = self.directory / "executed"
        (target / "pamolive_ext_notes" / "__init__.py").write_text(
            f"from pathlib import Path;Path({str(marker)!r}).touch()", encoding="utf8"
        )
        with self.assertRaises(ExtensionError):
            verify_installed(self.envelope, self.trust)
        self.assertFalse(marker.exists())

    def test_unlisted_source_or_bytecode_is_rejected(self):
        target = self.installed()
        extra = target / "pamolive_ext_notes" / "hidden.pyc"
        extra.write_bytes(b"code")
        with self.assertRaises(ExtensionError):
            verify_installed(self.envelope, self.trust)

    def test_untrusted_key_file_and_shadowed_import_are_rejected(self):
        self.assertEqual(load_trust_keys(json.dumps(self.trust)), self.trust)
        for value in ("[]", '{"bad":"not-base64"}'):
            with self.assertRaises(ExtensionError):
                load_trust_keys(value)
        with self.assertRaises(ExtensionError):
            load_trust_keys(json.dumps(self.trust), str(self.catalog))
        self.installed()
        with patch(
            "platform_core.extensions.releases.importlib.machinery.PathFinder.find_spec"
        ) as finder:
            finder.return_value.origin = str(self.directory / "other" / "__init__.py")
            with self.assertRaises(ExtensionError):
                verify_installed(self.envelope, self.trust)

    def test_dependency_compatibility_is_checked_before_any_import(self):
        data = self.manifest.to_dict()
        data["dependencies"][0]["version_spec"] = ">=99"
        self.wheel = build_wheel(
            self.directory, {"pamolive_ext_notes/manifest.json": json.dumps(data).encode()}
        )
        payload = inspect_wheel(self.wheel, ModuleManifest.from_dict(data))
        self.installed()
        envelope = self.signed(payload)
        self.catalog.write_text(
            json.dumps({"schema": "pamolive.extension-catalog.v1", "releases": [envelope]}),
            encoding="utf8",
        )
        with self.assertRaises(ExtensionError):
            load_catalog(self.catalog, self.trust)
        self.assertNotIn(self.manifest.package, sys.modules)

    def test_missing_package_and_duplicate_catalog_keys_are_rejected(self):
        with patch(
            "platform_core.extensions.releases.importlib.metadata.distribution",
            side_effect=importlib.metadata.PackageNotFoundError,
        ):
            with self.assertRaises(ExtensionError):
                verify_installed(self.envelope, self.trust)
        self.installed()
        self.catalog.write_text(
            json.dumps(
                {
                    "schema": "pamolive.extension-catalog.v1",
                    "releases": [self.envelope, self.envelope],
                }
            ),
            encoding="utf8",
        )
        with self.assertRaises(ExtensionError):
            load_catalog(self.catalog, self.trust)
