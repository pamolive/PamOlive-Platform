from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.test import TestCase
from django.utils import timezone

from platform_core.extensions.api import require_delivery
from platform_core.models import ExtensionDeployment, ModuleActivation, Organization
from platform_core.registry import ModuleDefinition
from platform_core.services import require_module


class ModuleDependencyClosureTests(TestCase):
    def setUp(self):
        self.first = Organization.objects.create(key="module-closure-a", name="A")
        self.second = Organization.objects.create(key="module-closure-b", name="B")
        for organization in (self.first, self.second):
            for key in ("identity", "access", "approvals", "pam"):
                self.activate(organization, key)

    def activate(self, organization, key, *, enabled=True, version="0.2.0", release_hash=""):
        return ModuleActivation.objects.update_or_create(
            organization=organization,
            module_key=key,
            defaults={"enabled": enabled, "version": version, "release_hash": release_hash},
        )[0]

    def test_builtin_checks_the_full_graph_in_one_query_without_cross_org_fallback(self):
        with self.assertNumQueries(1):
            require_module(self.first, "pam")
        self.activate(self.first, "identity", enabled=False)
        with self.assertNumQueries(1), self.assertRaises(PermissionDenied):
            require_module(self.first, "pam")
        require_module(self.second, "pam")
        self.assertTrue(
            ModuleActivation.objects.get(organization=self.first, module_key="pam").enabled
        )
        self.activate(self.first, "identity")
        require_module(self.first, "pam")

    def test_missing_definition_or_cycle_fails_closed_before_database_access(self):
        def definition(key, *dependencies):
            return ModuleDefinition(key, key, "0.2.0", "", "test", dependencies=dependencies)

        with patch.dict(
            "platform_core.registry._modules",
            {
                "mock_unresolved": definition("mock_unresolved", "missing"),
                "mock_cycle_a": definition("mock_cycle_a", "mock_cycle_b"),
                "mock_cycle_b": definition("mock_cycle_b", "mock_cycle_a"),
            },
        ):
            for key in ("mock_unresolved", "mock_cycle_a"):
                with (
                    self.subTest(key=key),
                    self.assertNumQueries(0),
                    self.assertRaises(PermissionDenied),
                ):
                    require_module(self.first, key)

    def test_extension_cannot_use_a_builtin_dependency_with_a_broken_chain(self):
        manifest = SimpleNamespace(
            key="closure_fixture",
            version="0.2.0",
            dependencies=(SimpleNamespace(key="pam", version_spec=">=0.2.0,<0.3"),),
        )
        release = SimpleNamespace(
            manifest=manifest, release_hash="a" * 64, manifest_hash="b" * 64, wheel_sha256="c" * 64
        )
        ExtensionDeployment.objects.create(
            module_key=manifest.key,
            version=manifest.version,
            release_hash=release.release_hash,
            manifest_hash=release.manifest_hash,
            wheel_hash=release.wheel_sha256,
            delivered_at=timezone.now(),
            delivered_by=get_user_model().objects.create_user("module-closure-publisher"),
        )
        for organization in (self.first, self.second):
            self.activate(organization, manifest.key, release_hash=release.release_hash)
        with self.settings(PAMOLIVE_EXTENSIONS=(release,)):
            self.assertIs(require_delivery(self.first, manifest.key), release)
            self.activate(self.first, "approvals", enabled=False)
            with self.assertRaises(PermissionDenied):
                require_delivery(self.first, manifest.key)
            self.assertIs(require_delivery(self.second, manifest.key), release)
