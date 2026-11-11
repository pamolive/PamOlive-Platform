"""The native UI, session API and export share one guarded contract reader."""

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.test import TestCase, override_settings
from django.urls import reverse

from platform_core.access_contract import build_access_contract
from platform_core.models import ModuleActivation, OrganizationMembership
from platform_core.product_modules import product_module_mapping

from . import test_platform as baseline


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class AccessContractViewsTests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        self.intent = baseline.PlatformTests.intent(self)
        self.client.force_login(self.operator)

    def test_ui_api_and_export_share_the_versioned_reading(self):
        page = self.client.get(reverse("access-contract-detail", args=[self.intent.pk]))
        self.assertContains(page, "Parcours de l’accès")
        self.assertContains(page, "Aucune exécution confirmée")
        for name in ("api-access-contract", "access-contract-export"):
            response = self.client.get(reverse(name, args=[self.intent.pk]))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["schema"], "pamolive.access-contract/1")
            self.assertEqual(response.json()["intention"]["id"], str(self.intent.pk))
            self.assertEqual(response["Cache-Control"], "no-store")
            self.assertEqual(response.json()["confirmed_executions"]["items"], [])
        self.assertIn("attachment", response["Content-Disposition"])

    def test_another_tenant_cannot_read_any_surface(self):
        foreign = get_user_model().objects.create_user("contract-other")
        OrganizationMembership.objects.create(
            organization=self.other, account=foreign, role="auditor"
        )
        ModuleActivation.objects.bulk_create([
            ModuleActivation(organization=self.other, module_key=key, enabled=True, version="test")
            for key in ("identity", "access")
        ])
        self.client.force_login(foreign)
        for name in ("access-contract-detail", "api-access-contract", "access-contract-export"):
            self.assertEqual(self.client.get(reverse(name, args=[self.intent.pk])).status_code, 404)

    def test_disabled_base_module_blocks_all_surfaces(self):
        ModuleActivation.objects.filter(organization=self.org, module_key="identity").update(
            enabled=False
        )
        for name in ("access-contract-detail", "api-access-contract", "access-contract-export"):
            self.assertEqual(self.client.get(reverse(name, args=[self.intent.pk])).status_code, 403)

    def test_disabled_optional_domain_is_explicitly_unavailable(self):
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        response = self.client.get(reverse("api-access-contract", args=[self.intent.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["confirmed_executions"], {
            "availability": "module_disabled", "items": [], "truncated": False,
        })

    def test_session_authentication_and_read_only_http(self):
        for name in ("access-contract-detail", "api-access-contract", "access-contract-export"):
            self.assertEqual(
                self.client.post(reverse(name, args=[self.intent.pk])).status_code, 405
            )
        self.client.logout()
        self.assertEqual(self.client.get(
            reverse("api-access-contract", args=[self.intent.pk])
        ).status_code, 302)

    def test_product_mapping_does_not_create_capabilities(self):
        mapping = product_module_mapping()
        self.assertEqual(len(mapping["modules"]), 11)
        self.assertEqual(len({row["key"] for row in mapping["modules"]}), 11)
        cloud = next(row for row in mapping["modules"] if row["key"] == "cloud")
        self.assertEqual(cloud["technical_modules"], [])
        mapping["modules"].clear()
        self.assertEqual(len(product_module_mapping()["modules"]), 11)

    def test_each_read_role_is_authorized_without_superuser_privileges(self):
        for role in ("admin", "operator", "reviewer", "auditor"):
            with self.subTest(role=role):
                account = get_user_model().objects.create_user("p1-reader-" + role)
                OrganizationMembership.objects.create(
                    organization=self.org, account=account, role=role
                )
                self.client.force_login(account)
                self.assertEqual(self.client.get(reverse(
                    "api-access-contract", args=[self.intent.pk]
                )).status_code, 200)

    def test_stale_superuser_object_cannot_retain_removed_authority(self):
        get_user_model().objects.filter(pk=self.admin.pk).update(is_superuser=False)
        with self.assertRaises(PermissionDenied):
            build_access_contract(self.intent.pk, actor=self.admin, organization=self.org)
