"""Synthetic Observe acceptance and adversarial read-path tests."""

import json
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from django.urls import reverse

from platform_core.models import ModuleActivation, Organization, OrganizationMembership
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessEvent
from platform_modules.access.observe import observation_index, observation_story
from platform_modules.access.observe_demo import create_observe_demo
from platform_modules.approvals.services import decide
from platform_modules.identity.models import Resource

from . import test_platform as baseline


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class ObserveStoryTests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        install_module("intelligence", actor=self.admin, organization=self.org)
        self.intent = baseline.PlatformTests.intent(self)
        decide(self.intent.pk, actor=self.reviewer, organization=self.org,
               approved=True, comment="Synthetic approval")
        self.event = baseline.PlatformTests.event(self)

    def read(self, **changes):
        return observation_story(self.event.pk, actor=changes.pop("actor", self.operator),
                                 organization=changes.pop("organization", self.org), **changes)

    def test_verified_story_joins_contract_without_claiming_causality(self):
        story = self.read()
        self.assertEqual(story["verdict"]["label"], "Conforme")
        self.assertTrue(story["evaluation"]["verified"])
        self.assertEqual(story["provenance"]["status"], "manual")
        self.assertTrue(story["provenance"]["verified"])
        self.assertEqual(story["access_contract"]["intention"]["id"], str(self.intent.pk))
        self.assertEqual(story["access_contract"]["confirmed_executions"]["items"], [])
        json.dumps(story)

    def test_unknown_observation_is_not_hidden_or_given_a_request(self):
        event = baseline.PlatformTests.event(self, external_id="unresolved", identity=None)
        story = observation_story(event.pk, actor=self.operator, organization=self.org)
        self.assertEqual(story["verdict"]["label"], "Indéterminé")
        self.assertIsNone(story["access_contract"])
        self.assertIn(str(event.pk), [x["id"] for x in observation_index(
            actor=self.operator, organization=self.org)["items"]])

    def test_pc991_comparison_is_distinct_from_global_authorization(self):
        other_target = Resource.objects.create(organization=self.org, name="PC-991", kind="device")
        event = baseline.PlatformTests.event(self, external_id="pc991", resource=other_target)
        story = observation_story(event.pk, actor=self.operator, organization=self.org,
                                  comparison_intent_id=self.intent.pk)
        self.assertEqual(story["verdict"]["label"], "Non conforme")
        self.assertIsNone(story["access_contract"])
        self.assertEqual(next(x["state"] for x in story["comparison"]["dimensions"]
                              if x["dimension"] == "resource_id"), "mismatch")
        alternative = baseline.PlatformTests.intent(self, resource=other_target)
        decide(alternative.pk, actor=self.reviewer, organization=self.org,
               approved=True, comment="Another legitimate synthetic scope")
        event2 = baseline.PlatformTests.event(
            self, external_id="pc991-second", resource=other_target)
        second = observation_story(event2.pk, actor=self.operator, organization=self.org,
                                   comparison_intent_id=self.intent.pk)
        self.assertEqual(second["verdict"]["code"], "expected")
        self.assertEqual(second["access_contract"]["intention"]["id"], str(alternative.pk))
        self.assertEqual(next(x["state"] for x in second["comparison"]["dimensions"]
                              if x["dimension"] == "resource_id"), "mismatch")

    def test_invalid_latest_evaluation_fails_closed_without_falling_back(self):
        with patch("platform_modules.access.observe.verify_evaluation", return_value=False):
            story = self.read()
        self.assertEqual(story["verdict"]["code"], "unknown")
        self.assertFalse(story["evaluation"]["verified"])
        self.assertIsNone(story["access_contract"])
        self.assertEqual(story["evaluation"]["findings"], [])

    def test_invalid_provenance_cannot_be_presented_as_compliant(self):
        with patch("platform_modules.access.observe.verified_origin_status",
                   return_value="invalid_provenance"):
            story = self.read()
        self.assertEqual(story["verdict"]["code"], "unknown")
        self.assertFalse(story["provenance"]["verified"])
        self.assertIsNone(story["provenance"]["principal_id"])
        self.assertIsNone(story["access_contract"])

    def test_foreign_scope_and_stale_permissions_are_denied(self):
        with organization_context(self.other), self.assertRaises(PermissionDenied):
            self.read()
        OrganizationMembership.objects.filter(account=self.operator).update(active=False)
        with self.assertRaises(PermissionDenied):
            self.read()
        get_user_model().objects.filter(pk=self.admin.pk).update(is_superuser=False)
        with self.assertRaises(PermissionDenied):
            self.read(actor=self.admin)

    def test_disabled_modules_block_service_and_boundaries(self):
        for key in ("identity", "access", "intelligence"):
            with self.subTest(module=key):
                ModuleActivation.objects.filter(module_key=key).update(enabled=False)
                with self.assertRaises(PermissionDenied):
                    self.read()
                ModuleActivation.objects.filter(module_key=key).update(enabled=True)
        for limit in (0, 101, True):
            with self.assertRaises(ValidationError):
                self.read(limit=limit)

    def test_verified_verdict_filters_do_not_promote_invalid_evidence(self):
        filtered = observation_index(actor=self.operator, organization=self.org, verdict="expected")
        self.assertEqual([row["id"] for row in filtered["items"]], [str(self.event.pk)])
        with patch("platform_modules.access.observe.verify_evaluation", return_value=False):
            filtered = observation_index(actor=self.operator, organization=self.org,
                                         verdict="expected")
            self.assertEqual(filtered["items"], [])
        with self.assertRaises(ValidationError):
            observation_index(actor=self.operator, organization=self.org, verdict="invalid")

    def test_ui_api_export_are_get_only_and_tenant_scoped(self):
        self.client.force_login(self.operator)
        for name in ("observe-detail", "api-observation-story", "observe-export"):
            response = self.client.get(reverse(name, args=[self.event.pk]))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response["Cache-Control"], "no-store")
            self.assertEqual(self.client.post(reverse(name, args=[self.event.pk])).status_code, 405)
        self.assertContains(self.client.get(reverse("observe-home")), "Observe")
        self.assertEqual(self.client.get(reverse("observe-detail", args=[self.event.pk]),
                                         {"compare_intent": "bad"}).status_code, 404)
        foreign = get_user_model().objects.create_user("observe-foreign")
        OrganizationMembership.objects.create(
            account=foreign, organization=self.other, role="auditor")
        with organization_context(self.other):
            for key in ("identity", "access", "intelligence"):
                install_module(key, actor=self.admin, organization=self.other)
        self.client.force_login(foreign)
        self.assertEqual(self.client.get(reverse("api-observation-story",
                                                args=[self.event.pk])).status_code, 404)


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class ObserveDemoTests(TestCase):
    def test_demo_operator_can_read_governance_workspace_in_both_organizations(self):
        manifest = create_observe_demo()
        operator = get_user_model().objects.get(username="observe-demo-operator")
        self.client.force_login(operator)
        for item in manifest["organizations"]:
            session = self.client.session
            session["organization_id"] = item["id"]
            session.save()
            with self.subTest(organization=item["key"]):
                self.assertEqual(
                    self.client.get(reverse("governance-workspace")).status_code, 200
                )
                for name in ("api-governance-workspace", "governance-workspace-export"):
                    response = self.client.get(reverse(name))
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json()["organization_id"], item["id"])
                    self.assertEqual(response.json()["schema"], "pamolive.governance-workspace/1")

    def test_demo_refuses_nonempty_database_without_deleting_anything(self):
        org = Organization.objects.create(key="existing", name="Preserve existing")
        with self.assertRaises(ValidationError):
            create_observe_demo()
        self.assertTrue(Organization.objects.filter(pk=org.pk).exists())

    def test_command_requires_explicit_synthetic_opt_in(self):
        with patch.dict("os.environ", {"PAMOLIVE_SYNTHETIC_DEMO": "0"}):
            with self.assertRaises(CommandError):
                call_command("pamolive_observe_demo", "--synthetic-only", stdout=StringIO())
        self.assertFalse(Organization.objects.exists())

    def test_demo_refuses_operational_database_name_before_any_write(self):
        from django.db import connection

        with patch.dict(connection.settings_dict, {"NAME": "pamolive_operational"}):
            with self.assertRaises(ValidationError):
                create_observe_demo()
        self.assertFalse(Organization.objects.exists())

    def test_demo_produces_three_verdicts_and_real_internal_flow_without_network(self):
        output = StringIO()
        with patch("socket.create_connection", side_effect=AssertionError("No network")), \
                patch.dict("os.environ", {"PAMOLIVE_SYNTHETIC_DEMO": "1"}):
            call_command("pamolive_observe_demo", "--synthetic-only", stdout=output)
        manifest = json.loads(output.getvalue())
        self.assertTrue(manifest["synthetic_only"])
        self.assertFalse(manifest["remote_system_contacted"])
        self.assertEqual(len(manifest["organizations"]), 2)
        for item in manifest["organizations"]:
            self.assertEqual(item["processed_changes"], 1)
            self.assertEqual([x["verdict"]["code"] for x in item["observations"]],
                             ["expected", "deviation", "unknown"])
            stages = item["stages"]
            self.assertEqual(stages["pending"]["confirmed_effects"], [])
            self.assertEqual(stages["confirmed"]["confirmed_effects"], ["add_membership"])
            self.assertNotIn("remove_membership",
                             stages["provider_unavailable"]["confirmed_effects"])
            self.assertIn({"kind": "remove_membership", "status": "retry"},
                          stages["provider_unavailable"]["changes"])
            self.assertEqual(stages["withdrawal_confirmed"]["confirmed_effects"],
                             ["add_membership", "remove_membership"])
            org = Organization.objects.get(pk=item["id"])
            operator = get_user_model().objects.get(username="observe-demo-operator")
            with organization_context(org):
                event = AccessEvent.objects.get(pk=item["observations"][0]["event_id"])
                story = observation_story(event.pk, actor=operator, organization=org)
                self.assertTrue(story["provenance"]["verified"])
                self.assertEqual(story["provenance"]["status"], "collector")
                contract = story["access_contract"]
                self.assertEqual(len(contract["approval_decisions"]["items"]), 1)
                self.assertEqual(len(contract["confirmed_executions"]["items"]), 2)
                self.assertEqual(contract["confirmed_executions"]["items"][0]
                                 ["origin"]["state"], "recorded_reference")
                self.assertEqual(len(contract["local_grant"]["items"]), 1)
                manual = AccessEvent.objects.get(pk=item["manual_collision_event_id"])
                self.assertNotEqual(manual.pk, event.pk)
                self.assertEqual(manual.external_id, event.external_id)
                self.assertEqual(manual.provenance_channel, "manual")
                self.assertEqual(event.provenance_channel, "collector")
            with organization_context(org), self.assertRaises(AccessEvent.DoesNotExist):
                foreign = next(x for x in manifest["organizations"] if x["id"] != item["id"])
                observation_story(foreign["observations"][0]["event_id"],
                                  actor=operator, organization=org)
        self.assertTrue(all(not user.has_usable_password()
                            for user in get_user_model().objects.all()))
