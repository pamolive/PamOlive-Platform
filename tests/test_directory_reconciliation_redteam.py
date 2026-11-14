"""Independent attacks on cross-domain history, provenance and negative authority."""

import json
import secrets
import time
from copy import copy
from html.parser import HTMLParser
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from django.apps import apps
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from deploy.prepare_restore_fixture import teamviewer_corpus
from platform_core.models import ModuleActivation, OrganizationMembership
from platform_core.security import cipher
from platform_modules.connectors import directory_inventory as inventory
from platform_modules.connectors.directory_reconciliation import directory_account_review
from platform_modules.connectors.models import (
    AccountBinding,
    ExecutionEvidence,
    ExternalChange,
    ProvisioningConnector,
)
from platform_modules.connectors.outbound import configure_connector
from platform_modules.identity.models import ExternalAccount, Identity

from .test_directory_reconciliation import ReconciliationFixture


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class DirectoryReconciliationRedTeamTests(ReconciliationFixture, TestCase):
    def scim(
        self,
        *,
        sealed=True,
        status="succeeded",
        code="read_after_write_confirmed",
        confirmed=True,
        host="other-realm.invalid",
        binding=True,
    ):
        token = secrets.token_urlsafe(32)
        if sealed:
            with override_settings(CONNECTOR_ALLOWED_HOSTS=(f"{host}:443",)):
                connector = self.mutate(
                    configure_connector,
                    name="Independent synthetic SCIM",
                    base_url=f"https://{host}/scim/v2",
                    token=token,
                )
        else:
            # This is the deliberate legacy state preserved by migration0011:
            # a previously edited connector lacks verifiable original destination.
            connector = ProvisioningConnector.objects.create(
                organization=self.org,
                name="Unreconciled synthetic legacy destination",
                base_url=f"https://{host}/scim/v2",
                revision=2,
                encrypted_token=cipher().encrypt(token.encode()).decode(),
            )
        account_binding = (
            AccountBinding.objects.create(
                organization=self.org,
                connector=connector,
                account=self.account,
                remote_id=self.remote_id,
            )
            if binding
            else None
        )
        change = ExternalChange.objects.create(
            organization=self.org,
            account=self.account,
            binding=account_binding,
            connector_revision=connector.revision if sealed else 1,
            kind="disable_account",
            status=status,
            attempts=1,
            idempotency_key=str(uuid4()),
        )
        proof = ExecutionEvidence.objects.create(
            organization=self.org,
            change=change,
            attempt=1,
            confirmed=confirmed,
            code=code,
            observed={"Authorization": token, "password": self.credential["password"]},
        )
        return connector, change, proof, token

    def link_teamviewer(self):
        teamviewer_corpus(self.admin, self.org)
        account = ExternalAccount.objects.get(system="TeamViewer")
        self.mutate(inventory.revoke_directory_mapping, self.mapping.pk)
        self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=account.pk,
        )
        return account

    def test_unsealed_legacy_url_is_not_asserted_as_historical_destination(self):
        connector, change, _, _ = self.scim(sealed=False)
        result = self.review()
        origin = result["scim_history"]["operations"]["items"][0]["origin"]
        self.assertEqual(origin["binding_id"], str(change.binding_id))
        self.assertEqual(origin["connector_id"], str(connector.pk))
        self.assertNotEqual(origin["state"], "recorded_operation_origin")
        self.assertIsNone(origin.get("base_url"))

    def test_valid_legacy_teamviewer_link_does_not_upgrade_event_provenance(self):
        from platform_modules.access.provenance_status import verified_origin_status
        from platform_modules.connectors.teamviewer_access import verify_observation
        from platform_modules.connectors.teamviewer_access_models import TeamViewerAccessObservation

        self.link_teamviewer()
        link = TeamViewerAccessObservation.objects.select_related(
            "audit",
            "event",
            "session__audit",
            "session__origin__report",
            "session__origin__run__audit",
        ).get()
        legacy = copy(link)
        legacy.event = copy(link.event)
        legacy.event.provenance_channel = "legacy_unknown"
        legacy.event.internal_principal = ""
        legacy.event.facts_schema = ""
        legacy.event.facts_digest = ""
        legacy.event._state = copy(legacy.event._state)
        legacy.event._state.fields_cache = {
            **legacy.event._state.fields_cache,
            "provenance_receipt": None,
        }
        # In-memory historical representation, not an ordinary new legacy writer.
        # Frozen source_snapshot excludes the new channel, preserving old MACs.
        self.assertTrue(verify_observation(legacy))
        self.assertEqual(verified_origin_status(legacy.event), "legacy_unknown")
        rows = Mock()
        rows.select_related.return_value = [legacy]
        with patch.object(TeamViewerAccessObservation.objects, "filter", return_value=rows):
            result = self.review()
        row = result["teamviewer_history"]["items"][0]
        self.assertEqual(row["provenance_link"], "verified")
        self.assertEqual(row.get("event_provenance"), "legacy_unknown")
        self.assertIs(row.get("provenance_receipt_verified"), False)

    def test_matching_external_uuid_never_establishes_directory_scim_realm(self):
        connector, change, proof, _ = self.scim()
        result = self.review()
        self.assertEqual(result["items"][0]["observation"]["remote_id"], self.remote_id)
        history = result["scim_history"]["results"]["items"][0]
        self.assertEqual(history["origin"]["remote_account_id"], self.remote_id)
        self.assertEqual(history["origin"]["connector_id"], str(connector.pk))
        self.assertEqual(history["id"], str(proof.pk))
        self.assertEqual(history["change_id"], str(change.pk))
        self.assertEqual(history["current_provider_state"], "not_asserted")
        self.assertEqual(history["origin"]["same_destination_relation"], "not_established")
        self.assertEqual(result["items"][0]["same_destination_relation"], "not_established")
        self.assertFalse(result["can_apply"])

    def test_other_source_same_uuid_and_name_cannot_inherit_mapping_or_history(self):
        self.scim()
        second = self.create_source(name="Other source", endpoint="ldap://second.invalid:389")
        self.mutate(inventory.set_directory_source_enabled, second.pk, enabled=True)
        self.mutate(
            inventory.import_directory_fixture,
            second.pk,
            records=self.records,
            idempotency_key="same-observation-another-source",
            operator=True,
        )
        result = directory_account_review(second.pk, actor=self.operator, organization=self.org)
        self.assertEqual(result["items"][0]["observation"]["remote_id"], self.remote_id)
        self.assertIsNone(result["items"][0]["local_account"])
        self.assertFalse(result["scim_history"]["operations"]["items"])

    def test_absent_binding_does_not_invent_a_destination(self):
        _, _, _, _ = self.scim(binding=False)
        origin = self.review()["scim_history"]["results"]["items"][0]["origin"]
        self.assertEqual(origin["state"], "not_recorded")
        self.assertIsNone(origin["connector_id"])
        self.assertNotIn("base_url", origin)

    def test_source_disabled_keeps_history_but_hides_active_account_join(self):
        self.scim()
        self.mutate(inventory.set_directory_source_enabled, self.source.pk, enabled=False)
        with CaptureQueriesContext(connection) as queries:
            result = self.review()
        self.assertIsNotNone(result["run"])
        self.assertIsNone(result["items"][0]["local_account"])
        self.assertEqual(
            result["scim_history"]["operations"]["availability"], "no_explicit_account_link"
        )
        self.assertFalse(any("connectors_externalchange" in q["sql"] for q in queries))

    def test_local_owner_change_does_not_become_historical_authentication(self):
        new_owner = Identity.objects.create(organization=self.org, name="New owner")
        self.account.identity = new_owner
        self.account.save(update_fields=["identity"])
        row = self.review()["items"][0]
        self.assertEqual(row["local_account"]["current_identity_id"], str(new_owner.pk))
        self.assertEqual(
            row["local_account"]["identity_relation"],
            "current_owner_not_historical_person_authentication",
        )
        self.assertNotIn("authenticated_person_id", json.dumps(row))

    def test_late_true_result_remains_discarded_and_pending_operation_unconfirmed(self):
        self.scim(status="retry", code="late_result_discarded", confirmed=True)
        result = self.review()
        proof = result["scim_history"]["results"]["items"][0]
        self.assertFalse(proof["confirmation_recorded"])
        self.assertEqual(proof["outcome"], "late_result_discarded")
        self.assertIn("scim_operation_not_confirmed", result["items"][0]["review_reasons"])
        self.assertNotIn("provisioned_right", result)

    def test_partial_unknown_and_empty_complete_inventory_do_not_revoke(self):
        self.scim()
        self.accept(records=[dict(self.records[0], enabled=None)], key="unknown-enabled")
        unknown = self.review()
        self.assertIn("source_enabled_state_unknown", unknown["items"][0]["review_reasons"])
        self.accept(records=[], complete=True, key="absent-complete")
        result = self.review()
        self.assertIn("missing_observation_is_not_deletion", result["items"][0]["review_reasons"])
        self.account.refresh_from_db()
        self.assertTrue(self.account.active)
        self.assertEqual(ExternalChange.objects.count(), 1)

    def test_removed_membership_and_identity_dependency_block_before_history_read(self):
        self.scim()
        OrganizationMembership.objects.filter(organization=self.org, account=self.operator).update(
            active=False
        )
        with CaptureQueriesContext(connection) as queries, self.assertRaises(PermissionDenied):
            self.review()
        self.assertFalse(any("connectors_" in q["sql"] for q in queries))
        OrganizationMembership.objects.filter(organization=self.org, account=self.operator).update(
            active=True
        )
        ModuleActivation.objects.filter(organization=self.org, module_key="identity").update(
            enabled=False
        )
        with CaptureQueriesContext(connection) as queries, self.assertRaises(PermissionDenied):
            self.review()
        self.assertFalse(any("connectors_" in q["sql"] for q in queries))

    def test_no_network_no_business_mutation_and_no_credentials_in_projection(self):
        connector, _, _, token = self.scim()
        labels = (
            "identity.Grant",
            "connectors.ExternalChange",
            "connectors.ExecutionEvidence",
            "connectors.ScimCreationRequest",
            "access.AccessEvent",
            "pam.SessionLease",
            "platform_core.AuditEvent",
            "approvals.ApprovalDecision",
        )

        def counts():
            return {name: apps.get_model(name)._base_manager.count() for name in labels}

        before = counts()
        with patch("socket.create_connection", side_effect=AssertionError("No remote calls")):
            output = json.dumps(self.review())
        self.assertEqual(counts(), before)
        for secret in (
            token,
            connector.encrypted_token,
            self.credential["password"],
            "Authorization",
            "destination_seal",
            "encrypted_credential",
        ):
            self.assertNotIn(secret, output)

    def test_global_history_budget_never_asserts_unseen_history_is_absent(self):
        _, change, _, _ = self.scim()
        ExecutionEvidence.objects.create(
            organization=self.org, change=change, attempt=2, code="not-confirmed", confirmed=False
        )
        result = self.review(history_limit=1)
        self.assertEqual(len(result["scim_history"]["results"]["items"]), 1)
        self.assertTrue(result["scim_history"]["results"]["truncated"])
        self.assertIn("related_history_truncated", result["items"][0]["review_reasons"])

    def test_os_account_same_remote_name_does_not_select_teamviewer_history(self):
        teamviewer_corpus(self.admin, self.org)
        account = ExternalAccount.objects.get(system="TeamViewer")
        self.account.username = account.username
        self.account.system = "Windows"
        self.account.save(update_fields=["username", "system"])
        with CaptureQueriesContext(connection) as queries:
            result = self.review()
        self.assertEqual(
            result["teamviewer_history"]["availability"],
            "no_explicit_teamviewer_operator_account_link",
        )
        self.assertFalse(any("connectors_teamviewer" in q["sql"] for q in queries))

    def test_p0_destination_immutability_blocks_sql_historical_rerouting(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL destination trigger required")
        connector, _, _, _ = self.scim()
        with self.assertRaises(DatabaseError), transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE connectors_provisioningconnector SET base_url=%s WHERE id=%s",
                    ["https://attacker.invalid/scim/v2", connector.pk],
                )
        origin = self.review()["scim_history"]["operations"]["items"][0]["origin"]
        self.assertEqual(origin["base_url"], connector.base_url)

    def test_invalid_history_limit_rejected_without_business_query(self):
        for value in (True, 0, 101, "1", None):
            with CaptureQueriesContext(connection) as queries, self.assertRaises(ValidationError):
                self.review(history_limit=value)
            self.assertFalse(any("connectors_" in q["sql"] for q in queries))

    def test_context_cannot_be_switched_by_even_a_superuser_parameter(self):
        from platform_core.tenancy import organization_context

        with organization_context(self.other):
            with CaptureQueriesContext(connection) as queries, self.assertRaises(PermissionDenied):
                directory_account_review(self.source.pk, actor=self.admin, organization=self.org)
        self.assertFalse(any("connectors_" in q["sql"] for q in queries))

    def test_invalid_normalization_link_does_not_export_a_verified_event_reference(self):
        from platform_modules.connectors.teamviewer_access_models import TeamViewerAccessObservation

        self.link_teamviewer()
        link = TeamViewerAccessObservation.objects.select_related(
            "audit",
            "event",
            "session__audit",
            "session__origin__report",
            "session__origin__run__audit",
        ).get()
        corrupted = copy(link)
        corrupted.signature = "0" * 64
        rows = Mock()
        rows.select_related.return_value = [corrupted]
        with patch.object(TeamViewerAccessObservation.objects, "filter", return_value=rows):
            result = self.review()
        item = result["teamviewer_history"]["items"][0]
        self.assertIsNone(item["source_event_id"])
        self.assertEqual(item["provenance_link"], "unavailable_or_invalid")
        self.assertEqual(item["os_account"], "not_asserted")
        self.assertEqual(item["historical_person_authentication"], "not_asserted")

    def test_identical_group_label_never_confirms_an_effective_right(self):
        from platform_modules.connectors.models import GroupBinding
        from platform_modules.identity.models import Grant

        connector, change, _, _ = self.scim()
        group = GroupBinding.objects.create(
            organization=self.org,
            connector=connector,
            resource=self.resource,
            entitlement="Finance-Admin",
            remote_id="Finance-Admin",
        )
        change.group = group
        change.save(update_fields=["group"])
        self.accept(
            records=[dict(self.records[0], memberOf=["Finance-Admin"])],
            key="same-group-label",
            complete=True,
        )
        before = Grant.objects.count()
        result = self.review()
        self.assertEqual(result["items"][0]["observation"]["groups"], ["Finance-Admin"])
        operation = result["scim_history"]["operations"]["items"][0]
        self.assertEqual(operation["origin"]["remote_group_id"], "Finance-Admin")
        self.assertEqual(operation["origin"]["same_destination_relation"], "not_established")
        self.assertEqual(result["items"][0]["current_provider_state"], "not_asserted")
        self.assertNotIn("provisioned_right", result)
        self.assertEqual(Grant.objects.count(), before)


class _Links(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.hrefs = []
        self.feed(html)

    def handle_starttag(self, tag, attributes):
        if tag == "a":
            self.hrefs.extend(value for name, value in attributes if name == "href")


@override_settings(
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
)
class DirectoryReconciliationHTTPRedTeamTests(ReconciliationFixture, TestCase):
    scim = DirectoryReconciliationRedTeamTests.scim
    link_teamviewer = DirectoryReconciliationRedTeamTests.link_teamviewer

    def setUp(self):
        super().setUp()
        self.client.force_login(self.operator)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time()
        session.save()

    def url(self, name="directory-account-review"):
        return reverse(name, args=[self.source.pk])

    def href(self, response, name):
        path = self.url(name)
        return next(
            value
            for value in _Links(response.content.decode()).hrefs
            if urlsplit(value).path == path
        )

    def many_facts(self):
        self.accept(key="bounded-page", records=[self.records[0], self.fact(), self.fact()])

    def test_f3_export_link_preserves_both_page_budgets(self):
        self.many_facts()
        response = self.client.get(self.url(), {"limit": 1, "history_limit": 1})
        self.assertEqual(response.status_code, 200)
        href = self.href(response, "directory-account-review-export")
        query = parse_qs(urlsplit(href).query)
        self.assertEqual(query.get("limit"), ["1"])
        self.assertEqual(query.get("history_limit"), ["1"])

    def test_f3_export_contains_the_page_actually_reviewed(self):
        self.many_facts()
        response = self.client.get(self.url(), {"limit": 1, "history_limit": 1})
        self.assertEqual(response.status_code, 200)
        reviewed = response.context["review"]
        exported = self.client.get(self.href(response, "directory-account-review-export"))
        self.assertEqual(exported.status_code, 200)

        def ids(rows):
            return [row["observation"]["remote_id"] for row in rows]

        self.assertEqual(ids(exported.json()["items"]), ids(reviewed["items"]))

    def test_continuation_cursor_and_budgets_survive_export_and_api_links(self):
        self.many_facts()
        first = self.client.get(self.url("api-directory-account-review"), {"limit": 1}).json()
        cursor = first["next_cursor"]
        response = self.client.get(self.url(), {"cursor": cursor, "limit": 1, "history_limit": 1})
        self.assertEqual(response.status_code, 200)
        for name in ("directory-account-review-export", "api-directory-account-review"):
            href = self.href(response, name)
            query = parse_qs(urlsplit(href).query)
            self.assertEqual(query.get("cursor"), [cursor])
            self.assertEqual(query.get("limit"), ["1"])
            self.assertEqual(query.get("history_limit"), ["1"])
            exported = self.client.get(href)
            self.assertEqual(exported.status_code, 200)
            self.assertEqual(exported.json()["run"]["id"], response.context["review"]["run"]["id"])
            self.assertEqual(
                [row["observation"]["remote_id"] for row in exported.json()["items"]],
                [row["observation"]["remote_id"] for row in response.context["review"]["items"]],
            )

    def test_live_export_discloses_refresh_and_identifies_the_newly_read_run(self):
        response = self.client.get(self.url(), {"limit": 1, "history_limit": 1})
        self.assertEqual(response.status_code, 200)
        original_run = response.context["review"]["run"]["id"]
        export_href = self.href(response, "directory-account-review-export")
        notice = "Les données sont relues au moment de l’export"
        self.assertContains(response, notice)
        self.assertContains(response, "Exporter l’état actualisé")
        new_run = self.accept(
            key="run-between-display-and-export",
            records=[self.fact(self.remote_id, "New observation")],
        )
        exported = self.client.get(export_href)
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.json()["run"]["id"], str(new_run.pk))
        self.assertNotEqual(exported.json()["run"]["id"], original_run)
        self.assertIsNotNone(exported.json()["run"]["accepted_at"])
        self.assertEqual(exported.json()["items"][0]["observation"]["username"], "New observation")
        inventory = self.client.get(self.url("directory-detail"), {"limit": 1})
        self.assertContains(inventory, notice)
        self.assertContains(inventory, "Exporter l’état actualisé")

    def test_f1_export_contains_the_inventory_page_actually_reviewed(self):
        self.many_facts()
        response = self.client.get(self.url("directory-detail"), {"limit": 1})
        self.assertEqual(response.status_code, 200)
        exported = self.client.get(self.href(response, "directory-export"))
        self.assertEqual(exported.status_code, 200)
        reviewed = response.context["inventory"]["items"]
        self.assertEqual(
            [row["remote_id"] for row in exported.json()["items"]],
            [row["remote_id"] for row in reviewed],
        )

    def test_legacy_scim_origin_is_unknown_on_html_api_and_export(self):
        connector, _, _, _ = self.scim(sealed=False)
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Origine non établie")
        self.assertNotContains(response, connector.base_url)
        for name in ("api-directory-account-review", "directory-account-review-export"):
            response = self.client.get(self.url(name))
            self.assertEqual(response.status_code, 200)
            origin = response.json()["scim_history"]["operations"]["items"][0]["origin"]
            self.assertEqual(origin["state"], "unverified_historical_destination")
            self.assertIsNone(origin["base_url"])

    def test_legacy_tv_link_and_v8_authority_remain_separate_on_html(self):
        from platform_modules.connectors.teamviewer_access import verify_observation
        from platform_modules.connectors.teamviewer_access_models import TeamViewerAccessObservation

        self.link_teamviewer()
        link = TeamViewerAccessObservation.objects.select_related(
            "audit",
            "event",
            "session__audit",
            "session__origin__report",
            "session__origin__run__audit",
        ).get()
        legacy = copy(link)
        legacy.event = copy(link.event)
        legacy.event.provenance_channel = "legacy_unknown"
        legacy.event.internal_principal = ""
        legacy.event.facts_schema = legacy.event.facts_digest = ""
        legacy.event._state = copy(legacy.event._state)
        legacy.event._state.fields_cache = {
            **legacy.event._state.fields_cache,
            "provenance_receipt": None,
        }
        self.assertTrue(verify_observation(legacy))
        rows = Mock()
        rows.select_related.return_value = [legacy]
        with patch.object(TeamViewerAccessObservation.objects, "filter", return_value=rows):
            response = self.client.get(self.url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Intégrité du lien de normalisation : verified")
        self.assertContains(response, "Canal de l’événement : legacy_unknown")
        self.assertContains(response, "Reçu de provenance : Non établi")
        self.assertNotContains(response, "Reçu de provenance : Vérifié")

    def test_untrusted_query_values_are_rejected_not_reflected(self):
        marker = '"><svg/onload=alert("synthetic")>'
        for name in (
            "directory-account-review",
            "api-directory-account-review",
            "directory-account-review-export",
        ):
            for field in ("limit", "history_limit", "cursor"):
                response = self.client.get(self.url(name), {field: marker})
                self.assertEqual(response.status_code, 400)
                self.assertNotIn(marker, response.content.decode())

    def test_html_escapes_source_and_observation_labels_and_uses_typed_links(self):
        marker = '"><img src=x onerror=alert("synthetic")>'
        source = self.create_source(name=marker, endpoint="ldap://ui-xss.invalid:389")
        self.source = source
        self.mutate(inventory.set_directory_source_enabled, source.pk, enabled=True)
        self.accept(key="xss-label", records=[self.fact(self.remote_id, marker)])
        self.mutate(
            inventory.map_directory_account,
            source.pk,
            remote_id=self.remote_id,
            account_id=self.account.pk,
        )
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, marker)
        self.assertContains(response, "&lt;img")
        for href in _Links(response.content.decode()).hrefs:
            self.assertFalse(href.lower().startswith(("javascript:", "data:", "//")))

    def test_foreign_session_scope_and_disabled_dependency_block_every_endpoint(self):
        from platform_core.services import install_module

        for module in ("identity", "access", "connectors"):
            install_module(module, actor=self.admin, organization=self.other)
        OrganizationMembership.objects.create(
            organization=self.other, account=self.operator, role="auditor"
        )
        session = self.client.session
        session["organization_id"] = str(self.other.pk)
        session.save()
        names = (
            "directory-account-review",
            "api-directory-account-review",
            "directory-account-review-export",
        )
        for name in names:
            self.assertEqual(self.client.get(self.url(name)).status_code, 404)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session.save()
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        for name in names:
            with CaptureQueriesContext(connection) as queries:
                response = self.client.get(self.url(name))
            self.assertEqual(response.status_code, 403)
            self.assertFalse(any("connectors_" in row["sql"] for row in queries))

    def test_invalid_and_source_mismatched_cursors_are_private_client_errors(self):
        self.many_facts()
        first = self.client.get(self.url("api-directory-account-review"), {"limit": 1}).json()
        source = self.create_source(name="Different cursor source")
        path = reverse("api-directory-account-review", args=[source.pk])
        response = self.client.get(path, {"cursor": first["next_cursor"], "limit": 1})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        for field, value in (("limit", 101), ("history_limit", 0), ("cursor", "x" * 4097)):
            response = self.client.get(self.url("directory-account-review-export"), {field: value})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response["Cache-Control"], "no-store")
