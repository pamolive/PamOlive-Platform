import copy
import json
import time
from datetime import timedelta
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity, AuditEvent
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.connectors.business import (
    FORMAT,
    canonical,
    configure_business_source,
    create_business_source,
    ingest_business_record,
    receipt_public,
    verify_business_receipt,
    verify_source,
)
from platform_modules.connectors.business_models import (
    BusinessReceipt,
    BusinessRecord,
    BusinessSource,
)
from platform_modules.connectors.services import create_source
from platform_modules.identity.models import Grant, Identity

from . import test_platform as baseline


class BusinessAPITests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        AccountSecurity.objects.create(account=self.admin, encrypted_secret="test-assurance")
        self.api = Client(enforce_csrf_checks=True)
        self.path = reverse("business-records-api")
        self.publisher, self.token = self.source("glpi")
        self.data = dict(
            schema=FORMAT,
            external_id="483",
            sequence=1,
            kind="incident",
            reference="INC-483",
            state="open",
            title="Intervention planifiée",
            url="https://glpi.example.test/ticket/483",
            source_updated_at=(timezone.now() - timedelta(hours=1)).isoformat(),
            observed_at=(timezone.now() - timedelta(seconds=2)).isoformat(),
        )

    def source(self, key, organization=None):
        organization = organization or self.org
        with organization_context(organization):
            with recent_authentication(self.admin, organization, time.time()):
                return create_business_source(
                    {"key": key, "name": key.upper()},
                    actor=self.admin,
                    organization=organization,
                )

    def post(self, data=None, token=None):
        return self.api.post(
            self.path,
            json.dumps(self.data if data is None else data),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer " + (token or self.token),
        )

    def test_http_round_trip_seals_minimal_facts_without_any_local_access_approval(self):
        counts = (Identity.unscoped.count(), AccessIntent.unscoped.count(), Grant.unscoped.count())
        response = self.post()
        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        self.assertTrue(body["proof_verified"])
        self.assertFalse(body["local_access_approval"])
        self.assertFalse(body["local_authorizations_modified"])
        self.assertEqual(body["authority"], "authenticated_source_assertion")
        found = self.api.get(
            self.path, {"external_id": "483"}, HTTP_AUTHORIZATION="Bearer " + self.token
        )
        self.assertEqual(found.status_code, 200)
        self.assertEqual(found.json()["receipt_id"], body["receipt_id"])
        self.assertEqual(
            (Identity.unscoped.count(), AccessIntent.unscoped.count(), Grant.unscoped.count()),
            counts,
        )
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertTrue(verify_chain(self.org))
        self.assertNotIn(self.token, str(BusinessReceipt.unscoped.get().payload))

    def test_sources_coexist_and_cannot_read_each_others_records_or_other_organizations(self):
        self.assertEqual(self.post().status_code, 201)
        jira, jira_token = self.source("jira")
        self.assertEqual(
            self.api.get(
                self.path, {"external_id": "483"}, HTTP_AUTHORIZATION="Bearer " + jira_token
            ).status_code,
            404,
        )
        self.assertEqual(self.post(token=jira_token).status_code, 201)
        from platform_core.services import install_module

        with organization_context(self.other):
            install_module("identity", actor=self.admin, organization=self.other)
            install_module("access", actor=self.admin, organization=self.other)
            install_module("connectors", actor=self.admin, organization=self.other)
        foreign, foreign_token = self.source("glpi", self.other)
        self.assertEqual(self.post(token=foreign_token).status_code, 201)
        self.assertEqual(BusinessRecord.unscoped.count(), 3)
        own_ids = set(BusinessRecord.objects.values_list("pk", flat=True))
        self.assertEqual(len(own_ids), 2)
        self.assertNotEqual(jira.organization_id, foreign.organization_id)

    def test_tokens_are_separate_from_telemetry_and_no_browser_session_can_replace_them(self):
        self.assertEqual(self.api.post(self.path, self.data).status_code, 401)
        self.api.force_login(self.admin)
        self.assertEqual(self.api.get(self.path, {"external_id": "483"}).status_code, 401)
        _, event_token = create_source("Telemetry", actor=self.admin, organization=self.org)
        self.assertEqual(self.post(token=event_token).status_code, 401)
        self.assertEqual(
            self.api.post(
                reverse("api-events"),
                "{}",
                content_type="application/json",
                HTTP_AUTHORIZATION="Bearer " + self.token,
            ).status_code,
            401,
        )

    def test_idempotent_replay_does_not_refresh_a_stale_read_or_add_proofs(self):
        self.assertEqual(self.post().status_code, 201)
        original = BusinessReceipt.objects.get()
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["created"])
        self.assertEqual(BusinessReceipt.objects.count(), 1)
        with patch(
            "platform_modules.connectors.business.timezone.now",
            return_value=original.received_at + timedelta(hours=2),
        ):
            stale = receipt_public(original)
        self.assertFalse(stale["source_read_recent"])

    def test_an_old_approved_receipt_is_not_presented_as_current_after_a_closed_read(self):
        self.assertEqual(self.post({**self.data, "state": "approved"}).status_code, 201)
        original = BusinessReceipt.objects.get()
        self.assertEqual(
            self.post({**self.data, "sequence": 2, "state": "closed"}).status_code, 201
        )
        previous = receipt_public(original)
        self.assertTrue(previous["source_read_recent"])
        self.assertFalse(previous["latest_for_record"])
        self.assertFalse(previous["current_source_assertion"])
        response = self.post({**self.data, "state": "approved"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["current_source_assertion"])
        with organization_context(self.other):
            with self.assertRaises(PermissionDenied):
                receipt_public(original)

    def test_sequence_collision_and_old_source_clock_do_not_overwrite_history(self):
        self.assertEqual(self.post().status_code, 201)
        self.assertEqual(self.post({**self.data, "state": "approved"}).status_code, 409)
        self.assertEqual(
            self.post(
                {
                    **self.data,
                    "sequence": 2,
                    "observed_at": (timezone.now() - timedelta(days=1)).isoformat(),
                    "source_updated_at": (timezone.now() - timedelta(days=2)).isoformat(),
                }
            ).status_code,
            409,
        )
        self.assertEqual(BusinessReceipt.objects.count(), 1)
        update = self.post({**self.data, "sequence": 2, "state": "approved"})
        self.assertEqual(update.status_code, 201)
        self.assertFalse(update.json()["local_access_approval"])
        self.assertEqual(BusinessReceipt.objects.count(), 2)

    def test_revocation_and_rotation_are_personal_mfa_operations(self):
        with self.assertRaises(PermissionDenied):
            configure_business_source(
                self.publisher.pk, actor=self.admin, organization=self.org, rotate=True
            )
        self.assertEqual(self.post().status_code, 201)
        original = BusinessReceipt.objects.get()
        with recent_authentication(self.admin, self.org, time.time()):
            source, replacement = configure_business_source(
                self.publisher.pk, actor=self.admin, organization=self.org, rotate=True
            )
        self.assertNotEqual(replacement, self.token)
        self.assertEqual(self.post().status_code, 401)
        self.assertEqual(self.post(token=replacement).status_code, 409)
        self.assertTrue(verify_business_receipt(original))
        original.record.source = source
        self.assertFalse(receipt_public(original)["source_configuration_current"])
        self.assertEqual(self.post({**self.data, "sequence": 2}, replacement).status_code, 201)
        with recent_authentication(self.admin, self.org, time.time()):
            configure_business_source(
                source.pk, actor=self.admin, organization=self.org, active=False
            )
        self.assertEqual(self.post(token=replacement).status_code, 401)
        self.assertEqual(BusinessReceipt.objects.count(), 2)

    def test_no_cross_organization_service_call_even_for_platform_administrator(self):
        with self.assertRaises(PermissionDenied):
            create_business_source(
                {"key": "foreign", "name": "Foreign"}, actor=self.admin, organization=self.other
            )
        with self.assertRaises(PermissionDenied):
            ingest_business_record(self.data, token=self.token, organization=self.other)

    def test_strict_payloads_reject_authority_fields_invalid_dates_and_urls(self):
        for changed in (
            {"organization_id": str(self.other.pk)},
            {"approved_by": self.admin.pk},
            {"sequence": True},
            {"kind": []},
            {"state": {}},
            {"reference": ""},
            {"url": "http://internal.invalid/"},
            {"url": "https://user:secret@example.test/"},
            {"observed_at": "2026-01-01T10:00:00"},
            {"source_updated_at": (timezone.now() + timedelta(days=1)).isoformat()},
        ):
            with self.subTest(changed=changed):
                self.assertEqual(self.post({**self.data, **changed}).status_code, 400)
        self.assertFalse(BusinessReceipt.objects.exists())
        self.assertFalse(BusinessRecord.objects.exists())

    def test_duplicate_json_and_oversized_payloads_and_enumeration_are_rejected(self):
        for raw in ('{"schema":"one","schema":"two"}', '{"sequence":NaN}', "null"):
            self.assertEqual(
                self.api.post(
                    self.path,
                    raw,
                    content_type="application/json",
                    HTTP_AUTHORIZATION="Bearer " + self.token,
                ).status_code,
                400,
            )
        self.assertEqual(
            self.api.post(
                self.path,
                " " * 16385,
                content_type="application/json",
                HTTP_AUTHORIZATION="Bearer " + self.token,
            ).status_code,
            413,
        )
        self.assertEqual(
            self.api.get(self.path, HTTP_AUTHORIZATION="Bearer " + self.token).status_code, 400
        )

    def test_rate_limit_is_per_authenticated_source_and_counts_bad_requests(self):
        with patch(
            "platform_modules.connectors.business.timezone.now", return_value=timezone.now()
        ):
            for _ in range(60):
                response = self.post({})
                self.assertEqual(response.status_code, 400)
            response = self.post()
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response["Retry-After"], "60")
            _, another = self.source("other-publisher")
            self.assertEqual(self.post(token=another).status_code, 201)

    def test_native_configuration_token_visibility_and_read_proof_require_personal_mfa(self):
        self.client.force_login(self.admin)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time()
        session.save()
        response = self.client.get(reverse("business-sources"))
        self.assertContains(response, "Systèmes métier et API")
        created = self.client.post(
            reverse("business-sources"),
            dict(
                name="Jira projets",
                key="jira-projets",
                freshness_seconds=900,
            ),
        )
        self.assertEqual(created.status_code, 200)
        token = created.context["token"]
        self.assertTrue(token.startswith("pobiz_"))
        self.assertEqual(created["Cache-Control"], "no-store")
        self.assertNotContains(self.client.get(reverse("business-sources")), token)
        self.assertEqual(self.post().status_code, 201)
        receipt = BusinessReceipt.objects.get()
        detail = self.client.get(reverse("business-receipt", args=[receipt.pk]))
        self.assertContains(detail, "INC-483")
        self.assertContains(detail, "ni une approbation PAM-olive")
        session = self.client.session
        session["mfa_verified_at"] = 0
        session.save()
        before = len(BusinessSource.unscoped.all())
        response = self.client.post(
            reverse("business-sources"),
            dict(
                name="Must wait",
                key="must-wait",
                freshness_seconds=900,
            ),
        )
        self.assertRedirects(response, reverse("account-security"), fetch_redirect_response=False)
        self.assertEqual(BusinessSource.unscoped.count(), before)
        response = self.client.get(reverse("business-receipt", args=[receipt.pk]))
        self.assertRedirects(response, reverse("account-security"), fetch_redirect_response=False)

    def test_microsecond_tampering_and_modified_source_configuration_are_detected(self):
        self.assertEqual(self.post().status_code, 201)
        receipt = BusinessReceipt.objects.get()
        changed = copy.copy(receipt)
        changed.received_at += timedelta(microseconds=1)
        self.assertFalse(verify_business_receipt(changed))
        source = copy.copy(self.publisher)
        source.freshness_seconds += 1
        self.assertFalse(verify_source(source))
        with self.assertRaises(ValidationError):
            source.save()
        self.assertNotEqual(canonical(receipt.received_at), canonical(changed.received_at))

    def test_model_evidence_and_source_scope_are_not_rewritable(self):
        self.assertEqual(self.post().status_code, 201)
        for obj in (BusinessReceipt.objects.get(), BusinessRecord.objects.get()):
            with self.assertRaises(ValidationError):
                obj.save()
            with self.assertRaises(ValidationError):
                type(obj).unscoped.filter(pk=obj.pk).delete()
        self.publisher.key = "different"
        with self.assertRaises(ValidationError):
            self.publisher.save()

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL immutable and scoped evidence")
    def test_database_guards_reject_rewrites_and_cross_tenant_relations(self):
        self.assertEqual(self.post().status_code, 201)
        receipt = BusinessReceipt.objects.get()
        for table, pk in (
            ("connectors_businessreceipt", receipt.pk),
            ("connectors_businessrecord", receipt.record_id),
        ):
            with self.assertRaises(DatabaseError) as error:
                with transaction.atomic(), connection.cursor() as cursor:
                    cursor.execute(f"UPDATE {table} SET id=id WHERE id=%s", [pk])
            self.assertEqual(error.exception.__cause__.sqlstate, "P0001")
        with self.assertRaises(DatabaseError) as error:
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE connectors_businesssource SET organization_id=%s WHERE id=%s",
                    [self.other.pk, self.publisher.pk],
                )
        self.assertEqual(error.exception.__cause__.sqlstate, "23514")
        foreign_audit = AuditEvent.objects.create(
            organization=self.other,
            sequence=1,
            action="synthetic",
            summary="foreign",
            previous_hash="0" * 64,
            event_hash="0" * 64,
        )
        with self.assertRaises(DatabaseError) as error:
            with transaction.atomic():
                BusinessReceipt.unscoped.create(
                    organization=self.org,
                    record=receipt.record,
                    sequence=2,
                    source_revision=1,
                    audit=foreign_audit,
                    signature="0" * 64,
                    content_hash="0" * 64,
                )
        self.assertEqual(error.exception.__cause__.sqlstate, "23503")
