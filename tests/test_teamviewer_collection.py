import json
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Barrier
from unittest import skipUnless
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.db import DatabaseError, close_old_connections, connection, connections, transaction
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import (
    AccountSecurity,
    AuditEvent,
    ModuleActivation,
    Organization,
    OrganizationMembership,
)
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.connectors.models import EventSource
from platform_modules.connectors.scim import IntegrationFailure
from platform_modules.connectors.teamviewer import (
    ConnectionReport,
    ReportBatch,
    ReportPage,
    TeamViewerClient,
)
from platform_modules.connectors.teamviewer_collection import (
    collector_config,
    enabled_ready,
    ready,
    save_configuration,
    set_enabled,
)
from platform_modules.connectors.teamviewer_collection import (
    test_configuration as probe_configuration,
)
from platform_modules.connectors.teamviewer_ingestion import (
    claim_page,
    finish_page,
    process_collectors,
    verify_report,
    verify_run,
)
from platform_modules.connectors.teamviewer_models import (
    TeamViewerCollector,
    TeamViewerReport,
    TeamViewerRun,
)
from platform_modules.connectors.teamviewer_restoration import verify_evidence
from tests.fixtures.oidc import tls_material


@override_settings(CONNECTOR_ALLOWED_HOSTS=["webapi.teamviewer.com:443"])
class TeamViewerFixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = get_user_model().objects.create_user("tv-admin")
        cls.operator = get_user_model().objects.create_user("tv-operator")
        cls.other_admin = get_user_model().objects.create_user("tv-other-admin")
        cls.org = Organization.objects.create(key="tv-one", name="TV one")
        cls.other = Organization.objects.create(key="tv-two", name="TV two")
        for actor, role in [
            (cls.admin, "admin"),
            (cls.operator, "operator"),
            (cls.other_admin, "admin"),
        ]:
            OrganizationMembership.objects.create(organization=cls.org, account=actor, role=role)
            AccountSecurity.objects.create(
                account=actor, encrypted_secret="fixture-enrolled-factor"
            )
        for key in ("identity", "access", "approvals", "connectors"):
            install_module(key, actor=cls.admin, organization=cls.org)

    def setUp(self):
        context = organization_context(self.org)
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.browser = "fixture-browser-session-key-1234567890"
        self.start = timezone.now().replace(microsecond=0) - timedelta(days=1)
        self.values = dict(
            name="Support",
            token="fixture-token-not-a-real-secret",
            start_at=self.start,
            collect_notes=False,
        )

    def draft(self, *, actor=None, batch=None, collector_id=None, **changes):
        actor = actor or self.admin
        with (
            recent_authentication(actor, self.org, time.time()),
            patch(
                "platform_modules.connectors.teamviewer.TeamViewerClient.fetch_completed",
                return_value=batch or ReportBatch((), 1, True, "pagination_finished"),
            ),
        ):
            return probe_configuration(
                actor=actor,
                organization=self.org,
                browser_key=self.browser,
                collector_id=collector_id,
                **(self.values | changes),
            )[0]

    def save(self, capsule=None, *, actor=None, browser=None, collector_id=None):
        capsule = capsule or self.draft(collector_id=collector_id)
        actor = actor or self.admin
        with recent_authentication(actor, self.org, time.time()):
            return save_configuration(
                capsule,
                actor=actor,
                organization=self.org,
                browser_key=browser or self.browser,
                collector_id=collector_id,
            )

    def enable(self, collector, enabled=True):
        with recent_authentication(self.admin, self.org, time.time()):
            return set_enabled(collector.pk, enabled, actor=self.admin, organization=self.org)


class TeamViewerConfigurationTests(TeamViewerFixture):
    def test_probe_is_non_persistent_and_draft_and_audit_do_not_expose_token(self):
        capsule = self.draft()
        self.assertNotIn(self.values["token"], capsule)
        self.assertFalse(TeamViewerCollector.objects.exists())
        self.assertFalse(EventSource.objects.exists())
        self.assertNotIn(self.values["token"], str(list(AuditEvent.objects.values())))
        self.assertTrue(verify_chain(self.org))

    def test_tested_configuration_saved_inactive_encrypted_and_requires_explicit_activation(self):
        collector = self.save()
        self.assertFalse(collector.enabled)
        self.assertFalse(collector.source.active)
        self.assertNotIn(self.values["token"], collector.encrypted_token)
        self.assertEqual(collector_config(collector)["token"], self.values["token"])
        self.assertTrue(ready(collector))
        self.assertFalse(enabled_ready(collector))
        collector = self.enable(collector)
        self.assertTrue(enabled_ready(collector))
        self.assertTrue(verify_chain(self.org))
        collector = self.enable(collector, False)
        self.assertFalse(enabled_ready(collector))
        collector.source.refresh_from_db()
        self.assertFalse(collector.source.active)

    def test_page_cap_proves_readability_not_complete_collection(self):
        capsule = self.draft(batch=ReportBatch((), 1, False, "page_limit"))
        self.assertTrue(ready(self.save(capsule)))
        audit = AuditEvent.objects.filter(action="connectors.teamviewer.tested.v1").latest("pk")
        self.assertFalse(audit.metadata["pagination_complete"])
        self.assertEqual(audit.metadata["imported"], 0)

    def test_failed_probe_never_saves_or_changes_existing_live_configuration(self):
        collector = self.enable(self.save())
        before = TeamViewerCollector.objects.values().get(pk=collector.pk)
        with self.assertRaises(IntegrationFailure):
            self.draft(
                collector_id=collector.pk,
                token="another-fixture-token",
                batch=ReportBatch((), 0, False, "teamviewer_http_403"),
            )
        self.assertEqual(TeamViewerCollector.objects.values().get(pk=collector.pk), before)
        self.assertTrue(enabled_ready(collector))

    def test_draft_rejects_other_actor_browser_expiry_and_tampering(self):
        capsule = self.draft()
        for kwargs in ({"actor": self.other_admin}, {"browser": "a-different-browser-session-key"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                self.save(capsule, **kwargs)
        with (
            patch(
                "platform_modules.connectors.teamviewer_collection.timezone.now",
                return_value=timezone.now() + timedelta(minutes=16),
            ),
            self.assertRaises(ValidationError),
        ):
            self.save(capsule)
        with self.assertRaises(ValidationError):
            self.save(capsule[:25] + "!" + capsule[26:])
        self.assertFalse(TeamViewerCollector.objects.exists())

    def test_draft_cannot_cross_organization_or_be_saved_twice(self):
        capsule = self.draft()
        with (
            organization_context(self.other),
            recent_authentication(self.admin, self.org, time.time()),
            self.assertRaises(PermissionDenied),
        ):
            save_configuration(
                capsule, actor=self.admin, organization=self.org, browser_key=self.browser
            )
        self.save(capsule)
        with self.assertRaises(ValidationError):
            self.save(capsule)
        self.assertEqual(TeamViewerCollector.objects.count(), 1)

    def test_configuration_update_invalidates_old_drafts_activation_and_claim(self):
        collector = self.enable(self.save())
        draft1 = self.draft(collector_id=collector.pk, name="Changed", collect_notes=True)
        draft2 = self.draft(collector_id=collector.pk)
        TeamViewerCollector.objects.filter(pk=collector.pk).update(
            claim_token=uuid.uuid4(), claim_until=timezone.now() + timedelta(minutes=1)
        )
        updated = self.save(draft1, collector_id=str(collector.pk))
        self.assertEqual(updated.name, "Changed")
        self.assertEqual(updated.revision, 2)
        self.assertTrue(updated.collect_notes)
        self.assertTrue(ready(updated))
        self.assertFalse(updated.enabled)
        self.assertIsNone(updated.claim_token)
        self.assertEqual(updated.activation, {})
        with self.assertRaises(ValidationError):
            self.save(draft2, collector_id=collector.pk)

    def test_service_denies_no_mfa_role_withdrawal_and_disabled_module(self):
        with self.assertRaises(PermissionDenied):
            probe_configuration(
                actor=self.admin, organization=self.org, browser_key=self.browser, **self.values
            )
        with self.assertRaises(PermissionDenied):
            self.draft(actor=self.operator)
        capsule = self.draft()
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        with self.assertRaises(PermissionDenied):
            self.save(capsule)
        self.assertFalse(TeamViewerCollector.objects.exists())

    def test_role_or_mfa_withdrawal_during_network_test_denies_draft(self):
        def withdraw(*args, **kwargs):
            OrganizationMembership.objects.filter(organization=self.org, account=self.admin).update(
                active=False
            )
            return ReportBatch((), 1, True, "pagination_finished")

        with (
            recent_authentication(self.admin, self.org, time.time()),
            patch(
                "platform_modules.connectors.teamviewer.TeamViewerClient.fetch_completed",
                side_effect=withdraw,
            ),
            self.assertRaises(PermissionDenied),
        ):
            probe_configuration(
                actor=self.admin, organization=self.org, browser_key=self.browser, **self.values
            )
        self.assertFalse(
            AuditEvent.objects.filter(action="connectors.teamviewer.tested.v1").exists()
        )

    def test_forged_configuration_or_enabled_flag_cannot_authorize_background_collection(self):
        collector = self.save()
        TeamViewerCollector.objects.filter(pk=collector.pk).update(enabled=True)
        EventSource.objects.filter(pk=collector.source_id).update(active=True)
        collector.refresh_from_db()
        self.assertFalse(enabled_ready(collector))
        collector = self.enable(collector)
        self.assertTrue(enabled_ready(collector))
        for field, value in (
            ("activation", {}),
            ("collect_notes", True),
            ("start_at", self.start - timedelta(days=1)),
            ("revision", 99),
        ):
            with self.subTest(field=field):
                original = getattr(collector, field)
                setattr(collector, field, value)
                self.assertFalse(enabled_ready(collector))
                setattr(collector, field, original)
        EventSource.objects.filter(pk=collector.source_id).update(active=False)
        self.assertFalse(enabled_ready(collector))

    def test_enabling_rechecks_deployment_allowlist_and_recent_test(self):
        collector = self.save()
        with override_settings(CONNECTOR_ALLOWED_HOSTS=[]), self.assertRaises(IntegrationFailure):
            self.enable(collector)
        with (
            patch(
                "platform_modules.connectors.teamviewer_collection.timezone.now",
                return_value=timezone.now() + timedelta(hours=2),
            ),
            self.assertRaises(ValidationError),
        ):
            self.enable(collector)
        collector.refresh_from_db()
        self.assertFalse(collector.enabled)

    def test_save_rolls_back_source_and_collector_if_audit_fails(self):
        capsule = self.draft()
        with (
            patch(
                "platform_modules.connectors.teamviewer_collection.record",
                side_effect=ValidationError("fixture"),
            ),
            self.assertRaises(ValidationError),
        ):
            self.save(capsule)
        self.assertFalse(TeamViewerCollector.objects.exists())
        self.assertFalse(EventSource.objects.exists())

    def test_scope_cannot_be_retargeted_or_deleted_through_orm(self):
        collector = self.save()
        with self.assertRaises(ValidationError):
            TeamViewerCollector.objects.filter(pk=collector.pk).update(organization=self.other)
        with self.assertRaises(ValidationError):
            collector.delete()
        with self.assertRaises(ValidationError):
            TeamViewerCollector.objects.filter(pk=collector.pk).delete()
        collector.organization = self.other
        with self.assertRaises(ValidationError):
            collector.save()

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL scope guards")
    def test_database_rejects_collector_retarget_and_delete(self):
        collector = self.save()
        for statement, parameters in (
            (
                "UPDATE connectors_teamviewercollector SET organization_id = %s WHERE id = %s",
                [self.other.pk, collector.pk],
            ),
            ("DELETE FROM connectors_teamviewercollector WHERE id = %s", [collector.pk]),
        ):
            with (
                self.subTest(statement=statement),
                self.assertRaises(DatabaseError),
                transaction.atomic(),
                connection.cursor() as cursor,
            ):
                cursor.execute(statement, parameters)


class TeamViewerViewTests(TeamViewerFixture):
    def browser_client(self, *, actor=None, fresh=True, csrf=False):
        client = Client(enforce_csrf_checks=csrf)
        client.force_login(actor or self.admin)
        session = client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time() if fresh else 0
        session.save()
        return client

    def test_native_test_save_activate_flow_uses_exact_tested_draft_not_changed_post_fields(self):
        client = self.browser_client()
        url = reverse("teamviewer-new")
        self.assertContains(client.get(url), "Tester la connexion avant")
        with patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.fetch_completed",
            return_value=ReportBatch((), 1, True, "pagination_finished"),
        ):
            response = client.post(
                url, self.values | {"start_at": self.start.isoformat(), "action": "test"}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertNotContains(response, self.values["token"])
        self.assertFalse(TeamViewerCollector.objects.exists())
        capsule = response.context["capsule"]
        response = client.post(
            url, {"action": "save", "capsule": capsule, "name": "FORGED", "token": "FORGED"}
        )
        self.assertRedirects(response, reverse("teamviewer-home"))
        collector = TeamViewerCollector.objects.get()
        self.assertEqual(collector.name, self.values["name"])
        self.assertFalse(collector.enabled)
        response = client.post(
            reverse("teamviewer-activation", args=[collector.pk]), {"action": "enable"}
        )
        self.assertRedirects(response, reverse("teamviewer-home"))
        collector.refresh_from_db()
        self.assertTrue(enabled_ready(collector))
        self.assertContains(client.get(reverse("connectors-home")), reverse("teamviewer-home"))

    def test_views_enforce_roles_scope_csrf_and_mfa_without_saving(self):
        client = self.browser_client(actor=self.operator)
        self.assertEqual(client.get(reverse("teamviewer-home")).status_code, 403)
        collector = self.save()
        OrganizationMembership.objects.create(
            organization=self.other, account=self.admin, role="admin"
        )
        for key in ("identity", "access", "approvals", "connectors"):
            install_module(key, actor=self.admin, organization=self.other)
        client = self.browser_client()
        session = client.session
        session["organization_id"] = str(self.other.pk)
        session.save()
        for method in (client.get, client.post):
            self.assertEqual(
                method(reverse("teamviewer-edit", args=[collector.pk])).status_code, 404
            )
        client = self.browser_client(csrf=True)
        self.assertEqual(
            client.post(reverse("teamviewer-new"), {"action": "test"}).status_code, 403
        )
        client = self.browser_client(fresh=False)
        response = client.post(reverse("teamviewer-new"), {"action": "test"})
        self.assertRedirects(response, reverse("account-security"), fetch_redirect_response=False)
        self.assertEqual(TeamViewerCollector.objects.count(), 1)

    def test_edit_does_not_display_secret_and_invalid_draft_or_second_browser_cannot_save(self):
        collector = self.save()
        client = self.browser_client()
        url = reverse("teamviewer-edit", args=[collector.pk])
        self.assertNotContains(client.get(url), self.values["token"])
        with patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.fetch_completed",
            return_value=ReportBatch((), 1, True, "pagination_finished"),
        ):
            response = client.post(
                url,
                self.values | {"token": "", "start_at": self.start.isoformat(), "action": "test"},
            )
        capsule = response.context["capsule"]
        self.assertIsNotNone(capsule)
        another = self.browser_client()
        response = another.post(url, {"action": "save", "capsule": capsule})
        self.assertContains(response, "autre navigateur")
        collector.refresh_from_db()
        self.assertEqual(collector.revision, 1)
        response = client.post(url, {"action": "save", "capsule": "invalid"})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context["capsule"])

    def test_real_https_form_to_job_and_mfa_protected_escaped_evidence(self):
        temp = tempfile.TemporaryDirectory(prefix="pamolive-tv-collection-")
        self.addCleanup(temp.cleanup)
        tls, ca = tls_material(temp.name)
        now = timezone.now().replace(microsecond=0)
        note = '<script>alert("source-not-code")</script>'
        source = dict(
            id=str(uuid.uuid4()),
            userid="remote-user",
            deviceid="remote-device",
            start_date=(now - timedelta(hours=1)).isoformat(),
            end_date=(now - timedelta(minutes=1)).isoformat(),
            notes=note,
        )
        observed = []
        token = self.values["token"]

        class Peer(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                observed.append((self.path, self.headers.get("Authorization")))
                body = json.dumps(dict(records=[source], records_remaining=0)).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(3)

        self.addCleanup(stop)
        adapter = partial(
            TeamViewerClient, base_url=f"https://127.0.0.1:{server.server_port}/api/v1"
        )
        with (
            override_settings(
                CONNECTOR_ALLOWED_HOSTS=[f"127.0.0.1:{server.server_port}"],
                CONNECTOR_ALLOWED_NETWORKS=["127.0.0.1/32"],
                CONNECTOR_CA_BUNDLE=ca,
            ),
            patch("platform_modules.connectors.teamviewer_collection.TeamViewerClient", adapter),
            patch("platform_modules.connectors.teamviewer_ingestion.TeamViewerClient", adapter),
        ):
            client = self.browser_client(csrf=True)
            url = reverse("teamviewer-new")
            client.get(url)
            csrf = client.cookies[settings.CSRF_COOKIE_NAME].value
            values = self.values | dict(
                start_at=self.start.isoformat(),
                collect_notes=True,
                action="test",
                csrfmiddlewaretoken=csrf,
            )
            response = client.post(url, values)
            self.assertEqual(response.status_code, 200)
            capsule = response.context["capsule"]
            self.assertIsNotNone(capsule)
            self.assertFalse(TeamViewerReport.objects.exists())
            response = client.post(
                url, dict(action="save", capsule=capsule, csrfmiddlewaretoken=csrf)
            )
            self.assertEqual(response.status_code, 302)
            collector = TeamViewerCollector.objects.get()
            response = client.post(
                reverse("teamviewer-activation", args=[collector.pk]),
                dict(action="enable", csrfmiddlewaretoken=csrf),
            )
            self.assertEqual(response.status_code, 302)
            call_command("runjobs", once=True)
            self.assertEqual(TeamViewerReport.objects.count(), 1)
            report = TeamViewerReport.objects.get()
            self.assertTrue(verify_report(report))
            self.assertTrue(verify_run(TeamViewerRun.objects.get()))
            self.assertEqual(len(observed), 2)
            for path, authorization in observed:
                self.assertEqual(authorization, "Bearer " + token)
                self.assertNotIn(token, path)
                self.assertNotIn("from_date=", path)
            url = reverse("teamviewer-report", args=[report.pk])
            response = client.get(url)
            self.assertContains(response, "&lt;script&gt;")
            self.assertNotContains(response, note)
            self.assertEqual(response["Cache-Control"], "no-store")
            session = client.session
            session["mfa_verified_at"] = 0
            session.save()
            response = client.get(url)
            self.assertRedirects(
                response, reverse("account-security"), fetch_redirect_response=False
            )


class TeamViewerCollectionTests(TeamViewerFixture):
    def source(
        self,
        *,
        identifier=None,
        notes="Declared private reason",
        end=None,
        account="user-123",
        device="device-456",
    ):
        return ConnectionReport(
            identifier or str(uuid.uuid4()),
            account,
            device,
            self.start - timedelta(days=1),
            end or timezone.now().replace(microsecond=0) - timedelta(minutes=1),
            notes,
        )

    def collector(self, *, notes=False):
        return self.enable(self.save(self.draft(collect_notes=notes)))

    def deliver(self, page, *, side_effect=None):
        with patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.read_page",
            return_value=page,
            side_effect=side_effect,
        ) as client:
            result = process_collectors(self.org)
        return result, client

    def due_again(self, collector):
        TeamViewerCollector.objects.filter(pk=collector.pk).update(
            next_run_at=timezone.now() - timedelta(seconds=1)
        )

    def test_jobs_require_activation_and_retain_unknown_refs_without_inventing_identity(self):
        collector = self.save()
        self.assertEqual(self.deliver(ReportPage((), None, None, True))[0], 0)
        self.enable(collector)
        source = self.source(account=None, device=None)
        result, client = self.deliver(ReportPage((source,), None, source.ended_at, True))
        self.assertEqual(result, 1)
        client.assert_called_once()
        report = TeamViewerReport.objects.get()
        self.assertEqual(report.account_ref, "")
        self.assertEqual(report.device_ref, "")
        self.assertEqual(report.encrypted_notes, "")
        self.assertFalse(report.notes_included)
        self.assertFalse(hasattr(report, "identity_id"))
        self.assertTrue(verify_report(report))
        run = TeamViewerRun.objects.select_related("audit").get()
        self.assertEqual(run.status, "complete")
        self.assertTrue(verify_run(run))
        self.assertFalse(run.audit.metadata["coverage_asserted"])
        self.assertEqual(run.audit.metadata["normalized_access_events"], 0)
        self.assertNotIn(source.notes, str(run.report_manifest) + str(run.audit.metadata))
        self.assertTrue(verify_chain(self.org))

    def test_restart_resumes_same_frozen_window_and_cursor_before_new_full_scan(self):
        collector = self.collector()
        source1 = self.source()
        offset = str(uuid.uuid4())
        self.deliver(ReportPage((source1,), offset, source1.ended_at, False))
        collector.refresh_from_db()
        frozen = collector.scan_until
        self.assertEqual(str(collector.next_offset), offset)
        self.assertIsNone(collector.claim_token)
        source2 = self.source(end=source1.ended_at - timedelta(minutes=1))
        _, client = self.deliver(ReportPage((source2,), None, source2.ended_at, True))
        self.assertEqual(client.call_args.args, (collector.start_at, frozen))
        self.assertEqual(str(client.call_args.kwargs["offset"]), offset)
        self.assertEqual(client.call_args.kwargs["previous_end"], source1.ended_at)
        collector.refresh_from_db()
        self.assertIsNone(collector.next_offset)
        self.assertIsNone(collector.scan_until)
        self.assertEqual(TeamViewerReport.objects.count(), 2)
        self.assertEqual(
            list(TeamViewerRun.objects.order_by("started_at").values_list("status", flat=True)),
            ["page", "complete"],
        )
        self.assertTrue(
            all(verify_run(item) for item in TeamViewerRun.objects.select_related("audit"))
        )

    def test_notes_default_off_deduplicate_note_changes_and_enabled_notes_retain_versions(self):
        collector = self.collector()
        source = self.source()
        self.deliver(ReportPage((source,), None, source.ended_at, True))
        self.due_again(collector)
        changed = self.source(
            identifier=source.id, notes="Changed confidential reason", end=source.ended_at
        )
        self.deliver(ReportPage((changed,), None, changed.ended_at, True))
        self.assertEqual(TeamViewerReport.objects.count(), 1)
        collector = self.enable(
            self.save(
                self.draft(collector_id=collector.pk, collect_notes=True), collector_id=collector.pk
            )
        )
        self.deliver(ReportPage((source,), None, source.ended_at, True))
        self.due_again(collector)
        self.deliver(ReportPage((changed,), None, changed.ended_at, True))
        self.assertEqual(TeamViewerReport.objects.count(), 3)
        for report in TeamViewerReport.objects.all():
            self.assertNotIn("confidential", report.encrypted_notes)
            self.assertTrue(verify_report(report))
        for run in TeamViewerRun.objects.select_related("audit"):
            self.assertTrue(verify_run(run))

    def test_retry_preserves_cursor_and_failed_read_is_not_successful_collection(self):
        collector = self.collector()
        source = self.source()
        offset = str(uuid.uuid4())
        self.deliver(ReportPage((source,), offset, source.ended_at, False))
        self.deliver(None, side_effect=IntegrationFailure("teamviewer_http_429", retryable=True))
        collector.refresh_from_db()
        self.assertTrue(collector.enabled)
        self.assertEqual(str(collector.next_offset), offset)
        self.assertIsNone(collector.claim_token)
        self.assertGreater(collector.next_run_at, timezone.now())
        failed = TeamViewerRun.objects.get(status="failed")
        self.assertTrue(verify_run(failed))
        self.assertEqual(failed.report_manifest, [])
        self.assertEqual(TeamViewerReport.objects.count(), 1)
        self.due_again(collector)
        self.deliver(ReportPage((), None, source.ended_at, True))
        self.assertEqual(TeamViewerRun.objects.filter(status="complete").count(), 1)

    def test_permanent_failure_suspends_and_never_retries_automatically(self):
        collector = self.collector()
        self.deliver(None, side_effect=IntegrationFailure("teamviewer_http_403"))
        collector.refresh_from_db()
        collector.source.refresh_from_db()
        self.assertFalse(collector.enabled)
        self.assertFalse(collector.source.active)
        self.assertTrue(verify_run(TeamViewerRun.objects.get()))
        self.due_again(collector)
        result, client = self.deliver(ReportPage((), None, None, True))
        self.assertEqual(result, 0)
        client.assert_not_called()

    def test_expired_lease_is_reclaimed_and_old_result_cannot_finish_new_attempt(self):
        collector = self.collector()
        old = claim_page(self.org)
        self.assertIsNone(claim_page(self.org))
        TeamViewerCollector.objects.filter(pk=collector.pk).update(
            claim_until=timezone.now() - timedelta(seconds=1)
        )
        new = claim_page(self.org)
        self.assertNotEqual(old.claim_token, new.claim_token)
        source = self.source()
        page = ReportPage((source,), None, source.ended_at, True)
        discarded = finish_page(old, page=page)
        self.assertEqual(discarded.status, "discarded")
        self.assertTrue(verify_run(discarded))
        self.assertFalse(TeamViewerReport.objects.exists())
        collector.refresh_from_db()
        self.assertEqual(collector.claim_token, new.claim_token)
        self.assertEqual(finish_page(new, page=page).status, "complete")
        self.assertEqual(TeamViewerReport.objects.count(), 1)

    def test_disable_or_module_withdrawal_during_network_read_discards_without_ingestion(self):
        collector = self.collector()
        source = self.source()

        def withdraw(*args, **kwargs):
            ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
                enabled=False
            )
            return ReportPage((source,), None, source.ended_at, True)

        self.deliver(None, side_effect=withdraw)
        self.assertFalse(TeamViewerReport.objects.exists())
        self.assertEqual(TeamViewerRun.objects.get().status, "discarded")
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=True
        )
        self.enable(collector)

        def disable(*args, **kwargs):
            self.enable(collector, False)
            return ReportPage((source,), None, source.ended_at, True)

        self.deliver(None, side_effect=disable)
        self.assertFalse(TeamViewerReport.objects.exists())
        self.assertEqual(TeamViewerRun.objects.filter(status="discarded").count(), 2)

    def test_forged_cursor_suspends_before_network_and_cross_page_cursor_loop_is_refused(self):
        collector = self.collector()
        TeamViewerCollector.objects.filter(pk=collector.pk).update(next_offset=uuid.uuid4())
        result, client = self.deliver(ReportPage((), None, None, True))
        self.assertEqual(result, 0)
        client.assert_not_called()
        self.enable(collector)
        source = self.source()
        a, b = str(uuid.uuid4()), str(uuid.uuid4())
        for offset in (a, b, a):
            self.deliver(ReportPage((source,), offset, source.ended_at, False))
        self.assertEqual(
            TeamViewerRun.objects.get(status="failed").code, "teamviewer_repeated_or_empty_cursor"
        )
        self.assertEqual(TeamViewerReport.objects.count(), 1)

    def test_proofs_reject_modified_content_manifest_audit_and_wrong_key(self):
        self.collector(notes=True)
        source = self.source()
        self.deliver(ReportPage((source,), None, source.ended_at, True))
        report, run = TeamViewerReport.objects.get(), TeamViewerRun.objects.get()
        self.assertTrue(verify_report(report))
        self.assertTrue(verify_run(run))
        report.account_ref = "different-account"
        self.assertFalse(verify_report(report))
        with override_settings(PAMOLIVE_ENCRYPTION_KEY="wrong-key"):
            self.assertFalse(verify_run(run))
        with override_settings(SECRET_KEY="wrong-signing-key"):
            self.assertFalse(verify_run(run))
        run.report_manifest = []
        self.assertFalse(verify_run(run))
        run.refresh_from_db()
        run.audit.metadata = dict(run.audit.metadata, coverage_asserted=True)
        self.assertFalse(verify_run(run))

    def test_offline_restore_verifies_disabled_configuration_history_without_network(self):
        collector = self.collector(notes=True)
        source = self.source()
        self.deliver(ReportPage((source,), None, source.ended_at, True))
        self.enable(collector, False)
        Organization.objects.filter(pk=self.org.pk).update(active=False)
        with patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.request_page",
            side_effect=AssertionError("offline verifier must not use network"),
        ):
            encrypted, signed = verify_evidence()
        self.assertEqual(encrypted, 2)
        self.assertGreaterEqual(signed, 4)
        for values in (
            {"SECRET_KEY": "wrong-signing-key"},
            {"PAMOLIVE_ENCRYPTION_KEY": "wrong-encryption-key"},
        ):
            with override_settings(**values), self.assertRaises(RuntimeError):
                verify_evidence()

    def test_report_and_run_cannot_be_rewritten_or_deleted_through_orm(self):
        self.collector()
        source = self.source()
        self.deliver(ReportPage((source,), None, source.ended_at, True))
        for model in (TeamViewerReport, TeamViewerRun):
            item = model.objects.get()
            with self.assertRaises(ValidationError):
                item.save()
            with self.assertRaises(ValidationError):
                item.delete()
            with self.assertRaises(ValidationError):
                model.objects.update(signature="forged")
            with self.assertRaises(ValidationError):
                model.objects.all().delete()

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL immutable and tenant guards")
    def test_database_protects_raw_evidence_run_audit_scope_and_report_scope(self):
        self.collector()
        source = self.source()
        self.deliver(ReportPage((source,), None, source.ended_at, True))
        for table in ("connectors_teamviewerreport", "connectors_teamviewerrun"):
            for statement in (f"UPDATE {table} SET signature = 'forged'", f"DELETE FROM {table}"):
                with (
                    self.subTest(statement=statement),
                    self.assertRaises(DatabaseError),
                    transaction.atomic(),
                    connection.cursor() as cursor,
                ):
                    cursor.execute(statement)
        report = TeamViewerReport.objects.get()
        with self.assertRaises(DatabaseError) as raised:
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO connectors_teamviewerreport "
                    "(id, remote_id, account_ref, device_ref, started_at, ended_at, "
                    "encrypted_notes, notes_included, content_hash, observed_at, signature, "
                    "collector_id, organization_id) SELECT %s, remote_id, account_ref, device_ref, "
                    "started_at, ended_at, encrypted_notes, notes_included, content_hash, "
                    "observed_at, signature, collector_id, %s "
                    "FROM connectors_teamviewerreport WHERE id = %s",
                    [uuid.uuid4(), self.other.pk, report.pk],
                )
        self.assertEqual(raised.exception.__cause__.sqlstate, "23503")


@skipUnless(connection.vendor == "postgresql", "PostgreSQL concurrent collector claims")
@override_settings(CONNECTOR_ALLOWED_HOSTS=["webapi.teamviewer.com:443"])
class TeamViewerConcurrentClaimTests(TransactionTestCase):
    def test_two_database_connections_cannot_claim_the_same_page(self):
        admin = get_user_model().objects.create_superuser("tv-race-admin")
        organization = Organization.objects.create(key="tv-race", name="TV race")
        AccountSecurity.objects.create(account=admin, encrypted_secret="fixture-enrolled-factor")
        with (
            organization_context(organization),
            recent_authentication(admin, organization, time.time()),
        ):
            for key in ("identity", "access", "approvals", "connectors"):
                install_module(key, actor=admin, organization=organization)
            with patch(
                "platform_modules.connectors.teamviewer.TeamViewerClient.fetch_completed",
                return_value=ReportBatch((), 1, True, "pagination_finished"),
            ):
                capsule, _ = probe_configuration(
                    actor=admin,
                    organization=organization,
                    browser_key="fixture-race-browser-key",
                    name="Concurrent collector",
                    token="fixture-not-a-real-token",
                    start_at=timezone.now().replace(microsecond=0) - timedelta(days=1),
                )
            collector = save_configuration(
                capsule,
                actor=admin,
                organization=organization,
                browser_key="fixture-race-browser-key",
            )
            set_enabled(collector.pk, True, actor=admin, organization=organization)
        barrier = Barrier(2)

        def claim():
            close_old_connections()
            try:
                barrier.wait(10)
                item = claim_page(organization)
                return item.claim_token if item else None
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(lambda _: claim(), range(2)))
        self.assertEqual(sum(item is not None for item in claims), 1)
        collector.refresh_from_db()
        self.assertIn(collector.claim_token, claims)
