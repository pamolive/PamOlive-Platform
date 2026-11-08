import ipaddress
import json
import socket
import ssl
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import skipUnless
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_modules.access.services import create_record, revoke_identity
from platform_modules.approvals.services import decide
from platform_modules.connectors.creation import (
    _claim_creation,
    _reserve_creation,
    process_creations,
    request_creation,
    retry_creation,
    verify_creations,
    verify_request,
)
from platform_modules.connectors.creation_models import (
    ScimCreationDispatch,
    ScimCreationJob,
    ScimCreationProof,
    ScimCreationRequest,
)
from platform_modules.connectors.models import AccountBinding, ExternalChange
from platform_modules.connectors.outbound import (
    _claim,
    _finish,
    bind_group,
    configure_connector,
    process_changes,
    set_connector_enabled,
)
from platform_modules.connectors.outbound import (
    test_connector as probe_connector,
)
from platform_modules.identity.models import ExternalAccount, Grant
from tests import test_provisioning as fixture


class CreationHandler(fixture.ScimHandler):
    def answer(self, code, payload=None, headers=None):
        if self.server.state.get("duplicate_json"):
            body = b'{"Resources":[],"Resources":[],"totalResults":0}'
            self.send_response(200)
            self.send_header("Content-Type", "application/scim+json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return super().answer(code, payload, headers)

    def do_GET(self):
        state = self.server.state
        if self.headers.get("Authorization") != "Bearer fixture-token-not-a-real-secret":
            return self.answer(401)
        path = urlsplit(self.path).path
        if path.endswith("/ServiceProviderConfig"):
            return self.answer(
                200,
                {"patch": {"supported": True}, "filter": {"supported": not state.get("no_filter")}},
            )
        if path.endswith("/Users"):
            query = parse_qs(urlsplit(self.path).query)
            users = list(state["users"].values())
            if "filter" in query:
                attribute, _, raw = query["filter"][0].partition(" eq ")
                value = json.loads(raw)
                users = [user for user in users if user.get(attribute) == value]
                if state.get("partial_lookup"):
                    return self.answer(200, {"totalResults": 1, "Resources": []})
            return self.answer(200, {"Resources": users[:2], "totalResults": len(users)})
        if "/Users/" in path:
            user = state["users"].get(path.rsplit("/", 1)[1])
            return self.answer(200 if user else 404, user)
        return super().do_GET()

    def do_POST(self):
        state = self.server.state
        if self.headers.get("Authorization") != "Bearer fixture-token-not-a-real-secret":
            return self.answer(401)
        if not self.path.endswith("/Users"):
            return self.answer(404)
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        state["posts"] += 1
        state["post_payloads"].append(payload)
        if state.get("post_error"):
            return self.answer(state["post_error"])
        if any(
            user["userName"].casefold() == payload["userName"].casefold()
            for user in state["users"].values()
        ):
            return self.answer(409)
        identifier = "created-" + str(len(state["users"]) + 1)
        user = dict(payload, id=identifier)
        if state.get("ignore_inactive"):
            user["active"] = True
        state["users"][identifier] = user
        if state.get("lose_post_response"):
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.answer(201, user)

    def do_PATCH(self):
        state = self.server.state
        if "/Users/created-" not in self.path:
            return super().do_PATCH()
        if self.headers.get("Authorization") != "Bearer fixture-token-not-a-real-secret":
            return self.answer(401)
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        identifier = self.path.rsplit("/", 1)[1]
        state["users"][identifier]["active"] = payload["Operations"][0]["value"]
        state["effects"] += 1
        self.answer(204)


class ScimCreationFixture:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.directory = tempfile.TemporaryDirectory()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = timezone.now()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SCIM creation fixture")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path, key_path = (
            Path(cls.directory.name) / "ca.pem",
            Path(cls.directory.name) / "key.pem",
        )
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CreationHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"https://127.0.0.1:{cls.server.server_port}/scim/v2"
        cls.policy = override_settings(
            CONNECTOR_ALLOWED_HOSTS={f"127.0.0.1:{cls.server.server_port}"},
            CONNECTOR_ALLOWED_NETWORKS=("127.0.0.1/32",),
            CONNECTOR_CA_BUNDLE=str(cert_path),
        )
        cls.policy.enable()

    @classmethod
    def tearDownClass(cls):
        cls.policy.disable()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        cls.directory.cleanup()
        super().tearDownClass()

    assurance = fixture.ProvisioningTests.assurance

    def setUp(self):
        fixture.ProvisioningTests.setUp(self)
        self.server.state.update(users={}, posts=0, post_payloads=[])
        with self.assurance():
            self.connector = configure_connector(
                actor=self.admin,
                organization=self.org,
                name="Annuaire",
                base_url=self.url,
                token="fixture-token-not-a-real-secret",
            )
            self.assertTrue(
                probe_connector(self.connector.pk, actor=self.admin, organization=self.org)[0]
            )
            self.connector = set_connector_enabled(
                self.connector.pk, actor=self.admin, organization=self.org, enabled=True
            )
            bind_group(
                actor=self.admin,
                organization=self.org,
                connector=self.connector,
                resource=self.resource,
                entitlement="reader",
                remote_identifier="group-1",
            )
        self.intent = self.approved_intent()

    def approved_intent(self, account=None):
        account, now = account or self.account, timezone.now()
        intent = create_record(
            "intent",
            dict(
                identity=self.identity,
                account=account,
                resource=self.resource,
                method="SCIM",
                privilege="reader",
                reason="Arrivée RH",
                reference="REQ-JOINER",
                fulfillment="iam_group",
                starts_at=now - timedelta(minutes=1),
                ends_at=now + timedelta(minutes=30),
            ),
            actor=self.operator,
            organization=self.org,
        )
        with self.assurance(self.reviewer):
            decide(
                intent.pk,
                actor=self.reviewer,
                organization=self.org,
                approved=True,
                comment="Mission approuvée",
            )
        intent.refresh_from_db()
        return intent

    def request(self, *, activate=False, intent=None):
        with self.assurance():
            return request_creation(
                (intent or self.intent).pk,
                self.connector.pk,
                actor=self.admin,
                organization=self.org,
                activate_after_grant=activate,
            )

    def due(self, job):
        ScimCreationJob.objects.filter(pk=job.pk).update(
            next_attempt_at=timezone.now() - timedelta(seconds=1)
        )


class ScimCreationTests(ScimCreationFixture, TestCase):
    def test_creation_only_is_inactive_signed_mapped_without_new_local_authority(self):
        grants = Grant.objects.count()
        job = self.request()
        self.assertTrue(verify_request(job.request))
        self.assertEqual(process_creations(self.org), 1)
        job.refresh_from_db()
        self.assertEqual(job.status, "created")
        self.assertEqual(self.server.state["posts"], 1)
        self.assertFalse(self.server.state["users"][job.binding.remote_id]["active"])
        self.assertEqual(self.server.state["members"], set())
        self.assertEqual(Grant.objects.count(), grants)
        self.assertFalse(ExternalChange.objects.filter(kind="activate_account").exists())
        self.assertEqual(verify_creations(), 3)
        self.assertTrue(verify_chain(self.org))
        self.assertEqual(process_creations(self.org), 0)

    def test_full_approved_joiner_creates_confirms_group_then_activates_and_leaver_disables(self):
        self.request(activate=True)
        process_creations(self.org)
        self.assertEqual(ScimCreationProof.objects.count(), 1)
        activation = ExternalChange.objects.get(kind="activate_account")
        self.assertEqual(activation.status, "queued")
        process_changes(self.org, limit=1)
        self.assertEqual(self.server.state["members"], {"created-1"})
        self.assertFalse(self.server.state["users"]["created-1"]["active"])
        process_changes(self.org)
        activation.refresh_from_db()
        self.assertEqual(activation.status, "succeeded")
        self.assertTrue(self.server.state["users"]["created-1"]["active"])
        with self.assurance():
            revoke_identity(
                self.identity.pk, actor=self.admin, organization=self.org, reason="Départ"
            )
        process_changes(self.org)
        self.assertFalse(self.server.state["users"]["created-1"]["active"])
        self.assertEqual(self.server.state["members"], set())
        self.assertEqual(verify_creations(), 3)
        self.assertEqual(self.server.state["posts"], 1)

    def test_activation_waits_for_confirmed_group_write(self):
        self.server.state["ignore_patch"] = True
        self.request(activate=True)
        process_creations(self.org)
        process_changes(self.org)
        self.assertFalse(self.server.state["users"]["created-1"]["active"])
        activation = ExternalChange.objects.get(kind="activate_account")
        self.assertEqual(activation.status, "queued")
        self.assertEqual(activation.result_code, "waiting_for_confirmed_initial_grant")

    def test_activation_rereads_group_instead_of_trusting_its_old_confirmation(self):
        self.request(activate=True)
        process_creations(self.org)
        process_changes(self.org, limit=1)
        self.server.state["members"].clear()
        process_changes(self.org)
        self.assertFalse(self.server.state["users"]["created-1"]["active"])
        activation = ExternalChange.objects.get(kind="activate_account")
        self.assertEqual(activation.result_code, "initial_membership_not_confirmed")

    def test_duplicate_json_never_authorizes_creation(self):
        self.request()
        self.server.state["duplicate_json"] = True
        process_creations(self.org)
        self.assertEqual(self.server.state["posts"], 0)

    def test_slow_post_tls_setup_cannot_outlive_authorization_and_send(self):
        from platform_modules.connectors.scim import PinnedHTTPSConnection

        self.request()
        original = PinnedHTTPSConnection.connect

        def delayed(connection):
            original(connection)
            # Reads have lazy TLS setup inside HTTPConnection.request; writes
            # explicitly connect first and therefore reach here before a method.
            if connection._method is None:
                self.intent.ends_at = timezone.now() - timedelta(seconds=1)
                self.intent.save()

        with patch.object(PinnedHTTPSConnection, "connect", delayed):
            process_creations(self.org)
        self.assertEqual(self.server.state["posts"], 0)
        self.assertFalse(ScimCreationDispatch.objects.exists())

    def test_late_activation_after_completed_leaver_requests_a_new_confirmed_disable(self):
        self.request(activate=True)
        process_creations(self.org)
        process_changes(self.org, limit=1)
        old = _claim(self.org)
        self.assertEqual(old.kind, "activate_account")
        past = timezone.now() - timedelta(seconds=1)
        ExternalChange.objects.filter(pk=old.pk).update(claim_expires_at=past)
        AccountBinding.objects.filter(pk=old.binding_id).update(claim_expires_at=past)
        with self.assurance():
            revoke_identity(
                self.identity.pk,
                actor=self.admin,
                organization=self.org,
                reason="Départ pendant un appel externe",
            )
        process_changes(self.org)
        self.assertFalse(self.server.state["users"]["created-1"]["active"])
        self.server.state["users"]["created-1"]["active"] = True
        _finish(
            old,
            code="late-active",
            observed=dict(remote_id="created-1", active=True),
            confirmed=True,
            retryable=False,
            organization=self.org,
        )
        self.assertTrue(
            ExternalChange.objects.filter(kind="disable_account", status="queued").exists()
        )
        process_changes(self.org)
        self.assertFalse(self.server.state["users"]["created-1"]["active"])
        self.assertEqual(ExternalChange.objects.get(pk=old.pk).status, "cancelled")

    def test_late_membership_after_withdrawal_is_reconciled_without_reauthorizing_it(self):
        self.request(activate=True)
        process_creations(self.org)
        old = _claim(self.org)
        self.assertEqual(old.kind, "add_membership")
        past = timezone.now() - timedelta(seconds=1)
        ExternalChange.objects.filter(pk=old.pk).update(claim_expires_at=past)
        AccountBinding.objects.filter(pk=old.binding_id).update(claim_expires_at=past)
        with self.assurance():
            revoke_identity(
                self.identity.pk,
                actor=self.admin,
                organization=self.org,
                reason="Départ pendant un appel externe",
            )
        process_changes(self.org)
        self.server.state["members"].add("created-1")
        _finish(
            old,
            code="late-member",
            observed=dict(remote_account_id="created-1", remote_group_id="group-1", member=True),
            confirmed=True,
            retryable=False,
            organization=self.org,
        )
        process_changes(self.org)
        self.assertEqual(self.server.state["members"], set())

    def test_activation_authorization_ending_before_group_confirmation_stays_inactive(self):
        self.request(activate=True)
        process_creations(self.org)
        self.intent.ends_at = timezone.now() - timedelta(seconds=1)
        self.intent.save()
        process_changes(self.org)
        self.assertFalse(self.server.state["users"]["created-1"]["active"])
        self.assertEqual(ExternalChange.objects.get(kind="activate_account").status, "cancelled")

    def test_lost_post_response_recovers_by_nonce_without_duplicate_post(self):
        self.server.state["lose_post_response"] = True
        job = self.request(activate=True)
        process_creations(self.org)
        job.refresh_from_db()
        self.assertEqual(job.status, "retry")
        self.assertEqual(ScimCreationDispatch.objects.count(), 1)
        self.assertEqual(AccountBinding.objects.count(), 0)
        self.due(job)
        process_creations(self.org)
        job.refresh_from_db()
        self.assertEqual(job.status, "created")
        self.assertEqual(self.server.state["posts"], 1)
        process_changes(self.org)
        self.assertTrue(self.server.state["users"]["created-1"]["active"])

    def test_failed_post_does_not_repeat_even_when_server_says_503(self):
        self.server.state["post_error"] = 503
        job = self.request()
        process_creations(self.org)
        self.server.state.pop("post_error")
        self.due(job)
        process_creations(self.org)
        self.assertEqual(self.server.state["posts"], 1)
        self.assertEqual(len(self.server.state["users"]), 0)
        self.assertFalse(AccountBinding.objects.exists())

    def test_crash_after_reservation_but_before_post_never_makes_second_reservation(self):
        job = self.request()
        claim = _claim_creation(self.org)
        _reserve_creation(claim, self.org)
        ScimCreationJob.objects.filter(pk=job.pk).update(
            claim_expires_at=timezone.now() - timedelta(seconds=1)
        )
        process_creations(self.org)
        self.assertEqual(self.server.state["posts"], 0)
        self.assertEqual(ScimCreationDispatch.objects.count(), 1)
        job.refresh_from_db()
        self.assertEqual(job.result_code, "creation_unconfirmed_no_second_post")

    def test_preexisting_same_name_is_not_adopted(self):
        self.server.state["users"]["preexisting"] = dict(
            id="preexisting", userName="alice", externalId="different-owner", active=True
        )
        job = self.request()
        process_creations(self.org)
        self.assertEqual(self.server.state["posts"], 0)
        self.assertEqual(ScimCreationDispatch.objects.count(), 0)
        self.assertFalse(AccountBinding.objects.exists())
        job.refresh_from_db()
        self.assertEqual(job.result_code, "scim_creation_preexisting_user")

    def test_absent_filter_or_partial_results_cannot_create_or_bind(self):
        job = self.request()
        self.server.state["no_filter"] = True
        process_creations(self.org)
        self.assertEqual(self.server.state["posts"], 0)
        self.server.state.pop("no_filter")
        with self.assurance():
            retry_creation(job.pk, actor=self.admin, organization=self.org)
        self.server.state["partial_lookup"] = True
        process_creations(self.org)
        self.assertEqual(self.server.state["posts"], 0)
        self.assertFalse(AccountBinding.objects.exists())

    def test_provider_ignoring_inactive_is_not_confirmed_or_activated(self):
        self.server.state["ignore_inactive"] = True
        self.request(activate=True)
        process_creations(self.org)
        self.assertEqual(self.server.state["posts"], 1)
        self.assertFalse(AccountBinding.objects.exists())
        self.assertFalse(ScimCreationProof.objects.exists())
        self.assertFalse(ExternalChange.objects.filter(kind="activate_account").exists())

    def test_mfa_admin_approval_scope_and_no_existing_binding_are_required(self):
        with self.assertRaises(PermissionDenied):
            request_creation(
                self.intent.pk,
                self.connector.pk,
                activate_after_grant=False,
                actor=self.admin,
                organization=self.org,
            )
        with self.assurance(self.operator), self.assertRaises(PermissionDenied):
            request_creation(
                self.intent.pk,
                self.connector.pk,
                activate_after_grant=False,
                actor=self.operator,
                organization=self.org,
            )
        self.intent.status = "pending"
        self.intent.save()
        with self.assertRaises(ValidationError):
            self.request()
        self.assertEqual(self.server.state["posts"], 0)

    def test_expired_or_changed_intent_is_not_created_or_activated(self):
        job = self.request(activate=True)
        self.intent.reason = "Changed after approval and preparation"
        self.intent.save()
        process_creations(self.org)
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(self.server.state["posts"], 0)

    def test_read_only_recovery_after_identity_departure_does_not_activate(self):
        self.server.state["lose_post_response"] = True
        job = self.request(activate=True)
        process_creations(self.org)
        with self.assurance():
            revoke_identity(
                self.identity.pk, actor=self.admin, organization=self.org, reason="Départ"
            )
        self.due(job)
        process_creations(self.org)
        job.refresh_from_db()
        self.assertEqual(job.status, "created")
        self.assertFalse(ExternalChange.objects.filter(kind="activate_account").exists())
        process_changes(self.org)
        self.assertTrue(
            ExternalChange.objects.filter(kind="disable_account", status="succeeded").exists()
        )
        self.assertFalse(self.server.state["users"]["created-1"]["active"])
        self.assertEqual(self.server.state["posts"], 1)

    def test_stale_claim_and_changed_connector_cannot_dispatch(self):
        job = self.request()
        claim = _claim_creation(self.org)
        ScimCreationJob.objects.filter(pk=job.pk).update(
            claim_expires_at=timezone.now() - timedelta(seconds=1)
        )
        from platform_modules.connectors.scim import IntegrationFailure

        with self.assertRaises(IntegrationFailure):
            _reserve_creation(claim, self.org)
        with self.assurance():
            configure_connector(
                actor=self.admin,
                organization=self.org,
                connector_id=self.connector.pk,
                name="Rotated",
                base_url=self.url,
                token="new-fixture-token",
            )
        process_creations(self.org)
        self.assertEqual(self.server.state["posts"], 0)

    def test_native_preview_confirm_history_and_export_require_personal_mfa(self):
        self.client.force_login(self.admin)
        path = reverse("scim-creation-new")
        payload = dict(intent=self.intent.pk, connector=self.connector.pk, command="preview")
        response = self.client.post(path, payload)
        self.assertEqual(response.status_code, 302)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        response = self.client.post(path, payload)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Confirmer la demande autorisée")
        signature = response.context["form"].initial["preview_signature"]
        self.assertFalse(ScimCreationRequest.objects.exists())
        payload.update(command="confirm", acknowledge="on", preview_signature=signature)
        response = self.client.post(path, payload)
        self.assertEqual(response.status_code, 302)
        job = ScimCreationJob.objects.get()
        process_creations(self.org)
        response = self.client.get(reverse("scim-creation-export", args=[job.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["inactive_read"]["verified"])
        self.assertEqual(response["Cache-Control"], "no-store")
        session = self.client.session
        session.pop("mfa_verified_at")
        session.save()
        self.assertEqual(
            self.client.get(reverse("scim-creation-export", args=[job.pk])).status_code, 302
        )

    def test_offline_proofs_remain_verifiable_after_revocation_and_config_change(self):
        self.request()
        process_creations(self.org)
        with self.assurance():
            revoke_identity(
                self.identity.pk, actor=self.admin, organization=self.org, reason="Départ"
            )
            configure_connector(
                actor=self.admin,
                organization=self.org,
                connector_id=self.connector.pk,
                name="New configuration",
                base_url=self.url,
                token="new-fixture-token",
            )
        from platform_core.tenancy import organization_context

        with organization_context(None):
            self.assertEqual(verify_creations(), 3)

    def test_populated_restore_corpus_has_real_signed_creation_rows_without_network(self):
        from deploy.prepare_restore_fixture import scim_creation_corpus

        scim_creation_corpus(self.admin, self.operator, self.org)
        self.assertEqual(verify_creations(), 3)
        self.assertEqual(ScimCreationJob.objects.get().status, "created")
        self.assertEqual(self.server.state["posts"], 0)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL constraints")
    def test_postgresql_proofs_and_request_account_relations_are_guarded(self):
        first_job = self.request()
        with (
            connection.cursor() as cursor,
            self.assertRaises(DatabaseError) as caught,
            transaction.atomic(),
        ):
            cursor.execute(
                "UPDATE connectors_scimcreationrequest SET username='changed' WHERE id=%s",
                [first_job.request_id],
            )
        self.assertEqual(caught.exception.__cause__.sqlstate, "P0001")
        second_account = ExternalAccount.objects.create(
            organization=self.org, identity=self.identity, username="alice-two", system="SCIM"
        )
        second_job = self.request(intent=self.approved_intent(second_account))
        with (
            connection.cursor() as cursor,
            self.assertRaises(DatabaseError) as caught,
            transaction.atomic(),
        ):
            cursor.execute(
                "UPDATE connectors_scimcreationjob SET request_id=%s WHERE id=%s",
                [second_job.request_id, first_job.pk],
            )
        self.assertEqual(caught.exception.__cause__.sqlstate, "23503")

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL constraints")
    def test_post_reservation_freezes_the_job_request_and_tenant_scopes(self):
        job = self.request()
        old_request = job.request_id
        job = self.request()
        claim = _claim_creation(self.org)
        _reserve_creation(claim, self.org)
        with (
            connection.cursor() as cursor,
            self.assertRaises(DatabaseError) as caught,
            transaction.atomic(),
        ):
            cursor.execute(
                "UPDATE connectors_scimcreationjob SET request_id=%s WHERE id=%s",
                [old_request, job.pk],
            )
        self.assertEqual(caught.exception.__cause__.sqlstate, "23503")


@skipUnless(connection.vendor == "postgresql", "PostgreSQL worker concurrency")
class ScimCreationConcurrencyTests(ScimCreationFixture, TransactionTestCase):
    def test_two_workers_claim_and_reserve_only_one_post(self):
        from platform_core.tenancy import organization_context
        from platform_modules.connectors.scim import IntegrationFailure

        job = self.request()

        def claim_worker():
            close_old_connections()
            try:
                with organization_context(self.org):
                    return _claim_creation(self.org)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = list(executor.map(lambda _: claim_worker(), range(2)))
        active = [claim for claim in claims if claim]
        self.assertEqual(len(active), 1)

        def reserve_worker():
            close_old_connections()
            try:
                with organization_context(self.org):
                    _reserve_creation(active[0], self.org)
                return True
            except IntegrationFailure:
                return False
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: reserve_worker(), range(2)))
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(ScimCreationDispatch.objects.filter(job=job).count(), 1)
        self.assertEqual(self.server.state["posts"], 0)
