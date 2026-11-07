import ipaddress
import json
import ssl
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import skipUnless
from unittest.mock import patch
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity, Organization, OrganizationMembership
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.access.services import create_record, revoke_identity
from platform_modules.approvals.services import decide
from platform_modules.connectors.models import ExternalChange, ProvisioningConnector
from platform_modules.connectors.outbound import (
    _check_dispatch,
    _claim,
    _finish,
    bind_account,
    bind_group,
    configure_connector,
    process_changes,
    queue_grant_state,
    retry_change,
    set_connector_enabled,
)
from platform_modules.connectors.outbound import (
    test_connector as probe_connector,
)
from platform_modules.connectors.scim import (
    IntegrationFailure,
    ScimAdapter,
    destination,
    resolve_destination,
)
from platform_modules.identity.models import ExternalAccount, Grant, Identity, Resource
from platform_modules.identity.services import expire_grants, revoke_grant
from platform_modules.recertification.models import Review
from platform_modules.recertification.services import review_grant, start_campaign


class ScimHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def answer(self, code, payload=None, headers=None):
        body = json.dumps(payload or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/scim+json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        state = self.server.state
        if self.headers.get("Authorization") != "Bearer fixture-token-not-a-real-secret":
            return self.answer(401)
        if state.get("redirect"):
            return self.answer(302, headers={"Location": "https://unapproved.invalid/"})
        path = urlsplit(self.path).path
        if path.endswith("/ServiceProviderConfig"):
            return self.answer(200, {"patch": {"supported": True}})
        if path.endswith("/Users"):
            return self.answer(200, {"Resources": [{"id": "user-1", "active": state["active"]}]})
        if path.endswith("/Users/user-1"):
            return self.answer(200, {"id": "user-1", "active": state["active"]})
        if path.endswith("/Groups/group-1"):
            data = {"id": "group-1"}
            if not state.get("omit_members"):
                data["members"] = [{"value": value} for value in sorted(state["members"])]
            return self.answer(200, data)
        self.answer(404)

    def do_PATCH(self):
        state = self.server.state
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.headers.get("Authorization") != "Bearer fixture-token-not-a-real-secret":
            return self.answer(401)
        if state.get("fail_next_patch"):
            code = state.pop("fail_next_patch")
            return self.answer(code)
        if not state.get("ignore_patch"):
            operation = payload["Operations"][0]
            if self.path.endswith("/Users/user-1"):
                state["active"] = operation["value"]
            elif self.path.endswith("/Groups/group-1"):
                if operation["op"] == "add":
                    state["members"].add(operation["value"][0]["value"])
                else:
                    value = json.loads(operation["path"].split(" eq ", 1)[1][:-1])
                    state["members"].discard(value)
            else:
                return self.answer(404)
            state["effects"] += 1
        self.answer(204)


class ProvisioningTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.directory = tempfile.TemporaryDirectory()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAM-olive test CA")])
        now = timezone.now()
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
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ScimHandler)
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

    def setUp(self):
        self.server.state = {"active": True, "members": set(), "effects": 0}
        User = get_user_model()
        self.admin = User.objects.create_superuser("admin", password="fixture-strong-password")
        self.operator = User.objects.create_user("operator")
        self.reviewer = User.objects.create_user("reviewer")
        self.org = Organization.objects.create(key="mopacy", name="Mopacy")
        self.other = Organization.objects.create(key="other", name="Other")
        for actor, role in [(self.operator, "operator"), (self.reviewer, "reviewer")]:
            OrganizationMembership.objects.create(organization=self.org, account=actor, role=role)
        for actor in (self.admin, self.operator, self.reviewer):
            AccountSecurity.objects.create(
                account=actor, encrypted_secret="fixture-enrolled-factor"
            )
        for key in ["identity", "access", "approvals", "connectors", "recertification", "pam"]:
            install_module(key, actor=self.admin, organization=self.org)
        self.ctx = organization_context(self.org)
        self.ctx.__enter__()
        self.addCleanup(self.ctx.__exit__, None, None, None)
        self.identity = Identity.objects.create(organization=self.org, name="Alice", kind="human")
        self.account = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.identity,
            username="alice",
            system="SCIM",
            kind="standard",
        )
        self.resource = Resource.objects.create(
            organization=self.org, name="App RH", kind="application"
        )

    @contextmanager
    def assurance(self, actor=None):
        with recent_authentication(actor or self.admin, self.org, time.time()):
            yield

    def configured(self):
        with self.assurance():
            connector = configure_connector(
                actor=self.admin,
                organization=self.org,
                name="Annuaire",
                base_url=self.url,
                token="fixture-token-not-a-real-secret",
            )
            self.assertTrue(
                probe_connector(connector.pk, actor=self.admin, organization=self.org)[0]
            )
            connector = set_connector_enabled(
                connector.pk, actor=self.admin, organization=self.org, enabled=True
            )
            bind_account(
                actor=self.admin,
                organization=self.org,
                connector=connector,
                account=self.account,
                remote_identifier="user-1",
            )
            bind_group(
                actor=self.admin,
                organization=self.org,
                connector=connector,
                resource=self.resource,
                entitlement="reader",
                remote_identifier="group-1",
            )
        return connector

    def grant(self):
        with self.assurance(self.operator):
            return create_record(
                "grant",
                {
                    "identity": self.identity,
                    "account": self.account,
                    "resource": self.resource,
                    "entitlement": "reader",
                    "justification": "Fonction RH",
                },
                actor=self.operator,
                organization=self.org,
            )

    def test_test_before_activation_and_mfa_service_contract(self):
        with self.assertRaises(PermissionDenied):
            configure_connector(
                actor=self.admin,
                organization=self.org,
                name="Denied",
                base_url=self.url,
                token="fixture-token-not-a-real-secret",
            )
        with self.assurance():
            connector = configure_connector(
                actor=self.admin,
                organization=self.org,
                name="Annuaire",
                base_url=self.url,
                token="fixture-token-not-a-real-secret",
            )
            self.assertNotIn("fixture-token-not-a-real-secret", connector.encrypted_token)
            with self.assertRaises(ValidationError):
                set_connector_enabled(
                    connector.pk, actor=self.admin, organization=self.org, enabled=True
                )
            self.assertTrue(
                probe_connector(connector.pk, actor=self.admin, organization=self.org)[0]
            )
            self.assertEqual(self.server.state["effects"], 0)

    def test_approved_intent_provisions_group_and_expiration_removes_it(self):
        self.configured()
        now = timezone.now()
        intent = create_record(
            "intent",
            {
                "identity": self.identity,
                "account": self.account,
                "resource": self.resource,
                "method": "SCIM",
                "privilege": "reader",
                "reason": "Mission RH",
                "reference": "REQ-42",
                "fulfillment": "iam_group",
                "starts_at": now - timedelta(minutes=1),
                "ends_at": now + timedelta(minutes=15),
            },
            actor=self.operator,
            organization=self.org,
        )
        with self.assurance(self.reviewer):
            decide(
                intent.pk,
                actor=self.reviewer,
                organization=self.org,
                approved=True,
                comment="Validé",
            )
        intent.refresh_from_db()
        self.assertIsNotNone(intent.provisioned_grant_id)
        process_changes(self.org)
        change = ExternalChange.objects.get()
        self.assertEqual(change.status, "succeeded")
        self.assertEqual(self.server.state["members"], {"user-1"})
        Grant.objects.filter(pk=intent.provisioned_grant_id).update(
            expires_at=now - timedelta(seconds=1)
        )
        expire_grants(self.org)
        process_changes(self.org)
        removal = ExternalChange.objects.get(kind="remove_membership")
        self.assertEqual(removal.status, "succeeded")
        self.assertFalse(self.server.state["members"])
        self.assertTrue(removal.proofs.get().confirmed)
        self.assertTrue(verify_chain(self.org))

    def test_recertification_is_wired_to_external_removal(self):
        self.configured()
        self.grant()
        process_changes(self.org)
        start_campaign(
            actor=self.reviewer,
            organization=self.org,
            name="Q4",
            due_at=timezone.now() + timedelta(days=2),
        )
        with self.assurance(self.reviewer):
            review_grant(
                Review.objects.get().pk,
                actor=self.reviewer,
                organization=self.org,
                keep=False,
                comment="Mission terminée",
            )
        process_changes(self.org)
        self.assertFalse(self.server.state["members"])
        self.assertEqual(ExternalChange.objects.get(kind="remove_membership").status, "succeeded")

    def test_departure_disables_remote_user_and_removes_membership(self):
        self.configured()
        self.grant()
        process_changes(self.org)
        with self.assurance(self.operator):
            revoke_identity(
                self.identity.pk, actor=self.operator, organization=self.org, reason="Départ"
            )
            revoke_identity(
                self.identity.pk, actor=self.operator, organization=self.org, reason="Rejeu"
            )
        process_changes(self.org)
        self.assertFalse(self.server.state["active"])
        self.assertFalse(self.server.state["members"])
        self.assertEqual(ExternalChange.objects.count(), 3)
        self.assertFalse(ExternalChange.objects.exclude(status="succeeded").exists())

    def test_write_failure_retries_and_never_fakes_confirmation(self):
        self.configured()
        self.grant()
        self.server.state["ignore_patch"] = True
        process_changes(self.org)
        change = ExternalChange.objects.get()
        self.assertEqual(change.status, "retry")
        self.assertFalse(change.proofs.get().confirmed)
        self.server.state["ignore_patch"] = False
        ExternalChange.objects.filter(pk=change.pk).update(next_attempt_at=timezone.now())
        process_changes(self.org)
        change.refresh_from_db()
        self.assertEqual(change.status, "succeeded")
        self.assertEqual(change.proofs.count(), 2)

    def test_restart_after_remote_effect_reconciles_without_second_write(self):
        self.configured()
        self.grant()
        claim = _claim(self.org)
        ScimAdapter(self.url, "fixture-token-not-a-real-secret").membership(
            "user-1", "group-1", present=True
        )
        from platform_modules.connectors.models import AccountBinding

        past = timezone.now() - timedelta(seconds=1)
        ExternalChange.objects.filter(pk=claim.pk).update(claim_expires_at=past)
        AccountBinding.objects.filter(pk=claim.binding_id).update(claim_expires_at=past)
        process_changes(self.org)
        self.assertEqual(self.server.state["effects"], 1)
        self.assertEqual(ExternalChange.objects.get().status, "succeeded")

    def test_fencing_discards_late_result_and_serializes_same_account(self):
        self.configured()
        self.grant()
        old = _claim(self.org)
        self.assertIsNone(_claim(self.org))
        from platform_modules.connectors.models import AccountBinding

        past = timezone.now() - timedelta(seconds=1)
        ExternalChange.objects.filter(pk=old.pk).update(claim_expires_at=past)
        AccountBinding.objects.filter(pk=old.binding_id).update(claim_expires_at=past)
        current = _claim(self.org)
        _finish(
            old, code="old", observed={}, confirmed=True, retryable=False, organization=self.org
        )
        self.assertEqual(ExternalChange.objects.get().status, "running")
        _finish(
            current,
            code="current",
            observed={},
            confirmed=False,
            retryable=False,
            organization=self.org,
        )
        self.assertEqual(ExternalChange.objects.get().status, "failed")
        self.assertTrue(
            ExternalChange.objects.get().proofs.filter(code="late_result_discarded").exists()
        )

    def test_pending_add_is_cancelled_after_revocation_before_dispatch(self):
        self.configured()
        grant = self.grant()
        with self.assurance(self.operator):
            revoke_grant(
                grant, actor=self.operator, organization=self.org, origin="recertification.revoked"
            )
        process_changes(self.org)
        self.assertEqual(ExternalChange.objects.get(kind="add_membership").status, "cancelled")
        self.assertEqual(self.server.state["effects"], 0)
        self.assertEqual(ExternalChange.objects.get(kind="remove_membership").status, "succeeded")

    def test_changed_configuration_requires_test_and_explicit_reauthorization(self):
        connector = self.configured()
        self.grant()
        with self.assurance():
            configure_connector(
                actor=self.admin,
                organization=self.org,
                connector_id=connector.pk,
                name="Annuaire modifié",
                base_url=self.url,
            )
        process_changes(self.org)
        change = ExternalChange.objects.get()
        self.assertEqual(change.status, "blocked")
        with self.assurance():
            probe_connector(connector.pk, actor=self.admin, organization=self.org)
            set_connector_enabled(
                connector.pk, actor=self.admin, organization=self.org, enabled=True
            )
            retry_change(change.pk, actor=self.admin, organization=self.org)
        process_changes(self.org)
        self.assertEqual(ExternalChange.objects.get().status, "succeeded")

    def test_destination_and_dns_rebinding_guards_and_redirects(self):
        with self.assertRaises(IntegrationFailure):
            destination("http://127.0.0.1/scim")
        with self.assertRaises(IntegrationFailure):
            destination("https://unapproved.invalid/scim")
        with (
            override_settings(CONNECTOR_ALLOWED_NETWORKS=()),
            self.assertRaises(IntegrationFailure),
        ):
            resolve_destination("127.0.0.1", self.server.server_port)
        with (
            patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("169.254.169.254", 443))]),
            self.assertRaises(IntegrationFailure),
        ):
            resolve_destination("allowed.example", 443)
        self.server.state["redirect"] = True
        with self.assurance():
            connector = configure_connector(
                actor=self.admin,
                organization=self.org,
                name="Redirect",
                base_url=self.url,
                token="fixture-token-not-a-real-secret",
            )
            verified, code = probe_connector(connector.pk, actor=self.admin, organization=self.org)
        self.assertFalse(verified)
        self.assertEqual(code, "remote_http_302")
        with (
            override_settings(CONNECTOR_ALLOWED_NETWORKS=("fd00::/8",)),
            patch(
                "socket.getaddrinfo", return_value=[(10, 1, 6, "", ("fd00:ec2::254", 443, 0, 0))]
            ),
            self.assertRaises(IntegrationFailure),
        ):
            resolve_destination("allowed.example", 443)

    def test_cross_tenant_binding_and_native_views(self):
        connector = self.configured()
        other_account = ExternalAccount.unscoped.create(
            organization=self.other,
            identity=Identity.unscoped.create(
                organization=self.other, name="Foreign", kind="service"
            ),
            username="foreign",
            system="Other",
        )
        with self.assurance(), self.assertRaises(ValidationError):
            bind_account(
                actor=self.admin,
                organization=self.org,
                connector=connector,
                account=other_account,
                remote_identifier="other-remote",
            )
        self.client.force_login(self.admin)
        session = self.client.session
        session["organization_id"], session["mfa_verified_at"] = str(self.org.pk), time.time()
        session.save()
        for name in ["provisioning-home", "connector-create", "account-bind", "group-bind"]:
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, "fixture-token-not-a-real-secret")
        response = self.client.post(reverse("connector-test", args=[connector.pk]))
        self.assertEqual(response.status_code, 302)

    def test_overlapping_local_rights_do_not_remove_shared_remote_membership(self):
        connector = self.configured()
        first = self.grant()
        second_resource = Resource.objects.create(
            organization=self.org, name="Reporting", kind="application"
        )
        with self.assurance():
            bind_group(
                actor=self.admin,
                organization=self.org,
                connector=connector,
                resource=second_resource,
                entitlement="report-reader",
                remote_identifier="group-1",
            )
        with self.assurance(self.operator):
            create_record(
                "grant",
                {
                    "identity": self.identity,
                    "account": self.account,
                    "resource": second_resource,
                    "entitlement": "report-reader",
                    "justification": "Reporting",
                },
                actor=self.operator,
                organization=self.org,
            )
        process_changes(self.org)
        with self.assurance(self.operator):
            revoke_grant(
                first, actor=self.operator, organization=self.org, origin="recertification.revoked"
            )
        process_changes(self.org)
        self.assertEqual(self.server.state["members"], {"user-1"})
        self.assertEqual(ExternalChange.objects.get(kind="remove_membership").status, "cancelled")

    def test_direct_grant_mutation_cannot_dispatch_without_recent_mfa(self):
        self.configured()
        with self.assertRaises(PermissionDenied):
            create_record(
                "grant",
                {
                    "identity": self.identity,
                    "account": self.account,
                    "resource": self.resource,
                    "entitlement": "reader",
                    "justification": "Denied",
                },
                actor=self.operator,
                organization=self.org,
            )
        self.assertEqual(Grant.objects.count(), 0)
        self.assertEqual(ExternalChange.objects.count(), 0)

    def test_expired_claim_is_checked_again_immediately_before_write(self):
        self.configured()
        self.grant()
        claim = _claim(self.org)
        ExternalChange.objects.filter(pk=claim.pk).update(claim_expires_at=timezone.now())
        with self.assertRaises(IntegrationFailure):
            _check_dispatch(claim, self.org)
        self.assertEqual(self.server.state["effects"], 0)

    def test_read_only_probe_does_not_interrupt_an_active_connector(self):
        connector = self.configured()
        self.server.state["redirect"] = True
        with self.assurance():
            self.assertFalse(
                probe_connector(connector.pk, actor=self.admin, organization=self.org)[0]
            )
        connector.refresh_from_db()
        self.assertTrue(connector.enabled)
        self.assertEqual(connector.verified_revision, connector.revision)
        self.assertEqual(self.server.state["effects"], 0)

    def test_unknown_membership_and_untrusted_tls_are_not_confirmed(self):
        self.configured()
        self.grant()
        self.server.state["omit_members"] = True
        process_changes(self.org)
        self.assertEqual(ExternalChange.objects.get().status, "failed")
        self.assertEqual(ExternalChange.objects.get().result_code, "invalid_scim_group")
        with override_settings(CONNECTOR_CA_BUNDLE=""), self.assertRaises(IntegrationFailure):
            ScimAdapter(self.url, "fixture-token-not-a-real-secret").test()

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL database boundary")
    def test_database_protects_execution_proofs_and_connector_tenant_relations(self):
        self.configured()
        self.grant()
        process_changes(self.org)
        proof = ExternalChange.objects.get().proofs.get()
        with self.assertRaises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(
                "UPDATE connectors_executionevidence SET code = 'tamper' WHERE id = %s", [proof.pk]
            )
        foreign = ExternalAccount.unscoped.create(
            organization=self.other,
            identity=Identity.unscoped.create(
                organization=self.other, name="Other", kind="machine"
            ),
            username="other",
            system="Other",
        )
        with self.assertRaises(DatabaseError), transaction.atomic():
            ExternalChange.unscoped.bulk_create(
                [
                    ExternalChange(
                        organization=self.org,
                        account=foreign,
                        kind="disable_account",
                        idempotency_key="cross-tenant",
                    )
                ]
            )


@skipUnless(connection.vendor == "postgresql", "PostgreSQL concurrent worker claims")
class ConcurrentClaimTests(TransactionTestCase):
    def test_two_instances_cannot_dispatch_two_changes_for_the_same_account(self):
        from platform_modules.connectors.models import AccountBinding, GroupBinding

        actor = get_user_model().objects.create_superuser("admin")
        organization = Organization.objects.create(key="concurrency", name="Concurrency")
        AccountSecurity.objects.create(account=actor, encrypted_secret="test-enrolled-factor")
        for module in ["identity", "access", "connectors"]:
            install_module(module, actor=actor, organization=organization)
        with (
            organization_context(organization),
            recent_authentication(actor, organization, time.time()),
        ):
            identity = Identity.objects.create(
                organization=organization, name="Service", kind="service"
            )
            account = ExternalAccount.objects.create(
                organization=organization, identity=identity, username="service", system="Fixture"
            )
            resource = Resource.objects.create(
                organization=organization, name="App", kind="application"
            )
            connector = ProvisioningConnector.objects.create(
                organization=organization,
                name="Fixture",
                base_url="https://not-contacted.invalid/scim",
                encrypted_token="test-encrypted",
                enabled=True,
                verified_revision=1,
            )
            AccountBinding.objects.create(
                organization=organization, account=account, connector=connector, remote_id="user"
            )
            GroupBinding.objects.create(
                organization=organization,
                connector=connector,
                resource=resource,
                entitlement="read",
                remote_id="group",
            )
            for index in range(2):
                grant = Grant.objects.create(
                    organization=organization,
                    account=account,
                    identity=identity,
                    resource=resource,
                    entitlement="read",
                    justification=f"test-{index}",
                )
                queue_grant_state(
                    grant, actor=actor, organization=organization, origin="grant.created"
                )

        def claim():
            close_old_connections()
            try:
                result = _claim(organization)
                return result.pk if result else None
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: claim(), range(2)))
        self.assertEqual(sum(value is not None for value in results), 1)
        with organization_context(organization):
            self.assertEqual(ExternalChange.objects.filter(status="running").count(), 1)
