import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest import skipUnless
from unittest.mock import AsyncMock, Mock, patch

import asyncssh
import pyotp
from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import (
    AccountSecurity,
    ModuleActivation,
    Organization,
    OrganizationMembership,
)
from platform_core.security import cipher
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.access.services import create_record
from platform_modules.approvals.services import decide
from platform_modules.identity.models import ExternalAccount, Identity, Resource
from platform_modules.pam.destination import TransportFailure
from platform_modules.pam.models import RecordingChunk, RelayConnection, SessionEndpoint
from platform_modules.pam.probe import ProbeResult
from platform_modules.pam.recordings import issue_recording_grant, recording_page
from platform_modules.pam.sessions import (
    append_recording,
    check_session,
    check_startup_session,
    chunk_digest,
    claim_session,
    configure_endpoint,
    endpoint_credentials,
    finish_session,
    launch_session,
    probe_endpoint,
    reap_connections,
    set_endpoint_enabled,
    stop_session,
)
from platform_modules.pam.target_binding import target_scope

from .pam_trust_fixtures import TrustFixture
from .person_fixtures import bind_person


class PamSessionFixtureMixin:
    @classmethod
    def setUpTestData(cls):
        users = get_user_model()
        cls.admin = users.objects.create_superuser("admin", password="fixture-password")
        cls.operator = users.objects.create_user("operator", password="fixture-password")
        cls.auditor = users.objects.create_user("auditor", password="fixture-password")
        cls.org = Organization.objects.create(key="test", name="Test organization")
        cls.other = Organization.objects.create(key="other", name="Other organization")
        for actor, role in ((cls.operator, "operator"), (cls.auditor, "auditor")):
            OrganizationMembership.objects.create(organization=cls.org, account=actor, role=role)
        for actor in (cls.admin, cls.operator):
            AccountSecurity.objects.create(
                account=actor,
                encrypted_secret=cipher().encrypt(pyotp.random_base32().encode()).decode(),
            )
        ModuleActivation.objects.bulk_create(
            [
                ModuleActivation(
                    organization=cls.org, module_key=module, version="test", enabled=True
                )
                for module in ("identity", "access", "approvals", "pam")
            ]
        )
        cls.host_key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()

    def setUp(self):
        self.context = organization_context(self.org)
        self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.identity = Identity.objects.create(organization=self.org, name="Person", kind="human")
        self.resource = Resource.objects.create(organization=self.org, name="Server", kind="server")
        self.account = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.identity,
            username="root",
            system="Server",
            kind="privileged",
        )
        bind_person(
            self.operator, organization=self.org, administrator=self.admin, identity=self.identity
        )
        reviewer = bind_person(
            self.admin, organization=self.org, administrator=self.admin, role="admin"
        )
        self.configured_endpoint = self.configure()
        self.trust = TrustFixture(self, self.org, [self.configured_endpoint], [
            (self.operator, self.identity, ["requester"]),
            (self.admin, reviewer.identity, ["reviewer", "sponsor"]),
        ])
        self.intent = self.approved_intent()
        self.client.force_login(self.operator)
        self.session_key = self.client.session.session_key

    def approved_intent(self, **changes):
        with self.assurance(self.operator):
            intent = create_record(
                "intent",
                {
                    "identity": self.identity,
                    "account": self.account,
                    "resource": self.resource,
                    "method": "SSH",
                    "reason": "Approved test maintenance",
                    "reference": "CHG-test",
                    "fulfillment": "pam",
                    "starts_at": timezone.now() - timedelta(minutes=1),
                    "ends_at": timezone.now() + timedelta(hours=1),
                    **changes,
                },
                actor=self.operator,
                organization=self.org,
            )
        with self.assurance():
            decide(
                intent.pk,
                actor=self.admin,
                organization=self.org,
                approved=True,
                comment="Independent fixture approval",
            )
        intent.refresh_from_db()
        return intent

    def assurance(self, actor=None):
        from contextlib import ExitStack

        actor = actor or self.admin
        context = ExitStack()
        context.enter_context(recent_authentication(actor, self.org, time.time()))
        if hasattr(self, "trust") and actor.pk in self.trust.authenticators:
            context.enter_context(self.trust.personal_action(actor))
        return context

    def configure(self):
        with self.assurance():
            endpoint = configure_endpoint(
                actor=self.admin,
                organization=self.org,
                name="SSH fixture",
                resource=self.resource,
                account=self.account,
                protocol="ssh",
                hostname="ssh.example.test",
                port=22,
                auth_method="password",
                password="secret-fixture-not-a-real-password",
                host_key=self.host_key,
            )
        return endpoint

    def enabled(self):
        endpoint = self.configured_endpoint
        result = ProbeResult(
            "ssh", endpoint.hostname, 22, "10.0.0.1", "SHA256:test", timezone.now()
        )
        with (
            self.assurance(),
            patch("platform_modules.pam.sessions.probe_ssh", AsyncMock(return_value=result)),
        ):
            self.assertTrue(probe_endpoint(endpoint.pk, actor=self.admin, organization=self.org)[0])
            set_endpoint_enabled(endpoint.pk, actor=self.admin, organization=self.org, enabled=True)
        endpoint.refresh_from_db()
        return endpoint

    def launched(self):
        self.endpoint = self.enabled()
        with self.assurance(self.operator):
            item, token = launch_session(
                self.intent.pk,
                actor=self.operator,
                organization=self.org,
                session_key=self.session_key,
                client_ip="127.0.0.1",
            )
        return item, token

    def claimed(self):
        item, token = self.launched()
        _, _, owner = claim_session(
            item.pk,
            actor=self.operator,
            session_key=self.session_key,
            client_ip="127.0.0.1",
            ticket=token,
            instance_id="test-node",
        )
        return item, owner


@override_settings(PAM_ALLOWED_HOSTS={"ssh.example.test:22"})
class PamSessionTests(PamSessionFixtureMixin, TestCase):
    def attest_target(self, endpoint):
        def attest(body):
            target = body["targets"].get(
                str(endpoint.pk), body["targets"][str(self.configured_endpoint.pk)]
            )
            body["targets"][str(endpoint.pk)] = {**target, "scope": target_scope(endpoint)}
            for actor in (self.operator, self.admin):
                person = body["persons"][self.trust.people[actor.pk]]
                if str(endpoint.pk) not in person["endpoint_ids"]:
                    person["endpoint_ids"].append(str(endpoint.pk))

        self.trust.update(attest)

    def reconfigure_target(self, endpoint, **changes):
        values = dict(
            actor=self.admin,
            organization=self.org,
            endpoint_id=endpoint.pk,
            name=endpoint.name,
            resource=endpoint.resource,
            account=endpoint.account,
            protocol=endpoint.protocol,
            hostname=endpoint.hostname,
            port=endpoint.port,
            domain=endpoint.domain,
            auth_method=endpoint.auth_method,
            host_key=endpoint.ssh_host_key,
            rdp_pin=endpoint.certificate_pin,
        )
        values.update(changes)
        with self.assurance():
            return configure_endpoint(**values)

    def activate_target(self, endpoint):
        result = ProbeResult(
            endpoint.protocol,
            endpoint.hostname,
            endpoint.port,
            "10.0.0.1",
            "SHA256:test",
            timezone.now(),
        )
        probe = "probe_ssh" if endpoint.protocol == "ssh" else "probe_rdp"
        with (
            self.assurance(),
            patch(f"platform_modules.pam.sessions.{probe}", AsyncMock(return_value=result)),
        ):
            self.assertTrue(probe_endpoint(endpoint.pk, actor=self.admin, organization=self.org)[0])
            set_endpoint_enabled(endpoint.pk, actor=self.admin, organization=self.org, enabled=True)
        endpoint.refresh_from_db()
        return endpoint

    def launch_intent(self, intent):
        with self.assurance(self.operator):
            return launch_session(
                intent.pk,
                actor=self.operator,
                organization=self.org,
                session_key=self.session_key,
                client_ip="127.0.0.1",
            )

    def test_target_round_trip_does_not_revive_an_old_vote_and_new_vote_can_open(self):
        endpoint = self.configured_endpoint
        old_pin = endpoint.ssh_host_key
        new_pin = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        endpoint = self.reconfigure_target(endpoint, host_key=new_pin, password="new-peer-secret")
        endpoint = self.reconfigure_target(
            endpoint, host_key=old_pin, password="fresh-secret-for-return-to-original-peer"
        )
        self.activate_target(endpoint)
        self.assertEqual(endpoint.destination_epoch, 3)
        with self.assertRaises((PermissionDenied, ValidationError)):
            self.launch_intent(self.intent)
        with self.assertRaises((PermissionDenied, ValidationError)):
            self.approved_intent()
        self.attest_target(endpoint)
        replacement = self.approved_intent()
        item, _ = self.launch_intent(replacement)
        self.assertEqual(item.endpoint_id, endpoint.pk)

    def test_same_destination_secret_rotation_preserves_the_mandate(self):
        endpoint = self.reconfigure_target(
            self.configured_endpoint, password="rotated-secret-for-the-same-peer"
        )
        self.activate_target(endpoint)
        self.assertEqual(endpoint.destination_epoch, 1)
        item, ticket = self.launch_intent(self.intent)
        _, _, owner = claim_session(
            item.pk,
            actor=self.operator,
            session_key=self.session_key,
            client_ip="127.0.0.1",
            ticket=ticket,
            instance_id="test-node",
        )
        loaded = check_startup_session(
            item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
        )
        self.assertEqual(
            endpoint_credentials(loaded)["password"], "rotated-secret-for-the-same-peer"
        )

    def test_changed_pin_requires_explicit_credentials(self):
        pin = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        with self.assertRaises(ValidationError):
            self.reconfigure_target(self.configured_endpoint, host_key=pin)

    def test_unclaimed_ticket_does_not_release_credentials(self):
        item, _ = self.launched()
        with (
            patch("platform_modules.pam.sessions.cipher") as encryption,
            self.assertRaises(TransportFailure),
        ):
            endpoint_credentials(item)
        encryption.assert_not_called()

    def test_retargeting_with_explicit_credentials_does_not_compare_the_old_secret(self):
        pin = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        encryption = Mock(wraps=cipher())
        encryption.decrypt.side_effect = AssertionError("Old credentials must not be compared")
        with patch("platform_modules.pam.sessions.cipher", return_value=encryption):
            self.reconfigure_target(
                self.configured_endpoint, host_key=pin, password="new-target-credential"
            )
        encryption.decrypt.assert_not_called()

    @override_settings(PAM_ALLOWED_HOSTS={"ssh.example.test:22", "rdp.example.test:3389"})
    def test_changed_rdp_certificate_requires_a_new_mandate(self):
        with self.assurance():
            endpoint = configure_endpoint(
                actor=self.admin,
                organization=self.org,
                resource=self.resource,
                account=self.account,
                name="RDP fixture",
                protocol="rdp",
                hostname="rdp.example.test",
                port=3389,
                domain="FIXTURE",
                auth_method="password",
                password="synthetic-rdp-credential",
                rdp_pin="a" * 64,
            )
        self.activate_target(endpoint)
        self.attest_target(endpoint)
        intent = self.approved_intent(method="RDP")
        with self.assertRaises(ValidationError):
            self.reconfigure_target(endpoint, rdp_pin="b" * 64)
        endpoint = self.reconfigure_target(
            endpoint, rdp_pin="b" * 64, password="synthetic-new-rdp-credential"
        )
        self.activate_target(endpoint)
        with self.assertRaises((PermissionDenied, ValidationError)):
            self.launch_intent(intent)
        with self.assertRaises((PermissionDenied, ValidationError)):
            self.approved_intent(method="RDP")
        self.attest_target(endpoint)
        replacement = self.approved_intent(method="RDP")
        item, _ = self.launch_intent(replacement)
        self.assertEqual(item.endpoint_id, endpoint.pk)

    def test_legacy_mandate_and_unbound_credential_cannot_open_a_relay(self):
        endpoint = self.enabled()
        from platform_modules.pam.services import open_lease

        with (
            patch("platform_modules.pam.mandates.mandate_endpoint", return_value=None),
            self.assertRaises((PermissionDenied, ValidationError)),
        ):
            self.approved_intent()
        legacy = AccessIntent.objects.create(
            organization=self.org,
            identity=self.identity,
            account=self.account,
            resource=self.resource,
            requested_by=self.operator,
            requester_binding=self.intent.requester_binding,
            account_snapshot=self.intent.account_snapshot,
            method="SSH",
            fulfillment="pam",
            privilege="native_full_account",
            reason="Historical mandate without target attestation",
            status="approved",
            approved_at=self.intent.approved_at,
            starts_at=self.intent.starts_at,
            ends_at=self.intent.ends_at,
        )
        self.assertEqual(legacy.pam_destination, {})
        with self.assertRaises((PermissionDenied, ValidationError)):
            open_lease(legacy.pk, actor=self.operator, organization=self.org)
        with self.assertRaises((PermissionDenied, ValidationError)):
            self.launch_intent(legacy)
        SessionEndpoint.objects.filter(pk=endpoint.pk).update(credential_seal="")
        with self.assurance(), self.assertRaises(ValidationError):
            set_endpoint_enabled(endpoint.pk, actor=self.admin, organization=self.org, enabled=True)

    def test_capture_remains_verifiable_after_target_identity_changes(self):
        item, owner = self.claimed()
        append_recording(item.pk, self.org, owner, b"3.nop;", 0)
        finish_session(item.pk, self.org, owner, reason="client_closed", complete=True)
        item.refresh_from_db()
        pin = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        self.reconfigure_target(self.endpoint, host_key=pin, password="new-target-secret")
        with self.assurance(self.operator):
            grant = issue_recording_grant(item, self.operator, self.session_key)
        data, _, _ = recording_page(item.pk, self.org, self.session_key, grant, 0, "")
        self.assertEqual(data, [b"3.nop;"])

    async def test_approved_ssh_target_cannot_be_replaced_and_receive_its_old_password(self):
        stolen = []

        class Attacker(asyncssh.SSHServer):
            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                stolen.append(password)
                return True

        old_key = asyncssh.generate_private_key("ssh-ed25519")
        new_key = asyncssh.generate_private_key("ssh-ed25519")
        async with (
            await asyncssh.create_server(
                asyncssh.SSHServer, "127.0.0.1", 0, server_host_keys=[old_key]
            ) as old_peer,
            await asyncssh.create_server(
                Attacker, "127.0.0.1", 0, server_host_keys=[new_key]
            ) as new_peer,
        ):
            old_port, new_port = old_peer.get_port(), new_peer.get_port()

            def attempt_retarget():
                def configure(key, port, **changes):
                    with self.assurance():
                        endpoint = configure_endpoint(
                            actor=self.admin,
                            organization=self.org,
                            name="Synthetic SSH target",
                            resource=self.resource,
                            account=self.account,
                            protocol="ssh",
                            hostname="127.0.0.1",
                            port=port,
                            auth_method="password",
                            host_key=key.export_public_key().decode(),
                            **changes,
                        )
                        self.assertTrue(
                            probe_endpoint(endpoint.pk, actor=self.admin, organization=self.org)[0]
                        )
                        return set_endpoint_enabled(
                            endpoint.pk, actor=self.admin, organization=self.org, enabled=True
                        )

                with override_settings(
                    PAM_ALLOWED_HOSTS={f"127.0.0.1:{port}" for port in (old_port, new_port)},
                    PAM_ALLOWED_NETWORKS=("127.0.0.1/32",),
                ):
                    endpoint = configure(
                        old_key,
                        old_port,
                        endpoint_id=self.configured_endpoint.pk,
                        password="old-synthetic-credential",
                    )
                    self.attest_target(endpoint)
                    intent = self.approved_intent()
                    try:
                        configure(new_key, new_port, endpoint_id=endpoint.pk)
                    except ValidationError:
                        # Even a legitimate replacement with fresh credentials
                        # cannot inherit the old approval.
                        configure(
                            new_key,
                            new_port,
                            endpoint_id=endpoint.pk,
                            password="new-synthetic-credential",
                        )
                    with self.assurance(self.operator):
                        try:
                            item, ticket = launch_session(
                                intent.pk,
                                actor=self.operator,
                                organization=self.org,
                                session_key=self.session_key,
                                client_ip="127.0.0.1",
                            )
                        except (ValidationError, PermissionDenied):
                            return None
                    _, _, owner = claim_session(
                        item.pk,
                        actor=self.operator,
                        session_key=self.session_key,
                        client_ip="127.0.0.1",
                        ticket=ticket,
                        instance_id="synthetic-ssh-peer",
                    )
                    loaded = check_startup_session(
                        item.pk,
                        self.org,
                        owner,
                        session_key=self.session_key,
                        client_ip="127.0.0.1",
                    )
                    return endpoint_credentials(
                        loaded, session_key=self.session_key, client_ip="127.0.0.1"
                    )["password"]

            password = await sync_to_async(attempt_retarget)()
            if password is not None:
                # Synthetic client consumes the credential returned by the broker's
                # credential loader; the Windows suite does not start guacd.
                async with asyncssh.connect(
                    "127.0.0.1",
                    new_port,
                    config=None,
                    agent_path=None,
                    known_hosts=([new_key.convert_to_public()], [], []),
                    username="root",
                    password=password,
                ):
                    pass
            self.assertEqual(stolen, [], "The replacement SSH server received an old credential")
            self.assertIsNone(password, "The old mandate issued a relay for a replacement target")

    @patch("platform_modules.pam.sessions._startup_read_only_supported", return_value=True)
    def test_startup_recheck_is_read_only_but_rechecks_endpoint_authority(self, _supported):
        item, owner = self.claimed()
        before = RelayConnection.objects.filter(pk=item.pk).values().get()
        with CaptureQueriesContext(connection) as queries:
            checked = check_startup_session(
                item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
            )
        self.assertEqual(checked.pk, item.pk)
        self.assertEqual(RelayConnection.objects.filter(pk=item.pk).values().get(), before)
        for query in queries.captured_queries:
            command = query["sql"].lstrip().upper()
            self.assertFalse(command.startswith(("UPDATE ", "INSERT ", "DELETE ")))
            self.assertNotIn("FOR UPDATE", command)
        SessionEndpoint.objects.filter(pk=self.endpoint.pk).update(enabled=False)
        with self.assertRaises(PermissionDenied):
            check_startup_session(
                item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
            )

    @patch("platform_modules.pam.sessions._startup_read_only_supported", return_value=True)
    def test_startup_recheck_does_not_reuse_a_logged_out_portal_session(self, _supported):
        item, owner = self.claimed()
        Session.objects.filter(session_key=self.session_key).delete()
        with self.assertRaises(PermissionDenied):
            check_startup_session(
                item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
            )

    def test_monitored_check_keeps_its_durable_heartbeat_and_row_lock(self):
        item, owner = self.claimed()
        item.refresh_from_db()
        next_heartbeat = item.heartbeat_at + timedelta(seconds=2)
        with (
            patch("platform_modules.pam.sessions.timezone.now", return_value=next_heartbeat),
            CaptureQueriesContext(connection) as queries,
        ):
            check_session(
                item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
            )
        item.refresh_from_db()
        self.assertEqual(item.heartbeat_at, next_heartbeat)
        self.assertEqual(item.status, "connecting")
        if connection.vendor == "postgresql":
            self.assertTrue(any("FOR UPDATE" in query["sql"].upper() for query in queries))

    def test_startup_recheck_uses_durable_fallback_for_stronger_isolation(self):
        item, owner = self.claimed()
        item.refresh_from_db()
        next_heartbeat = item.heartbeat_at + timedelta(seconds=2)
        with (
            patch("platform_modules.pam.sessions._startup_read_only_supported", return_value=False),
            patch("platform_modules.pam.sessions.timezone.now", return_value=next_heartbeat),
            CaptureQueriesContext(connection) as queries,
        ):
            check_startup_session(
                item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
            )
        item.refresh_from_db()
        self.assertEqual(item.heartbeat_at, next_heartbeat)
        if connection.vendor == "postgresql":
            self.assertTrue(any("FOR UPDATE" in query["sql"].upper() for query in queries))
        RelayConnection.objects.filter(pk=item.pk).update(status="active")
        with (
            patch("platform_modules.pam.sessions._startup_read_only_supported", return_value=False),
            self.assertRaises(PermissionDenied),
        ):
            check_startup_session(
                item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
            )

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL isolation gate")
    def test_startup_read_only_gate_checks_actual_transaction_isolation(self):
        from platform_modules.pam.sessions import _startup_read_only_supported

        with connection.cursor() as cursor:
            cursor.execute("SHOW transaction_isolation")
            expected = cursor.fetchone()[0] == "read committed"
        self.assertEqual(_startup_read_only_supported(), expected)
        for isolation in ("repeatable read", "serializable", "unrecognized"):
            with self.subTest(isolation=isolation), patch.object(connection, "cursor") as cursor:
                cursor.return_value.__enter__.return_value.fetchone.return_value = (isolation,)
                self.assertFalse(_startup_read_only_supported())
                cursor.return_value.__enter__.return_value.execute.assert_called_once_with(
                    "SHOW transaction_isolation"
                )

    @patch("platform_modules.pam.sessions._startup_read_only_supported", return_value=True)
    def test_startup_recheck_revalidates_fence_after_authority_reads(self, _supported):
        from platform_modules.pam.sessions import _check_authority

        item, owner = self.claimed()
        changes = [
            {"owner_token": uuid.uuid4()},
            {"status": "failed"},
            {"stop_requested_at": timezone.now()},
            {"authority_seal": "0" * 64},
            {"expires_at": item.expires_at + timedelta(minutes=1)},
            {"authority_snapshot": {**item.authority_snapshot, "reason": "changed"}},
        ]
        for mutation in changes:
            with self.subTest(fields=list(mutation)):

                def changed_after_validation(checked, **kwargs):
                    _check_authority(checked, **kwargs)
                    RelayConnection.objects.filter(pk=item.pk).update(**mutation)

                with (
                    patch(
                        "platform_modules.pam.sessions._check_authority",
                        side_effect=changed_after_validation,
                    ),
                    self.assertRaises(PermissionDenied),
                ):
                    check_startup_session(
                        item.pk,
                        self.org,
                        owner,
                        session_key=self.session_key,
                        client_ip="127.0.0.1",
                    )
                # The rejected transaction must not leave its injected alteration behind.
                item.refresh_from_db()
                self.assertEqual(item.owner_token, owner)
                self.assertEqual(item.status, "connecting")
                self.assertIsNone(item.stop_requested_at)

    def test_read_only_recheck_cannot_replace_an_active_monitor_or_opening_evidence(self):
        item, owner = self.claimed()
        with self.assertRaises(ValueError):
            check_session(
                item.pk,
                self.org,
                owner,
                session_key=self.session_key,
                client_ip="127.0.0.1",
                write_heartbeat=False,
                target_snapshot={"protocol": "ssh"},
            )
        RelayConnection.objects.filter(pk=item.pk).update(status="active")
        with self.assertRaises(PermissionDenied):
            check_startup_session(
                item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
            )

    def test_configuration_is_encrypted_and_requires_service_level_mfa(self):
        with self.assertRaises(PermissionDenied):
            self.configure_without_assurance()
        endpoint = self.configured_endpoint
        self.assertNotIn("secret-fixture", endpoint.encrypted_secret)
        self.assertEqual(
            json.loads(cipher().decrypt(endpoint.encrypted_secret.encode())),
            {"password": "secret-fixture-not-a-real-password"},
        )
        with self.assurance(), self.assertRaises(ValidationError):
            set_endpoint_enabled(endpoint.pk, actor=self.admin, organization=self.org, enabled=True)
        self.assertTrue(verify_chain(self.org))

    def configure_without_assurance(self):
        return configure_endpoint(
            actor=self.admin,
            organization=self.org,
            name="SSH fixture",
            resource=self.resource,
            account=self.account,
            protocol="ssh",
            hostname="ssh.example.test",
            port=22,
            auth_method="password",
            password="secret",
            host_key=self.host_key,
        )

    def test_encrypted_openssh_key_is_imported_without_retaining_its_passphrase(self):
        key = asyncssh.generate_private_key("ssh-ed25519")
        protected = key.export_private_key("openssh", passphrase="fixture-import-passphrase")
        with self.assurance():
            endpoint = configure_endpoint(
                actor=self.admin,
                organization=self.org,
                name="Private key fixture",
                resource=self.resource,
                account=self.account,
                protocol="ssh",
                hostname="ssh.example.test",
                port=22,
                auth_method="private_key",
                private_key=protected.decode(),
                passphrase="fixture-import-passphrase",
                host_key=self.host_key,
                endpoint_id=self.configured_endpoint.pk,
            )
        material = json.loads(cipher().decrypt(endpoint.encrypted_secret.encode()))
        self.assertEqual(set(material), {"private_key"})
        self.assertEqual(
            asyncssh.import_private_key(material["private_key"]).public_data, key.public_data
        )
        self.assertNotIn("fixture-import-passphrase", endpoint.encrypted_secret)

    def test_ticket_is_one_use_and_bound_to_actor_browser_address_and_organization(self):
        item, token = self.launched()
        for changes in (
            {"ticket": "incorrect"},
            {"client_ip": "127.0.0.2"},
            {"actor": self.admin},
            {"session_key": "a" * 32},
        ):
            params = dict(
                actor=self.operator,
                session_key=self.session_key,
                client_ip="127.0.0.1",
                ticket=token,
                instance_id="test-node",
            )
            params.update(changes)
            with self.assertRaises(PermissionDenied):
                claim_session(item.pk, **params)
        args = dict(
            actor=self.operator,
            session_key=self.session_key,
            client_ip="127.0.0.1",
            ticket=token,
            instance_id="test-node",
        )
        claim_session(item.pk, **args)
        with self.assertRaises(PermissionDenied):
            claim_session(item.pk, **args)
        item.refresh_from_db()
        self.assertEqual(item.ticket_hash, "")
        self.assertNotIn(token, item.browser_session_hash)
        with organization_context(self.other):
            self.assertFalse(RelayConnection.objects.filter(pk=item.pk).exists())

    def test_no_new_connection_without_mfa_or_without_pam_fulfillment(self):
        self.enabled()
        params = dict(
            actor=self.operator,
            organization=self.org,
            session_key=self.session_key,
            client_ip="127.0.0.1",
        )
        with self.assertRaises(PermissionDenied):
            launch_session(self.intent.pk, **params)
        AccessIntent.objects.filter(pk=self.intent.pk).update(fulfillment="observe")
        with self.assurance(self.operator), self.assertRaises(ValidationError):
            launch_session(self.intent.pk, **params)
        self.assertFalse(RelayConnection.objects.exists())

    def test_open_session_does_not_rechallenge_mfa_and_owner_can_stop_without_mfa(self):
        item, owner = self.claimed()
        later = timezone.now() + timedelta(minutes=20)
        with patch("platform_modules.pam.sessions.timezone.now", return_value=later):
            self.trust.checkpoint()
            check_session(
                item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
            )
            stop_session(item.pk, actor=self.operator, organization=self.org)
            with self.assertRaises(PermissionDenied):
                check_session(
                    item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
                )

    def test_logout_account_disable_endpoint_change_and_expiry_cut_authority(self):
        item, owner = self.claimed()
        arguments = dict(session_key=self.session_key, client_ip="127.0.0.1")
        for model, pk, field, original, revoked in (
            (ExternalAccount, self.account.pk, "active", True, False),
            (Identity, self.identity.pk, "status", "active", "departed"),
            (SessionEndpoint, self.endpoint.pk, "enabled", True, False),
            (SessionEndpoint, self.endpoint.pk, "revision", 1, 2),
        ):
            model.objects.filter(pk=pk).update(**{field: revoked})
            with self.assertRaises(PermissionDenied):
                check_session(item.pk, self.org, owner, **arguments)
            model.objects.filter(pk=pk).update(**{field: original})
        with patch("platform_modules.pam.sessions.timezone.now", return_value=item.expires_at):
            with self.assertRaises(PermissionDenied):
                check_session(item.pk, self.org, owner, **arguments)
        Session.objects.filter(session_key=self.session_key).delete()
        with self.assertRaises(PermissionDenied):
            check_session(item.pk, self.org, owner, **arguments)

    def test_fenced_encrypted_recording_chain_and_quota(self):
        item, owner = self.claimed()
        with self.assertRaises(PermissionDenied):
            append_recording(item.pk, self.org, uuid.uuid4(), b"3.nop;", 0)
        first = append_recording(item.pk, self.org, owner, b"3.nop;", 0)
        last = append_recording(item.pk, self.org, owner, b"4.sync,1.1;", 100)
        chunks = list(RecordingChunk.objects.filter(connection=item))
        self.assertEqual(chunks[1].previous_hash, first)
        self.assertEqual(last, chunks[1].chunk_hash)
        for chunk in chunks:
            self.assertEqual(
                chunk.chunk_hash,
                chunk_digest(
                    item,
                    chunk.sequence,
                    chunk.previous_hash,
                    chunk.elapsed_ms,
                    chunk.payload_size,
                    chunk.encrypted_payload,
                ),
            )
            self.assertNotIn(b"nop", bytes(chunk.encrypted_payload))
        self.assertEqual(cipher().decrypt(bytes(chunks[0].encrypted_payload)), b"3.nop;")
        with override_settings(PAM_MAX_RECORDING_BYTES=17):
            with self.assertRaisesMessage(TransportFailure, "recording_quota_exceeded"):
                append_recording(item.pk, self.org, owner, b"3.nop;", 200)
        finish_session(item.pk, self.org, owner, reason="client_closed", complete=True)
        item.refresh_from_db()
        self.assertEqual(item.recording_hash, last)
        self.assertEqual(item.recording_chunks, 2)
        self.assertTrue(item.recording_complete)
        self.assertTrue(verify_chain(self.org))
        with self.assertRaises(PermissionDenied):
            append_recording(item.pk, self.org, owner, b"3.nop;", 300)

    def test_owner_lost_never_marks_a_recording_complete(self):
        item, owner = self.claimed()
        append_recording(item.pk, self.org, owner, b"3.nop;", 0)
        RelayConnection.objects.filter(pk=item.pk).update(
            heartbeat_at=timezone.now() - timedelta(seconds=20)
        )
        reap_connections(self.org)
        item.refresh_from_db()
        self.assertEqual(item.end_reason, "relay_owner_lost")
        self.assertFalse(item.recording_complete)
        self.assertEqual(item.recording_chunks, 1)

    def test_recording_grant_requires_mfa_and_cannot_be_forged_or_reused_by_another_browser(self):
        item, owner = self.claimed()
        append_recording(item.pk, self.org, owner, b"3.nop;", 0)
        finish_session(item.pk, self.org, owner, reason="client_closed", complete=True)
        item.refresh_from_db()
        with self.assertRaises(PermissionDenied):
            issue_recording_grant(item, self.operator, self.session_key)
        with self.assurance(self.operator):
            grant = issue_recording_grant(item, self.operator, self.session_key)
        data, sequence, previous = recording_page(item.pk, self.org, self.session_key, grant, 0, "")
        self.assertEqual(data, [b"3.nop;"])
        with self.assertRaises(PermissionDenied):
            recording_page(
                item.pk,
                self.org,
                self.session_key,
                dict(grant, expires_at=grant["expires_at"] + 60),
                0,
                "",
            )
        with self.assurance(self.admin), self.assertRaises(PermissionDenied):
            issue_recording_grant(item, self.admin, self.session_key)
        RelayConnection.objects.filter(pk=item.pk).update(recording_bytes=100)
        with self.assertRaises(ValidationError):
            recording_page(item.pk, self.org, self.session_key, grant, sequence, previous)

    def test_snapshot_and_ciphertext_swap_cannot_retarget_a_claim(self):
        item, token = self.launched()
        SessionEndpoint.objects.filter(pk=self.endpoint.pk).update(
            encrypted_secret=cipher().encrypt(b'{"password":"changed"}').decode()
        )
        with self.assertRaises(PermissionDenied):
            claim_session(
                item.pk,
                actor=self.operator,
                session_key=self.session_key,
                client_ip="127.0.0.1",
                ticket=token,
                instance_id="node",
            )

    def test_owner_stop_view_does_not_challenge_mfa_after_it_has_expired(self):
        from django.urls import reverse

        item, owner = self.claimed()
        session = self.client.session
        session["mfa_verified_at"] = time.time() - 3600
        session.save()
        response = self.client.post(reverse("pam-stop", args=[item.pk]))
        self.assertRedirects(response, reverse("pam-connection", args=[item.pk]))
        item.refresh_from_db()
        self.assertIsNotNone(item.stop_requested_at)
        self.assertNotIn("post_mfa_action", self.client.session)

    def test_endpoint_views_do_not_echo_stored_credentials_or_allow_unknown_actions(self):
        from django.urls import reverse

        endpoint = self.enabled()
        self.client.force_login(self.admin)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time()
        session.save()
        response = self.client.get(reverse("pam-endpoint-edit", args=[endpoint.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "secret-fixture-not-a-real-password")
        self.assertContains(response, "Tester le réseau")
        response = self.client.post(reverse("pam-endpoint-action", args=[endpoint.pk, "unknown"]))
        self.assertEqual(response.status_code, 404)
        endpoint.refresh_from_db()
        self.assertTrue(endpoint.enabled)

    def test_no_secret_decryption_after_configuration_loss(self):
        item, owner = self.claimed()
        loaded = check_session(
            item.pk, self.org, owner, session_key=self.session_key, client_ip="127.0.0.1"
        )
        self.assertIn("password", endpoint_credentials(loaded))
        loaded.endpoint.encrypted_secret = "invalid"
        with self.assertRaises(TransportFailure):
            endpoint_credentials(loaded)

    def test_empty_capture_does_not_open_a_broken_player(self):
        from django.urls import reverse

        item, owner = self.claimed()
        finish_session(item.pk, self.org, owner, reason="native_closed", complete=True)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        response = self.client.post(reverse("pam-recording", args=[item.pk]))
        self.assertRedirects(response, reverse("pam-connection", args=[item.pk]))
        self.assertNotIn(str(item.pk), self.client.session.get("pam_recording_grants", {}))

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL append-only and tenant guards")
    def test_postgresql_rejects_recording_mutation_and_cross_tenant_bulk_insert(self):
        item, owner = self.claimed()
        append_recording(item.pk, self.org, owner, b"3.nop;", 0)
        for operation in (
            lambda: RecordingChunk.objects.filter(connection=item).update(chunk_hash="f" * 64),
            lambda: RecordingChunk.objects.filter(connection=item).delete(),
        ):
            with self.assertRaises(DatabaseError), transaction.atomic():
                operation()
        with self.assertRaises(DatabaseError), transaction.atomic():
            RecordingChunk.unscoped.bulk_create(
                [
                    RecordingChunk(
                        organization=self.other,
                        connection=item,
                        sequence=10,
                        elapsed_ms=10,
                        payload_size=1,
                        encrypted_payload=b"x",
                        chunk_hash="f" * 64,
                    )
                ]
            )


@skipUnless(connection.vendor == "postgresql", "PostgreSQL concurrent startup fence")
@override_settings(PAM_ALLOWED_HOSTS={"ssh.example.test:22"})
class StartupFenceConcurrencyTests(PamSessionFixtureMixin, TransactionTestCase):
    def setUp(self):
        type(self).setUpTestData()
        super().setUp()

    def test_committed_owner_change_in_another_transaction_invalidates_the_recheck(self):
        from platform_modules.pam.sessions import _check_authority, _startup_read_only_supported

        self.assertTrue(_startup_read_only_supported(), "This gate requires READ COMMITTED")
        item, owner = self.claimed()
        replacement = uuid.uuid4()

        def change_owner():
            close_old_connections()
            try:
                with organization_context(self.org), transaction.atomic():
                    RelayConnection.objects.filter(pk=item.pk).update(owner_token=replacement)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as executor:

            def changed_after_validation(checked, **kwargs):
                _check_authority(checked, **kwargs)
                executor.submit(change_owner).result(timeout=5)

            with (
                patch(
                    "platform_modules.pam.sessions._check_authority",
                    side_effect=changed_after_validation,
                ),
                self.assertRaises(PermissionDenied),
            ):
                check_startup_session(
                    item.pk,
                    self.org,
                    owner,
                    session_key=self.session_key,
                    client_ip="127.0.0.1",
                )
        # The other connection's commit survives our rejected read transaction.
        item.refresh_from_db()
        self.assertEqual(item.owner_token, replacement)
