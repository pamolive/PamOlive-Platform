"""PostgreSQL ordering of independent trust, action proofs and credential release."""

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from unittest import skipUnless
from unittest.mock import Mock, patch

from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase, override_settings

from platform_core.tenancy import organization_context
from platform_modules.pam import trust_auth
from platform_modules.pam.recordings import issue_recording_grant, recording_page
from platform_modules.pam.sessions import (
    append_recording,
    check_startup_session,
    endpoint_credentials,
    finish_session,
)
from platform_modules.pam.trust import launch_payload, verify_launch
from platform_modules.pam.trust_auth_models import PAMTrustAuthorization, PAMTrustChallenge
from platform_modules.pam.trust_registry import historical_registry, recognized_registry

from .test_pam_sessions import PamSessionFixtureMixin


@skipUnless(connection.vendor == "postgresql", "PostgreSQL independent trust transactions")
@override_settings(PAM_ALLOWED_HOSTS={"ssh.example.test:22"})
class PAMTrustConcurrencyTests(PamSessionFixtureMixin, TransactionTestCase):
    def setUp(self):
        type(self).setUpTestData()
        super().setUp()

    def independent_connection(self, operation):
        close_old_connections()
        try:
            with organization_context(self.org):
                return operation()
        finally:
            connections.close_all()

    def loaded_relay(self):
        item, owner = self.claimed()
        return check_startup_session(
            item.pk,
            self.org,
            owner,
            session_key=self.session_key,
            client_ip="127.0.0.1",
        )

    def revoke_requester(self):
        person = self.trust.people[self.operator.pk]
        self.trust.update(lambda body: body["persons"][person].update(active=False))

    def wait_for_database_lock(self, backend_pid):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
                    [backend_pid],
                )
                row = cursor.fetchone()
            if row and row[0] == "Lock":
                return
            Event().wait(0.01)
        self.fail("The concurrent registry publication did not wait for the credential lock.")

    def test_committed_revocation_invalidates_a_previously_loaded_relay_before_decryption(self):
        stale = self.loaded_relay()
        with ThreadPoolExecutor(max_workers=1) as executor:
            executor.submit(self.independent_connection, self.revoke_requester).result(timeout=10)
        with (
            patch("platform_modules.pam.sessions.cipher") as encryption,
            self.assertRaises(PermissionDenied),
        ):
            endpoint_credentials(stale, session_key=self.session_key, client_ip="127.0.0.1")
        encryption.assert_not_called()

    def test_revocation_waits_for_a_credential_release_already_under_the_common_lock(self):
        from platform_core.security import cipher

        stale = self.loaded_relay()
        decrypting, release_decryption, revoking = Event(), Event(), Event()
        backend_pid = []
        encryption = cipher()

        def paused_decrypt(payload):
            decrypting.set()
            if not release_decryption.wait(timeout=10):
                raise AssertionError("The credential release was not allowed to finish.")
            return encryption.decrypt(payload)

        wrapped = Mock(wraps=encryption)
        wrapped.decrypt.side_effect = paused_decrypt

        def release():
            return endpoint_credentials(
                stale, session_key=self.session_key, client_ip="127.0.0.1"
            )

        def revoke():
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pid.append(cursor.fetchone()[0])
            revoking.set()
            self.revoke_requester()

        with (
            ThreadPoolExecutor(max_workers=2) as executor,
            patch("platform_modules.pam.sessions.cipher", return_value=wrapped),
        ):
            release_result = executor.submit(self.independent_connection, release)
            try:
                self.assertTrue(decrypting.wait(timeout=10))
                revoke_result = executor.submit(self.independent_connection, revoke)
                self.assertTrue(revoking.wait(timeout=10))
                self.wait_for_database_lock(backend_pid[0])
            finally:
                release_decryption.set()
            self.assertIn("password", release_result.result(timeout=10))
            revoke_result.result(timeout=10)
        with (
            patch("platform_modules.pam.sessions.cipher") as rejected,
            self.assertRaises(PermissionDenied),
        ):
            endpoint_credentials(stale)
        rejected.assert_not_called()

    def test_two_connections_cannot_finish_the_same_webauthn_challenge(self):
        request = self.trust.request(self.operator)
        options = trust_auth.begin_action(request, "launch", launch_payload(self.intent))
        response = self.trust.authenticators[self.operator.pk].response(options)
        ready = Barrier(2)

        def finish():
            ready.wait(timeout=5)
            try:
                trust_auth.finish_action(request, options["challenge"], response)
            except PermissionDenied:
                return "rejected"
            return "verified"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = [executor.submit(self.independent_connection, finish) for _ in range(2)]
            self.assertEqual(
                sorted(result.result(timeout=10) for result in results),
                ["rejected", "verified"],
            )
        challenge = PAMTrustChallenge.unscoped.get(pk=options["challenge"])
        self.assertIsNotNone(challenge.used_at)
        self.assertEqual(PAMTrustAuthorization.unscoped.filter(challenge=challenge).count(), 1)

    def test_two_connections_cannot_consume_the_same_action_authorization(self):
        request = self.trust.request(self.operator)
        payload = launch_payload(self.intent)
        token = self.trust.proof(self.operator, "launch", payload, request)
        request.POST = request.POST.copy()
        request.POST["_pam_trust_proof"] = token
        ready = Barrier(2)

        def consume():
            ready.wait(timeout=5)
            try:
                with trust_auth.action_authentication(request):
                    proof = trust_auth.require_action(self.operator, self.org, "launch", payload)
            except PermissionDenied:
                return "rejected"
            return "consumed" if proof.consumed_at else "unconsumed"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = [executor.submit(self.independent_connection, consume) for _ in range(2)]
            self.assertEqual(
                sorted(result.result(timeout=10) for result in results),
                ["consumed", "rejected"],
            )
        proof = PAMTrustAuthorization.unscoped.get(
            token_hash=hashlib.sha256(token.encode()).hexdigest()
        )
        self.assertIsNotNone(proof.consumed_at)
        self.assertTrue(trust_auth.verify_authorization_evidence(trust_auth.authorization_evidence(proof)))

    def test_rolled_back_database_cannot_pass_a_newer_independent_checkpoint(self):
        recorded = self.loaded_relay()
        owner = recorded.owner_token
        append_recording(recorded.pk, self.org, owner, b"3.nop;", 0)
        finish_session(recorded.pk, self.org, owner, reason="client_closed", complete=True)
        recorded.refresh_from_db()
        stale = self.loaded_relay()
        old_registry = self.trust.row
        launch_evidence = stale.authority_snapshot["pam_trust_launch"]

        with transaction.atomic():
            self.revoke_requester()
            transaction.set_rollback(True)

        self.assertEqual(
            historical_registry(self.org, old_registry.revision_hash).revision_hash,
            old_registry.revision_hash,
        )
        self.assertTrue(verify_launch(self.intent, launch_evidence))
        with self.assertRaises(PermissionDenied):
            recognized_registry(self.org)
        with (
            patch("platform_modules.pam.sessions.cipher") as encryption,
            self.assertRaises(PermissionDenied),
        ):
            endpoint_credentials(stale)
        encryption.assert_not_called()
        with self.assurance(self.operator):
            grant = issue_recording_grant(recorded, self.operator, self.session_key)
        data, _, _ = recording_page(recorded.pk, self.org, self.session_key, grant, 0, "")
        self.assertEqual(data, [b"3.nop;"])
