"""Independent recovery checks: a surviving daemon never renews old PAM authority."""

from collections import deque
from datetime import timedelta
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import PermissionDenied
from django.db import OperationalError, connection
from django.test import TransactionTestCase, override_settings

from platform_core.management.commands import runjobs
from platform_modules.pam.destination import TransportFailure
from platform_modules.pam.models import RelayConnection, SessionLease
from platform_modules.pam.sessions import check_session, endpoint_credentials

from .test_pam_sessions import PamSessionFixtureMixin


class StopRecoveryLoop(Exception):
    """Terminate the synthetic daemon after one successful recovery pass."""


@skipUnless(connection.vendor == "postgresql", "PostgreSQL connection recovery is required")
@override_settings(
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
    PAM_ALLOWED_HOSTS={"ssh.example.test:22"},
)
class JobsPAMRecoveryTests(PamSessionFixtureMixin, TransactionTestCase):
    def setUp(self):
        # TransactionTestCase permits a real close_all/reconnect. The existing
        # synthetic PAM fixture otherwise uses TestCase's class-data hook.
        self.setUpTestData()
        super().setUp()

    def test_database_recovery_reaps_stale_relay_without_renewing_expired_lease(self):
        relay, owner = self.claimed()
        relay.refresh_from_db()
        lease = SessionLease.objects.get(pk=relay.lease_id)
        original_connection = connection.connection
        heartbeat, deadline = relay.heartbeat_at, lease.expires_at
        recovered_at = deadline + timedelta(seconds=1)
        with (
            patch.object(runjobs, "ThreadPoolExecutor"),
            patch.object(runjobs, "cleanup_expired", side_effect=[
                OperationalError("synthetic connection loss"), None, StopRecoveryLoop,
            ]),
            patch.object(runjobs, "refill", return_value=deque()),
            patch.object(runjobs, "expire_grants"),
            patch.object(runjobs, "reconcile_contracts"),
            patch.object(runjobs.time, "sleep"),
            patch("django.utils.timezone.now", return_value=recovered_at),
            self.assertLogs(runjobs.logger, level="WARNING"),
            self.assertRaises(StopRecoveryLoop),
        ):
            runjobs.Command().handle(once=False)

        relay = RelayConnection.objects.get(pk=relay.pk)
        lease.refresh_from_db()
        self.assertTrue(original_connection.closed)
        self.assertIsNot(connection.connection, original_connection)
        self.assertEqual(relay.status, "failed")
        self.assertEqual(relay.end_reason, "relay_owner_lost")
        self.assertFalse(relay.recording_complete)
        self.assertEqual(relay.heartbeat_at, heartbeat)
        self.assertEqual(lease.status, "expired")
        self.assertEqual(lease.expires_at, deadline)
        with self.assertRaises(PermissionDenied):
            check_session(
                relay.pk, self.org, owner, session_key=self.session_key,
                client_ip="127.0.0.1",
            )
        with self.assertRaises(TransportFailure):
            endpoint_credentials(relay, session_key=self.session_key, client_ip="127.0.0.1")
        relay.refresh_from_db()
        self.assertEqual(relay.heartbeat_at, heartbeat)
