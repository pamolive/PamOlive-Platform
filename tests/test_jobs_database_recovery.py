"""A database outage must not stop the supervisor's Web process via runjobs."""

from collections import deque
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.db import IntegrityError, InterfaceError, OperationalError, ProgrammingError
from django.test import SimpleTestCase

from platform_core.management.commands import runjobs


class StopLoop(Exception):
    """Bound the daemon test without sleeping or launching a real executor."""


class JobsDatabaseRecoveryTests(SimpleTestCase):
    def test_global_database_failure_waits_and_retries_instead_of_exiting(self):
        for error in (OperationalError, InterfaceError):
            with (
                self.subTest(error=error.__name__),
                patch.object(runjobs, "ThreadPoolExecutor"),
                patch.object(runjobs, "close_old_connections"),
                patch.object(runjobs.connections, "close_all") as close,
                patch.object(runjobs, "cleanup_expired", side_effect=[
                    error("synthetic database diagnostics must not be logged"), StopLoop,
                ]),
                patch.object(runjobs.time, "sleep") as pause,
            ):
                with self.assertLogs(runjobs.logger, level="WARNING") as output:
                    with self.assertRaises(StopLoop):
                        runjobs.Command().handle(once=False)
                pause.assert_called_once_with(5)
                close.assert_called_once()
                self.assertNotIn("synthetic database diagnostics", " ".join(output.output))

    def test_failed_delivery_is_removed_before_retry_without_losing_other_pending_work(self):
        organization = SimpleNamespace(pk="synthetic-organization")
        failed = Mock()
        failed.done.return_value = True
        failed.result.side_effect = OperationalError("synthetic worker database outage")
        still_running = Mock()
        still_running.done.return_value = False
        observed = {}

        def refill(executor, pending, organizations, queue):
            pending[organization.pk] = failed
            pending["other"] = still_running
            observed["pending"] = pending
            return deque([organization.pk])

        with (
            patch.object(runjobs, "ThreadPoolExecutor"),
            patch.object(runjobs, "close_old_connections"),
            patch.object(runjobs.connections, "close_all"),
            patch.object(runjobs, "cleanup_expired", side_effect=[None, None, StopLoop]),
            patch.object(runjobs.Organization.objects, "filter", return_value=[organization]),
            patch.object(runjobs.Organization.objects, "all", return_value=[]),
            patch.object(runjobs, "expire_leases"),
            patch.object(runjobs, "expire_grants"),
            patch.object(runjobs, "reconcile_contracts"),
            patch.object(runjobs, "refill", side_effect=refill),
            patch.object(runjobs.time, "sleep"),
            self.assertRaises(StopLoop),
        ):
            runjobs.Command().handle(once=False)
        self.assertNotIn(organization.pk, observed["pending"])
        self.assertIs(observed["pending"]["other"], still_running)

    def test_once_still_reports_database_failure_and_logic_errors_are_not_swallowed(self):
        for once, error in (
            (True, OperationalError), (True, InterfaceError), (False, ValueError),
            (False, IntegrityError), (False, ProgrammingError),
        ):
            with (
                self.subTest(once=once, error=error.__name__),
                patch.object(runjobs, "ThreadPoolExecutor"),
                patch.object(runjobs, "close_old_connections"),
                patch.object(runjobs, "cleanup_expired", side_effect=error("synthetic failure")),
                patch.object(runjobs.time, "sleep") as pause,
                self.assertRaises(error),
            ):
                runjobs.Command().handle(once=once)
            pause.assert_not_called()

    def test_recovery_reloads_organizations_before_resuming_durable_processors(self):
        organization = SimpleNamespace(pk="synthetic-reloaded-organization")
        with (
            patch.object(runjobs, "ThreadPoolExecutor"),
            patch.object(runjobs, "close_old_connections") as refresh,
            patch.object(runjobs.connections, "close_all"),
            patch.object(runjobs, "cleanup_expired", side_effect=[
                OperationalError("synthetic database outage"), None, StopLoop,
            ]),
            patch.object(
                runjobs.Organization.objects, "filter", return_value=[organization]
            ) as read,
            patch.object(runjobs.Organization.objects, "all", return_value=[]),
            patch.object(runjobs, "expire_leases") as leases,
            patch.object(runjobs, "expire_grants") as grants,
            patch.object(runjobs, "reconcile_contracts") as reconcile,
            patch.object(runjobs, "refill", return_value=deque()) as refill,
            patch.object(runjobs.time, "sleep") as pause,
            self.assertRaises(StopLoop),
        ):
            runjobs.Command().handle(once=False)
        self.assertEqual(refresh.call_count, 3)
        read.assert_called_once_with(active=True)
        for processor in (leases, grants, reconcile):
            processor.assert_called_once_with(organization)
        self.assertEqual(refill.call_count, 1)
        self.assertEqual(pause.call_count, 2)
