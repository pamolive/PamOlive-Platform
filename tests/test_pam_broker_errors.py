"""Diagnostic metadata must not expose database values or credentials."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from django.conf import settings
from django.db import OperationalError
from django.test import SimpleTestCase

from platform_modules.pam.broker import DatabaseDeadlineExceeded, Relay, database
from platform_modules.pam.sessions import finish_session


class BrokerDatabaseErrorTests(SimpleTestCase):
    async def test_transactions_of_one_relay_are_serialized_without_a_global_lock(self):
        active, peak = 0, 0

        async def operation(function):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.02)
            finally:
                active -= 1

        first = Relay("first", {}, AsyncMock(), AsyncMock())
        second = Relay("second", {}, AsyncMock(), AsyncMock())
        with patch("platform_modules.pam.broker.database", side_effect=operation):
            await asyncio.gather(*(first.state(object()) for _ in range(4)))
            self.assertEqual(peak, 1)
            peak = 0
            await asyncio.gather(first.state(object()), second.state(object()))
            self.assertEqual(peak, 2)

    async def test_queue_wait_is_included_in_the_database_deadline(self):
        relay = Relay("first", {}, AsyncMock(), AsyncMock())
        await relay.database_lock.acquire()
        with (
            patch("platform_modules.pam.broker.DATABASE_DEADLINE_SECONDS", 0.02),
            patch("platform_modules.pam.broker.database", new_callable=AsyncMock) as called,
            self.assertLogs("platform_modules.pam.broker", level="ERROR") as captured,
        ):
            with self.assertRaises(DatabaseDeadlineExceeded):
                await relay.state(object())
            called.assert_not_awaited()
        self.assertIn("phase=queue operation=unknown", " ".join(captured.output))
        relay.database_lock.release()

    async def test_database_execution_deadline_has_its_own_safe_error(self):
        async def never_finishes():
            await asyncio.Event().wait()

        def untrusted_operation(value):
            raise AssertionError("The execution adapter is stubbed in this test")

        untrusted_operation.__name__ = "secret\nmultiline"
        with (
            patch("platform_modules.pam.broker.DATABASE_DEADLINE_SECONDS", 0.02),
            patch("platform_modules.pam.broker.sync_to_async", return_value=never_finishes),
            self.assertLogs("platform_modules.pam.broker", level="ERROR") as captured,
        ):
            with self.assertRaises(DatabaseDeadlineExceeded):
                await database(untrusted_operation, "secret-parameter")
        output = " ".join(captured.output)
        self.assertIn("phase=operation operation=unknown", output)
        self.assertNotIn("secret", output)

    async def test_operation_timeout_is_not_misreported_as_our_database_deadline(self):
        operation = AsyncMock(side_effect=TimeoutError("synthetic-operation-value"))
        with (
            patch("platform_modules.pam.broker.sync_to_async", return_value=operation),
            self.assertNoLogs("platform_modules.pam.broker", level="ERROR"),
        ):
            with self.assertRaises(TimeoutError) as raised:
                await database(object())
        self.assertNotIsInstance(raised.exception, DatabaseDeadlineExceeded)

    async def test_cancelled_state_releases_the_lock_without_reporting_a_deadline(self):
        entered = asyncio.Event()

        async def operation(function):
            entered.set()
            await asyncio.Event().wait()

        relay = Relay("fixture", {}, AsyncMock(), AsyncMock())
        with (
            patch("platform_modules.pam.broker.database", side_effect=operation),
            self.assertNoLogs("platform_modules.pam.broker", level="ERROR"),
        ):
            task = asyncio.create_task(relay.state(object()))
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertFalse(relay.database_lock.locked())

    async def test_deadline_cuts_native_before_sealing_partial_database_failure(self):
        ordering = []

        async def closed():
            ordering.append("transport_closed")

        responses = [SimpleNamespace(pk=1), ("fixture", "tenant", "owner"), "tenant", None]

        async def operation(function, *args, **kwargs):
            if function is finish_session:
                ordering.append("evidence_finalization")
            return responses.pop(0)

        receive = AsyncMock(
            side_effect=[
                {"type": "websocket.connect"},
                {
                    "type": "websocket.receive",
                    "text": json.dumps({"ticket": "synthetic-ticket", "width": 320, "height": 200}),
                },
            ]
        )
        send = AsyncMock()
        relay = Relay("fixture", {}, receive, send)
        relay.native = SimpleNamespace(close=AsyncMock(side_effect=closed))
        cookie = f"{settings.SESSION_COOKIE_NAME}=" + "a" * 32
        with (
            patch(
                "platform_modules.pam.broker.check_websocket_origin",
                return_value=({"cookie": cookie}, "127.0.0.1"),
            ),
            patch("platform_modules.pam.broker.database", side_effect=operation) as calls,
            patch.object(relay, "race", side_effect=DatabaseDeadlineExceeded),
        ):
            await relay.run()
        self.assertEqual(ordering, ["transport_closed", "evidence_finalization"])
        self.assertIs(calls.await_args_list[-1].args[0], finish_session)
        self.assertEqual(
            calls.await_args_list[-1].kwargs, {"reason": "database_unavailable", "complete": False}
        )
        self.assertEqual(
            send.await_args_list[-1].args[0], {"type": "websocket.close", "code": 4403}
        )

    async def test_only_operation_and_valid_sqlstate_are_logged(self):
        class DatabaseCause(Exception):
            sqlstate = "55P03"

        def guarded_check():
            raise OperationalError("secret-query-arguments") from DatabaseCause("secret-DSN")

        with self.assertLogs("platform_modules.pam.broker", level="ERROR") as captured:
            with self.assertRaises(OperationalError):
                await database(guarded_check)
        output = " ".join(captured.output)
        self.assertIn("operation=guarded_check sqlstate=55P03", output)
        self.assertNotIn("secret", output)

    async def test_untrusted_exception_metadata_is_not_logged(self):
        class DatabaseCause(Exception):
            sqlstate = "secret-key-material"

        def guarded_check():
            raise OperationalError("secret-query-arguments") from DatabaseCause("secret-DSN")

        guarded_check.__name__ = "secret\nmultiline"
        with self.assertLogs("platform_modules.pam.broker", level="ERROR") as captured:
            with self.assertRaises(OperationalError):
                await database(guarded_check)
        output = " ".join(captured.output)
        self.assertIn("operation=unknown sqlstate=unknown", output)
        self.assertNotIn("secret", output)
