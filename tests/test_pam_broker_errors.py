"""Diagnostic metadata must not expose database values or credentials."""

import asyncio
from unittest.mock import AsyncMock, patch

from django.db import OperationalError
from django.test import SimpleTestCase

from platform_modules.pam.broker import Relay, database


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
        ):
            with self.assertRaises(TimeoutError):
                await relay.state(object())
            called.assert_not_awaited()
        relay.database_lock.release()

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
