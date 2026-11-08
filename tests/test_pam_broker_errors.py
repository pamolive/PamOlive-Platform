"""Diagnostic metadata must not expose database values or credentials."""

from django.db import OperationalError
from django.test import SimpleTestCase

from platform_modules.pam.broker import database


class BrokerDatabaseErrorTests(SimpleTestCase):
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
