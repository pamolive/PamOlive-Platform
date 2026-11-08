import io
import json
import tempfile
import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.core.management import call_command, get_commands
from django.core.management.base import CommandError
from django.test import SimpleTestCase, override_settings

from platform_modules.connectors.scim import IntegrationFailure
from platform_modules.connectors.teamviewer import (
    MAX_BODY,
    ConnectionReport,
    ReportBatch,
    TeamViewerClient,
)
from tests.fixtures.oidc import tls_material

SINCE = datetime(2024, 1, 2, tzinfo=UTC)
UNTIL = SINCE + timedelta(days=1)
TOKEN = "test-only-teamviewer-script-token"


def record(*, identifier=None, end=None, start=None, **changes):
    value = dict(
        id=identifier or str(uuid.uuid4()),
        userid="u123",
        deviceid="12345678",
        start_date=(start or SINCE - timedelta(days=2)).isoformat(),
        end_date=(end or SINCE + timedelta(hours=1)).isoformat(),
        notes="Declared reason",
    )
    value.update(changes)
    return value


@override_settings(CONNECTOR_ALLOWED_HOSTS={"webapi.teamviewer.com:443"})
class TeamViewerReportingTests(SimpleTestCase):
    def make_client(self):
        return TeamViewerClient(TOKEN)

    def batch(self, pages, **options):
        client = self.make_client()
        with patch.object(client, "request_page", side_effect=pages):
            return client.fetch_completed(SINCE, UNTIL, **options)

    def test_completed_time_window_includes_long_session_started_before_window(self):
        value = record()
        result = self.batch([{"records": [value], "records_remaining": 0}])
        self.assertTrue(result.pagination_complete)
        self.assertLess(result.reports[0].started_at, SINCE)
        self.assertEqual(result.reports[0].notes, "Declared reason")

    def test_unknown_source_account_or_device_never_becomes_a_person(self):
        parsed = ConnectionReport.parse(record(userid=None, deviceid=None))
        self.assertIsNone(parsed.account_ref)
        self.assertIsNone(parsed.device_ref)
        self.assertFalse(hasattr(parsed, "identity_id"))
        self.assertFalse(hasattr(parsed, "privilege"))

    def test_pagination_preserves_completed_records_and_bounds_by_end_time(self):
        cursor = str(uuid.uuid4())
        result = self.batch(
            [
                {
                    "records": [record(end=SINCE + timedelta(hours=3))],
                    "next_offset": cursor,
                    "records_remaining": 1,
                },
                {"records": [record(end=SINCE - timedelta(seconds=1))], "records_remaining": 0},
            ]
        )
        self.assertTrue(result.pagination_complete)
        self.assertEqual(len(result.reports), 1)
        self.assertEqual(result.pages, 2)

    def test_page_limit_is_partial_not_successful_collection(self):
        result = self.batch(
            [{"records": [record()], "next_offset": str(uuid.uuid4()), "records_remaining": 5}],
            max_pages=1,
        )
        self.assertFalse(result.pagination_complete)
        self.assertEqual(result.code, "page_limit")

    def test_record_limit_does_not_silently_drop_records(self):
        result = self.batch([{"records": [record(), record()]}], max_records=1)
        self.assertFalse(result.pagination_complete)
        self.assertEqual(result.code, "record_limit")

    def test_missing_repeated_or_url_cursor_is_not_followed(self):
        cursor = str(uuid.uuid4())
        cases = [
            [{"records": [record()], "records_remaining": 1}],
            [{"records": [record()], "next_offset": "https://attacker.invalid/token"}],
            [
                {"records": [record()], "next_offset": cursor},
                {"records": [record()], "next_offset": cursor},
            ],
        ]
        for pages in cases:
            with self.subTest(pages=len(pages)):
                self.assertFalse(self.batch(pages).pagination_complete)

    def test_inconsistent_order_and_window_do_not_claim_completeness(self):
        for values in (
            [record(end=UNTIL)],
            [record(end=SINCE + timedelta(hours=1)), record(end=SINCE + timedelta(hours=2))],
        ):
            result = self.batch([{"records": values}])
            self.assertFalse(result.pagination_complete)

    def test_conflicting_duplicate_report_in_same_page_is_not_overwritten(self):
        value = record()
        result = self.batch([{"records": [value, dict(value, notes="changed")]}])
        self.assertFalse(result.pagination_complete)
        self.assertEqual(result.code, "teamviewer_conflicting_report")
        self.assertEqual(result.reports, ())

    def test_naive_times_invalid_notes_and_backwards_duration_are_refused(self):
        for changes in (
            {"start_date": "2024-01-02T00:00:00"},
            {"notes": False},
            {"start_date": UNTIL.isoformat()},
            {"id": "bad-id"},
        ):
            with self.subTest(changes=changes), self.assertRaises(IntegrationFailure):
                ConnectionReport.parse(record(**changes))
        with self.assertRaises(IntegrationFailure):
            self.make_client().fetch_completed(SINCE.replace(tzinfo=None), UNTIL)

    def test_upstream_failure_after_page_one_keeps_partial_result(self):
        result = self.batch(
            [
                {"records": [record()], "next_offset": str(uuid.uuid4())},
                IntegrationFailure("teamviewer_http_429", retryable=True),
            ]
        )
        self.assertFalse(result.pagination_complete)
        self.assertEqual(len(result.reports), 1)
        self.assertEqual(result.code, "teamviewer_http_429")

    def test_probe_command_is_wired_and_never_prints_notes_or_token(self):
        self.assertEqual(get_commands()["pamolive_teamviewer_probe"], "platform_modules.connectors")
        parsed = ConnectionReport.parse(record(notes="PRIVATE SOURCE NOTE"))
        output = io.StringIO()
        with (
            patch.dict("os.environ", {"PAMOLIVE_TEAMVIEWER_PROBE_TOKEN": TOKEN}),
            patch(
                "platform_modules.connectors.management.commands.pamolive_teamviewer_probe.TeamViewerClient"
            ) as client,
        ):
            client.return_value.fetch_completed.return_value = ReportBatch((parsed,), 1, True, "ok")
            call_command(
                "pamolive_teamviewer_probe",
                since=SINCE.isoformat(),
                until=UNTIL.isoformat(),
                stdout=output,
            )
            client.assert_called_once_with(TOKEN)
            client.return_value.fetch_completed.assert_called_once()
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertNotIn("PRIVATE SOURCE NOTE", output.getvalue())
        result = json.loads(output.getvalue())
        self.assertEqual(result["records"], 1)
        self.assertEqual(result["imported_records"], 0)
        self.assertFalse(result["collector_activated"])

    def test_probe_fails_for_partial_pagination(self):
        with patch(
            "platform_modules.connectors.management.commands.pamolive_teamviewer_probe.TeamViewerClient"
        ) as client:
            client.return_value.fetch_completed.return_value = ReportBatch(
                (), 1, False, "page_limit"
            )
            with self.assertRaises(CommandError):
                call_command(
                    "pamolive_teamviewer_probe",
                    since=SINCE.isoformat(),
                    until=UNTIL.isoformat(),
                    stdout=io.StringIO(),
                )

    def test_http_errors_and_redirects_never_forward_the_token_or_claim_completeness(self):
        for status in (302, 403, 429, 503):
            with (
                self.subTest(status=status),
                patch(
                    "platform_modules.connectors.teamviewer.resolve_destination",
                    return_value="8.8.8.8",
                ),
                patch("platform_modules.connectors.teamviewer.PinnedHTTPSConnection") as transport,
            ):
                transport.return_value.getresponse.return_value.status = status
                result = self.make_client().fetch_completed(SINCE, UNTIL)
                self.assertFalse(result.pagination_complete)
                self.assertEqual(result.code, "teamviewer_http_" + str(status))
                transport.return_value.request.assert_called_once()
                transport.return_value.close.assert_called_once()

    def test_duplicate_keys_nonfinite_json_and_oversized_response_are_refused(self):
        for body in (
            b'{"records":[],"records":[]}',
            b'{"records":[],"x":NaN}',
            b"X" * (MAX_BODY + 1),
        ):
            with (
                self.subTest(length=len(body)),
                patch(
                    "platform_modules.connectors.teamviewer.resolve_destination",
                    return_value="8.8.8.8",
                ),
                patch("platform_modules.connectors.teamviewer.PinnedHTTPSConnection") as transport,
            ):
                transport.return_value.getresponse.return_value.status = 200
                transport.return_value.getresponse.return_value.read.return_value = body
                result = self.make_client().fetch_completed(SINCE, UNTIL)
                self.assertFalse(result.pagination_complete)
                self.assertNotIn(TOKEN, result.code)


class TeamViewerTLSTests(SimpleTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pamolive-teamviewer-")
        self.addCleanup(self.temp.cleanup)
        tls, ca_file = tls_material(self.temp.name)
        observed = self.observed = []
        value = record()

        class Peer(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                observed.append((self.path, self.headers.get("Authorization")))
                body = json.dumps({"records": [value], "records_remaining": 0}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        settings = override_settings(
            CONNECTOR_ALLOWED_HOSTS={f"127.0.0.1:{self.server.server_port}"},
            CONNECTOR_ALLOWED_NETWORKS=("127.0.0.1/32",),
            CONNECTOR_CA_BUNDLE=ca_file,
        )
        settings.enable()
        self.addCleanup(settings.disable)
        self.client = TeamViewerClient(
            TOKEN, base_url=f"https://127.0.0.1:{self.server.server_port}/api/v1"
        )

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def test_real_pinned_tls_uses_end_bound_only_and_sends_bearer_outside_url(self):
        result = self.client.fetch_completed(SINCE, UNTIL)
        self.assertTrue(result.pagination_complete)
        self.assertEqual(len(result.reports), 1)
        path, authorization = self.observed[0]
        self.assertEqual(urlsplit(path).path, "/api/v1/reports/connections")
        query = parse_qs(urlsplit(path).query)
        self.assertEqual(query, {"to_date": ["2024-01-03T00:00:00Z"]})
        self.assertEqual(authorization, "Bearer " + TOKEN)
        self.assertNotIn(TOKEN, path)

    def test_untrusted_tls_returns_unavailable_not_empty_complete_result(self):
        with override_settings(CONNECTOR_CA_BUNDLE=""):
            result = self.client.fetch_completed(SINCE, UNTIL)
        self.assertFalse(result.pagination_complete)
        self.assertEqual(result.code, "tls_verification_failed")
        self.assertEqual(self.observed, [])
