"""Transport-only mocks: no egress, package execution, or real retry sleeps."""

import copy
import hashlib
import io
import os
import socket
import ssl
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from deploy import python_materials as pm
from tests.test_python_materials import Response, manifest


class Clock:
    def __init__(self):
        self.now, self.sleeps = 0.0, []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class ResilienceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.row = copy.deepcopy(manifest()["materials"][0])
        self.row.update(size=5, sha256=hashlib.sha256(b"bytes").hexdigest())
        self.clock = Clock()
        for name, value in (("monotonic", self.clock.monotonic), ("sleep", self.clock.sleep)):
            patch = mock.patch.object(pm.time, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def good(self):
        return Response(b"bytes", self.row["url"])

    def run_download(self, events, **kwargs):
        opener = mock.Mock()
        opener.open.side_effect = events
        pm.download(self.row, self.root, opener, **kwargs)
        self.assertEqual((self.root / self.row["filename"]).read_bytes(), b"bytes")
        for call in opener.open.call_args_list:
            request = call.args[0]
            self.assertEqual(request.full_url, self.row["url"])
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(
                request.headers,
                {"Accept-encoding": "identity", "User-agent": "PamOlive-materials/1"},
            )
        return opener

    def test_typed_handshake_timeout_then_success(self):
        opener = self.run_download(
            [urllib.error.URLError(TimeoutError("unpublished detail")), self.good()]
        )
        self.assertEqual(opener.open.call_count, 2)
        self.assertEqual(self.clock.sleeps, [1])
        self.assertEqual([c.kwargs["timeout"] for c in opener.open.call_args_list], [30, 30])

    def test_each_allowed_typed_transport_condition(self):
        for error in (
            TimeoutError(),
            ConnectionResetError(),
            ConnectionAbortedError(),
            socket.gaierror(socket.EAI_AGAIN, "unpublished"),
        ):
            for wrapped in (False, True):
                with self.subTest(error=type(error).__name__, wrapped=wrapped):
                    self.assertTrue(
                        pm.retryable_transport(
                            urllib.error.URLError(error) if wrapped else error, self.row["url"]
                        )
                    )

    def test_http_transients_both_opener_and_response_forms(self):
        for code in sorted(pm.RETRY_HTTP):
            for is_exception in (False, True):
                with self.subTest(code=code, exception=is_exception):
                    failure = (
                        urllib.error.HTTPError(self.row["url"], code, "", {}, io.BytesIO())
                        if is_exception
                        else Response(b"never consumed", self.row["url"], code)
                    )
                    opener = self.run_download([failure, self.good()])
                    self.assertEqual(opener.open.call_count, 2)
                    (self.root / self.row["filename"]).unlink()
                    if is_exception:
                        self.assertTrue(failure.fp.closed)

    def test_three_attempts_and_fixed_backoff(self):
        opener = mock.Mock()
        opener.open.side_effect = [TimeoutError(), TimeoutError(), TimeoutError()]
        with self.assertRaisesRegex(pm.MaterialsError, "^download_retry_exhausted$"):
            pm.download(self.row, self.root, opener)
        self.assertEqual(opener.open.call_count, 3)
        self.assertEqual(self.clock.sleeps, [1, 2])
        self.assertFalse((self.root / self.row["filename"]).exists())

    def test_partial_response_is_removed_before_fresh_full_get(self):
        first = self.good()
        first.read = mock.Mock(side_effect=[b"by", ConnectionResetError()])
        opener = mock.Mock()

        def open_request(*_, **__):
            if opener.open.call_count == 1:
                return first
            self.assertFalse((self.root / self.row["filename"]).exists())
            return self.good()

        opener.open.side_effect = open_request
        pm.download(self.row, self.root, opener)
        self.assertEqual((self.root / self.row["filename"]).read_bytes(), b"bytes")
        self.assertEqual(opener.open.call_count, 2)
        self.assertEqual(self.clock.sleeps, [1])

    def test_material_budget_not_reset_and_remaining_socket_timeout(self):
        opener = mock.Mock()

        def open_request(*_, **__):
            if opener.open.call_count == 1:
                self.clock.now = 297
                raise TimeoutError()
            return self.good()

        opener.open.side_effect = open_request
        pm.download(self.row, self.root, opener)
        self.assertEqual([c.kwargs["timeout"] for c in opener.open.call_args_list], [30, 2])
        (self.root / self.row["filename"]).unlink()
        self.clock.now, self.clock.sleeps = 0, []

        def expire(*_, **__):
            self.clock.now += 150
            raise TimeoutError()

        opener.open.reset_mock()
        opener.open.side_effect = expire
        with self.assertRaisesRegex(pm.MaterialsError, "^download_deadline$"):
            pm.download(self.row, self.root, opener)
        self.assertEqual(opener.open.call_count, 2)
        self.assertEqual(self.clock.sleeps, [1])

    def test_outer_budget_and_read_finishing_late_refuse(self):
        opener = mock.Mock()

        def expire(*_, **__):
            self.clock.now = 9.5
            raise TimeoutError()

        opener.open.side_effect = expire
        with self.assertRaisesRegex(pm.MaterialsError, "download_deadline"):
            pm.download(self.row, self.root, opener, deadline=10)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 10)
        self.assertEqual(self.clock.sleeps, [])
        self.clock.now = 0
        response = self.good()

        def late(_):
            self.clock.now = 300
            return b"bytes"

        response.read = late
        opener.open.side_effect = [response]
        with self.assertRaisesRegex(pm.MaterialsError, "download_deadline"):
            pm.download(self.row, self.root, opener)
        self.assertFalse((self.root / self.row["filename"]).exists())

    def test_acquisition_passes_one_deadline_and_stops_after_expiry(self):
        observed = []

        def download(row, directory, opener, *, deadline):
            observed.append(deadline)
            self.clock.now = 1800

        with (
            mock.patch.object(pm, "download", download),
            mock.patch.object(pm, "verify_file", side_effect=AssertionError("late verification")),
            self.assertRaisesRegex(pm.MaterialsError, "^acquisition_deadline$"),
        ):
            pm.acquire(manifest(), self.root / "acquire", mock.Mock())
        self.assertEqual(observed, [1800])

    def test_certificates_permanent_errors_and_unknown_fail_once(self):
        for error in (
            ssl.SSLCertVerificationError("private detail"),
            ssl.SSLError("protocol failure"),
            urllib.error.URLError("timed out"),
            socket.gaierror(socket.EAI_NONAME, "not transient"),
            OSError("filesystem"),
            ValueError("unknown"),
            pm.MaterialsError("redirect_forbidden"),
        ):
            with self.subTest(error=type(error).__name__):
                opener = mock.Mock()
                opener.open.side_effect = error
                with self.assertRaises(type(error)):
                    pm.download(self.row, self.root, opener)
                self.assertEqual(opener.open.call_count, 1)
                self.assertEqual(self.clock.sleeps, [])
                self.assertFalse(pm.retryable_transport(error, self.row["url"]))
        for code in (301, 302, 400, 401, 403, 404, 410, 418, 501, 505):
            opener = mock.Mock()
            opener.open.side_effect = urllib.error.HTTPError(self.row["url"], code, "", {}, None)
            with self.subTest(code=code), self.assertRaises(urllib.error.HTTPError):
                pm.download(self.row, self.root, opener)
            self.assertEqual(opener.open.call_count, 1)

    def test_changed_origin_never_retries_even_transient_http(self):
        for error in (
            urllib.error.HTTPError("https://evil.test/", 503, "", {}, None),
            Response(b"", "https://evil.test/", 503),
        ):
            opener = mock.Mock()
            opener.open.side_effect = [error] if isinstance(error, Response) else error
            with self.assertRaises((pm.MaterialsError, urllib.error.HTTPError)):
                pm.download(self.row, self.root, opener)
            self.assertEqual(opener.open.call_count, 1)
            self.assertEqual(self.clock.sleeps, [])

    def test_integrity_and_encoding_never_retry(self):
        for body, headers in (
            (b"other", {}),
            (b"by", {}),
            (b"bytes!", {}),
            (b"bytes", {"Content-Length": "6"}),
            (b"bytes", {"Content-Encoding": "gzip"}),
        ):
            opener = mock.Mock()
            opener.open.return_value = Response(body, self.row["url"], headers=headers)
            with self.subTest(body=body, headers=headers), self.assertRaises(pm.MaterialsError):
                pm.download(self.row, self.root, opener)
            self.assertEqual(opener.open.call_count, 1)
            self.assertEqual(self.clock.sleeps, [])
            self.assertFalse((self.root / self.row["filename"]).exists())

    def test_cleanup_preserves_foreign_replacement_and_no_retry(self):
        path = self.root / self.row["filename"]
        response = self.good()
        original = self.root / "attempt-owned"
        real_cleanup = pm.cleanup_download

        def replace(target, identity, directory_identity):
            path.rename(original)
            path.write_bytes(b"foreign")
            real_cleanup(target, identity, directory_identity)

        response.read = mock.Mock(side_effect=TimeoutError())
        opener = mock.Mock()
        opener.open.return_value = response
        with (
            mock.patch.object(pm, "cleanup_download", replace),
            self.assertRaisesRegex(pm.MaterialsError, "^download_cleanup_changed$"),
        ):
            pm.download(self.row, self.root, opener)
        self.assertEqual(path.read_bytes(), b"foreign")
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(self.clock.sleeps, [])

    def test_hardlink_and_missing_created_file_refuse_cleanup(self):
        path = self.root / self.row["filename"]
        real_cleanup = pm.cleanup_download
        for hardlink in (True, False):
            response = self.good()

            def mutate(target, identity, directory_identity):
                if hardlink:
                    os.link(path, self.root / "alias")
                else:
                    path.unlink()
                real_cleanup(target, identity, directory_identity)

            response.read = mock.Mock(side_effect=TimeoutError())
            opener = mock.Mock()
            opener.open.return_value = response
            with (
                mock.patch.object(pm, "cleanup_download", mutate),
                self.assertRaises((pm.MaterialsError, FileNotFoundError)),
            ):
                pm.download(self.row, self.root, opener)
            self.assertEqual(opener.open.call_count, 1)
            if hardlink:
                self.assertTrue(path.exists())
                path.unlink()
                (self.root / "alias").unlink()

    def test_filesystem_write_failure_not_transport_retry(self):
        opener = mock.Mock()
        opener.open.return_value = self.good()
        real_open = Path.open

        def open_file(path, mode="r", *args, **kwargs):
            if mode == "xb":
                raise ConnectionResetError("file operation, not network")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch.object(Path, "open", open_file), self.assertRaises(ConnectionResetError):
            pm.download(self.row, self.root, opener)
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(self.clock.sleeps, [])

    def test_transient_then_bad_bytes_is_terminal(self):
        opener = mock.Mock()
        opener.open.side_effect = [TimeoutError(), Response(b"wrong", self.row["url"]), self.good()]
        with self.assertRaisesRegex(pm.MaterialsError, "^download_integrity$"):
            pm.download(self.row, self.root, opener)
        self.assertEqual(opener.open.call_count, 2)
        self.assertEqual(self.clock.sleeps, [1])
        self.assertFalse((self.root / self.row["filename"]).exists())

    def test_wrapped_certificate_and_http_encoding_remain_terminal(self):
        for error in (
            urllib.error.URLError(ssl.SSLCertVerificationError("never logged")),
            urllib.error.HTTPError(self.row["url"], 503, "", {"Content-Encoding": "gzip"}, None),
        ):
            opener = mock.Mock()
            opener.open.side_effect = error
            with self.assertRaises(type(error)):
                pm.download(self.row, self.root, opener)
            self.assertEqual(opener.open.call_count, 1)
        opener = mock.Mock()
        opener.open.return_value = Response(b"", self.row["url"], 503, {"Content-Encoding": "gzip"})
        with self.assertRaisesRegex(pm.MaterialsError, "^http_encoding$"):
            pm.download(self.row, self.root, opener)
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(self.clock.sleeps, [])

    def test_retry_after_cannot_override_fixed_delay_or_get_headers(self):
        self.run_download(
            [Response(b"", self.row["url"], 429, {"Retry-After": "999999999"}), self.good()]
        )
        self.assertEqual(self.clock.sleeps, [1])

    def test_cleanup_identity_rejects_types_links_and_reparse(self):
        info = self.root / "regular"
        info.write_bytes(b"public")
        original = info.stat()
        for mode, links, attributes in (
            (0o040755, 1, 0),
            (0o120777, 1, 0),
            (original.st_mode, 2, 0),
            (original.st_mode, 1, 1024),
        ):
            fake = mock.Mock(
                st_mode=mode,
                st_nlink=links,
                st_file_attributes=attributes,
                st_dev=original.st_dev,
                st_ino=original.st_ino,
            )
            with self.subTest(mode=mode, links=links, attributes=attributes):
                with self.assertRaisesRegex(pm.MaterialsError, "^download_file_identity$"):
                    pm.download_identity(fake)


if __name__ == "__main__":
    unittest.main()
