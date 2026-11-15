"""Bounded reservation endpoint; TLS identity comes from a closure, never scope/headers."""

import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor

from .admission import MAX_REQUEST
from .bounded import Refusal, need


class Application:
    def __init__(self, reservations):
        self.reservations = reservations
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vault-reservation")
        self._jobs = asyncio.Semaphore(4)

    def close(self):
        self._pool.shutdown(wait=True, cancel_futures=False)

    async def __call__(self, scope, receive, send):
        # Uvicorn stock, a forged scope or a direct ASGI invocation cannot supply peer identity.
        await self._response(send, 503, {"error": "unavailable", "authorized": False})

    def for_tls_peer(self, der):
        need(type(der) is bytes and 0 < len(der) <= 16384, "caller_refused", 403)

        async def bound(scope, receive, send):
            await self._request(der, scope, receive, send)

        return bound

    async def _run(self, body, der):
        await asyncio.wait_for(self._jobs.acquire(), timeout=1)
        try:
            pending = asyncio.get_running_loop().run_in_executor(
                self._pool, self.reservations.prepare, body, der
            )
        except BaseException:
            self._jobs.release()
            raise

        # A disconnected/cancelled client does not free capacity while its SQL is still running.
        def finished(future):
            try:
                if not future.cancelled():
                    future.exception()  # Consume a late failure after client timeout/cancellation.
            finally:
                self._jobs.release()

        pending.add_done_callback(finished)
        return await asyncio.wait_for(asyncio.shield(pending), timeout=8)

    async def _request(self, der, scope, receive, send):
        try:
            need(
                scope.get("type") == "http"
                and scope.get("scheme") == "https"
                and scope.get("http_version") in ("1.0", "1.1")
            )
            need(
                scope.get("method") == "POST"
                and scope.get("path") == "/v1/reservations"
                and scope.get("raw_path") == b"/v1/reservations"
                and scope.get("query_string") == b""
            )
            headers = scope.get("headers")
            need(type(headers) is list and len(headers) <= 32)
            parsed, total = {}, 0
            for header in headers:
                need(type(header) is tuple and len(header) == 2)
                key, value = header
                need(type(key) is bytes and type(value) is bytes)
                total += len(key) + len(value)
                need(total <= 8192 and key not in parsed)
                need(
                    key
                    in {
                        b"host",
                        b"content-type",
                        b"content-length",
                        b"accept",
                        b"user-agent",
                        b"connection",
                    }
                )
                need(not any(c < 32 or c == 127 for c in value))
                parsed[key] = value
            need(parsed.get(b"content-type") == b"application/json")
            size = parsed.get(b"content-length", b"")
            need(0 < len(size) <= 7 and size.isdigit() and 0 < int(size) <= MAX_REQUEST)
            expected, total, parts = int(size), 0, []
            deadline = time.monotonic() + 5
            while True:
                remaining = deadline - time.monotonic()
                need(remaining > 0)
                event = await asyncio.wait_for(receive(), timeout=remaining)
                need(type(event) is dict and event.get("type") == "http.request")
                body = event.get("body", b"")
                need(type(body) is bytes and type(event.get("more_body", False)) is bool)
                total += len(body)
                need(total <= expected and len(parts) < 256)
                parts.append(body)
                if not event.get("more_body", False):
                    break
            need(total == expected)
            result = await self._run(b"".join(parts), der)
            response, status = result.public(), 200
        except Refusal as error:
            status, response = error.status, {"error": error.code, "authorized": False}
        except Exception:
            status, response = 503, {"error": "unavailable", "authorized": False}
        await self._response(send, status, response)

    @staticmethod
    async def _response(send, status, value):
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        need(len(raw) <= 1024, "unavailable", 503)
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"no-store"),
                    (b"content-length", str(len(raw)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": raw})
