"""Bounded W endpoints; only the per-connection adapter supplies TLS peer DER."""

import asyncio
import time

from pamolive_vault_runtime.asgi import Application as VaultApplication

from .codec import Error, encode, need
from .service import OBSERVE_TERMINAL

LIMITS = {
    "/v1/operations/bind": 32768,
    "/v1/operations/consume": 2097152,
    OBSERVE_TERMINAL: 2097152,
    "/v1/activations/begin": 4096,
    "/v1/activations/finish": 131072,
}


class Application(VaultApplication):
    routes = frozenset(LIMITS)

    def __init__(self, service):
        super().__init__(service)
        self.service = service

    async def __call__(self, scope, receive, send):
        await self._response(
            send, 503, encode({"error": "unavailable", "authorized": False}, 4096, special=True)
        )

    async def _run_route(self, route, body, der):
        await asyncio.wait_for(self._jobs.acquire(), timeout=1)
        try:
            future = asyncio.get_running_loop().run_in_executor(
                self._pool, self.service.dispatch, route, body, der
            )
        except BaseException:
            self._jobs.release()
            raise

        def finished(result):
            try:
                if not result.cancelled():
                    result.exception()
            finally:
                self._jobs.release()

        future.add_done_callback(finished)
        return await asyncio.wait_for(asyncio.shield(future), timeout=8)

    async def _request(self, der, scope, receive, send):
        try:
            route = scope.get("path")
            need(
                type(route) is str
                and route in LIMITS
                and scope.get("raw_path") == route.encode("ascii")
                and scope.get("method") == "POST"
                and scope.get("query_string") == b""
                and scope.get("type") == "http"
                and scope.get("scheme") == "https"
                and scope.get("http_version") in ("1.0", "1.1")
            )
            need(route in self.routes, "context_refused", 403)
            headers = scope.get("headers")
            need(type(headers) is list and len(headers) <= 32)
            parsed, size = {}, 0
            for item in headers:
                need(type(item) is tuple and len(item) == 2)
                key, value = item
                need(type(key) is bytes and type(value) is bytes and key not in parsed)
                size += len(key) + len(value)
                need(
                    size <= 8192
                    and key
                    in {
                        b"host",
                        b"content-type",
                        b"content-length",
                        b"accept",
                        b"user-agent",
                        b"connection",
                    }
                    and not any(c < 32 or c == 127 for c in value)
                )
                parsed[key] = value
            n = parsed.get(b"content-length", b"")
            need(
                parsed.get(b"content-type") == b"application/json"
                and n.isdigit()
                and 0 < len(n) <= 7
                and 0 < int(n) <= LIMITS[route]
            )
            expected, total, parts = int(n), 0, []
            end = time.monotonic() + 5
            while True:
                need(time.monotonic() < end)
                event = await asyncio.wait_for(
                    receive(), timeout=max(0.001, end - time.monotonic())
                )
                need(type(event) is dict and event.get("type") == "http.request")
                part, more = event.get("body", b""), event.get("more_body", False)
                need(type(part) is bytes and type(more) is bool)
                total += len(part)
                need(total <= expected and len(parts) < 256)
                parts.append(part)
                if not more:
                    break
            need(total == expected)
            status, raw = await self._run_route(route, b"".join(parts), der)
        except Error as error:
            status, raw = (
                error.status,
                encode({"error": error.code, "authorized": False}, 4096, special=True),
            )
        except Exception:
            status, raw = (
                503,
                encode({"error": "unavailable", "authorized": False}, 4096, special=True),
            )
        await self._response(send, status, raw)

    @staticmethod
    async def _response(send, status, raw):
        need(type(raw) is bytes and len(raw) <= 196608, "unavailable", 503)
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"no-store"),
                    (b"content-length", str(len(raw)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": raw})


class HistoryApplication(Application):
    routes = frozenset({OBSERVE_TERMINAL})
