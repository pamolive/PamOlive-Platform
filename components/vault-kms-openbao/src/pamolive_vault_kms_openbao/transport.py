"""One bounded Transit request; no discovery, environment, retry or pool.

The commissioning caller supplies the numeric endpoint and dedicated TLS files.
post() is synchronous and must run outside an event loop (service worker only).
Cancellation/failed closure never returns response bytes. No zeroization claim.
"""

import asyncio
import ipaddress
import json
import math
import re
import socket
import ssl
from pathlib import Path

import h11

MAX_BODY = 8192
MAX_TOKEN = 1024
MAX_HEADERS = 8192
MAX_WIRE = MAX_BODY + 2 * MAX_HEADERS
MAX_EVENTS = 256
ROUTE = re.compile(r"/v1/transit/(?:encrypt|decrypt)/[a-z0-9][a-z0-9-]{0,62}\Z")
DNS_NAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z"
)


class TransportError(ValueError):
    """Constant diagnostic, without response, token or underlying exception."""

    def __init__(self):
        super().__init__("openbao_transport_refused")


def _require(value):
    if not value:
        raise TransportError()


def _no_password():
    # An encrypted key must fail rather than invoke OpenSSL's interactive prompt.
    raise TransportError()


def _tls_context(ca_file, cert_file, key_file):
    paths = [Path(value) for value in (ca_file, cert_file, key_file)]
    _require(all(path.is_absolute() and ".." not in path.parts for path in paths))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.hostname_checks_common_name = False
    context.options |= ssl.OP_NO_COMPRESSION
    context.keylog_filename = None
    context.set_alpn_protocols(["http/1.1"])
    context.load_verify_locations(cafile=str(paths[0]))
    context.load_cert_chain(str(paths[1]), str(paths[2]), password=_no_password)
    return context


def _unique(rows):
    value = {}
    for key, item in rows:
        _require(key not in value)
        value[key] = item
    return value


def _finite(value):
    number = float(value)
    _require(math.isfinite(number))
    return number


def _not_json(_value):
    raise TransportError()


def _json_object(raw):
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_not_json,
            parse_float=_finite,
        )
    except Exception:
        return False
    return type(value) is dict


def _new_socket(family):
    return socket.socket(family, socket.SOCK_STREAM)


async def _connect_socket(loop, owned, endpoint):
    await loop.sock_connect(owned, endpoint)


def _abort(writer):
    try:
        writer.transport.abort()
    except Exception:
        pass


def _headers(event):
    _require(event.status_code == 200 and event.http_version == b"1.1")
    rows = list(event.headers)
    _require(
        len(rows) <= 32
        and sum(len(k) + len(v) + 4 for k, v in rows) + len(event.reason) + 32 <= MAX_HEADERS
    )
    headers = {}
    for key, value in rows:
        _require(key not in headers)
        headers[key] = value
    _require(
        headers.get(b"content-type", b"").lower()
        in (b"application/json", b"application/json; charset=utf-8")
    )
    _require(headers.get(b"content-encoding", b"identity").lower() == b"identity")
    _require(not {b"set-cookie", b"location", b"upgrade"}.intersection(headers))
    length = headers.get(b"content-length")
    transfer = headers.get(b"transfer-encoding")
    _require(length is None or (length.isdigit() and 0 < int(length) <= MAX_BODY))
    _require(transfer is None or transfer.lower() == b"chunked")
    _require(length is None or transfer is None)


async def _receive(reader, connection, loop, deadline):
    body, wire, response = bytearray(), 0, False
    for _ in range(MAX_EVENTS):
        _require(loop.time() < deadline)
        event = connection.next_event()
        if event is h11.NEED_DATA:
            chunk = await reader.read(min(4096, MAX_WIRE - wire + 1))
            wire += len(chunk)
            _require(type(chunk) is bytes and wire <= MAX_WIRE)
            connection.receive_data(chunk)
        elif type(event) is h11.Response:
            _require(not response)
            _headers(event)
            response = True
        elif type(event) is h11.Data:
            _require(response and len(body) + len(event.data) <= MAX_BODY)
            body.extend(event.data)
        elif type(event) is h11.EndOfMessage:
            _require(response and not event.headers and not connection.trailing_data[0])
            # Connection: close is mandatory: reject surplus and a peer that stays open.
            _require(await reader.read(1) == b"" and loop.time() < deadline)
            raw = bytes(body)
            _require(0 < len(raw) <= MAX_BODY and _json_object(raw))
            return raw
        else:
            raise TransportError()
    raise TransportError()


class TransitTransport:
    def __init__(self, address, server_name, port, *, ca_file, cert_file, key_file, timeout=3.0):
        valid = False
        try:
            _require(type(address) is str and len(address) <= 45 and "%" not in address)
            numeric = ipaddress.ip_address(address)
            _require(not numeric.is_unspecified and not numeric.is_multicast)
            _require(
                type(server_name) is str
                and 0 < len(server_name) <= 253
                and DNS_NAME.fullmatch(server_name)
            )
            try:
                ipaddress.ip_address(server_name)
            except ValueError:
                pass
            else:
                raise TransportError()
            _require(type(port) is int and 1 <= port <= 65535)
            _require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 30)
            context = _tls_context(ca_file, cert_file, key_file)
            valid = True
        except Exception:
            pass
        if not valid:
            raise TransportError()
        self._address, self._name, self._port = str(numeric), server_name, port
        self._family = socket.AF_INET if numeric.version == 4 else socket.AF_INET6
        self._context, self._timeout = context, float(timeout)

    def post(self, path: str, token: str, body: bytes) -> bytes:
        """A fresh connection, outside any active loop; errors never expose payloads."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise TransportError()
        failed, result = False, None
        try:
            _require(type(path) is str and len(path) <= 128 and ROUTE.fullmatch(path))
            _require(
                type(token) is str
                and 0 < len(token) <= MAX_TOKEN
                and all(33 <= ord(char) <= 126 for char in token)
            )
            _require(type(body) is bytes and 0 < len(body) <= MAX_BODY and _json_object(body))
            connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=MAX_HEADERS)
            request = h11.Request(
                method=b"POST",
                target=path.encode("ascii"),
                headers=[
                    (b"host", f"{self._name}:{self._port}".encode("ascii")),
                    (b"x-vault-token", token.encode("ascii")),
                    (b"content-type", b"application/json"),
                    (b"accept", b"application/json"),
                    (b"accept-encoding", b"identity"),
                    (b"connection", b"close"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            )
            wire = connection.send(request) + connection.send(h11.Data(data=body))
            wire += connection.send(h11.EndOfMessage())
            _require(len(wire) <= MAX_BODY + MAX_HEADERS)
            result = asyncio.run(self._post(connection, wire))
        except Exception:
            failed = True
        if failed:
            raise TransportError()
        return result

    async def _post(self, connection, wire):
        loop = asyncio.get_running_loop()
        end = loop.time() + self._timeout
        reserve = min(0.25, self._timeout / 5)
        io_end = end - reserve
        owned, writer, result = None, None, None
        failed = cancelled = False
        try:
            async with asyncio.timeout_at(io_end):
                owned = _new_socket(self._family)
                owned.setblocking(False)
                # A validated literal with its matching family bypasses resolution.
                await _connect_socket(loop, owned, (self._address, self._port))
                _require(loop.time() < io_end)
                reader, writer = await asyncio.open_connection(
                    sock=owned,
                    ssl=self._context,
                    server_hostname=self._name,
                    limit=MAX_HEADERS,
                    ssl_handshake_timeout=io_end - loop.time(),
                    ssl_shutdown_timeout=reserve,
                )
                tls = writer.get_extra_info("ssl_object")
                _require(
                    tls is not None
                    and tls.version() == "TLSv1.3"
                    and tls.selected_alpn_protocol() in (None, "http/1.1")
                )
                _require(loop.time() < io_end)
                writer.write(wire)
                await writer.drain()
                result = await _receive(reader, connection, loop, io_end)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            failed = True
        finally:
            if writer is not None:
                try:
                    if failed or cancelled:
                        writer.transport.abort()
                    else:
                        writer.close()
                    _require(loop.time() < end)
                    async with asyncio.timeout_at(end):
                        await writer.wait_closed()
                    _require(writer.is_closing() and loop.time() < end)
                except asyncio.CancelledError:
                    cancelled = True
                    _abort(writer)
                except Exception:
                    failed = True
                    _abort(writer)
            if owned is not None:
                try:
                    # Idempotent after stream closure; release even after failed setup.
                    owned.close()
                except Exception:
                    failed = True
        if cancelled:
            raise asyncio.CancelledError()
        if failed or result is None:
            raise TransportError()
        return result
