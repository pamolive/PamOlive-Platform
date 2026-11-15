"""Application-owned, version-specific H11 TLS bridge; no copied HTTP parser."""

import ssl

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from .asgi import Application
from .bounded import need


def protocol_class(application):
    need(uvicorn.__version__ == "0.54.0", "unavailable", 503)

    async def unavailable(scope, receive, send):
        await Application._response(send, 503, {"error": "unavailable", "authorized": False})

    class PeerH11(H11Protocol):
        def connection_made(self, transport):
            self._peer_ready = False
            self.app = unavailable
            # Initialize inherited callback/flow/connection tracking BEFORE any refusal.
            super().connection_made(transport)
            try:
                tls = transport.get_extra_info("ssl_object")
                need(isinstance(tls, (ssl.SSLObject, ssl.SSLSocket)), "caller_refused", 403)
                need(tls.context.verify_mode == ssl.CERT_REQUIRED, "caller_refused", 403)
                der = tls.getpeercert(binary_form=True)
                # Only this protocol instance is rebound. No config/app_state/global mutation.
                bound = application.for_tls_peer(der)
            except Exception:
                transport.close()
                return
            self.app = bound
            self._peer_ready = True

        def data_received(self, data):
            if self._peer_ready:
                super().data_received(data)

        def connection_lost(self, exc):
            self._peer_ready = False
            self.app = unavailable
            super().connection_lost(exc)

    return PeerH11


def tls_context(*, certificate, private_key, client_ca):
    """Trusted startup paths only. Called later by Root, never by the prototype pure suite."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.keylog_filename = None
    context.load_verify_locations(
        cafile=client_ca
    )  # No default CA store, env or private user profile.
    context.load_cert_chain(certfile=certificate, keyfile=private_key)
    return context


def configuration(application, context, *, host="127.0.0.1", port=9443):
    need(
        type(context) is ssl.SSLContext and context.verify_mode == ssl.CERT_REQUIRED,
        "unavailable",
        503,
    )
    need(context.keylog_filename is None, "unavailable", 503)
    need(
        type(port) is int
        and 1024 <= port <= 65535
        and type(host) is str
        and host in {"127.0.0.1", "10.253.249.3"},
        "unavailable",
        503,
    )
    return uvicorn.Config(
        application,
        host=host,
        port=port,
        http=protocol_class(application),
        http2=False,
        loop="asyncio",
        ws="none",
        interface="asgi3",
        lifespan="off",
        proxy_headers=False,
        reload=False,
        workers=1,
        log_config=None,
        access_log=False,
        log_level="critical",
        server_header=False,
        date_header=False,
        limit_concurrency=16,
        backlog=16,
        timeout_keep_alive=2,
        timeout_graceful_shutdown=5,
        h11_max_incomplete_event_size=8192,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_context_factory=lambda config, default_factory: context,
    )
