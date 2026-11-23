"""Own a private HTTPS/WSS listener for the real PamOlive ASGI test application."""

import socket
import threading
import time

import uvicorn
from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler


class TLSASGIServer:
    host = "127.0.0.1"

    def __init__(self, certificate, key):
        from config.asgi import application

        self._server = uvicorn.Server(uvicorn.Config(
            ASGIStaticFilesHandler(application),
            log_config=None, log_level="critical", access_log=False, proxy_headers=False,
            interface="asgi3", lifespan="on", timeout_graceful_shutdown=3,
            ws="websockets-sansio", ws_max_size=65536, ws_per_message_deflate=False,
            ssl_certfile=certificate, ssl_keyfile=key,
        ))
        self._listener = None
        self._thread = None
        self._finished = threading.Event()
        self._error = None

    def __enter__(self):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.bind((self.host, 0))
            self.port = self._listener.getsockname()[1]
            self.origin = f"https://{self.host}:{self.port}"
            self.websocket_origin = f"wss://{self.host}:{self.port}"
            self._thread = threading.Thread(
                target=self._run, name="pamolive-test-asgi", daemon=True,
            )
            self._thread.start()
            deadline = time.monotonic() + 8
            while not self._server.started and not self._finished.wait(0.02):
                if time.monotonic() >= deadline:
                    break
            if not self._server.started or self._finished.is_set():
                raise RuntimeError("Test ASGI listener failed to start") from self._error
            return self
        except BaseException:
            self.close()
            raise

    def _run(self):
        try:
            self._server.run(sockets=[self._listener])
        except BaseException as error:
            self._error = error
        finally:
            self._finished.set()

    def close(self):
        self._server.should_exit = True
        try:
            if self._thread is not None and self._thread.ident is not None:
                self._thread.join(5)
                if self._thread.is_alive():
                    self._server.force_exit = True
                    self._listener.close()
                    self._thread.join(2)
                    raise RuntimeError("Test ASGI listener failed to shut down gracefully")
                if self._server.started and self._error is not None:
                    raise RuntimeError("Test ASGI listener failed while running") from self._error
        finally:
            if self._listener is not None:
                self._listener.close()

    def __exit__(self, *_):
        self.close()

    def is_alive(self):
        return self._thread is not None and self._thread.is_alive()
