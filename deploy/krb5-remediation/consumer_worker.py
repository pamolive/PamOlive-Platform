"""Linux-only synthetic loopback KDC. Never contacts a real realm or service."""

import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from abi_data import capture
from common import ENV, command, read, record, write_new
from source_model import json_value, need, sha

CONFIG = """[libdefaults]
 default_realm = PAMOLIVE.INVALID
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 canonicalize = false
 udp_preference_limit = 1
 request_timeout = 2s
[realms]
 PAMOLIVE.INVALID = {
  kdc = 127.0.0.1:PORT
 }
"""


def provider_check(value, abi):
    mapping = {"gss_provider": "libgssapi-krb5-2", "krb5_provider": "libkrb5-3"}
    for key, package in mapping.items():
        path = Path(value[key])
        need(
            path.is_absolute()
            and path.name
            in {abi["libraries"][package]["file"], abi["libraries"][package]["soname"]},
            "consumer_provider_name",
        )
        real = path.resolve(strict=True)
        need(
            real.parent == Path("/usr/lib/x86_64-linux-gnu")
            and sha(read(real, 64 * 1024**2)) == abi["libraries"][package]["file_sha256"],
            "consumer_provider_bytes",
        )


def main(work, binary):
    work, binary = Path(work).resolve(), Path(binary).resolve(strict=True)
    work.mkdir(mode=0o700)
    need(sorted(p.name for p in Path("/sys/class/net").iterdir()) == ["lo"], "loopback_only")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(0.1)
    stop = threading.Event()
    overflow = threading.Event()
    accepted, connections = [], []

    def silent():
        while not stop.is_set():
            try:
                conn, address = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if address[0] != "127.0.0.1" or len(connections) >= 4:
                overflow.set()
                conn.close()
                break
            accepted.append(True)
            connections.append(conn)
        for conn in connections:
            conn.close()

    thread = threading.Thread(target=silent)
    thread.start()
    try:
        config = work / "krb5.conf"
        write_new(config, CONFIG.replace("PORT", str(listener.getsockname()[1])).encode())
        env = ENV | {
            "KRB5_CONFIG": str(config),
            "KRB5_KDC_PROFILE": "/dev/null",
            "KRB5CCNAME": "MEMORY:pamolive-synthetic",
            "KRB5_CLIENT_KTNAME": "/nonexistent",
            "KRB5_KTNAME": "/nonexistent",
        }
        abi = capture(Path("/"))
        mechanisms = json_value(
            command([str(binary), "mechanisms"], work, work / "mechanisms", seconds=5, env=env)
        )
        provider_check(mechanisms, abi)
        need(
            mechanisms["mechanisms_enumerated"] is True
            and mechanisms["kerberos_mechanism_present"] is True,
            "GSS_mechanisms",
        )
        started = time.monotonic()
        refusal = json_value(
            command([str(binary), "silent-kdc"], work, work / "silent-kdc", seconds=6, env=env)
        )
        elapsed = time.monotonic() - started
        provider_check(refusal, abi)
        need(
            refusal["synthetic_acquire_failed"] is True
            and accepted
            and not overflow.is_set()
            and 1.5 <= elapsed < 6,
            "silent_KDC_deadline_not_observed",
        )
        record(
            work / "CONSUMER-DATA.json",
            {
                "real_GSS_consumer": mechanisms,
                "silent_loopback_KDC": refusal,
                "accepted_connections": len(accepted),
                "elapsed_seconds": elapsed,
                "real_KDC_or_AD_contacted": False,
                "authentication_success_qualified": False,
                "operational_GO": False,
            },
        )
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=2)
        need(not thread.is_alive(), "silent_KDC_worker_not_drained")


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_new_work_compiled_consumer")
    main(*sys.argv[1:])
