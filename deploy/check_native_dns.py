"""Test-image-only NLA availability gate, using a loopback synthetic resolver.

Run as non-root, with --network none --dns 127.0.0.1 --cap-drop ALL,
--security-opt no-new-privileges --read-only and a private writable /tmp.
This qualifies the synthetic NTLM fixture, never Kerberos or a real directory.
"""

import asyncio
import json
import time
from unittest.mock import patch

from deploy import check_native_rdp
from deploy.check_guacd import run_check
from tests.fixtures.native_dns import SyntheticDNS
from tests.fixtures.rdp import RDPFixture


def run_case(mode):
    peers = []

    class ObservedPeer(RDPFixture):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            peers.append(self)

    async def check(port):
        async with asyncio.timeout(20):
            await check_native_rdp.exercise(port)

    started = time.monotonic()
    timed_out = False
    with SyntheticDNS(mode) as resolver, patch.object(check_native_rdp, "RDPFixture", ObservedPeer):
        try:
            run_check(check)
        except TimeoutError:
            timed_out = True
    observed = resolver.snapshot()
    if observed["errors"] or not observed["question_count"] or len(peers) != 1:
        raise RuntimeError("native_dns_observation_failed")
    events = {event["event"] for event in peers[0].events}
    if "peer_ready" not in events:
        raise RuntimeError("native_dns_peer_not_reached")
    authenticated = {"nla_verified", "authenticated"} <= events
    if mode == "nxdomain":
        if timed_out or not authenticated or not {"key_a", "disconnected"} <= events:
            raise RuntimeError("native_dns_fast_negative_authentication_failed")
    elif not timed_out or events & {"nla_verified", "authenticated", "key_a"}:
        raise RuntimeError("native_dns_silence_did_not_fail_closed")
    print(json.dumps({"mode": mode, "seconds": round(time.monotonic() - started, 3),
                      "expected_timeout": timed_out, "authenticated": authenticated,
                      "external_dns": False, **observed}, sort_keys=True), flush=True)


def main():
    run_case("nxdomain")
    run_case("silent")


if __name__ == "__main__":
    main()
