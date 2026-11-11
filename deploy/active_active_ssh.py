"""Exercise the actual PAM relay from inside the disposable two-node project."""

import asyncio
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket as sockets
import sys
import time
from contextlib import asynccontextmanager
from datetime import timedelta
from urllib.parse import urlencode
from uuid import UUID

import asyncssh
from asgiref.sync import sync_to_async
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from platform_modules.pam.protocol import Instruction, Parser

from .active_active_fixture import require_test_database

TARGET = "ha-ssh-fixture"
PORT = 22222
WEB_A, WEB_B = "ha-web-a", "ha-web-b"
PHASE = "setup"


class FixtureError(RuntimeError):
    """Only fixed fixture messages, never response bodies or exception arguments."""


def require(condition, message):
    if not condition:
        raise FixtureError(message)


def prepare(
    run, public_key, password, *, authority, browser_session,
    protocol="ssh", hostname=TARGET, port=PORT,
):
    import pyotp
    from django.contrib.auth import get_user_model
    from django.utils import timezone

    from platform_core.authorization import recent_authentication
    from platform_core.models import AccountSecurity, Organization, OrganizationMembership
    from platform_core.security import cipher
    from platform_core.services import install_module
    from platform_core.tenancy import organization_context
    from platform_modules.access.services import create_record
    from platform_modules.approvals.services import decide
    from platform_modules.identity.bindings import create_binding
    from platform_modules.identity.models import ExternalAccount, Identity, Resource
    from platform_modules.pam.sessions import (
        configure_endpoint,
        probe_endpoint,
        set_endpoint_enabled,
    )

    from .active_active_trust import CommissionedFixture

    require_test_database()
    require(re.fullmatch(r"[0-9a-f]{32}", run), "Invalid qualification run.")
    require(protocol in ("ssh", "rdp"), "Unknown fixture protocol.")
    label = protocol.upper()
    org = Organization.objects.get(key="ha-" + run)
    actor = get_user_model().objects.get(username="ha-" + run)
    reviewer = get_user_model().objects.create_user(f"ha-{protocol}-reviewer-{run}")
    OrganizationMembership.objects.create(account=reviewer, organization=org, role="reviewer")
    AccountSecurity.objects.create(
        account=reviewer, encrypted_secret=cipher().encrypt(pyotp.random_base32().encode()).decode()
    )
    for key in ("approvals", "pam"):
        install_module(key, actor=actor, organization=org)
    with organization_context(org), recent_authentication(actor, org, time.time()):
        identity = Identity.objects.get(name="HA person " + run)
        independent = Identity.objects.create(organization=org, name="HA reviewer", kind="human")
        for user, person in ((actor, identity), (reviewer, independent)):
            create_binding(
                login_account=user,
                identity=person,
                verification_reference="Synthetic active-active fixture",
                actor=actor,
                organization=org,
            )
        resource = Resource.objects.create(
            organization=org, name=f"Isolated HA {label}", kind="server"
        )
        account = ExternalAccount.objects.create(
            organization=org,
            identity=identity,
            kind="privileged",
            username="ha-fixture" if protocol == "ssh" else "fixture",
            system="HA",
        )
        endpoint = configure_endpoint(
            actor=actor,
            organization=org,
            name=f"Isolated HA {label}",
            resource=resource,
            account=account,
            protocol=protocol,
            hostname=hostname,
            port=port,
            auth_method="password",
            password=password,
            **(
                {"host_key": public_key}
                if protocol == "ssh"
                else {"rdp_pin": public_key, "domain": "FIXTURE"}
            ),
        )
        verified, _ = probe_endpoint(endpoint.pk, actor=actor, organization=org)
        require(verified, f"The {label} identity probe failed.")
        set_endpoint_enabled(endpoint.pk, actor=actor, organization=org, enabled=True)
        endpoint.refresh_from_db()
        trust = CommissionedFixture(
            org, endpoint,
            [(actor, identity, ["requester"]), (reviewer, independent, ["reviewer", "sponsor"])],
            authority, browser_session=browser_session,
        )
        intents = []
        for node in ("A", "B"):
            values = dict(
                    identity=identity,
                    resource=resource,
                    account=account,
                    method=label,
                    reason=f"Isolated native active-active check on {node}",
                    fulfillment="pam",
                    starts_at=timezone.now() - timedelta(seconds=5),
                    ends_at=timezone.now() + timedelta(minutes=10),
            )
            intents.append(trust.perform(actor, lambda: create_record(
                "intent", values, actor=actor, organization=org,
            )))
    with organization_context(org), recent_authentication(reviewer, org, time.time()):
        for intent in intents:
            trust.perform(reviewer, lambda: decide(
                intent.pk,
                actor=reviewer,
                organization=org,
                approved=True,
                comment="Fixture approved",
            ))
    return org.pk, *(item.pk for item in intents), trust.devices[actor.pk].document()


def post(node, path, session, csrf, *, fields=None, json_payload=None):
    connection = http.client.HTTPConnection(node, 8000, timeout=10)
    try:
        connection.request(
            "POST",
            path,
            json.dumps(json_payload) if json_payload is not None else urlencode(
                {"csrfmiddlewaretoken": csrf, **(fields or {})}
            ),
            {
                "Cookie": (
                    f"pamolive_platform_session={session}; pamolive_platform_csrftoken={csrf}"
                ),
                "Content-Type": "application/json" if json_payload is not None
                else "application/x-www-form-urlencoded",
                "X-CSRFToken": csrf,
            },
        )
        response = connection.getresponse()
        return response.status, response.read(2_097_152).decode()
    finally:
        connection.close()


def launch(node, intent, session, csrf, authenticator):
    status, html = post(node, f"/pam/intents/{intent}/open/", session, csrf)
    ceremony = re.search(
        r'<script id="pam-trust-ceremony" type="application/json">(.*?)</script>', html
    )
    require(status == 200 and ceremony, "The launch did not require a personal PAM ceremony.")
    options = json.loads(ceremony[1])
    require(options.get("endpoint") == "/pam/trust/action/", "Unexpected PAM ceremony route.")
    status, answer = post(node, options["endpoint"], session, csrf, json_payload={
        "operation": "finish", "challenge": options["challenge"],
        "credential": authenticator.response(options),
    })
    require(status == 200, "The signed personal launch action was refused.")
    proof = json.loads(answer)
    require(proof["resume"]["path"] == f"/pam/intents/{intent}/open/",
            "The launch action targeted another path.")
    status, html = post(node, proof["resume"]["path"], session, csrf, fields={
        **dict(proof["resume"]["fields"]), "_pam_trust_proof": proof["proof"],
    })
    match = re.search(
        r'<script id="pam-player-config" type="application/json">(.*?)</script>', html
    )
    require(status == 200 and match, "The native launch form did not return a ticket.")
    config = json.loads(match[1])
    key = re.fullmatch(r"/ws/pam/([a-f0-9-]{36})/", config["websocket_path"])
    require(key, "Unexpected WebSocket path.")
    return UUID(key[1]), config


def socket(node, config, session):
    return connect(
        f"ws://{node}:8000" + config["websocket_path"],
        proxy=None,
        origin=f"http://{node}:8000",
        subprotocols=["guacamole"],
        additional_headers={"Cookie": f"pamolive_platform_session={session}"},
        max_size=4 * 1024 * 1024,
    )


async def submit_ticket(websocket, config):
    await websocket.send(json.dumps({"ticket": config["ticket"], "width": 1280, "height": 720}))


@asynccontextmanager
async def relay(node, config, session):
    async with socket(node, config, session) as websocket:
        await submit_ticket(websocket, config)
        display_ready = asyncio.Event()

        async def drain():
            parser = Parser()
            try:
                async for frame in websocket:
                    for item in parser.feed(frame.encode()):
                        if item.opcode == "sync":
                            await websocket.send(
                                Instruction("sync", (item.arguments[0],)).encode().decode()
                            )
                            display_ready.set()
            except ConnectionClosed:
                pass

        worker = asyncio.create_task(drain())
        try:
            yield websocket, display_ready
        finally:
            await websocket.close()
            await worker


def state(organization, key):
    from django.db import close_old_connections

    from platform_modules.pam.models import RecordingChunk, RelayConnection

    close_old_connections()
    item = RelayConnection.unscoped.get(organization_id=organization, pk=key)
    return (
        item.status,
        item.instance_id,
        item.end_reason,
        item.recording_complete,
        RecordingChunk.unscoped.filter(organization_id=organization, connection=item).exists(),
    )


async def await_state(organization, key, expected):
    async with asyncio.timeout(48):
        while True:
            item = await sync_to_async(state)(organization, key)
            if item == expected:
                return
            await asyncio.sleep(0.25)


def emit(stage, **fields):
    print(json.dumps(dict(stage=stage, **fields)), flush=True)


async def exercise(info):
    global PHASE

    from django.conf import settings

    address = ipaddress.IPv4Address(info["peer_ip"])
    require(address.is_private and not address.is_loopback, "Unsafe fixture bind address.")
    require(settings.PAM_INSTANCE_ID == "qualification-b", "The peer must live on test node B.")
    require(
        {row[4][0] for row in sockets.getaddrinfo(TARGET, PORT, type=sockets.SOCK_STREAM)}
        == {str(address)},
        "The SSH fixture alias is not exclusively on the isolated project network.",
    )
    password = secrets.token_urlsafe(24)
    key = asyncssh.generate_private_key("ssh-ed25519")
    opened = asyncio.Queue()

    class Peer(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, value):
            return username == "ha-fixture" and secrets.compare_digest(value, password)

    async def terminal(process):
        commands, disconnected = asyncio.Queue(), asyncio.Event()
        await opened.put((commands, disconnected))
        try:
            process.stdout.write("Isolated SSH active-active proof\r\n")
            while line := await process.stdin.readline():
                process.stdout.write("Keyboard received\r\n")
                await commands.put(line.strip())
        finally:
            disconnected.set()

    async def prove(websocket, commands, marker):
        for key in (*map(ord, marker), 65293):
            for pressed in ("1", "0"):
                await websocket.send(Instruction("key", (str(key), pressed)).encode().decode())
        received = await asyncio.wait_for(commands.get(), 12)
        require(received == marker, f"SSH input mismatch: {len(received)} characters.")

    server = await asyncssh.create_server(
        Peer, str(address), PORT, server_host_keys=[key], process_factory=terminal
    )
    try:
        PHASE = "synthetic mandates and endpoint probe"
        org, intent_a, intent_b, device = await sync_to_async(prepare)(
            info["run"], key.export_public_key().decode(), password,
            authority=info["authority"], browser_session=info["session"],
        )
        from .active_active_trust import RemoteAuthenticator

        authenticator = RemoteAuthenticator(device)
        session, csrf = info["session"], info["csrf"]
        PHASE = "first launch and cross-node replay"
        aid, cfg_a = await asyncio.to_thread(launch, WEB_A, intent_a, session, csrf, authenticator)
        async with relay(WEB_A, cfg_a, session) as (a, display_a):
            commands_a, disconnected_a = await asyncio.wait_for(opened.get(), 15)
            await asyncio.wait_for(display_a.wait(), 12)
            async with socket(WEB_B, cfg_a, session) as replay:
                await submit_ticket(replay, cfg_a)
                await asyncio.wait_for(replay.wait_closed(), 10)
            require(opened.empty(), "Replay established another native SSH connection.")
            PHASE = "independent native relays on both nodes"
            bid, cfg_b = await asyncio.to_thread(
                launch, WEB_B, intent_b, session, csrf, authenticator
            )
            async with relay(WEB_B, cfg_b, session) as (b, display_b):
                commands_b, _ = await asyncio.wait_for(opened.get(), 15)
                await asyncio.wait_for(display_b.wait(), 12)
                await prove(a, commands_a, "node-a")
                await prove(b, commands_b, "node-b")
                await await_state(org, aid, ("active", "qualification-a", "", False, True))
                await await_state(org, bid, ("active", "qualification-b", "", False, True))
                PHASE = "cross-node stop HTTP"
                status, _ = await asyncio.to_thread(
                    post, WEB_B, f"/pam/connections/{aid}/stop/", session, csrf
                )
                require(status == 302, f"Node B stop HTTP {status}.")
                PHASE = "cross-node stop WebSocket"
                await asyncio.wait_for(a.wait_closed(), 12)
                await asyncio.wait_for(disconnected_a.wait(), 12)
                PHASE = "cross-node stop durable state"
                await await_state(
                    org, aid, ("ended", "qualification-a", "stop_requested", False, True)
                )
                PHASE = "new ticket on node A"
                cid, cfg_c = await asyncio.to_thread(
                    launch, WEB_A, intent_a, session, csrf, authenticator
                )
                PHASE = "new native relay on node A"
                async with relay(WEB_A, cfg_c, session) as (c, display_c):
                    commands_c, disconnected_c = await asyncio.wait_for(opened.get(), 15)
                    await asyncio.wait_for(display_c.wait(), 12)
                    await await_state(org, cid, ("active", "qualification-a", "", False, True))
                    await prove(c, commands_c, "before-crash")
                    PHASE = "surviving relay and orphan reaper"
                    emit("kill-node-a")
                    answer = await asyncio.to_thread(sys.stdin.readline, 256)
                    require(answer.strip() == "node-a-killed", "Missing host crash confirmation.")
                    await asyncio.wait_for(c.wait_closed(), 12)
                    await asyncio.wait_for(disconnected_c.wait(), 12)
                    await prove(b, commands_b, "node-b-after-crash")
                    await await_state(
                        org, cid, ("failed", "qualification-a", "relay_owner_lost", False, True)
                    )
        emit(
            "complete",
            both_native_relays_active=True,
            shared_ticket_replay_refused=True,
            stopped_on_other_node=True,
            surviving_ssh_session_roundtrip=True,
            lost_relay_reaped_with_partial_capture=True,
        )
    finally:
        server.close()
        await server.wait_closed()


def main():
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    django.setup()
    require_test_database()
    try:
        asyncio.run(exercise(json.loads(sys.stdin.readline(4096))))
    except Exception as error:
        emit(
            "failed",
            phase=PHASE,
            error=str(error) if isinstance(error, FixtureError) else type(error).__name__,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
