"""Protocol adversaries and real, isolated pre-authentication SSH/RDP sockets."""

import asyncio
import hashlib
import json
import socket
import ssl
import struct
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import asyncssh
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.test import SimpleTestCase, override_settings

from platform_modules.pam.context import check_websocket_origin, client_address
from platform_modules.pam.destination import TransportFailure, host_port, resolve_destination
from platform_modules.pam.native import DisplayBoundary
from platform_modules.pam.probe import certificate_pin, probe_rdp, probe_ssh, ssh_host_key
from platform_modules.pam.protocol import Instruction, Parser, ProtocolFailure, validate_input


class FramingTests(SimpleTestCase):
    def test_native_cursor_positions_are_bounded_display_updates(self):
        instruction = Instruction("mouse", ("640", "480"))
        self.assertEqual(DisplayBoundary().outbound(instruction), instruction)
        self.assertEqual(
            DisplayBoundary().outbound(
                Instruction("mouse", ("640", "480", "0", "1794096000000"))
            ),
            instruction,
        )
        for arguments in (("9000", "0"), ("0", "0", "0"), ("0",)):
            with self.assertRaises(ProtocolFailure):
                DisplayBoundary().outbound(Instruction("mouse", arguments))

    def test_native_connection_parameter_streams_never_reach_display_or_recording(self):
        boundary = DisplayBoundary()
        self.assertIsNone(boundary.outbound(Instruction("argv", ("1", "text/plain", "password"))))
        self.assertIsNone(boundary.outbound(Instruction("blob", ("1", "c2VjcmV0"))))
        self.assertIsNone(boundary.outbound(Instruction("end", ("1",))))
        for opcode in ("clipboard", "file", "required", "ready", "select", "connect"):
            with self.assertRaises(ProtocolFailure):
                boundary.outbound(Instruction(opcode, ("secret",)))
        for instruction in (
            Instruction("size", ("0", "20000", "20000")),
            Instruction("img", ("0", "1", "0", "image/svg+xml", "0", "0")),
        ):
            with self.assertRaises(ProtocolFailure):
                DisplayBoundary().outbound(instruction)

    @override_settings(
        ALLOWED_HOSTS=["pam.example"],
        PAM_PUBLIC_ORIGIN="https://pam.example",
        PAM_TRUSTED_PROXY_NETWORKS=(),
    )
    def test_websocket_requires_exact_origin_no_url_ticket_and_explicit_proxy_trust(self):
        scope = {
            "scheme": "ws",
            "headers": [(b"host", b"pam.example"), (b"origin", b"https://pam.example")],
            "subprotocols": ["guacamole"],
            "client": ("192.0.2.1", 1234),
            "query_string": b"",
        }
        self.assertEqual(check_websocket_origin(scope)[1], "192.0.2.1")
        for changes in (
            {"query_string": b"ticket=secret"},
            {"subprotocols": []},
            {"headers": [(b"host", b"pam.example"), (b"origin", b"https://attacker.invalid")]},
            {"headers": scope["headers"] + [(b"origin", b"https://pam.example")]},
        ):
            with self.assertRaises(PermissionDenied):
                check_websocket_origin(dict(scope, **changes))
        self.assertEqual(client_address("192.0.2.1", "10.0.0.1"), "192.0.2.1")
        with override_settings(PAM_TRUSTED_PROXY_NETWORKS=("192.0.2.1/32",)):
            self.assertEqual(client_address("192.0.2.1", "10.0.0.1"), "10.0.0.1")
            with self.assertRaises(PermissionDenied):
                client_address("192.0.2.1", "10.0.0.1, 10.0.0.2")

    def test_vendored_client_matches_published_provenance(self):
        provenance = json.loads(
            (settings.BASE_DIR / "third_party/guacamole/provenance.json").read_text()
        )
        client = provenance["javascript"]
        self.assertEqual(
            hashlib.sha256((settings.BASE_DIR / client["vendored_path"]).read_bytes()).hexdigest(),
            client["vendored_sha256"],
        )
        for filename in ("LICENSE.txt", "NOTICE.txt"):
            self.assertTrue((settings.BASE_DIR / "third_party/guacamole" / filename).is_file())

    def test_unicode_and_delimiters_survive_every_possible_fragment_boundary(self):
        expected = [Instruction("name", ("Cyriel : été 🫒,.;",)), Instruction("nop")]
        wire = b"".join(instruction.encode() for instruction in expected)
        for boundary in range(len(wire) + 1):
            parser = Parser()
            actual = parser.feed(wire[:boundary]) + parser.feed(wire[boundary:])
            parser.finish()
            self.assertEqual(actual, expected)
        parser = Parser()
        actual = []
        for byte in wire:
            actual.extend(parser.feed(bytes([byte])))
        parser.finish()
        self.assertEqual(actual, expected)

    def test_invalid_frames_close_parser_without_echoing_untrusted_payload(self):
        for wire in (
            b"99999999.secret",
            b"-1.x;",
            b"01.x;",
            b".x;",
            b"1.x!",
            "١.x;".encode(),
            b"1.\xff;",
            b"0.;",
            b"3.XSS;",
            b"1.\x00;",
        ):
            with self.subTest(wire=wire):
                parser = Parser()
                with self.assertRaises(ProtocolFailure) as caught:
                    parser.feed(wire)
                self.assertNotIn("secret", str(caught.exception))
                with self.assertRaisesMessage(ProtocolFailure, "parser_closed"):
                    parser.feed(b"3.nop;")

    def test_truncation_and_resource_budgets(self):
        for wire in (b"3.no", b"3.nop", b"3.nop,", b"3.nop,1.", b"3.nop,1.\xf0"):
            with self.subTest(wire=wire):
                parser = Parser()
                parser.feed(wire)
                with self.assertRaises(ProtocolFailure):
                    parser.finish()
        for parser, wire in (
            (Parser(max_element=2), b"3.nop;"),
            (Parser(max_elements=2), b"1.a,1.b,1.c;"),
            (Parser(max_instruction=10), b"1.a,5.12345;"),
            (Parser(), b"3.nop;" * 4097),
            (Parser(), b"x" * 65537),
        ):
            with self.assertRaises(ProtocolFailure):
                parser.feed(wire)

    def test_client_cannot_supply_credentials_connections_or_stream_content(self):
        for opcode in (
            "connect",
            "select",
            "args",
            "argv",
            "required",
            "clipboard",
            "file",
            "blob",
            "end",
            "put",
            "get",
            "pipe",
            "audio",
            "video",
            "touch",
            "join",
        ):
            with (
                self.subTest(opcode=opcode),
                self.assertRaisesMessage(ProtocolFailure, "input_not_authorized"),
            ):
                validate_input(Instruction(opcode, ("sensitive-value",)))

    def test_only_bounded_display_input_and_output_ack_are_allowed(self):
        for instruction in (
            Instruction("key", ("65293", "1")),
            Instruction("key", ("65293", "0")),
            Instruction("mouse", ("120", "220", "1")),
            Instruction("size", ("1280", "720")),
            Instruction("sync", ("1234567890123",)),
            Instruction("ack", ("0", "OK", "0")),
            Instruction("nop"),
            Instruction("disconnect"),
        ):
            self.assertEqual(validate_input(instruction), instruction)
        for instruction in (
            Instruction("key", ("42", "2")),
            Instruction("key", ("-1", "0")),
            Instruction("mouse", ("9000", "0", "0")),
            Instruction("size", ("1", "1")),
            Instruction("sync", ("9007199254740992",)),
            Instruction("nop", ("x",)),
            Instruction("ack", ("0", "secret\nlog", "0")),
            Instruction("ack", ("0", "a" * 129, "0")),
            Instruction("ack", ("-1", "", "0")),
            Instruction("ack", ("0", "0")),
            Instruction("key", ("１", "0")),
        ):
            with self.subTest(instruction=instruction), self.assertRaises(ProtocolFailure):
                validate_input(instruction)


class DestinationTests(SimpleTestCase):
    def test_empty_policy_and_malformed_hosts_fail_before_any_dns(self):
        with override_settings(PAM_ALLOWED_HOSTS=frozenset()):
            with self.assertRaisesMessage(TransportFailure, "destination_not_authorized"):
                host_port("example.com", 22)
        with override_settings(PAM_ALLOWED_HOSTS={"example.com:22"}):
            for hostname, port in (
                ("user@example.com", 22),
                ("https://example.com", 22),
                ("example.com\n", 22),
                ("example.com.", 22),
                ("-example.com", 22),
                ("example.com", True),
                ("example.com", "22"),
                ("example.com", 0),
                ("example.com", 65536),
                ("example.com", 23),
            ):
                with (
                    self.subTest(hostname=hostname, port=port),
                    self.assertRaises(TransportFailure),
                ):
                    host_port(hostname, port)
            self.assertEqual(host_port("EXAMPLE.COM", 22), ("example.com", 22))

    @override_settings(PAM_ALLOWED_HOSTS={"ssh.example.test:22"})
    async def test_every_dns_address_must_be_in_explicit_deployment_networks(self):
        loop = asyncio.get_running_loop()

        def entries(*addresses):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 22)) for address in addresses
            ]

        for networks, addresses in (
            ((), ("93.184.216.34",)),
            (("10.0.0.0/24",), ("10.0.0.9", "10.0.1.2")),
            (("0.0.0.0/0",), ("169.254.169.254",)),
            (("0.0.0.0/0",), ("100.100.100.200",)),
            (("0.0.0.0/0",), ("168.63.129.16",)),
            (("0.0.0.0/0",), ("224.0.0.1",)),
            (("0.0.0.0/0",), ("0.0.0.0",)),
            (("::/0",), ("::ffff:127.0.0.1",)),
            (("::/0",), ("fd00:ec2::254",)),
            (("::/0",), ("fe80::1",)),
            (("invalid",), ("10.0.0.9",)),
            (("10.0.0.0/24",), ()),
        ):
            with (
                override_settings(PAM_ALLOWED_NETWORKS=networks),
                patch.object(loop, "getaddrinfo", AsyncMock(return_value=entries(*addresses))),
                self.assertRaisesMessage(TransportFailure, "address_not_authorized"),
            ):
                await resolve_destination("ssh.example.test", 22)
        with (
            override_settings(PAM_ALLOWED_NETWORKS=("10.0.0.0/24",)),
            patch.object(
                loop, "getaddrinfo", AsyncMock(return_value=entries("10.0.0.9"))
            ) as resolver,
        ):
            target = await resolve_destination("ssh.example.test", 22)
        self.assertEqual(target.address, "10.0.0.9")
        self.assertEqual(resolver.await_count, 1)

    def test_pins_are_mandatory_and_unambiguous(self):
        pin = "ab" * 32
        self.assertEqual(certificate_pin(pin), pin)
        self.assertEqual(certificate_pin("SHA256:" + ":".join(["AB"] * 32)), pin)
        for value in ("", "ignore", "sha1:" + "ab" * 20, "g" * 64, "a:" * 64, None):
            with self.assertRaises(TransportFailure):
                certificate_pin(value)
        for value in ("", "known_hosts=None", "ssh-ed25519 invalid", "x" * 16385, None):
            with self.assertRaises(TransportFailure):
                ssh_host_key(value)


class ProbeTests(SimpleTestCase):
    @override_settings(PAM_ALLOWED_NETWORKS=("127.0.0.0/8",))
    async def test_real_ssh_key_exchange_never_attempts_user_authentication(self):
        state = {"authentication_attempts": 0}

        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                state["authentication_attempts"] += 1
                return True

        key = asyncssh.generate_private_key("ssh-ed25519")
        server = await asyncssh.create_server(Server, "127.0.0.1", 0, server_host_keys=[key])
        port = server.get_port()
        try:
            with override_settings(PAM_ALLOWED_HOSTS={f"127.0.0.1:{port}"}):
                result = await probe_ssh("127.0.0.1", port, key.export_public_key().decode())
                self.assertEqual(result.fingerprint, key.get_fingerprint("sha256"))
                self.assertFalse(result.credentials_tested)
                other = asyncssh.generate_private_key("ssh-ed25519")
                with self.assertRaisesMessage(TransportFailure, "ssh_host_key_mismatch"):
                    await probe_ssh("127.0.0.1", port, other.export_public_key().decode())
            self.assertEqual(state["authentication_attempts"], 0)
        finally:
            server.close()
            await server.wait_closed()

    @asynccontextmanager
    async def rdp_fixture(self, *, selected=2, expired=False):
        with tempfile.TemporaryDirectory(prefix="pamolive-rdp-probe-") as directory:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.invalid")])
            now = datetime.now(UTC)
            certificate = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=2))
                .not_valid_after(now + timedelta(days=-1 if expired else 1))
                .sign(key, hashes.SHA256())
            )
            certificate_file, key_file = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            certificate_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_file.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certificate_file, key_file)
            state = {"application_bytes": b"", "negotiations": 0}
            complete = asyncio.Event()

            async def accept(reader, writer):
                try:
                    request = await reader.readexactly(19)
                    self.assertEqual(
                        request, bytes.fromhex("030000130ee00000000000010008000b000000")
                    )
                    state["negotiations"] += 1
                    writer.write(
                        bytes.fromhex("030000130ed0000000000002000800")
                        + struct.pack("<I", selected)
                    )
                    await writer.drain()
                    if selected in (2, 8):
                        await writer.start_tls(context, ssl_handshake_timeout=3)
                        state["application_bytes"] += await reader.read(1)
                except (OSError, asyncio.IncompleteReadError):
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass
                    complete.set()

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            pin = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
            try:
                with override_settings(
                    PAM_ALLOWED_HOSTS={f"127.0.0.1:{port}"},
                    PAM_ALLOWED_NETWORKS=("127.0.0.0/8",),
                ):
                    yield port, pin, state
                    await asyncio.wait_for(complete.wait(), timeout=5)
            finally:
                server.close()
                await server.wait_closed()

    async def test_real_rdp_negotiation_tls_and_pin_without_sending_credentials(self):
        async with self.rdp_fixture() as (port, pin, state):
            result = await probe_rdp("127.0.0.1", port, pin)
            self.assertEqual(result.fingerprint, "sha256:" + pin)
            self.assertIn(result.tls_version, ("TLSv1.2", "TLSv1.3"))
            self.assertFalse(result.credentials_tested)
        self.assertEqual(state["application_bytes"], b"")
        self.assertEqual(state["negotiations"], 1)

    async def test_wrong_certificate_is_rejected_before_any_credssp_data(self):
        async with self.rdp_fixture() as (port, pin, state):
            with self.assertRaisesMessage(TransportFailure, "rdp_certificate_mismatch"):
                await probe_rdp("127.0.0.1", port, "00" * 32)
        self.assertEqual(state["application_bytes"], b"")

    async def test_rdp_rejects_security_downgrade_and_expired_pinned_certificate(self):
        for selected in (0, 1, 3, 0x100):
            async with self.rdp_fixture(selected=selected) as (port, pin, state):
                with self.assertRaisesMessage(TransportFailure, "rdp_nla_required"):
                    await probe_rdp("127.0.0.1", port, pin)
        async with self.rdp_fixture(expired=True) as (port, pin, state):
            with self.assertRaisesMessage(TransportFailure, "expired_or_not_yet_valid"):
                await probe_rdp("127.0.0.1", port, pin)

    @override_settings(PAM_ALLOWED_HOSTS={"127.0.0.1:22"}, PAM_ALLOWED_NETWORKS=())
    async def test_probe_policy_denial_never_opens_socket(self):
        key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        with (
            patch("asyncssh.get_server_host_key", AsyncMock()) as ssh,
            patch("asyncio.open_connection", AsyncMock()) as rdp,
        ):
            for operation in (
                probe_ssh("127.0.0.1", 22, key),
                probe_rdp("127.0.0.1", 22, "ab" * 32),
            ):
                with self.assertRaisesMessage(TransportFailure, "address_not_authorized"):
                    await operation
            ssh.assert_not_called()
            rdp.assert_not_called()
