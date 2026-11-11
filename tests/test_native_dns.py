"""Adversarial regression tests for the test-only native DNS profile."""

import struct
import time
import unittest

from tests.fixtures.native_dns import SyntheticDNS, loopback_resolvers


def dns_question(name="_kerberos.fixture", kind=256):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    return struct.pack("!6H", 1, 0x100, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!2H", kind, 1)


class DatagramSocket:
    def __init__(self, packet):
        self.packet, self.calls = packet, 0

    def recvfrom(self, size):
        self.calls += 1
        if self.calls > 1024:
            raise AssertionError("Synthetic DNS consumed an unbounded datagram stream")
        return self.packet[:size], ("127.0.0.1", 12345)


class NativeDNSProfileTests(unittest.TestCase):
    def test_external_resolver_hidden_by_comment_is_refused(self):
        for suffix in ("# synthetic", "; synthetic", "unexpected-token"):
            with self.subTest(suffix=suffix), self.assertRaises(RuntimeError):
                loopback_resolvers("nameserver 127.0.0.1\nnameserver 203.0.113.53 " + suffix)

    def test_malformed_nameserver_is_not_silently_ignored(self):
        for line in ("nameserver", "nameserver127.0.0.1", "nameserver 127.0.0.1 extra"):
            with self.subTest(line=line), self.assertRaises(RuntimeError):
                loopback_resolvers("nameserver 127.0.0.1\n" + line)

    def test_loopback_comments_and_docker_options_are_accepted(self):
        loopback_resolvers("# synthetic\nnameserver 127.0.0.1 # lab\noptions ndots:0\n")

    def test_resolver_input_has_a_fixed_budget(self):
        for text in ("x" * 4097, "nameserver 127.0.0.1\x00", ""):
            with self.assertRaises(RuntimeError):
                loopback_resolvers(text)

    def serve(self, packet):
        resolver = SyntheticDNS("silent")
        resolver.socket = DatagramSocket(packet)
        resolver.deadline = time.monotonic() + 2
        resolver.serve()
        return resolver.snapshot(), resolver.socket.calls

    def test_invalid_datagram_flood_stops_on_first_datagram(self):
        for packet in (b"bad", b"x" * 513):
            with self.subTest(size=len(packet)):
                result, received = self.serve(packet)
                self.assertEqual(received, 1)
                self.assertEqual(result["received_count"], 1)
                self.assertEqual(result["question_count"], 0)
                self.assertEqual(result["errors"], ["invalid_dns_question"])

    def test_unexpected_question_flood_stops_on_first_datagram(self):
        result, received = self.serve(dns_question("unexpected.invalid"))
        self.assertEqual(received, 1)
        self.assertEqual(result["received_count"], 1)
        self.assertEqual(result["question_count"], 0)
        self.assertEqual(result["errors"], ["unexpected_dns_question"])

    def test_authorized_question_flood_has_a_total_datagram_limit(self):
        result, received = self.serve(dns_question())
        self.assertEqual(received, SyntheticDNS.MAX_DATAGRAMS)
        self.assertEqual(result["received_count"], SyntheticDNS.MAX_DATAGRAMS)
        self.assertLess(result["question_count"], result["received_count"])
        self.assertEqual(result["errors"], ["dns_datagram_budget"])


if __name__ == "__main__":
    unittest.main()
