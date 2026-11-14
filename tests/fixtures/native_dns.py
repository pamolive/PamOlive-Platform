"""Bounded DNS answers for the isolated native RDP release gate only."""

import os
import socket
import struct
import sys
import threading
import time
from collections import Counter
from pathlib import Path


def loopback_resolvers(text):
    """Reject malformed or additional resolvers, including trailing comments."""
    if len(text) > 4096 or "\x00" in text:
        raise RuntimeError("native_dns_resolver_config_budget")
    resolvers = set()
    for raw in text.splitlines():
        fields = raw.split("#", 1)[0].split(";", 1)[0].split()
        if not fields:
            continue
        if fields[0].startswith("nameserver"):
            if fields[0] != "nameserver" or len(fields) != 2:
                raise RuntimeError("native_dns_malformed_resolver")
            resolvers.add(fields[1])
    if resolvers != {"127.0.0.1"}:
        raise RuntimeError("native_dns_requires_loopback_resolver")


def require_isolated_profile():
    """Refuse a host, a routed namespace, root, or an external resolver."""
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("native_dns_requires_unprivileged_linux")
    if {path.name for path in Path("/sys/class/net").iterdir()} != {"lo"}:
        raise RuntimeError("native_dns_requires_network_none")
    if not Path("/proc/1/comm").read_text().strip().startswith("python"):
        raise RuntimeError("native_dns_requires_python_container")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    if status.get("NoNewPrivs", "").strip() != "1" or any(
        int(status.get(key, "1").strip(), 16)
        for key in ("CapEff", "CapPrm", "CapBnd", "CapAmb")
    ):
        raise RuntimeError("native_dns_requires_no_capabilities")
    if not os.statvfs("/").f_flag & os.ST_RDONLY:
        raise RuntimeError("native_dns_requires_readonly_root")
    with Path("/etc/resolv.conf").open() as resolver_file:
        loopback_resolvers(resolver_file.read(4097))


def question(packet):
    """Read one bounded, uncompressed IN question; never parse credentials."""
    if not 17 <= len(packet) <= 512:
        raise ValueError("dns_packet_limit")
    _, flags, count, answers, authority, additional = struct.unpack_from("!6H", packet)
    if flags & 0xF800 or count != 1 or answers or authority or additional > 1:
        raise ValueError("dns_question_header")
    offset, labels = 12, []
    while offset < len(packet):
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or len(labels) >= 16 or offset + size > len(packet):
            raise ValueError("dns_question_name")
        labels.append(packet[offset:offset + size].decode("ascii").lower())
        offset += size
    else:
        raise ValueError("dns_question_name")
    if offset + 4 > len(packet) or offset > 267:
        raise ValueError("dns_question_name")
    kind, dns_class = struct.unpack_from("!2H", packet, offset)
    if dns_class != 1:
        raise ValueError("dns_question_class")
    return ".".join(labels), kind, offset + 4


class SyntheticDNS:
    MAX_DATAGRAMS = 64
    MAX_SECONDS = 35
    ALLOWED_NAMES = {"_kerberos.fixture", "_kerberos._udp.fixture", "_kerberos._tcp.fixture"}

    def __init__(self, mode):
        if mode not in {"nxdomain", "silent"}:
            raise ValueError("invalid_synthetic_dns_mode")
        self.mode = mode
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.questions = []
        self.errors = set()
        self.received_count = 0

    def __enter__(self):
        require_isolated_profile()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
            self.socket.bind(("127.0.0.1", 53))
            self.socket.settimeout(0.1)
        except OSError:
            self.socket.close()
            raise RuntimeError("native_dns_loopback_port53_unavailable") from None
        self.deadline = time.monotonic() + self.MAX_SECONDS
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self

    def serve(self):
        while not self.stop.is_set() and time.monotonic() < self.deadline:
            try:
                packet, peer = self.socket.recvfrom(513)
            except TimeoutError:
                continue
            except OSError:
                return
            with self.lock:
                self.received_count += 1
                if self.received_count >= self.MAX_DATAGRAMS:
                    self.errors.add("dns_datagram_budget")
                    return
            try:
                name, kind, end = question(packet)
            except (ValueError, UnicodeError):
                with self.lock:
                    self.errors.add("invalid_dns_question")
                return
            with self.lock:
                if name not in self.ALLOWED_NAMES or kind not in {33, 256}:
                    self.errors.add("unexpected_dns_question")
                    return
                self.questions.append((name, kind))
            if self.mode == "nxdomain":
                response = packet[:2] + struct.pack("!5H", 0x8183, 1, 0, 0, 0) + packet[12:end]
                try:
                    self.socket.sendto(response, peer)
                except OSError:
                    with self.lock:
                        self.errors.add("dns_response_failed")
                    return

    def snapshot(self):
        with self.lock:
            counts = sorted(Counter(self.questions).items())
            return {"questions": [{"name": name, "type": kind, "count": count}
                                  for (name, kind), count in counts],
                    "question_count": len(self.questions), "received_count": self.received_count,
                    "errors": sorted(self.errors)}

    def __exit__(self, kind, value, traceback):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=1)
        if self.thread.is_alive():
            raise RuntimeError("synthetic_dns_thread_not_stopped")
