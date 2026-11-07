"""Deployment-owned PAM egress policy; DNS is checked once and IP-pinned."""

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass

from django.conf import settings


class TransportFailure(Exception):
    """Only stable public codes may cross the UI/audit boundary."""


@dataclass(frozen=True)
class Destination:
    hostname: str
    port: int
    address: str


def host_port(hostname, port):
    try:
        if (
            not isinstance(hostname, str)
            or not hostname
            or len(hostname) > 253
            or any(char in hostname for char in " /\\\t\r\n\x00@?#%[]")
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError
        try:
            host = str(ipaddress.ip_address(hostname))
        except ValueError:
            host = hostname.encode("idna").decode().lower()
            if any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.split(".")
            ):
                raise ValueError
        key = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        if key not in settings.PAM_ALLOWED_HOSTS:
            raise ValueError
        return host, port
    except (ValueError, UnicodeError):
        raise TransportFailure("destination_not_authorized") from None


async def resolve_destination(hostname, port):
    hostname, port = host_port(hostname, port)
    try:
        networks = tuple(ipaddress.ip_network(value) for value in settings.PAM_ALLOWED_NETWORKS)
        if not networks:
            raise ValueError
        async with asyncio.timeout(5):
            entries = await asyncio.get_running_loop().getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM
            )
        addresses = {entry[4][0] for entry in entries}
        if not addresses or len(addresses) > 16:
            raise ValueError
        for value in addresses:
            address = ipaddress.ip_address(value)
            if (
                address.is_link_local
                or address.is_multicast
                or address.is_unspecified
                or getattr(address, "ipv4_mapped", None)
                or str(address) in {"fd00:ec2::254", "100.100.100.200", "168.63.129.16"}
                or not any(address in network for network in networks)
            ):
                raise ValueError
        # The caller must connect to this literal IP, never resolve hostname again.
        return Destination(hostname, port, sorted(addresses)[0])
    except (ValueError, OSError, TimeoutError):
        raise TransportFailure("address_not_authorized") from None
