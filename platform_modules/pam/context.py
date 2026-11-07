"""Connection context from the peer and explicitly trusted deployment inventory."""

import ipaddress
from urllib.parse import urlsplit

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http.request import split_domain_port, validate_host


def client_address(peer, forwarded=""):
    try:
        address = ipaddress.ip_address(peer)
        trusted = any(
            address in ipaddress.ip_network(value) for value in settings.PAM_TRUSTED_PROXY_NETWORKS
        )
        if trusted:
            # The last trusted reverse proxy must OVERWRITE this with one IP.
            address = ipaddress.ip_address(forwarded.strip())
        return str(address)
    except (ValueError, TypeError):
        raise PermissionDenied("Origine réseau invérifiable.") from None


def network_context(address):
    address = ipaddress.ip_address(address)
    matches = []
    for entry in settings.PAM_NETWORK_CONTEXT:
        network = ipaddress.ip_network(entry["network"])
        if address in network:
            matches.append((network.prefixlen, entry))
    if matches:
        entry = max(matches, key=lambda pair: pair[0])[1]
        return entry.get("location", str(address)), entry.get("country", "").upper()
    return str(address), ""


def check_websocket_origin(scope):
    if scope.get("query_string"):
        raise PermissionDenied
    values = {}
    for key, value in scope.get("headers", []):
        key = key.decode("ascii").lower()
        if key in values and key in {"host", "origin", "cookie", "x-forwarded-for"}:
            raise PermissionDenied
        values[key] = value.decode("latin1")
    host = values.get("host", "").lower()
    domain, _ = split_domain_port(host)
    if not domain or not validate_host(domain, settings.ALLOWED_HOSTS):
        raise PermissionDenied
    expected = settings.PAM_PUBLIC_ORIGIN or (
        ("https://" if scope.get("scheme") in ("wss", "https") else "http://") + host
    )
    origin = values.get("origin", "")
    parsed = urlsplit(origin)
    if (
        origin != expected
        or parsed.scheme not in ("http", "https")
        or parsed.netloc.lower() != host
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or "guacamole" not in scope.get("subprotocols", [])
    ):
        raise PermissionDenied
    return values, client_address(
        (scope.get("client") or (None,))[0], values.get("x-forwarded-for", "")
    )
