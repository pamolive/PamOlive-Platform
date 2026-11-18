"""Finite acquisition IO; blocking calls additionally require the process owner."""

import hashlib
import math
import time
import urllib.parse
import urllib.request
from pathlib import Path

BASE_URL = "https://security.debian.org/debian-security/"


def remaining(deadline, *, clock=None):
    clock = time.monotonic if clock is None else clock
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("ACQUISITION_UNKNOWN_DEADLINE")
    left = deadline - clock()
    if left <= 0:
        raise ValueError("ACQUISITION_UNKNOWN_DEADLINE")
    return left


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("ACQUISITION_UNKNOWN_REDIRECT")


def acquire_blob(url, path, maximum, expected=None, *, deadline):
    """Caller must use the owned-process boundary for DNS/TLS/kernel stalls."""
    remaining(deadline)
    parts = urllib.parse.urlsplit(url)
    if not (
        parts.scheme == "https"
        and parts.hostname == "security.debian.org"
        and parts.netloc == "security.debian.org"
        and url.startswith(BASE_URL)
        and not parts.fragment
        and not parts.username
        and not parts.password
    ):
        raise ValueError("source_origin")
    if type(maximum) is not int or not 0 < maximum <= 64 * 1024**2:
        raise ValueError("acquisition_cap")
    path = Path(path)
    digest, size = hashlib.sha256(), 0
    opener = urllib.request.build_opener(NoRedirect())
    remaining(deadline)
    request = urllib.request.Request(url, headers={"User-Agent": "PamOlive-source-build"})
    # The owned process horizon covers DNS/TLS/headers even if a kernel call ignores this timeout.
    with opener.open(request, timeout=min(30.0, remaining(deadline))) as response:
        remaining(deadline)
        if response.status != 200:
            raise ValueError("acquisition_http")
        # CPython urllib HTTPResponse/HTTPSHandler, not a receipt-provided socket.
        sock = response.fp.raw._sock
        sock.settimeout(min(30.0, remaining(deadline)))
        remaining(deadline)
        with path.open("xb") as stream:
            remaining(deadline)
            while True:
                sock.settimeout(min(30.0, remaining(deadline)))
                remaining(deadline)
                count = min(65536, maximum - size + 1)
                raw = response.read1(count)
                remaining(deadline)
                if type(raw) is not bytes or len(raw) > count:
                    raise ValueError("acquisition_read_contract")
                if not raw:
                    break
                size += len(raw)
                if size > maximum:
                    raise ValueError("acquisition_budget")
                remaining(deadline)
                digest.update(raw)
                remaining(deadline)
                if stream.write(raw) != len(raw):
                    raise ValueError("acquisition_short_write")
                remaining(deadline)
            stream.flush()
            remaining(deadline)
        remaining(deadline)
    remaining(deadline)
    if size <= 0:
        raise ValueError("acquisition_empty")
    result = digest.hexdigest()
    remaining(deadline)
    if expected is not None and (size, result) != tuple(expected):
        raise ValueError("acquisition_hash_or_size")
    remaining(deadline)
    return {"bytes": size, "sha256": result, "url": url, "opened_as_archive": False}
