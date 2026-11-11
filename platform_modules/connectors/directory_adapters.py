"""Read-only directory readers. Real environments remain disabled in P1-F.

LDAP uses python-ldap/OpenLDAP in the Linux image, never a local BER codec.
Windows development fails closed without that optional native dependency.
A server-side service owns credentials, policy and persistence.
"""

import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from threading import BoundedSemaphore
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ValidationError

from platform_modules.identity.directory_simulation import normalize_fixture

from .scim import IntegrationFailure, PinnedHTTPSConnection, resolve_destination

MAX_RECORDS = 1000
MAX_PAGES = 20
PAGE_SIZE = 100
MAX_BYTES = 4 * 1024 * 1024
MAX_GROUPS = 32
DEADLINE_SECONDS = 45
_DNS_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="directory-dns")
_DNS_SLOTS = BoundedSemaphore(4)


class DirectoryFailure(Exception):
    def __init__(self, code, *, retryable=False):
        self.code, self.retryable = code, retryable
        super().__init__(code)


@dataclass(frozen=True)
class ReadResult:
    records: list
    complete: bool
    page_count: int
    synthetic: bool
    transport_identity: dict
    limitations: tuple = ()


def _text(value, maximum=1024):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(c) < 32 for c in value)
    ):
        raise DirectoryFailure("directory_configuration_invalid")
    return value


def normalize_destination(provider, endpoint, certificate_sha256, scope):
    """Canonical, offline identity. No DNS lookup and no credential material."""
    if provider not in {"ad", "ldap", "entra"}:
        raise DirectoryFailure("directory_provider_invalid")
    endpoint = _text(endpoint, 2048)
    if not isinstance(certificate_sha256, str) or not re.fullmatch(
        r"[a-f0-9]{64}", certificate_sha256
    ):
        raise DirectoryFailure("directory_certificate_pin_required")
    try:
        parsed = urlsplit(endpoint)
        host = (parsed.hostname or "").encode("idna").decode().lower()
        if (
            not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "\\" in endpoint
            or any(p in {".", ".."} for p in unquote(parsed.path).split("/"))
        ):
            raise ValueError
        if type(scope) is not dict:
            raise ValueError
        if provider == "entra":
            if parsed.scheme != "https" or parsed.path != "/v1.0/users":
                raise ValueError
            port = parsed.port or 443
            if set(scope) != {"tenant_id"}:
                raise ValueError
            canonical_scope = {"tenant_id": str(UUID(scope["tenant_id"]))}
            path = "/v1.0/users"
        else:
            if parsed.scheme == "ldaps":
                # python-ldap's initialized connected fd does not install
                # implicit TLS. Never fall back to DNS reconnection or an
                # unverified/private C API merely to accept this configuration.
                raise DirectoryFailure("directory_ldaps_not_qualified")
            if parsed.scheme != "ldap" or parsed.path not in {"", "/"}:
                raise ValueError
            port = parsed.port or 389
            if set(scope) != {"base_dn", "bind_dn"}:
                raise ValueError
            canonical_scope = {k: _text(scope[k]) for k in ("base_dn", "bind_dn")}
            path = ""
        if not 1 <= port <= 65535:
            raise ValueError
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    except (ValueError, TypeError, AttributeError, UnicodeError):
        raise DirectoryFailure("directory_destination_invalid") from None
    return {
        "schema": "pamolive.directory-destination/1",
        "provider": provider,
        "endpoint": urlunsplit((parsed.scheme, authority, path, "", "")),
        "certificate_sha256": certificate_sha256,
        "scope": canonical_scope,
    }


def normalize_directory_records(provider, records):
    """Inventory v2: unknown account state stays None, never implicitly False.

    P1 preview's strict-bool normalize_fixture is intentionally unchanged. Its
    established validation is reused with a temporary known value solely for
    syntactic checking, then every unknown state is restored before returning.
    """
    if provider not in {"ad", "ldap", "entra"} or type(records) is not list:
        raise DirectoryFailure("directory_record_invalid")
    if len(records) > MAX_RECORDS:
        raise DirectoryFailure("directory_record_limit")
    state_key = "accountEnabled" if provider == "entra" else "enabled"
    checked, unknown = [], set()
    try:
        for row in records:
            if type(row) is not dict:
                raise ValueError
            nullable = provider in {"ldap", "entra"} and row.get(state_key) is None
            value = dict(row)
            if nullable:
                value[state_key] = True
            result = normalize_fixture(provider, [value])[0]
            if nullable:
                unknown.add(result["remote_id"])
            checked.append(value)
        normalized = normalize_fixture(provider, checked)
    except (ValidationError, ValueError, TypeError, IndexError):
        raise DirectoryFailure("directory_record_invalid") from None
    for row in normalized:
        if row["remote_id"] in unknown:
            row["enabled"] = None
    return normalized


def _bounded_resolve(host, port, deadline):
    _remaining(deadline)
    if not _DNS_SLOTS.acquire(blocking=False):
        raise DirectoryFailure("directory_dns_capacity_exceeded", retryable=True)
    try:
        future = _DNS_POOL.submit(resolve_destination, host, port)
    except BaseException:
        _DNS_SLOTS.release()
        raise
    # A timed-out caller does not free the slot while its resolver still runs.
    # Thus even stuck OS DNS cannot create an unbounded task queue.
    future.add_done_callback(lambda _: _DNS_SLOTS.release())
    try:
        return future.result(timeout=_remaining(deadline))
    except FutureTimeout:
        future.cancel()
        raise DirectoryFailure("directory_dns_deadline_exceeded", retryable=True) from None


def _connection_address(destination, deadline):
    parsed = urlsplit(destination["endpoint"])
    host, port = parsed.hostname, parsed.port
    host_key = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    if host_key not in settings.CONNECTOR_ALLOWED_HOSTS or not (
        host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".invalid")
    ):
        raise DirectoryFailure("directory_synthetic_destination_required")
    try:
        address = _bounded_resolve(host, port, deadline)
        # The first implementation only permits local fixtures. A configured
        # host allowlist never enables an Internet/NAS/production connection.
        if not ipaddress.ip_address(address).is_loopback:
            raise DirectoryFailure("directory_synthetic_address_required")
        return address
    except IntegrationFailure:
        raise DirectoryFailure("directory_address_not_authorized") from None


def _pin(certificate, expected):
    if (
        not isinstance(certificate, bytes)
        or not certificate
        or not hmac.compare_digest(hashlib.sha256(certificate).hexdigest(), expected)
    ):
        raise DirectoryFailure("directory_certificate_mismatch")


def _remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise DirectoryFailure("directory_deadline_exceeded", retryable=True)
    return min(8, seconds)


def _credential(provider, destination, secret):
    if type(secret) is not dict:
        raise DirectoryFailure("directory_credential_invalid")
    keys = {"token"} if provider == "entra" else {"bind_dn", "password"}
    if set(secret) != keys or any(
        not isinstance(v, str) or not v or len(v) > 8192 or any(ord(c) < 32 for c in v)
        for v in secret.values()
    ):
        raise DirectoryFailure("directory_credential_invalid")
    if provider != "entra" and secret["bind_dn"] != destination["scope"]["bind_dn"]:
        raise DirectoryFailure("directory_credential_identity_mismatch")
    if provider == "entra" and not re.fullmatch(r"[!-~]+", secret["token"]):
        raise DirectoryFailure("directory_credential_invalid")


def _strict_json(content):
    def unique(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError
            out[k] = v
        return out

    try:
        return json.loads(
            content,
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (ValueError, UnicodeError):
        raise DirectoryFailure("directory_response_invalid") from None


class _GraphReader:
    def __init__(self):
        self.identity = {}

    def _request(self, destination, target, secret, before_auth, deadline):
        parsed = urlsplit(destination["endpoint"])
        address = _connection_address(destination, deadline)
        try:
            context = ssl.create_default_context(cafile=settings.CONNECTOR_CA_BUNDLE or None)
        except (OSError, ssl.SSLError):
            raise DirectoryFailure("directory_tls_configuration_invalid") from None
        connection = PinnedHTTPSConnection(parsed.hostname, parsed.port, address, context)
        connection.timeout = _remaining(deadline)
        try:
            connection.connect()
            tls_socket = connection.sock
            _pin(tls_socket.getpeercert(binary_form=True), destination["certificate_sha256"])
            before_auth()
            tls_socket.settimeout(_remaining(deadline))
            connection.request(
                "GET",
                target,
                headers={
                    "Authorization": "Bearer " + secret["token"],
                    "Accept": "application/json",
                },
            )
            response = connection.getresponse()
            content = bytearray()
            while not response.isclosed():
                # Bound the entire body, including a peer that trickles bytes
                # often enough to avoid a per-recv socket timeout.
                tls_socket.settimeout(_remaining(deadline))
                chunk = response.read1(min(65536, 1_048_577 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > 1_048_576:
                    raise DirectoryFailure("directory_response_too_large")
            if response.status != 200:
                raise DirectoryFailure(
                    "directory_http_failed",
                    retryable=response.status == 429 or response.status >= 500,
                )
            return _strict_json(content)
        except ssl.SSLError:
            raise DirectoryFailure("directory_tls_verification_failed") from None
        except (OSError, TimeoutError, http.client.HTTPException):
            raise DirectoryFailure("directory_network_failed", retryable=True) from None
        finally:
            connection.close()

    def pages(self, destination, secret, before_auth, deadline):
        realm = self._request(
            destination, "/v1.0/organization?$select=id", secret, before_auth, deadline
        )
        expected = destination["scope"]["tenant_id"]
        if (
            type(realm) is not dict
            or type(realm.get("value")) is not list
            or len(realm["value"]) != 1
            or realm["value"][0] != {"id": expected}
            or realm.get("@odata.nextLink")
        ):
            raise DirectoryFailure("directory_realm_mismatch")
        self.identity = {"realm_id": expected}
        target = "/v1.0/users?$select=id,userPrincipalName,accountEnabled&$top=100"
        seen = set()
        for _ in range(MAX_PAGES):
            if target in seen:
                raise DirectoryFailure("directory_cursor_cycle")
            seen.add(target)
            page = self._request(destination, target, secret, before_auth, deadline)
            if type(page) is not dict or type(page.get("value")) is not list:
                raise DirectoryFailure("directory_response_invalid")
            rows = []
            for row in page["value"]:
                if (
                    type(row) is not dict
                    or not {"id", "userPrincipalName"} <= set(row)
                    or not set(row) <= {"id", "userPrincipalName", "accountEnabled"}
                ):
                    raise DirectoryFailure("directory_response_invalid")
                rows.append({**row, "accountEnabled": row.get("accountEnabled"), "groups": []})
            next_link = page.get("@odata.nextLink")
            yield rows, bool(next_link), ("graph_group_memberships_not_collected",)
            if not next_link:
                return
            if not isinstance(next_link, str) or len(next_link) > 8192 or "\\" in next_link:
                raise DirectoryFailure("directory_next_link_invalid")
            try:
                new, origin = urlsplit(next_link), urlsplit(destination["endpoint"])
                next_port = new.port or 443
            except ValueError:
                raise DirectoryFailure("directory_next_link_invalid") from None
            if (
                new.scheme != origin.scheme
                or new.hostname != origin.hostname
                or next_port != origin.port
                or new.path != origin.path
                or new.fragment
                or new.username
                or new.password
            ):
                raise DirectoryFailure("directory_next_link_invalid")
            pairs = parse_qsl(new.query, keep_blank_values=True)
            allowed = {"$select", "$top", "$skiptoken", "$skip"}
            if (
                len(pairs) != len(dict(pairs))
                or any(k not in allowed for k, _ in pairs)
                or dict(pairs).get("$select") != "id,userPrincipalName,accountEnabled"
                or dict(pairs).get("$top") != "100"
                or not any(k in {"$skiptoken", "$skip"} for k, _ in pairs)
            ):
                raise DirectoryFailure("directory_next_link_invalid")
            target = new.path + "?" + new.query


def _one(attributes, name):
    values = attributes.get(name, [])
    if len(values) != 1 or not isinstance(values[0], bytes):
        raise DirectoryFailure("directory_attribute_invalid")
    return values[0]


def _ldap_rows(provider, entries):
    rows, limitations = [], set()
    for dn, attrs in entries:
        if dn is None:
            limitations.add("ldap_referral_not_followed")
            continue
        if not isinstance(dn, str) or type(attrs) is not dict:
            raise DirectoryFailure("directory_response_invalid")
        try:
            groups = []
            for key, values in attrs.items():
                if key.lower().startswith("memberof;range="):
                    limitations.add("ad_ranged_membership_incomplete")
                if key.lower() == "memberof" or key.lower().startswith("memberof;range="):
                    groups.extend(value.decode("utf-8") for value in values)
            if len(groups) > MAX_GROUPS:
                limitations.add("directory_group_limit")
                groups = groups[:MAX_GROUPS]
            if provider == "ad":
                raw_id = _one(attrs, "objectGUID")
                identifier = str(UUID(bytes_le=raw_id))
                enabled = not bool(int(_one(attrs, "userAccountControl")) & 2)
                row = {
                    "objectGUID": identifier,
                    "sAMAccountName": _one(attrs, "sAMAccountName").decode("utf-8"),
                    "enabled": enabled,
                    "memberOf": groups,
                }
            else:
                identifier = str(UUID(_one(attrs, "entryUUID").decode("ascii")))
                row = {
                    "entryUUID": identifier,
                    "uid": _one(attrs, "uid").decode("utf-8"),
                    "enabled": None,
                    "memberOf": groups,
                }
                limitations.add("directory_enabled_state_unknown")
                if not any(key.lower() == "memberof" for key in attrs):
                    limitations.add("ldap_group_memberships_unknown")
            rows.append(row)
        except (UnicodeError, ValueError, TypeError):
            raise DirectoryFailure("directory_attribute_invalid") from None
    return rows, tuple(sorted(limitations))


class _LdapReader:
    def __init__(self):
        self.identity = {}

    def pages(self, destination, secret, before_auth, deadline):
        try:
            import ldap
            from ldap.controls import SimplePagedResultsControl
        except ImportError:
            raise DirectoryFailure("directory_ldap_dependency_unavailable") from None
        required = (
            "INIT_FD_AVAIL",
            "OPT_X_TLS_PEERCERT",
            "OPT_X_TLS_PROTOCOL_MIN",
            "OPT_X_TLS_PROTOCOL_TLS1_2",
            "OPT_X_TLS_REQUIRE_SAN",
        )
        if not all(hasattr(ldap, key) for key in required) or not ldap.INIT_FD_AVAIL:
            raise DirectoryFailure("directory_ldap_tls_features_unavailable")
        parsed = urlsplit(destination["endpoint"])
        address = _connection_address(destination, deadline)
        raw, connection = None, None
        try:
            raw = socket.create_connection((address, parsed.port), _remaining(deadline))
            connection = ldap.initialize(
                destination["endpoint"], fileno=raw.fileno(), trace_level=0
            )
            raw.detach()  # OpenLDAP now owns this exact connected descriptor.
            raw = None
            connection._trace_level = 0
            ldap.set_option(ldap.OPT_DEBUG_LEVEL, 0)
            for key, value in (
                (ldap.OPT_PROTOCOL_VERSION, 3),
                (ldap.OPT_REFERRALS, 0),
                (ldap.OPT_DEREF, ldap.DEREF_NEVER),
                (ldap.OPT_NETWORK_TIMEOUT, _remaining(deadline)),
                (ldap.OPT_TIMEOUT, _remaining(deadline)),
                (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND),
                (ldap.OPT_X_TLS_REQUIRE_SAN, ldap.OPT_X_TLS_DEMAND),
                (ldap.OPT_X_TLS_PROTOCOL_MIN, ldap.OPT_X_TLS_PROTOCOL_TLS1_2),
            ):
                connection.set_option(key, value)
            if settings.CONNECTOR_CA_BUNDLE:
                connection.set_option(ldap.OPT_X_TLS_CACERTFILE, settings.CONNECTOR_CA_BUNDLE)
            connection.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
            connection.start_tls_s()
            _pin(connection.get_option(ldap.OPT_X_TLS_PEERCERT), destination["certificate_sha256"])
            before_auth()
            connection.set_option(ldap.OPT_TIMEOUT, _remaining(deadline))
            connection.simple_bind_s(secret["bind_dn"], secret["password"])
            self.identity = {
                "base_dn": destination["scope"]["base_dn"],
                "bind_dn": destination["scope"]["bind_dn"],
            }
            cookie, seen = b"", set()
            attrs = (
                ["objectGUID", "sAMAccountName", "userAccountControl", "memberOf"]
                if destination["provider"] == "ad"
                else ["entryUUID", "uid", "memberOf"]
            )
            for _ in range(MAX_PAGES):
                # An already-bound connection must not keep reading after a
                # source/module/actor revocation between two result pages.
                before_auth()
                control = SimplePagedResultsControl(criticality=True, size=PAGE_SIZE, cookie=cookie)
                msgid = connection.search_ext(
                    destination["scope"]["base_dn"],
                    ldap.SCOPE_SUBTREE,
                    "(objectClass=person)",
                    attrs,
                    serverctrls=[control],
                    timeout=_remaining(deadline),
                    sizelimit=MAX_RECORDS + 1,
                )
                _, entries, _, controls = connection.result3(msgid, timeout=_remaining(deadline))
                pages = [c for c in controls if c.controlType == control.controlType]
                if len(pages) != 1 or not isinstance(pages[0].cookie, bytes):
                    raise DirectoryFailure("directory_paging_control_missing")
                cookie = pages[0].cookie
                if len(cookie) > 8192 or (cookie and cookie in seen):
                    raise DirectoryFailure("directory_cursor_cycle")
                if cookie:
                    seen.add(cookie)
                rows, limitations = _ldap_rows(destination["provider"], entries)
                yield rows, bool(cookie), limitations
                if not cookie:
                    return
        except ldap.LDAPError:
            raise DirectoryFailure("directory_ldap_failed", retryable=True) from None
        except OSError:
            raise DirectoryFailure("directory_network_failed", retryable=True) from None
        finally:
            if raw is not None:
                raw.close()
            if connection is not None:
                try:
                    connection.unbind_s()
                except ldap.LDAPError:
                    pass


def read_directory(
    *, provider, destination, secret, synthetic=True, transport=None, before_auth=None
):
    """Bounded read; incomplete observations never prove remote deletion.

    transport is solely an internal test seam, never a client/API parameter.
    This function does not grant rights, write remote data or persist results.
    """
    if synthetic is not True:
        raise DirectoryFailure("directory_real_execution_disabled")
    if type(destination) is not dict:
        raise DirectoryFailure("directory_destination_invalid")
    canonical = normalize_destination(
        provider,
        destination.get("endpoint"),
        destination.get("certificate_sha256"),
        destination.get("scope"),
    )
    if canonical != destination:
        raise DirectoryFailure("directory_destination_invalid")
    _credential(provider, destination, secret)
    reader = transport or (_GraphReader() if provider == "entra" else _LdapReader())
    rows, warnings, size, page_count, complete, seen = [], set(), 0, 0, False, set()
    pages = reader.pages(
        destination, secret, before_auth or (lambda: None), time.monotonic() + DEADLINE_SECONDS
    )
    try:
        for page, has_more, limitations in pages:
            page_count += 1
            if page_count > MAX_PAGES:
                break
            if type(page) is not list:
                raise DirectoryFailure("directory_response_invalid")
            warnings.update(limitations)
            size += len(json.dumps(page, ensure_ascii=False).encode())
            if size > MAX_BYTES:
                warnings.add("directory_byte_limit")
                break
            for row in page:
                try:
                    normalized = normalize_directory_records(provider, [row])[0]
                except (ValidationError, ValueError, TypeError, IndexError):
                    raise DirectoryFailure("directory_record_invalid") from None
                if normalized["remote_id"] in seen:
                    raise DirectoryFailure("directory_duplicate_identifier")
                seen.add(normalized["remote_id"])
                if normalized["enabled"] is None:
                    warnings.add("directory_enabled_state_unknown")
                if len(rows) == MAX_RECORDS:
                    warnings.add("directory_record_limit")
                    break
                rows.append(row)
            if "directory_record_limit" in warnings:
                break
            if not has_more:
                complete = True
                break
        else:
            warnings.add("directory_page_limit")
    finally:
        if hasattr(pages, "close"):
            pages.close()
    # Users-only Graph preparation cannot claim a complete directory snapshot.
    complete = complete and not warnings
    identity = {
        "provider": provider,
        "endpoint": destination["endpoint"],
        "certificate_sha256": destination["certificate_sha256"],
        "scope": destination["scope"],
        **reader.identity,
    }
    if provider == "entra" and identity.get("realm_id") != destination["scope"]["tenant_id"]:
        raise DirectoryFailure("directory_realm_mismatch")
    return ReadResult(rows, complete, page_count, True, identity, tuple(sorted(warnings)))
