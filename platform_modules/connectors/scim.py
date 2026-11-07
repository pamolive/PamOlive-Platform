"""SCIM 2.0 desired-state writes over explicitly authorized, pinned HTTPS destinations."""

import http.client
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import quote, unquote, urlsplit

from django.conf import settings

PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


class IntegrationFailure(Exception):
    def __init__(self, code, *, retryable=False):
        self.code, self.retryable = code, retryable
        super().__init__(code)


def destination(url):
    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").encode("idna").decode().lower()
        port = parsed.port or 443
        host_key = f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
        if (
            parsed.scheme != "https"
            or not hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or "\\" in url
            or any(part in (".", "..") for part in unquote(parsed.path).split("/"))
            or host_key not in settings.CONNECTOR_ALLOWED_HOSTS
        ):
            raise ValueError
        return hostname, port, parsed.path.rstrip("/")
    except (ValueError, UnicodeError):
        raise IntegrationFailure("destination_not_authorized") from None


def resolve_destination(hostname, port):
    try:
        addresses = {
            entry[4][0] for entry in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        }
        networks = [ipaddress.ip_network(value) for value in settings.CONNECTOR_ALLOWED_NETWORKS]
        if not addresses:
            raise ValueError
        for value in addresses:
            address = ipaddress.ip_address(value)
            if (
                address.is_link_local
                or address.is_multicast
                or address.is_unspecified
                or str(address) in {"fd00:ec2::254", "100.100.100.200"}
                or getattr(address, "ipv4_mapped", None)
            ):
                raise ValueError
            if not address.is_global and not any(address in network for network in networks):
                raise ValueError
        return sorted(addresses)[0]
    except (ValueError, OSError):
        raise IntegrationFailure("address_not_authorized") from None


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, port, address, context):
        super().__init__(hostname, port, timeout=8, context=context)
        self.address = address

    def connect(self):
        # Resolve once in the policy layer, connect to that address, preserve hostname/SNI.
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def remote_id(value):
    if not re.fullmatch(r"[A-Za-z0-9_:@.\-]{1,180}", value) or value in (".", ".."):
        raise IntegrationFailure("invalid_remote_identifier")
    return quote(value, safe="")


class ScimAdapter:
    def __init__(self, base_url, token, *, before_write=None):
        self.hostname, self.port, self.base_path = destination(base_url)
        self.token = token
        self.before_write = before_write or (lambda: None)

    def request(self, method, path, payload=None):
        address = resolve_destination(self.hostname, self.port)
        context = ssl.create_default_context(cafile=settings.CONNECTOR_CA_BUNDLE or None)
        connection = PinnedHTTPSConnection(self.hostname, self.port, address, context)
        body = json.dumps(payload).encode() if payload is not None else None
        try:
            connection.request(
                method,
                self.base_path + path,
                body=body,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/scim+json",
                    "Content-Type": "application/scim+json",
                },
            )
            response = connection.getresponse()
            content = response.read(1_048_577)
            if len(content) > 1_048_576:
                raise IntegrationFailure("response_too_large")
            if not 200 <= response.status < 300:
                raise IntegrationFailure(
                    f"remote_http_{response.status}",
                    retryable=response.status in (409, 412, 429) or response.status >= 500,
                )
            # Redirects are errors; tokens never leave this configured origin.
            if response.status == 204:
                return {}
            result = json.loads(content)
            if not isinstance(result, dict):
                raise ValueError
            return result
        except ssl.SSLError:
            raise IntegrationFailure("tls_verification_failed") from None
        except (OSError, http.client.HTTPException):
            raise IntegrationFailure("network_error", retryable=True) from None
        except (ValueError, UnicodeError):
            raise IntegrationFailure("invalid_scim_response") from None
        finally:
            connection.close()

    def test(self):
        configuration = self.request("GET", "/ServiceProviderConfig")
        patch = configuration.get("patch")
        if not isinstance(patch, dict) or patch.get("supported") is not True:
            raise IntegrationFailure("scim_patch_not_supported")
        users = self.request("GET", "/Users?count=1")
        if not isinstance(users.get("Resources"), list):
            raise IntegrationFailure("invalid_scim_list_response")
        return {"patch_supported": True, "read_users_confirmed": True}

    def disable_account(self, account_id):
        path = "/Users/" + remote_id(account_id)
        user = self.request("GET", path)
        if user.get("id") != account_id or not isinstance(user.get("active"), bool):
            raise IntegrationFailure("invalid_scim_user")
        if user["active"]:
            self.before_write()
            self.request(
                "PATCH",
                path,
                {
                    "schemas": [PATCH_SCHEMA],
                    "Operations": [{"op": "replace", "path": "active", "value": False}],
                },
            )
        confirmed = self.request("GET", path)
        if confirmed.get("id") != account_id or confirmed.get("active") is not False:
            raise IntegrationFailure("write_not_confirmed", retryable=True)
        return {"remote_account_id": account_id, "active": False}

    def membership(self, account_id, group_id, *, present):
        remote_id(account_id)
        path = "/Groups/" + remote_id(group_id)

        def read_members():
            group = self.request("GET", path + "?attributes=id,members")
            members = group.get("members")
            if group.get("id") != group_id or not isinstance(members, list):
                raise IntegrationFailure("invalid_scim_group")
            if any(not isinstance(m, dict) or not isinstance(m.get("value"), str) for m in members):
                raise IntegrationFailure("invalid_scim_group_members")
            return {member["value"] for member in members}

        if (account_id in read_members()) != present:
            self.before_write()
            operation = (
                {"op": "add", "path": "members", "value": [{"value": account_id}]}
                if present
                else {"op": "remove", "path": f"members[value eq {json.dumps(account_id)}]"}
            )
            self.request("PATCH", path, {"schemas": [PATCH_SCHEMA], "Operations": [operation]})
        if (account_id in read_members()) != present:
            raise IntegrationFailure("write_not_confirmed", retryable=True)
        return {"remote_account_id": account_id, "remote_group_id": group_id, "member": present}
