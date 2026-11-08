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
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate SCIM JSON key")
        result[key] = value
    return result


def _invalid_number(value):
    raise ValueError("Non-finite SCIM number")


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
        if method not in {"GET", "POST", "PATCH"}:
            raise IntegrationFailure("invalid_scim_method")
        address = resolve_destination(self.hostname, self.port)
        context = ssl.create_default_context(cafile=settings.CONNECTOR_CA_BUNDLE or None)
        connection = PinnedHTTPSConnection(self.hostname, self.port, address, context)
        body = json.dumps(payload).encode() if payload is not None else None
        try:
            if method in {"POST", "PATCH"}:
                # DNS and TLS may block. Revalidate only after that work, before
                # any HTTP credentials/body are sent on this pinned connection.
                connection.connect()
                self.before_write()
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
            result = json.loads(
                content, object_pairs_hook=_strict_object, parse_constant=_invalid_number
            )
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

    def find_user(self, attribute, value):
        """An exact, complete lookup; never adopt an unfiltered or partial list."""
        if attribute not in {"userName", "externalId"} or not isinstance(value, str):
            raise IntegrationFailure("invalid_scim_lookup")
        if not value or len(value) > 180 or any(ord(c) < 33 for c in value):
            raise IntegrationFailure("invalid_scim_lookup")
        expression = attribute + " eq " + json.dumps(value, ensure_ascii=False)
        result = self.request("GET", "/Users?filter=" + quote(expression, safe="") + "&count=2")
        items, total = result.get("Resources"), result.get("totalResults")
        if (
            not isinstance(items, list)
            or type(total) is not int
            or total < 0
            or total > 1
            or len(items) != total
            or (items and (not isinstance(items[0], dict) or items[0].get(attribute) != value))
        ):
            raise IntegrationFailure("scim_lookup_not_unique_or_complete")
        return items[0] if items else None

    def creation_capabilities(self):
        configuration = self.request("GET", "/ServiceProviderConfig")
        if not isinstance(configuration.get("filter"), dict) or (
            configuration["filter"].get("supported") is not True
        ):
            raise IntegrationFailure("scim_filter_not_supported")
        if not isinstance(configuration.get("patch"), dict) or (
            configuration["patch"].get("supported") is not True
        ):
            raise IntegrationFailure("scim_patch_not_supported")

    def read_created_user(self, username, external_identifier, *, active=False):
        found = self.find_user("externalId", external_identifier)
        named = self.find_user("userName", username)
        if found is None and named is None:
            return None
        if not found or not named or found.get("id") != named.get("id"):
            raise IntegrationFailure("scim_creation_identity_conflict")
        identifier = found.get("id")
        if not isinstance(identifier, str):
            raise IntegrationFailure("invalid_scim_user")
        user = self.request("GET", "/Users/" + remote_id(identifier))
        if (
            user.get("id") != identifier
            or user.get("userName") != username
            or user.get("externalId") != external_identifier
            or user.get("active") is not active
        ):
            raise IntegrationFailure("scim_creation_readback_mismatch")
        return dict(
            remote_id=identifier, username=username, external_id=external_identifier, active=active
        )

    def create_inactive_user(self, username, external_identifier):
        """The caller durably reserves its sole POST in before_write()."""
        self.creation_capabilities()
        if self.find_user("userName", username) or self.find_user(
            "externalId", external_identifier
        ):
            raise IntegrationFailure("scim_creation_preexisting_user")
        result = self.request(
            "POST",
            "/Users",
            {
                "schemas": [USER_SCHEMA],
                "userName": username,
                "externalId": external_identifier,
                "active": False,
            },
        )
        if (
            not isinstance(result.get("id"), str)
            or result.get("userName") != username
            or result.get("externalId") != external_identifier
            or result.get("active") is not False
        ):
            raise IntegrationFailure("scim_creation_response_mismatch")
        remote_id(result["id"])
        confirmed = self.read_created_user(username, external_identifier)
        if not confirmed or confirmed["remote_id"] != result["id"]:
            raise IntegrationFailure("scim_creation_not_confirmed", retryable=True)
        return confirmed

    def activate_created_user(self, identifier, username, external_identifier, group_id):
        group = self.request("GET", "/Groups/" + remote_id(group_id) + "?attributes=id,members")
        members = group.get("members")
        if (
            group.get("id") != group_id
            or not isinstance(members, list)
            or any(
                not isinstance(item, dict) or not isinstance(item.get("value"), str)
                for item in members
            )
            or not any(item["value"] == identifier for item in members)
        ):
            raise IntegrationFailure("initial_membership_not_confirmed", retryable=True)
        path = "/Users/" + remote_id(identifier)
        user = self.request("GET", path)
        if (
            user.get("id") != identifier
            or user.get("userName") != username
            or user.get("externalId") != external_identifier
            or type(user.get("active")) is not bool
        ):
            raise IntegrationFailure("scim_creation_identity_conflict")
        if user["active"] is False:
            self.request(
                "PATCH",
                path,
                {
                    "schemas": [PATCH_SCHEMA],
                    "Operations": [{"op": "replace", "path": "active", "value": True}],
                },
            )
        confirmed = self.read_created_user(username, external_identifier, active=True)
        if not confirmed or confirmed["remote_id"] != identifier:
            raise IntegrationFailure("write_not_confirmed", retryable=True)
        return confirmed

    def disable_account(self, account_id):
        path = "/Users/" + remote_id(account_id)
        user = self.request("GET", path)
        if user.get("id") != account_id or not isinstance(user.get("active"), bool):
            raise IntegrationFailure("invalid_scim_user")
        if user["active"]:
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
            operation = (
                {"op": "add", "path": "members", "value": [{"value": account_id}]}
                if present
                else {"op": "remove", "path": f"members[value eq {json.dumps(account_id)}]"}
            )
            self.request("PATCH", path, {"schemas": [PATCH_SCHEMA], "Operations": [operation]})
        if (account_id in read_members()) != present:
            raise IntegrationFailure("write_not_confirmed", retryable=True)
        return {"remote_account_id": account_id, "remote_group_id": group_id, "member": present}
