"""Pinned HTTPS and strict ID-token validation. No redirects or token-controlled key URLs."""

import base64
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.parse import unquote, urlencode, urlsplit

import jwt
from django.conf import settings
from django.utils.crypto import constant_time_compare


class OIDCFailure(ValueError):
    pass


def endpoint(url):
    if not isinstance(url, str):
        raise OIDCFailure("destination_not_authorized")
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").encode("idna").decode().lower()
        port = parsed.port if parsed.port is not None else 443
        key = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or "\\" in url
            or any(ord(c) < 32 for c in url)
            or any(part in (".", "..") for part in unquote(parsed.path).split("/"))
            or key not in settings.OIDC_ALLOWED_HOSTS
            or not 1 <= port <= 65535
            or len(url) > 2048
        ):
            raise ValueError
        return host, port, parsed.path or "/"
    except (ValueError, UnicodeError, AttributeError):
        raise OIDCFailure("destination_not_authorized") from None


def address(host, port):
    try:
        addresses = {
            entry[4][0] for entry in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        }
        networks = [ipaddress.ip_network(value) for value in settings.OIDC_ALLOWED_NETWORKS]
        if not addresses or len(addresses) > 16:
            raise ValueError
        for item in addresses:
            value = ipaddress.ip_address(item)
            if (
                value.is_link_local
                or value.is_multicast
                or value.is_unspecified
                or getattr(value, "ipv4_mapped", None)
                or str(value) in {"fd00:ec2::254", "100.100.100.200", "168.63.129.16"}
                or (not value.is_global and not any(value in network for network in networks))
            ):
                raise ValueError
        return sorted(addresses)[0]
    except (ValueError, OSError):
        raise OIDCFailure("address_not_authorized") from None


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, selected):
        super().__init__(
            host,
            port,
            timeout=8,
            context=ssl.create_default_context(cafile=settings.OIDC_CA_BUNDLE or None),
        )
        self.selected = selected

    def connect(self):
        raw = socket.create_connection((self.selected, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def strict_json(content):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    return json.loads(
        content,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
    )


def request_json(url, *, fields=None, basic=None):
    host, port, path = endpoint(url)
    connection = None
    headers = {"Accept": "application/json"}
    body = None
    if fields is not None:
        body = urlencode(fields).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if basic is not None:
        # OAuth client credentials use form encoding before Basic encoding.
        from urllib.parse import quote_plus

        value = ":".join(quote_plus(part) for part in basic).encode()
        headers["Authorization"] = "Basic " + base64.b64encode(value).decode()
    try:
        connection = PinnedHTTPS(host, port, address(host, port))
        connection.request(
            "POST" if fields is not None else "GET", path, body=body, headers=headers
        )
        response = connection.getresponse()
        if response.status != 200:
            raise OIDCFailure("provider_response_refused")
        content = response.read(262145)
        if len(content) > 262144:
            raise OIDCFailure("provider_response_too_large")
        result = strict_json(content)
        if not isinstance(result, dict):
            raise ValueError
        return result
    except OIDCFailure:
        raise
    except (OSError, http.client.HTTPException, ValueError, UnicodeError, RecursionError):
        raise OIDCFailure("provider_unavailable_or_invalid") from None
    finally:
        if connection is not None:
            connection.close()


def discover(config):
    endpoint(config["issuer"])
    metadata = request_json(config["issuer"].rstrip("/") + "/.well-known/openid-configuration")
    if metadata.get("issuer") != config["issuer"]:
        raise OIDCFailure("issuer_mismatch")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        endpoint(metadata.get(field, ""))
    required = {
        "response_types_supported": "code",
        "id_token_signing_alg_values_supported": config["algorithm"],
        "token_endpoint_auth_methods_supported": config["auth_method"],
    }
    if "code_challenge_methods_supported" in metadata:
        required["code_challenge_methods_supported"] = "S256"
    for field, expected in required.items():
        default = (
            ["client_secret_basic"] if field == "token_endpoint_auth_methods_supported" else []
        )
        values = metadata.get(field, default)
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) for value in values)
            or expected not in values
        ):
            raise OIDCFailure("unsupported_provider_contract")
    return {
        key: metadata[key]
        for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")
    }


def validate_token(token, jwks, config, nonce):
    try:
        if not isinstance(token, str) or len(token) > 16384 or token.count(".") != 2:
            raise ValueError
        # Reject duplicate JOSE/claim keys before asking the library to decode.
        for segment in token.split(".")[:2]:
            strict_json(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        header = jwt.get_unverified_header(token)
        if (
            header.get("alg") != config["algorithm"]
            or config["algorithm"] not in {"RS256", "ES256"}
            or set(header) & {"jku", "x5u", "jwk", "x5c", "crit", "b64"}
            or header.get("typ", "JWT") != "JWT"
            or not isinstance(header.get("kid"), str)
            or not 1 <= len(header["kid"]) <= 128
        ):
            raise ValueError
        keys = jwks.get("keys")
        if not isinstance(keys, list) or not 1 <= len(keys) <= 32:
            raise ValueError
        selected = [
            key for key in keys if isinstance(key, dict) and key.get("kid") == header["kid"]
        ]
        if len(selected) != 1:
            raise ValueError
        key = selected[0]
        if config["algorithm"] == "RS256" and (
            not isinstance(key.get("n"), str)
            or not 256 <= len(key["n"]) <= 1400
            or not isinstance(key.get("e"), str)
            or not 1 <= len(key["e"]) <= 16
        ):
            raise ValueError
        if (
            key.get("use", "sig") != "sig"
            or key.get("alg", config["algorithm"]) != config["algorithm"]
            or ("key_ops" in key and key["key_ops"] != ["verify"])
            or set(key) & {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
        ):
            raise ValueError
        public = jwt.PyJWK.from_dict(key, algorithm=config["algorithm"]).key
        if config["algorithm"] == "RS256":
            if key.get("kty") != "RSA" or not 2048 <= public.key_size <= 8192:
                raise ValueError
        elif key.get("kty") != "EC" or key.get("crv") != "P-256":
            raise ValueError
        claims = jwt.decode(
            token,
            public,
            algorithms=[config["algorithm"]],
            issuer=config["issuer"],
            audience=config["client_id"],
            leeway=0,
            options={"require": ["iss", "sub", "aud", "iat", "exp", "nonce"]},
        )
        if (
            claims["iss"] != config["issuer"]
            or claims["aud"] not in (config["client_id"], [config["client_id"]])
            or claims.get("azp", config["client_id"]) != config["client_id"]
            or not isinstance(claims["nonce"], str)
            or not constant_time_compare(claims["nonce"], nonce)
            or not isinstance(claims["sub"], str)
            or not re.fullmatch(r"[\x21-\x7e]{1,255}", claims["sub"])
            or any(type(claims[field]) is not int for field in ("iat", "exp"))
            or claims["iat"] > time.time()
            or claims["exp"] <= time.time()
            or claims["exp"] <= claims["iat"]
            or ("nbf" in claims and type(claims["nbf"]) is not int)
        ):
            raise ValueError
        return claims["sub"]
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise OIDCFailure("id_token_refused") from None


def exchange(flow, code):
    if not isinstance(code, str) or not 1 <= len(code) <= 4096 or any(ord(c) < 32 for c in code):
        raise OIDCFailure("invalid_authorization_response")
    fields = dict(
        grant_type="authorization_code",
        code=code,
        redirect_uri=flow["redirect_uri"],
        code_verifier=flow["verifier"],
    )
    basic = None
    if flow["auth_method"] == "client_secret_basic":
        basic = (flow["client_id"], flow["client_secret"])
    else:
        fields.update(client_id=flow["client_id"], client_secret=flow["client_secret"])
    tokens = request_json(flow["metadata"]["token_endpoint"], fields=fields, basic=basic)
    jwks = request_json(flow["metadata"]["jwks_uri"])
    return validate_token(tokens.get("id_token"), jwks, flow, flow["nonce"])
