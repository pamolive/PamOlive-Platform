"""Obtain and submit a scoped PamOlive proof; signing stays in the holder's tool."""

import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, build_opener
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from .business_bridge import BridgeError, Client, NoRedirect, decode

SCHEMA = "pamolive.certificate-possession/1"
PREFIX = b"PamOlive certificate possession v1\n"
TOKEN_ENV = "PAMOLIVE_CERTIFICATE_SOURCE_TOKEN"
IDS = {"organization_id", "source_id", "event_id", "credential_id"}
HEX = re.compile(r"[a-f0-9]{64}\Z")


class DirectTLS(Client):
    def __init__(self, ca_file=None):
        # Explicit client context avoids honoring SSLKEYLOGFILE for this token.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if ca_file:
            context.load_verify_locations(cafile=ca_file)
        else:
            context.load_default_certs()
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))


def _file(path, limit):
    if not path.is_file():
        raise BridgeError("Un fichier régulier est requis.")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if not 0 < len(data) <= limit:
        raise BridgeError("Fichier vide ou trop volumineux.")
    return data


def target(data):
    try:
        if not isinstance(data, dict) or set(data) != IDS | {"origin"}:
            raise ValueError
        raw = data["origin"]
        if not raw.isascii() or any(ord(ch) <= 32 or ch in "\\%?#" for ch in raw):
            raise ValueError
        url = urlsplit(raw)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.path not in ("", "/")
            or url.port == 0
        ):
            raise ValueError
        return {
            "origin": f"https://{url.netloc.lower()}",
            **{key: str(UUID(data[key])) for key in IDS},
        }
    except (AttributeError, TypeError, ValueError) as error:
        raise BridgeError("Origine HTTPS ou identifiants de périmètre invalides.") from error


def public_certificate(path):
    der = _file(path, 8192)
    try:
        cert = x509.load_der_x509_certificate(der)
        if cert.public_bytes(serialization.Encoding.DER) != der:
            raise ValueError
    except (ValueError, UnsupportedAlgorithm, x509.InvalidVersion) as error:
        raise BridgeError("Fournir uniquement un certificat public X.509 en DER.") from error
    return der, cert


def _encoded(data):
    return base64.b64encode(data).decode("ascii")


def validate_challenge(response, scope, der, *, now):
    try:
        token = response["challenge"]
        message_encoded = response["message_b64"]
        if (
            set(response)
            != {"schema", "challenge", "message_b64", "certificate_sha256", "expires_in_seconds"}
            or response["schema"] != SCHEMA
            or response["expires_in_seconds"] != 120
            or not re.fullmatch(
                r"[A-Za-z0-9_-]{1,1700}:[A-Za-z0-9_-]{1,25}:[A-Za-z0-9_-]{1,100}", token
            )
            or not 0 < len(message_encoded) <= 2048
        ):
            raise ValueError
        message = base64.b64decode(message_encoded, validate=True)
        if not message.startswith(PREFIX) or _encoded(message) != message_encoded:
            raise ValueError
        payload = decode(message[len(PREFIX) :])
        expected = {key: scope[key] for key in IDS}
        expected["schema"] = SCHEMA
        expected["certificate_sha256"] = hashlib.sha256(der).hexdigest()
        unsigned_token = token.split(":", 1)[0]
        decoded_token = decode(
            base64.urlsafe_b64decode(unsigned_token + "=" * (-len(unsigned_token) % 4))
        )
        if (
            response["certificate_sha256"] != expected["certificate_sha256"]
            or set(payload) != set(expected) | {"issued_at", "nonce", "event_sha256"}
            or any(payload[key] != value for key, value in expected.items())
            or type(payload["issued_at"]) is not int
            or not -5 <= now - payload["issued_at"] < 120
            or not HEX.fullmatch(payload["nonce"])
            or not HEX.fullmatch(payload["event_sha256"])
            or payload != decoded_token
            or message
            != PREFIX
            + json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "ascii"
            )
        ):
            raise ValueError
        return message
    except (KeyError, TypeError, ValueError, BridgeError) as error:
        raise BridgeError("Défi expiré, incohérent ou hors du périmètre attendu.") from error


def _verify_detached(cert, signed, message):
    try:
        key = cert.public_key()
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signed, message)
            return "Ed25519"
        if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
            key.verify(signed, message, ec.ECDSA(hashes.SHA256()))
            return "ECDSA-P256-SHA256"
        if isinstance(key, rsa.RSAPublicKey) and 2048 <= key.key_size <= 4096:
            key.verify(
                signed,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
            return "RSA-PSS-SHA256"
    except (InvalidSignature, UnsupportedAlgorithm, ValueError) as error:
        raise BridgeError("Signature détachée invalide ; aucun fichier envoyé.") from error
    raise BridgeError("Algorithme de clé non pris en charge.")


def _endpoint(scope, name):
    return f"{scope['origin']}/api/v1/events/{scope['event_id']}/certificate-{name}/"


def _token(environ):
    value = environ.get(TOKEN_ENV, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{64}", value):
        raise BridgeError(f"Fournir le jeton de source dans {TOKEN_ENV}.")
    return {"Authorization": "Bearer " + value}


def _post(client, url, payload, environ, expected_status):
    status, data = client.request(url, _token(environ), payload)
    if status == 409:
        raise BridgeError("Une preuve existe déjà ; consulter l’événement avant de réessayer.")
    if 300 <= status < 400:
        raise BridgeError("Redirection refusée ; utiliser l’origine HTTPS finale.")
    if status != expected_status or not isinstance(data, dict):
        raise BridgeError(f"Réponse HTTP {status} inattendue. Aucun corps n’est affiché.")
    return data


def _write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def fetch(client, scope, certificate, bundle, *, environ, clock=time.time):
    if os.path.lexists(bundle):
        raise BridgeError("Le répertoire de défi existe déjà.")
    der, _ = public_certificate(certificate)
    response = _post(client, _endpoint(scope, "challenge"), {}, environ, 200)
    message = validate_challenge(response, scope, der, now=clock())
    bundle.mkdir(mode=0o700)
    _write(
        bundle / "challenge.json",
        json.dumps({"origin": scope["origin"], "response": response}).encode(),
    )
    _write(bundle / "message.bin", message)


def submit(client, scope, certificate, bundle, signature, *, environ, clock=time.time):
    der, cert = public_certificate(certificate)
    document = decode(_file(bundle / "challenge.json", 8192))
    if set(document) != {"origin", "response"} or document["origin"] != scope["origin"]:
        raise BridgeError("Le défi appartient à une autre origine HTTPS.")
    response = document["response"]
    message = validate_challenge(response, scope, der, now=clock())
    if message != _file(bundle / "message.bin", 2048):
        raise BridgeError("Les octets destinés au signataire ont été modifiés.")
    signed = _file(signature, 512)
    algorithm = _verify_detached(cert, signed, message)
    receipt = _post(
        client,
        _endpoint(scope, "proof"),
        {
            "challenge": response["challenge"],
            "certificate": _encoded(der),
            "signature": _encoded(signed),
        },
        environ,
        201,
    )
    if (
        receipt.get("status") != "verified"
        or receipt.get("algorithm") != algorithm
        or receipt.get("certificate_sha256") != hashlib.sha256(der).hexdigest()
        or receipt.get("historical_access_verified") is not False
        or receipt.get("authorization_inferred") is not False
        or not re.fullmatch(r"[1-9][0-9]{0,18}", str(receipt.get("proof_id", "")))
    ):
        raise BridgeError("Reçu incohérent ; consulter l’événement avant toute nouvelle tentative.")
    return {"status": "verified", "proof_id": str(receipt["proof_id"]), "algorithm": algorithm}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("fetch", "submit"))
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--ca-file", type=Path)
    options = parser.parse_args(argv)
    if (options.mode == "submit") != (options.signature is not None):
        parser.error("--signature is required only for submit")
    try:
        scope = target(decode(_file(options.target, 8192)))
        client = DirectTLS(options.ca_file)
        args = (client, scope, options.certificate, options.bundle)
        if options.mode == "fetch":
            fetch(*args, environ=os.environ)
            print("Défi reçu : faire signer message.bin par le détenteur de la clé.")
        else:
            print(json.dumps(submit(*args, options.signature, environ=os.environ), sort_keys=True))
    except BridgeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except OSError:
        print("Fichier local ou configuration TLS inaccessible.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
