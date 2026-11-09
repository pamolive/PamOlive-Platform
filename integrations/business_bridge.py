"""Read one dossier from a JSON API and optionally publish its evidence to PAM-olive."""

import argparse
import http.client
import ipaddress
import json
import os
import re
import ssl
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import UUID

FORMAT = "pamolive.business-record/1"
KINDS = {"ticket", "incident", "change", "maintenance", "project", "emergency", "other"}
STATES = {"unknown", "open", "approved", "closed", "cancelled"}
LIMITS = {"external_id": 180, "reference": 180, "title": 240, "url": 500}
REQUIRED = {"external_id", "reference", "source_updated_at", "state"}
AUTH_HEADERS = {"authorization", "app-token", "session-token", "private-token", "x-api-key"}
LOCAL = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


class BridgeError(Exception):
    pass


class TransportError(BridgeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _reject_constant(value):
    raise ValueError("Nonfinite JSON number")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def decode(raw):
    try:
        result = json.loads(raw, object_pairs_hook=_unique, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise BridgeError("Réponse ou configuration JSON invalide.") from exc
    if type(result) is not dict:
        raise BridgeError("Un objet JSON est requis.")
    return result


def _url(value, *, local_http=False, origin_only=False):
    if type(value) is not str or not value or any(ord(ch) <= 32 or ch == "\\" for ch in value):
        raise BridgeError("Adresse HTTP invalide.")
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as exc:
        raise BridgeError("Adresse HTTP invalide.") from exc
    if not url.hostname or url.username is not None or url.password is not None or url.fragment:
        raise BridgeError("L’adresse doit exclure identifiants et fragment.")
    if port == 0 or (origin_only and (url.path not in ("", "/") or url.query)):
        raise BridgeError("L’adresse PAM-olive doit être une origine, sans chemin ni requête.")
    if url.scheme != "https":
        if not local_http or url.scheme != "http":
            raise BridgeError("HTTPS est requis.")
        try:
            ip = ipaddress.ip_address(url.hostname)
        except ValueError as exc:
            raise BridgeError("HTTP local exige une adresse IP littérale de confiance.") from exc
        if not (ip.is_loopback or any(ip in network for network in LOCAL)):
            raise BridgeError("HTTP local est réservé aux IP privées ou de bouclage.")
    return url


def _secret(env_key, environ):
    if type(env_key) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", env_key):
        raise BridgeError("Nom de variable d’authentification invalide.")
    value = environ.get(env_key, "")
    if not value or len(value) > 4096 or not value.isascii() or any(ord(ch) < 32 for ch in value):
        raise BridgeError("Variable d’authentification absente ou invalide.")
    return value


def _pointer(data, pointer):
    if type(pointer) is not str or not pointer.startswith("/") or len(pointer) > 512:
        raise BridgeError("Chaque champ source doit être un pointeur JSON non vide.")
    for raw in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise BridgeError("Échappement de pointeur JSON invalide.")
        key = raw.replace("~1", "/").replace("~0", "~")
        if type(data) is dict and key in data:
            data = data[key]
        elif (
            type(data) is list and re.fullmatch(r"0|[1-9][0-9]{0,5}", key) and int(key) < len(data)
        ):
            data = data[int(key)]
        else:
            raise BridgeError("Un champ requis est absent de la réponse du fournisseur.")
    return data


def _time(value):
    try:
        date = datetime.fromisoformat(value)
        if date.utcoffset() is not None:
            return date.astimezone(UTC)
    except (TypeError, ValueError, OverflowError):
        pass
    raise BridgeError("Une date source invalide ou sans fuseau a été reçue.")


def _stamp(date):
    return date.isoformat(timespec="microseconds")


def normalize(document, source, record_id, observed):
    fields, states, kind = source.get("fields"), source.get("states"), source.get("kind")
    if (
        type(fields) is not dict
        or not REQUIRED <= fields.keys() <= REQUIRED | {"title", "url"}
        or type(states) is not dict
        or any(type(state) is not str or state not in STATES for state in states.values())
        or type(kind) is not str
        or kind not in KINDS
    ):
        raise BridgeError("Correspondance des champs, type ou états source invalide.")
    data = {name: _pointer(document, path) for name, path in fields.items()}
    raw_state = data.pop("state")
    if type(raw_state) not in (str, int):
        raise BridgeError("L’état du fournisseur doit être un libellé ou un entier.")
    state = states.get(str(raw_state), "unknown")
    modified = _time(data.pop("source_updated_at"))
    if modified > observed:
        raise BridgeError(
            "La modification source est postérieure à la lecture. Vérifier les horloges."
        )
    for name, maximum in LIMITS.items():
        value = data.get(name, "")
        if name in ("external_id", "reference") and type(value) is int:
            value = str(value)
        if type(value) is not str or len(value) > maximum or any(ord(ch) < 32 for ch in value):
            raise BridgeError(f"Valeur source invalide pour {name}.")
        data[name] = value.strip()
    if data["external_id"] != record_id or not data["reference"]:
        raise BridgeError(
            "L’identifiant immuable de la réponse ne correspond pas au dossier demandé."
        )
    if data["url"]:
        _url(data["url"])
    return dict(
        data,
        schema=FORMAT,
        kind=kind,
        state=state,
        source_updated_at=_stamp(modified),
        observed_at=_stamp(observed),
    )


class Client:
    def __init__(self, ca_file=None):
        self.opener = build_opener(
            ProxyHandler({}),
            NoRedirect(),
            HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)),
        )

    def request(self, url, headers, payload=None):
        values = {"Accept": "application/json", **headers}
        body = None
        if payload is not None:
            values["Content-Type"] = "application/json"
            body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()
        try:
            request = Request(url, data=body, headers=values)
            with self.opener.open(request, timeout=10) as response:
                content_type = response.headers.get_content_type()
                if content_type != "application/json" and not content_type.endswith("+json"):
                    raise BridgeError("Le serveur n’a pas renvoyé de JSON.")
                raw = response.read(1048577)
                if len(raw) > 1048576:
                    raise BridgeError("Réponse JSON supérieure à 1 Mio.")
                return response.status, decode(raw)
        except HTTPError as exc:
            with exc:
                return exc.code, None
        except (URLError, OSError, http.client.HTTPException) as exc:
            raise TransportError("Connexion interrompue ou certificat refusé.") from exc


def _identity(meta, target):
    try:
        if (
            meta["schema"] != "pamolive.business-source/1"
            or any(
                str(UUID(target[key])) != str(UUID(meta[key]))
                for key in ("organization_id", "source_id")
            )
            or type(meta["source_revision"]) is not int
            or meta["source_revision"] < 1
        ):
            raise ValueError
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise BridgeError(
            "Le jeton ne correspond pas à l’organisation et à la source attendues."
        ) from exc


def _status(code, phase):
    if code == 429:
        raise BridgeError(
            "Limite d’appels atteinte. Attendre au moins une minute avant de reprendre."
        )
    if 300 <= code < 400:
        raise BridgeError("Redirection HTTP refusée ; configurer l’adresse finale.")
    raise BridgeError(f"{phase} : réponse HTTP {code}. Aucun corps de réponse n’est affiché.")


def _receipt(data, meta, record_id):
    try:
        payload = data["payload"]
        if (
            data["source_id"] != meta["source_id"]
            or data["proof_verified"] is not True
            or type(data["source_revision"]) is not int
            or data["source_revision"] < 1
            or type(data["current_source_assertion"]) is not bool
            or data["local_access_approval"] is not False
            or data["local_authorizations_modified"] is not False
            or payload["external_id"] != record_id
            or payload["schema"] != FORMAT
            or type(payload["sequence"]) is not int
            or not 1 <= payload["sequence"] <= 2147483647
        ):
            raise ValueError
        UUID(data["receipt_id"])
        _time(payload["source_updated_at"])
        _time(payload["observed_at"])
        return payload
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise BridgeError(
            "Le reçu PAM-olive ne correspond pas à cette source et à ce dossier."
        ) from exc


def publish(client, origin, headers, meta, payload):
    endpoint = origin + "/api/v1/business-records/"
    query = endpoint + "?" + urlencode({"external_id": payload["external_id"]})
    for attempt in range(2):
        status, current = client.request(query, headers)
        last = 0
        if status == 200:
            previous = _receipt(current, meta, payload["external_id"])
            last = previous["sequence"]
            if current["source_revision"] > meta["source_revision"]:
                raise BridgeError(
                    "La révision de la source a changé ; vérifier le jeton et reprendre."
                )
            if current["source_revision"] == meta["source_revision"] and previous == dict(
                payload, sequence=last
            ):
                return current
            if _time(previous["source_updated_at"]) > _time(payload["source_updated_at"]) or _time(
                previous["observed_at"]
            ) >= _time(payload["observed_at"]):
                raise BridgeError("Une lecture concurrente est aussi récente ou plus récente.")
        elif status != 404:
            _status(status, "Lecture PAM-olive")
        if last == 2147483647:
            raise BridgeError("La source a atteint la limite de séquence de ce dossier.")
        request = dict(payload, sequence=last + 1)
        try:
            status, receipt = client.request(endpoint, headers, request)
        except TransportError:
            # Repeat the exact same sequence and timestamps once: if the first
            # call committed, the server replays its original signed receipt.
            status, receipt = client.request(endpoint, headers, request)
        if status == 409 and not attempt:
            continue
        if status == 409:
            raise BridgeError("Conflit de séquence persistant. Relire le dossier et recommencer.")
        if status not in (200, 201):
            _status(status, "Publication PAM-olive")
        if (
            _receipt(receipt, meta, payload["external_id"]) != request
            or receipt["source_revision"] != meta["source_revision"]
        ):
            raise BridgeError(
                "Le contenu ou la révision du reçu ne correspond pas à la publication."
            )
        return receipt
    raise BridgeError("Conflit de séquence. Relire le dossier et recommencer.")


def run(config, record_id, *, write, local_http, environ, source_client, platform_client, now):
    if (
        config.keys() != {"source", "pamolive"}
        or type(config["source"]) is not dict
        or type(config["pamolive"]) is not dict
    ):
        raise BridgeError("La configuration doit contenir les sections source et pamolive.")
    source, target = config["source"], config["pamolive"]
    if (
        source.keys() != {"url", "headers_env", "fields", "states", "kind"}
        or target.keys() != {"url", "token_env", "organization_id", "source_id"}
        or type(source["headers_env"]) is not dict
    ):
        raise BridgeError("Paramètres de connexion non reconnus ou incomplets.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,179}", record_id):
        raise BridgeError("L’identifiant doit être un segment d’URL non vide.")
    template = source["url"]
    if type(template) is not str or template.count("{id}") != 1:
        raise BridgeError("L’URL du fournisseur doit contenir exactement un segment {id}.")
    template_url = _url(template)
    if "{id}" not in template_url.path.split("/"):
        raise BridgeError("Le paramètre {id} doit être un segment du chemin source.")
    source_url = template.replace("{id}", quote(record_id, safe=""))
    _url(source_url)
    origin = _url(target["url"], local_http=local_http, origin_only=True).geturl().rstrip("/")
    source_headers = {}
    for name, env_key in source["headers_env"].items():
        name = name.lower()
        if name not in AUTH_HEADERS or name in source_headers or env_key == target["token_env"]:
            raise BridgeError("En-tête source invalide, répété ou partagé avec le jeton PAM-olive.")
        source_headers[name] = _secret(env_key, environ)
    if write:
        token = _secret(target["token_env"], environ)
        if any(token == value or value.endswith(" " + token) for value in source_headers.values()):
            raise BridgeError(
                "Les identifiants du fournisseur et de PAM-olive doivent être distincts."
            )
        headers = {"Authorization": "Bearer " + token}
        status, meta = platform_client.request(origin + "/api/v1/business-source/", headers)
        if status != 200:
            _status(status, "Vérification du jeton PAM-olive")
        _identity(meta, target)
    status, document = source_client.request(source_url, source_headers)
    if status != 200:
        _status(status, "Lecture du fournisseur")
    payload = normalize(document, source, record_id, now())
    if not write:
        return {
            "mode": "preview",
            "kind": payload["kind"],
            "state": payload["state"],
            "written": False,
        }
    result = publish(platform_client, origin, headers, meta, payload)
    return {
        "mode": "publish",
        "receipt_id": result["receipt_id"],
        "sequence": result["payload"]["sequence"],
        "current_source_assertion": result["current_source_assertion"],
        "local_access_approval": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configuration", type=Path)
    parser.add_argument("external_id")
    parser.add_argument(
        "--publish", action="store_true", help="écrit dans PAM-olive après contrôle"
    )
    parser.add_argument(
        "--allow-http-local", action="store_true", help="IP locale PAM-olive uniquement"
    )
    parser.add_argument("--source-ca-file", type=Path)
    parser.add_argument("--platform-ca-file", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.configuration.open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise BridgeError("Configuration supérieure à 64 Kio.")
        result = run(
            decode(raw),
            args.external_id,
            write=args.publish,
            local_http=args.allow_http_local,
            environ=os.environ,
            source_client=Client(args.source_ca_file),
            platform_client=Client(args.platform_ca_file),
            now=lambda: datetime.now(UTC),
        )
    except (BridgeError, OSError) as exc:
        # Files, URLs, response bodies and underlying transport errors are not logged.
        print(
            str(exc) if isinstance(exc, BridgeError) else "Configuration ou certificat illisible.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
