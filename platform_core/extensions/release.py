"""Offline release tooling. No Django setup, network download or package execution."""

import argparse
import base64
import getpass
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .manifest import ExtensionError, ModuleManifest
from .releases import DOMAIN, canonical, inspect_wheel, read_json, verify_payload, verify_wheelhouse


def write_new(path, data, mode=0o644):
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def sign_payload(payload, key, key_id):
    return {
        "key_id": key_id,
        "payload": payload,
        "signature": base64.b64encode(key.sign(DOMAIN + canonical(payload))).decode(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    generate = subparsers.add_parser("keygen")
    generate.add_argument("--private-key", required=True)
    generate.add_argument("--public-keys", required=True)
    generate.add_argument("--key-id", required=True)
    sign = subparsers.add_parser("sign")
    sign.add_argument("--wheel", required=True)
    sign.add_argument("--manifest", required=True)
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--output", required=True)
    verify = subparsers.add_parser("verify-wheel")
    verify.add_argument("--wheel", required=True)
    verify.add_argument("--release", required=True)
    verify.add_argument("--public-keys", required=True)
    catalog = subparsers.add_parser("catalog")
    catalog.add_argument("--release", action="append", required=True)
    catalog.add_argument("--public-keys", required=True)
    catalog.add_argument("--output", required=True)
    catalog.add_argument("--lock-output")
    wheelhouse = subparsers.add_parser("verify-catalog-wheels")
    wheelhouse.add_argument("--catalog", required=True)
    wheelhouse.add_argument("--wheelhouse", required=True)
    wheelhouse.add_argument("--public-keys", required=True)
    wheelhouse.add_argument("--requirements-lock", required=True)
    options = parser.parse_args()
    try:
        if options.action == "keygen":
            # Refuse overwrites before asking for the passphrase or writing either file.
            if Path(options.private_key).exists() or Path(options.public_keys).exists():
                raise ExtensionError("Les fichiers de clés existent déjà.")
            password = getpass.getpass(
                "Phrase de protection de la clé privée (12 caractères minimum) : "
            )
            confirmation = getpass.getpass("Confirmer la phrase : ")
            if len(password) < 12 or password != confirmation:
                raise ExtensionError("Phrase trop courte ou confirmation différente.")
            key = Ed25519PrivateKey.generate()
            pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password.encode()),
            )
            write_new(options.private_key, pem, 0o600)
            public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
            write_new(options.public_keys, canonical({options.key_id: public}) + b"\n")
            print("Clé privée chiffrée créée. Distribuez uniquement le fichier de clés publiques.")
        elif options.action == "sign":
            manifest = ModuleManifest.from_dict(read_json(Path(options.manifest).read_bytes()))
            payload = inspect_wheel(options.wheel, manifest)
            password = getpass.getpass("Phrase de protection de la clé privée : ")
            key = serialization.load_pem_private_key(
                Path(options.private_key).read_bytes(), password.encode()
            )
            if not isinstance(key, Ed25519PrivateKey):
                raise ExtensionError("Une clé Ed25519 est requise.")
            write_new(options.output, canonical(sign_payload(payload, key, options.key_id)) + b"\n")
            print("Livraison signée sans import ni exécution du paquet.")
        else:
            trust_keys = read_json(Path(options.public_keys).read_bytes())
            if options.action == "verify-wheel":
                envelope = read_json(Path(options.release).read_bytes())
                manifest, payload = verify_payload(envelope, trust_keys)
                if inspect_wheel(options.wheel, manifest) != payload:
                    raise ExtensionError("La wheel ne correspond pas à la livraison signée.")
                print("Signature, wheel, manifeste et inventaire vérifiés avant installation.")
            elif options.action == "verify-catalog-wheels":
                catalog = read_json(Path(options.catalog).read_bytes())
                verify_wheelhouse(
                    catalog, trust_keys, options.wheelhouse, options.requirements_lock
                )
                print(
                    "Toutes les wheels du catalogue sont signées "
                    "et correspondent à leurs inventaires."
                )
            else:
                releases = [read_json(Path(path).read_bytes()) for path in options.release]
                for envelope in releases:
                    verify_payload(envelope, trust_keys)
                write_new(
                    options.output,
                    canonical({"schema": "pamolive.extension-catalog.v1", "releases": releases})
                    + b"\n",
                )
                if options.lock_output:
                    lines = [
                        f"{item['payload']['distribution']}=={item['payload']['version']} "
                        f"--hash=sha256:{item['payload']['wheel_sha256']}"
                        for item in releases
                    ]
                    write_new(options.lock_output, ("\n".join(lines) + "\n").encode())
                print("Catalogue créé. Les clés privées ne doivent pas entrer dans l’image.")
    except (ExtensionError, OSError, ValueError) as error:
        parser.exit(2, f"Livraison refusée : {error}\n")


if __name__ == "__main__":
    main()
