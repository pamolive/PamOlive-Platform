"""Signed, data-only wheel inventories checked before any extension import."""

import base64
import hashlib
import importlib.machinery
import importlib.metadata
import json
import re
import stat
import sys
import zipfile
from configparser import ConfigParser
from configparser import Error as ConfigParserError
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PurePosixPath, PureWindowsPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name, parse_wheel_filename

from .manifest import BUILTIN_VERSIONS, ExtensionError, ModuleManifest, fields

SCHEMA = "pamolive.extension-release.v1"
DOMAIN = b"pamolive.extension-release.v1\x00"
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_WHEEL_BYTES = 32 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ExtensionError("Clé JSON dupliquée.")
        value[key] = item
    return value


def read_json(data):
    if len(data) > MAX_CATALOG_BYTES:
        raise ExtensionError("Catalogue d’extensions trop grand.")
    try:
        return json.loads(
            data,
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ExtensionError("Constante JSON interdite.")
            ),
        )
    except (ValueError, UnicodeError) as error:
        raise ExtensionError("Document JSON d’extension invalide.") from error


def _relative(name):
    if not isinstance(name, str):
        raise ExtensionError("Chemin de paquet invalide.")
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or path.is_absolute()
        or any(p in (".", "..") for p in path.parts)
        or str(path) != name
        or len(name) > 240
        or any(
            ":" in part or part.endswith((" ", ".")) or PureWindowsPath(part).is_reserved()
            for part in path.parts
        )
    ):
        raise ExtensionError("Chemin de paquet invalide.")
    return path


def inspect_wheel(path, manifest):
    """Inspect bytes, never execute the wheel or its entry point."""
    path = Path(path)
    if path.stat().st_size > MAX_WHEEL_BYTES:
        raise ExtensionError("Wheel trop grande pour le contrat V1.")
    try:
        name, release_version, _, tags = parse_wheel_filename(path.name)
    except ValueError as error:
        raise ExtensionError("Nom de wheel invalide.") from error
    if (
        str(release_version) != manifest.version
        or not tags
        or any(str(tag) != "py3-none-any" for tag in tags)
    ):
        raise ExtensionError(
            "Seules les wheels Python py3-none-any de la version exacte sont admises."
        )
    files = {}
    metadata_root = None
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            names = [info.filename for info in archive.infolist()]
            if (
                len(names) != len({name.rstrip("/").casefold() for name in names})
                or len(names) > 2000
            ):
                raise ExtensionError("Wheel dupliquée ou trop de fichiers.")
            for info in archive.infolist():
                relative = _relative(info.filename[:-1] if info.is_dir() else info.filename)
                total += info.file_size
                if total > MAX_WHEEL_BYTES or stat.S_ISLNK(info.external_attr >> 16):
                    raise ExtensionError("Wheel trop grande ou contenant un lien symbolique.")
                root = relative.parts[0]
                if root.endswith(".dist-info"):
                    if metadata_root and metadata_root != root:
                        raise ExtensionError("Plusieurs distributions dans la même wheel.")
                    metadata_root = root
                elif root != manifest.package:
                    raise ExtensionError("Une extension ne peut livrer que son propre package.")
                if relative.suffix.casefold() in (
                    ".pyc",
                    ".pyo",
                    ".pth",
                    ".so",
                    ".pyd",
                ) or "__pycache__" in {part.casefold() for part in relative.parts}:
                    raise ExtensionError(
                        "Hooks de démarrage, bytecode et bibliothèques natives refusés."
                    )
                if info.is_dir():
                    continue
                if relative.name != "RECORD" or root == manifest.package:
                    files[str(relative)] = digest(archive.read(info))
            needed = {
                f"{manifest.package}/__init__.py",
                f"{manifest.package}/apps.py",
                f"{manifest.package}/manifest.py",
                f"{manifest.package}/manifest.json",
                f"{metadata_root}/METADATA",
                f"{metadata_root}/WHEEL",
                f"{metadata_root}/entry_points.txt",
            }
            if not needed <= files.keys():
                raise ExtensionError("Wheel incomplète.")
            embedded = ModuleManifest.from_dict(
                read_json(archive.read(f"{manifest.package}/manifest.json"))
            )
            if embedded != manifest:
                raise ExtensionError("Le manifeste embarqué diffère du manifeste de livraison.")
            metadata = BytesParser().parsebytes(archive.read(f"{metadata_root}/METADATA"))
            if (
                canonicalize_name(metadata["Name"] or "") != str(name)
                or metadata["Version"] != manifest.version
            ):
                raise ExtensionError("Métadonnées de distribution incohérentes.")
            wheel = BytesParser().parsebytes(archive.read(f"{metadata_root}/WHEEL"))
            if wheel.get("Root-Is-Purelib", "").casefold() != "true":
                raise ExtensionError("La wheel doit être pure Python.")
            entries = ConfigParser(interpolation=None)
            entries.read_string(archive.read(f"{metadata_root}/entry_points.txt").decode())
            expected_entry = f"{manifest.package}.manifest:module"
            if entries.sections() != ["pamolive.modules"] or dict(entries["pamolive.modules"]) != {
                manifest.key: expected_entry
            }:
                raise ExtensionError("Point d’entrée PAM-olive exclusif et exact requis.")
    except (zipfile.BadZipFile, KeyError, UnicodeError, ConfigParserError) as error:
        raise ExtensionError("Contenu de wheel invalide.") from error
    return {
        "schema": SCHEMA,
        "distribution": str(name),
        "version": manifest.version,
        "wheel_name": path.name,
        "wheel_sha256": digest(path.read_bytes()),
        "entry_point": expected_entry,
        "manifest": manifest.to_dict(),
        "files": dict(sorted(files.items())),
    }


@dataclass(frozen=True)
class VerifiedRelease:
    manifest: ModuleManifest
    distribution: str
    wheel_sha256: str
    release_hash: str
    manifest_hash: str
    entry_point: object


def verify_payload(envelope, trust_keys):
    fields(envelope, ("key_id", "payload", "signature"))
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or key_id not in trust_keys:
        raise ExtensionError("Éditeur du paquet non approuvé par le déploiement.")
    try:
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(trust_keys[key_id], validate=True)
        )
        signature = base64.b64decode(envelope["signature"], validate=True)
        key.verify(signature, DOMAIN + canonical(envelope["payload"]))
    except (ValueError, TypeError, InvalidSignature) as error:
        raise ExtensionError("Signature de livraison invalide.") from error
    payload = envelope["payload"]
    fields(
        payload,
        (
            "schema",
            "distribution",
            "version",
            "wheel_name",
            "wheel_sha256",
            "entry_point",
            "manifest",
            "files",
        ),
    )
    if payload["schema"] != SCHEMA:
        raise ExtensionError("Schéma de livraison inconnu.")
    manifest = ModuleManifest.from_dict(payload["manifest"])
    if (
        payload["version"] != manifest.version
        or payload["entry_point"] != f"{manifest.package}.manifest:module"
    ):
        raise ExtensionError("Version ou point d’entrée de livraison incohérent.")
    if not isinstance(payload["distribution"], str) or not re.fullmatch(
        r"[a-z0-9]+(?:-[a-z0-9]+)*", payload["distribution"]
    ):
        raise ExtensionError("Nom de distribution invalide.")
    if not isinstance(payload["wheel_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", payload["wheel_sha256"]
    ):
        raise ExtensionError("Empreinte de wheel invalide.")
    files = payload["files"]
    if not isinstance(files, dict) or not files or len(files) > 2000:
        raise ExtensionError("Inventaire de fichiers invalide.")
    metadata_roots = set()
    for name, expected_hash in files.items():
        relative = _relative(name)
        root = relative.parts[0]
        if root != manifest.package:
            if not root.endswith(".dist-info"):
                raise ExtensionError("Fichier hors package d’extension.")
            metadata_roots.add(root)
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise ExtensionError("Empreinte de fichier invalide.")
        if relative.suffix.casefold() in (
            ".pyc",
            ".pyo",
            ".pth",
            ".so",
            ".pyd",
        ) or "__pycache__" in {part.casefold() for part in relative.parts}:
            raise ExtensionError("Fichier de démarrage ou bytecode refusé.")
    if len(metadata_roots) != 1:
        raise ExtensionError("Inventaire de métadonnées incomplet.")
    metadata_root = next(iter(metadata_roots))
    required_files = {
        f"{manifest.package}/__init__.py",
        f"{manifest.package}/apps.py",
        f"{manifest.package}/manifest.py",
        f"{manifest.package}/manifest.json",
        f"{metadata_root}/METADATA",
        f"{metadata_root}/WHEEL",
        f"{metadata_root}/entry_points.txt",
    }
    if not required_files <= files.keys():
        raise ExtensionError("Inventaire de package incomplet.")
    return manifest, payload


def verify_installed(envelope, trust_keys):
    manifest, payload = verify_payload(envelope, trust_keys)
    try:
        distribution = importlib.metadata.distribution(payload["distribution"])
    except importlib.metadata.PackageNotFoundError as error:
        raise ExtensionError("Paquet signé absent de ce déploiement.") from error
    if (
        distribution.version != manifest.version
        or canonicalize_name(distribution.metadata["Name"]) != payload["distribution"]
    ):
        raise ExtensionError("Version installée différente du paquet signé.")
    points = [entry for entry in distribution.entry_points if entry.group == "pamolive.modules"]
    if (
        len(points) != 1
        or points[0].name != manifest.key
        or points[0].value != payload["entry_point"]
    ):
        raise ExtensionError("Point d’entrée installé différent du paquet signé.")
    base = Path(distribution.locate_file("")).resolve()
    installed_bytes = 0
    for name, expected_hash in payload["files"].items():
        candidate = base.joinpath(*_relative(name).parts)
        if (
            any(parent.is_symlink() for parent in (candidate, *candidate.parents) if parent != base)
            or not candidate.is_file()
            or not candidate.resolve().is_relative_to(base)
        ):
            raise ExtensionError("Fichier signé absent, détourné ou symbolique.")
        installed_bytes += candidate.stat().st_size
        if installed_bytes > MAX_WHEEL_BYTES or digest(candidate.read_bytes()) != expected_hash:
            raise ExtensionError("Le contenu installé diffère du paquet signé.")
    root = base / manifest.package
    actual = set()
    for index, candidate in enumerate(root.rglob("*"), start=1):
        if index > 4000:
            raise ExtensionError("Arborescence installée trop grande.")
        if candidate.is_symlink():
            raise ExtensionError("Lien symbolique dans le package installé.")
        if candidate.is_file():
            actual.add(candidate.relative_to(base).as_posix())
    expected = {name for name in payload["files"] if name.startswith(manifest.package + "/")}
    if actual != expected:
        raise ExtensionError("Fichiers ajoutés ou bytecode non signé dans le package installé.")
    embedded = ModuleManifest.from_dict(read_json((root / "manifest.json").read_bytes()))
    if embedded != manifest:
        raise ExtensionError("Le manifeste installé diffère de la livraison signée avant import.")
    if manifest.package in sys.modules:
        raise ExtensionError("Le package a été importé avant sa vérification.")
    spec = importlib.machinery.PathFinder.find_spec(manifest.package)
    if (
        not spec
        or not spec.origin
        or Path(spec.origin).resolve() != (root / "__init__.py").resolve()
    ):
        raise ExtensionError("Un autre package masque l’extension signée.")
    return VerifiedRelease(
        manifest,
        payload["distribution"],
        payload["wheel_sha256"],
        digest(canonical(payload)),
        digest(canonical(payload["manifest"])),
        points[0],
    )


def load_catalog(path, trust_keys):
    if not path:
        return ()
    path = Path(path)
    if not path.is_absolute() or not path.is_file() or path.stat().st_size > MAX_CATALOG_BYTES:
        raise ExtensionError("Le catalogue doit être un fichier local absolu et borné.")
    catalog = read_json(path.read_bytes())
    fields(catalog, ("schema", "releases"))
    if (
        catalog["schema"] != "pamolive.extension-catalog.v1"
        or not isinstance(catalog["releases"], list)
        or len(catalog["releases"]) > 32
    ):
        raise ExtensionError("Catalogue de livraison invalide.")
    releases = tuple(verify_installed(item, trust_keys) for item in catalog["releases"])
    available = BUILTIN_VERSIONS | {r.manifest.key: r.manifest.version for r in releases}
    for release in releases:
        for dependency in release.manifest.dependencies:
            if dependency.key not in available or not SpecifierSet(
                dependency.version_spec
            ).contains(available[dependency.key], prereleases=True):
                raise ExtensionError("Dépendance de paquet absente ou incompatible avant import.")
    for values in (
        [r.manifest.key for r in releases],
        [r.manifest.package for r in releases],
        [r.distribution for r in releases],
    ):
        if len(values) != len(set(values)):
            raise ExtensionError("Plusieurs extensions partagent une clé ou un package.")
    # Stable dependency order, before Django imports the application packages.
    pending = {r.manifest.key: r for r in releases}
    ordered = []
    while pending:
        ready = [
            r
            for key, r in sorted(pending.items())
            if not any(d.key in pending for d in r.manifest.dependencies)
        ]
        if not ready:
            raise ExtensionError("Cycle de dépendances entre extensions.")
        for release in ready:
            ordered.append(release)
            del pending[release.manifest.key]
    return tuple(ordered)


def load_trust_keys(inline="", path=""):
    if inline and path:
        raise ExtensionError("Choisissez un fichier ou une valeur de clés publiques, pas les deux.")
    if path:
        source = Path(path)
        if (
            not source.is_absolute()
            or not source.is_file()
            or source.stat().st_size > MAX_CATALOG_BYTES
        ):
            raise ExtensionError("Fichier local de clés publiques invalide.")
        keys = read_json(source.read_bytes())
    else:
        keys = read_json((inline or "{}").encode())
    if not isinstance(keys, dict) or len(keys) > 32:
        raise ExtensionError("Répertoire de clés publiques invalide.")
    for key_id, value in keys.items():
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", key_id) or not isinstance(value, str):
            raise ExtensionError("Identifiant de clé publique invalide.")
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))
        except (ValueError, TypeError) as error:
            raise ExtensionError("Clé publique Ed25519 invalide.") from error
    return keys


def verify_wheelhouse(catalog, trust_keys, wheelhouse, requirements_lock):
    """The installer may consume exactly the signed wheels, no extra URL or pip option."""
    fields(catalog, ("schema", "releases"))
    if (
        catalog["schema"] != "pamolive.extension-catalog.v1"
        or not isinstance(catalog["releases"], list)
        or len(catalog["releases"]) > 32
    ):
        raise ExtensionError("Catalogue invalide.")
    expected_lines = []
    keys, distributions, packages = set(), set(), set()
    for envelope in catalog["releases"]:
        manifest, payload = verify_payload(envelope, trust_keys)
        if (
            manifest.key in keys
            or manifest.package in packages
            or payload["distribution"] in distributions
        ):
            raise ExtensionError("Distribution ou module dupliqué avant installation.")
        keys.add(manifest.key)
        packages.add(manifest.package)
        distributions.add(payload["distribution"])
        name = payload["wheel_name"]
        if not isinstance(name, str) or Path(name).name != name or "/" in name or "\\" in name:
            raise ExtensionError("Nom de wheel hors du répertoire de livraison.")
        wheel = Path(wheelhouse) / name
        if wheel.is_symlink() or inspect_wheel(wheel, manifest) != payload:
            raise ExtensionError("Wheel différente de la livraison signée.")
        expected_lines.append(
            f"{payload['distribution']}=={payload['version']} "
            f"--hash=sha256:{payload['wheel_sha256']}"
        )
    expected = "\n".join(expected_lines) + "\n"
    lock = Path(requirements_lock)
    if lock.stat().st_size > MAX_CATALOG_BYTES or lock.read_text(encoding="utf-8") != expected:
        raise ExtensionError(
            "Le verrou doit contenir exactement les wheels signées, "
            "sans option ni URL supplémentaire."
        )
