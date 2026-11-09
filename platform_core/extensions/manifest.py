"""Data-only public contract; validation never imports extension code."""

import keyword
import re
from dataclasses import asdict, dataclass

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

CORE_VERSION = "0.2.0a19"
API_VERSION = "3"
PERIODIC_TOPIC = "core.module_schedule.elapsed.v1"
PERIODIC_INTERVALS = frozenset({15, 60, 1440})
BUILTIN_KEYS = frozenset(
    {
        "identity",
        "access",
        "approvals",
        "connectors",
        "recertification",
        "pam",
        "governance",
        "intelligence",
    }
)
ROLES = frozenset({"admin", "operator", "reviewer", "auditor"})
BUILTIN_VERSIONS = dict.fromkeys(BUILTIN_KEYS, "0.2.0") | {"identity": "0.1.0"}
KEY = re.compile(r"[a-z][a-z0-9_]{1,39}\Z")
DOTTED = re.compile(r"[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)+\Z", re.ASCII)


class ExtensionError(ValueError):
    """A release is not admissible in this deployment."""


def fields(value, required, optional=()):
    if (
        not isinstance(value, dict)
        or set(value) - set(required) - set(optional)
        or set(required) - set(value)
    ):
        raise ExtensionError("Champs de contrat absents ou non reconnus.")


def text(value, maximum=255):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(c) < 32 for c in value)
    ):
        raise ExtensionError("Texte de manifeste invalide.")
    return value


def version(value):
    try:
        result = Version(text(value, 30))
    except InvalidVersion as error:
        raise ExtensionError("Version de module invalide.") from error
    if str(result) != value:
        raise ExtensionError("La version doit utiliser sa représentation canonique PEP 440.")
    return value


def specification(value):
    try:
        SpecifierSet(text(value, 120))
    except InvalidSpecifier as error:
        raise ExtensionError("Plage de versions invalide.") from error
    return value


@dataclass(frozen=True)
class Dependency:
    key: str
    version_spec: str


@dataclass(frozen=True)
class Permission:
    code: str
    roles: tuple[str, ...]
    sensitive: bool = False


@dataclass(frozen=True)
class Route:
    name: str
    path: str
    view: str
    permission: str
    methods: tuple[str, ...] = ("GET",)


@dataclass(frozen=True)
class EmittedEvent:
    topic: str
    permission: str


@dataclass(frozen=True)
class ConsumedEvent:
    name: str
    topic: str
    handler: str


@dataclass(frozen=True)
class PeriodicSignal:
    name: str
    handler: str
    interval_minutes: int

    @property
    def topic(self):
        return PERIODIC_TOPIC


@dataclass(frozen=True)
class ModuleManifest:
    key: str
    name: str
    version: str
    summary: str
    category: str
    core_spec: str
    api_version: str
    license_kind: str
    package: str
    django_app: str
    dependencies: tuple[Dependency, ...]
    permissions: tuple[Permission, ...]
    routes: tuple[Route, ...]
    emitted_events: tuple[EmittedEvent, ...] = ()
    consumed_events: tuple[ConsumedEvent, ...] = ()
    periodic_signals: tuple[PeriodicSignal, ...] = ()

    def to_dict(self):
        # A JSON round trip turns the immutable tuple fields into contract arrays.
        import json

        result = json.loads(json.dumps(asdict(self)))
        if self.api_version in ("1", "2"):
            result.pop("periodic_signals")
        if self.api_version == "1":
            # Retain the byte-equivalent signed V1 manifest representation.
            result.pop("emitted_events")
            result.pop("consumed_events")
        return result

    @classmethod
    def from_dict(cls, value):
        event_fields = {"emitted_events", "consumed_events"}
        optional_fields = event_fields | {"periodic_signals"}
        fields(value, set(cls.__dataclass_fields__) - optional_fields, optional_fields)
        key = text(value["key"], 40)
        if not KEY.fullmatch(key) or keyword.iskeyword(key) or key in BUILTIN_KEYS:
            raise ExtensionError("Clé d’extension réservée ou invalide.")
        root = text(value["package"], 100)
        if not re.fullmatch(r"pamolive_ext_[a-z][a-z0-9_]{1,60}", root):
            raise ExtensionError("Une extension possède son propre package pamolive_ext_*. ")
        app = text(value["django_app"], 200)
        if not DOTTED.fullmatch(app) or not app.startswith(root + ".apps."):
            raise ExtensionError("AppConfig doit appartenir au package de l’extension.")
        if value["api_version"] not in ("1", "2", API_VERSION):
            raise ExtensionError("Version d’API d’extension non prise en charge.")
        if value["api_version"] == "1" and event_fields & set(value):
            raise ExtensionError("Les événements exigent le contrat d’extension V2.")
        if value["api_version"] in ("2", "3") and event_fields - set(value):
            raise ExtensionError("Le contrat V2 ou V3 déclare explicitement ses événements.")
        if ("periodic_signals" in value) != (value["api_version"] == "3"):
            raise ExtensionError("Les signaux périodiques exigent une liste explicite en V3.")
        if value["license_kind"] != "community":
            raise ExtensionError(
                "Seules les extensions communautaires sont chargeables par ce contrat. "
                "Un entitlement ne résout pas la licence du code commercial."
            )
        core_spec = specification(value["core_spec"])
        if not SpecifierSet(core_spec).contains(CORE_VERSION, prereleases=True):
            raise ExtensionError("Cette extension est incompatible avec la version du noyau.")
        for name in ("dependencies", "permissions", "routes"):
            if not isinstance(value[name], list) or len(value[name]) > 100:
                raise ExtensionError("Liste de manifeste invalide ou trop grande.")
        dependencies = []
        for dependency in value["dependencies"]:
            fields(dependency, ("key", "version_spec"))
            target = text(dependency["key"], 40)
            if not KEY.fullmatch(target) or target == key:
                raise ExtensionError("Dépendance invalide.")
            dependencies.append(Dependency(target, specification(dependency["version_spec"])))
        permissions = []
        for permission in value["permissions"]:
            fields(permission, ("code", "roles", "sensitive"))
            code = text(permission["code"], 160)
            if not re.fullmatch(re.escape(key) + r"\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*", code):
                raise ExtensionError("Permission attendue : module.ressource.action.")
            roles = permission["roles"]
            if (
                not isinstance(roles, list)
                or not roles
                or len(set(roles)) != len(roles)
                or set(roles) - ROLES
            ):
                raise ExtensionError("Rôles techniques de permission invalides.")
            if not isinstance(permission["sensitive"], bool):
                raise ExtensionError("Le caractère sensible est un booléen explicite.")
            permissions.append(Permission(code, tuple(roles), permission["sensitive"]))
        by_permission = {permission.code: permission for permission in permissions}
        emitted, consumed = [], []
        for name in event_fields:
            if not isinstance(value.get(name, []), list) or len(value.get(name, [])) > 32:
                raise ExtensionError("Liste d’événements invalide ou trop grande.")
        topic_pattern = r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.v[1-9][0-9]{0,3}"
        for item in value.get("emitted_events", []):
            fields(item, ("topic", "permission"))
            topic = text(item["topic"], 120)
            permission = by_permission.get(item["permission"])
            if (
                not re.fullmatch(topic_pattern, topic)
                or not topic.startswith(key + ".")
                or not permission
                or not permission.sensitive
            ):
                raise ExtensionError("Publication hors module ou permission sensible absente.")
            emitted.append(EmittedEvent(topic, permission.code))
        for item in value.get("consumed_events", []):
            fields(item, ("name", "topic", "handler"))
            name, topic, handler = (
                text(item["name"], 60),
                text(item["topic"], 120),
                text(item["handler"], 200),
            )
            if (
                not re.fullmatch(r"[a-z][a-z0-9_]*_v[1-9][0-9]{0,3}", name)
                or not re.fullmatch(topic_pattern, topic)
                or topic == PERIODIC_TOPIC
                or not DOTTED.fullmatch(handler)
                or not handler.startswith(root + ".")
            ):
                raise ExtensionError("Consommateur versionné ou chemin de gestionnaire invalide.")
            consumed.append(ConsumedEvent(name, topic, handler))
        declared = value.get("periodic_signals", [])
        if not isinstance(declared, list) or len(declared) > 4:
            raise ExtensionError("Un module peut déclarer jusqu’à quatre signaux périodiques.")
        periodic = []
        for item in declared:
            fields(item, ("name", "handler", "interval_minutes"))
            name = text(item["name"], 60)
            handler = text(item["handler"], 200)
            interval = item["interval_minutes"]
            if (
                not re.fullmatch(r"[a-z][a-z0-9_]*_v[1-9][0-9]{0,3}", name)
                or not DOTTED.fullmatch(handler)
                or not handler.startswith(root + ".")
                or type(interval) is not int
                or interval not in PERIODIC_INTERVALS
            ):
                raise ExtensionError("Nom, gestionnaire ou période du signal invalide.")
            periodic.append(PeriodicSignal(name, handler, interval))
        if len({item.topic for item in emitted}) != len(emitted) or len(
            {item.name for item in (*consumed, *periodic)}
        ) != len(consumed) + len(periodic):
            raise ExtensionError("Déclaration d’événement dupliquée.")
        routes = []
        for route in value["routes"]:
            fields(route, ("name", "path", "view", "permission", "methods"))
            name = text(route["name"], 60)
            if not re.fullmatch(r"[a-z][a-z0-9_-]*", name):
                raise ExtensionError("Nom de route invalide.")
            path = route["path"]
            if not isinstance(path, str) or len(path) > 200 or ".." in path or path.startswith("/"):
                raise ExtensionError("Chemin de route invalide.")
            # Only Django path converters, never a raw regex or catch-all path converter.
            plain = re.sub(r"<(?:uuid|int|slug|str):[a-z][a-z0-9_]*>", "x", path)
            if not re.fullmatch(r"[a-zA-Z0-9_/-]*", plain):
                raise ExtensionError("Chemin de route hors du contrat HTTP V1.")
            view = text(route["view"], 200)
            if not DOTTED.fullmatch(view) or not view.startswith(root + "."):
                raise ExtensionError("La vue doit appartenir au package de l’extension.")
            permission = by_permission.get(route["permission"])
            methods = route["methods"]
            if (
                not permission
                or not isinstance(methods, list)
                or not methods
                or len(set(methods)) != len(methods)
                or set(methods) - {"GET", "POST"}
            ):
                raise ExtensionError("Permission ou méthodes de route invalides.")
            if "POST" in methods and not permission.sensitive:
                raise ExtensionError("Une route d’écriture exige une permission sensible.")
            routes.append(Route(name, path, view, permission.code, tuple(methods)))
        if (
            not permissions
            or not routes
            or not any(route.path == "" and "GET" in route.methods for route in routes)
        ):
            raise ExtensionError("Une extension HTTP exige des permissions et une page d’accueil.")
        for items in (
            [dependency.key for dependency in dependencies],
            [p.code for p in permissions],
            [route.name for route in routes],
            [route.path for route in routes],
        ):
            if len(items) != len(set(items)):
                raise ExtensionError("Déclaration de manifeste dupliquée.")
        return cls(
            key,
            text(value["name"], 120),
            version(value["version"]),
            text(value["summary"], 500),
            text(value["category"], 80),
            core_spec,
            value["api_version"],
            "community",
            root,
            app,
            tuple(dependencies),
            tuple(permissions),
            tuple(routes),
            tuple(emitted),
            tuple(consumed),
            tuple(periodic),
        )
