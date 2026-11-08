from django.apps import AppConfig, apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from packaging.specifiers import SpecifierSet

from platform_core.registry import ModuleDefinition, all_modules, register_module

from .manifest import ModuleManifest


class ExtensionRegistryConfig(AppConfig):
    name = "platform_core.extensions"
    label = "pamolive_extension_registry"
    verbose_name = "PAM-olive Extension API"

    def ready(self):
        releases = settings.PAMOLIVE_EXTENSIONS
        # File inventories and signatures were checked in settings, before Django imports apps.
        for release in releases:
            manifest = release.manifest
            app = apps.get_app_config(manifest.key)
            if (
                app.name != manifest.package
                or app.__class__.__module__ != manifest.package + ".apps"
            ):
                raise ImproperlyConfigured(
                    "L’AppConfig d’extension ne correspond pas au manifeste."
                )
            exposed = release.entry_point.load()
            if not isinstance(exposed, ModuleManifest) or exposed != manifest:
                raise ImproperlyConfigured("Le point d’entrée diffère du manifeste signé.")
            home = next(
                route for route in manifest.routes if route.path == "" and "GET" in route.methods
            )
            register_module(
                ModuleDefinition(
                    key=manifest.key,
                    name=manifest.name,
                    version=manifest.version,
                    summary=manifest.summary,
                    category=manifest.category,
                    dependencies=tuple(item.key for item in manifest.dependencies),
                    permissions=tuple(item.code for item in manifest.permissions),
                    url_name=f"ext-{manifest.key}:{home.name}",
                    metadata={
                        "extension_release": release.release_hash,
                        "manifest_hash": release.manifest_hash,
                        "distribution": release.distribution,
                    },
                )
            )
        definitions = {definition.key: definition for definition in all_modules()}
        for release in releases:
            for dependency in release.manifest.dependencies:
                definition = definitions.get(dependency.key)
                if not definition or not SpecifierSet(dependency.version_spec).contains(
                    definition.version, prereleases=True
                ):
                    raise ImproperlyConfigured("Dépendance d’extension absente ou incompatible.")
