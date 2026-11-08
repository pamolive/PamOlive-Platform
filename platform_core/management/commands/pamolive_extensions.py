"""Deployment authority is local infrastructure access, not a browser permission."""

from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError, no_translations
from django.db import connection, transaction
from django.db.migrations.autodetector import MigrationAutodetector
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.state import ProjectState
from django.utils import timezone

from platform_core.audit import record
from platform_core.models import ExtensionDeployment


class Command(BaseCommand):
    help = "Vérifie les extensions signées ou atteste leur livraison après migrations."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=("verify", "deliver"))
        parser.add_argument("--actor")

    # Like Django makemigrations: translated auth labels are not schema changes.
    @no_translations
    def handle(self, *args, **options):
        releases = settings.PAMOLIVE_EXTENSIONS
        if options["action"] == "verify":
            for release in releases:
                self.stdout.write(
                    f"{release.manifest.key} {release.manifest.version} {release.release_hash}"
                )
            self.stdout.write(f"{len(releases)} paquet(s) signé(s) vérifié(s) avant import.")
            return
        actor = (
            get_user_model()
            .objects.filter(username=options["actor"], is_active=True, is_superuser=True)
            .first()
        )
        if not actor:
            raise CommandError(
                "--actor doit désigner le compte technique d’un superadministrateur actif."
            )
        executor = MigrationExecutor(connection)
        if executor.migration_plan(executor.loader.graph.leaf_nodes()):
            raise CommandError("Des migrations sont en attente. Aucun paquet n’a été attesté.")
        for release in releases:
            config = apps.get_app_config(release.manifest.key)
            if tuple(config.get_models()) and config.label not in executor.loader.migrated_apps:
                raise CommandError("Un paquet avec modèles doit posséder ses migrations.")
        changes = MigrationAutodetector(
            executor.loader.project_state(), ProjectState.from_apps(apps)
        ).changes(graph=executor.loader.graph)
        if changes:
            detail = ", ".join(
                f"{label}:"
                + "/".join(
                    type(operation).__name__
                    for migration in migrations
                    for operation in migration.operations
                )
                for label, migrations in sorted(changes.items())
            )
            raise CommandError(
                "Les modèles et les migrations publiées divergent. Livraison refusée : " + detail
            )
        with transaction.atomic():
            for release in releases:
                delivery, _ = ExtensionDeployment.objects.update_or_create(
                    module_key=release.manifest.key,
                    defaults={
                        "version": release.manifest.version,
                        "release_hash": release.release_hash,
                        "manifest_hash": release.manifest_hash,
                        "wheel_hash": release.wheel_sha256,
                        "delivered_at": timezone.now(),
                        "delivered_by": actor,
                    },
                )
                record(
                    action="core.extension.delivered.v1",
                    summary=f"Paquet {release.manifest.key} livré après migrations",
                    actor=actor,
                    target=delivery,
                    metadata={
                        "release_hash": release.release_hash,
                        "wheel_hash": release.wheel_sha256,
                    },
                )
        self.stdout.write(
            f"{len(releases)} livraison(s) attestée(s). Aucune organisation n’a été activée."
        )
