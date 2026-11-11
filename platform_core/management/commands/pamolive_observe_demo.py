"""Populate a new synthetic-only test database; never an installation in use."""

import json
import os

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from platform_modules.access.observe_demo import create_observe_demo


class Command(BaseCommand):
    help = "Créer le démonstrateur Observe dans une base synthétique entièrement neuve."

    def add_arguments(self, parser):
        parser.add_argument("--synthetic-only", action="store_true")

    def handle(self, *args, **options):
        if not options["synthetic_only"] or os.environ.get("PAMOLIVE_SYNTHETIC_DEMO") != "1":
            raise CommandError("Exiger --synthetic-only et PAMOLIVE_SYNTHETIC_DEMO=1.")
        try:
            manifest = create_observe_demo()
        except ValidationError as error:
            raise CommandError(str(error)) from error
        self.stdout.write(json.dumps(manifest, ensure_ascii=False, indent=2))
