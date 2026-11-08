"""Connector-owned read probe; no import, activation or core dependency on TeamViewer."""

import json
import os

from django.core.management.base import BaseCommand, CommandError

from platform_modules.connectors.scim import IntegrationFailure
from platform_modules.connectors.teamviewer import TeamViewerClient, _time


class Command(BaseCommand):
    help = (
        "Sonde de lecture sans import ni activation. Jeton via PAMOLIVE_TEAMVIEWER_PROBE_TOKEN ; "
        "autoriser webapi.teamviewer.com:443 dans PAMOLIVE_CONNECTOR_HOSTS. "
        "Ne jamais passer le jeton dans les arguments."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--since", required=True, help="Fin de session à partir de cette date UTC."
        )
        parser.add_argument(
            "--until", required=True, help="Fin strictement avant cette date UTC passée."
        )
        parser.add_argument("--max-pages", type=int, default=5)

    def handle(self, *args, **options):
        try:
            client = TeamViewerClient(os.environ.get("PAMOLIVE_TEAMVIEWER_PROBE_TOKEN", ""))
            batch = client.fetch_completed(
                _time(options["since"]), _time(options["until"]), max_pages=options["max_pages"]
            )
        except IntegrationFailure as error:
            raise CommandError(error.code) from None
        self.stdout.write(
            json.dumps(
                dict(
                    records=len(batch.reports),
                    pages=batch.pages,
                    pagination_complete=batch.pagination_complete,
                    code=batch.code,
                    imported_records=0,
                    collector_activated=False,
                    coverage="API token visibility only; not organization-wide collection proof",
                )
            )
        )
        if not batch.pagination_complete:
            raise CommandError("Lecture incomplète : " + batch.code)
