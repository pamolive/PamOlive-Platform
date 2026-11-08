import json

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Count

from platform_core.events import process_events
from platform_core.models import EventDelivery, Organization
from platform_core.tenancy import organization_context


class Command(BaseCommand):
    help = "Observer ou traiter les notifications locales d’une seule organisation."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=("status", "process"))
        parser.add_argument("--organization", required=True)
        parser.add_argument("--limit", type=int, default=10)

    def handle(self, *args, **options):
        try:
            organization = Organization.objects.get(key=options["organization"])
        except Organization.DoesNotExist as error:
            raise CommandError("Organisation inconnue.") from error
        if not 1 <= options["limit"] <= 100:
            raise CommandError("La limite doit être comprise entre 1 et 100.")
        with organization_context(organization):
            processed = (
                process_events(organization, limit=options["limit"])
                if options["action"] == "process"
                else 0
            )
            states = list(EventDelivery.objects.values("status").annotate(count=Count("pk")))
        self.stdout.write(
            json.dumps(
                {
                    "organization_id": str(organization.pk),
                    "processed": processed,
                    "deliveries": states,
                },
                sort_keys=True,
            )
        )
