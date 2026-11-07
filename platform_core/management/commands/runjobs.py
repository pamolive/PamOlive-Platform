import time
from concurrent.futures import ThreadPoolExecutor

from django.core.management.base import BaseCommand
from django.db import close_old_connections, connections

from platform_core.models import Organization
from platform_modules.connectors.outbound import process_changes
from platform_modules.identity.services import expire_grants
from platform_modules.pam.services import expire_leases


def deliver(organization):
    close_old_connections()
    try:
        return process_changes(organization, limit=1)
    finally:
        connections.close_all()


class Command(BaseCommand):
    help = "Traiter les expirations durables ; chaque opération est verrouillée dans PostgreSQL."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")

    def handle(self, *args, **options):
        pending = {}
        with ThreadPoolExecutor(max_workers=4) as executor:
            while True:
                close_old_connections()
                organizations = list(Organization.objects.filter(active=True))
                for organization in organizations:
                    expire_leases(organization)
                    expire_grants(organization)
                if options["once"]:
                    for organization in organizations:
                        process_changes(organization)
                    return
                for key, future in list(pending.items()):
                    if future.done():
                        future.result()
                        del pending[key]
                for organization in organizations:
                    if organization.pk not in pending and len(pending) < 4:
                        pending[organization.pk] = executor.submit(deliver, organization)
                time.sleep(5)
