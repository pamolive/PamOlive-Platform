import time
from concurrent.futures import ThreadPoolExecutor

from django.core.management.base import BaseCommand
from django.db import close_old_connections, connections

from platform_core.events import process_events
from platform_core.models import Organization
from platform_core.oidc.services import cleanup_expired
from platform_modules.connectors.outbound import process_changes
from platform_modules.connectors.teamviewer_ingestion import process_collectors
from platform_modules.connectors.teamviewer_sessions import process_sessions
from platform_modules.connectors.teamviewer_sightings import process_sightings
from platform_modules.governance.reconcile import reconcile_contracts
from platform_modules.identity.services import expire_grants
from platform_modules.pam.services import expire_leases
from platform_modules.pam.sessions import reap_connections


def deliver(organization):
    close_old_connections()
    try:
        notifications = process_events(organization, limit=1)
        changes = process_changes(organization, limit=1)
        collected = process_collectors(organization, limit=1)
        indexed = process_sightings(organization)
        return notifications + changes + collected + indexed + process_sessions(organization)
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
                cleanup_expired()
                organizations = list(Organization.objects.filter(active=True))
                for organization in Organization.objects.all():
                    reap_connections(organization)
                for organization in organizations:
                    expire_leases(organization)
                    expire_grants(organization)
                    reconcile_contracts(organization)
                if options["once"]:
                    for organization in organizations:
                        process_events(organization)
                        process_changes(organization)
                        process_collectors(organization, limit=1)
                        process_sightings(organization)
                        process_sessions(organization)
                    return
                for key, future in list(pending.items()):
                    if future.done():
                        future.result()
                        del pending[key]
                for organization in organizations:
                    if organization.pk not in pending and len(pending) < 4:
                        pending[organization.pk] = executor.submit(deliver, organization)
                time.sleep(5)
