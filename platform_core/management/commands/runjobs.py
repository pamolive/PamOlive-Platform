import logging
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from django.core.management.base import BaseCommand
from django.db import InterfaceError, OperationalError, close_old_connections, connections

from platform_core.events import process_events
from platform_core.models import Organization
from platform_core.oidc.services import cleanup_expired
from platform_core.periodic_signals import enqueue_periodic_signals
from platform_modules.connectors.creation import process_creations
from platform_modules.connectors.outbound import process_changes
from platform_modules.connectors.teamviewer_access import process_access_observations
from platform_modules.connectors.teamviewer_ingestion import process_collectors
from platform_modules.connectors.teamviewer_sessions import process_sessions
from platform_modules.connectors.teamviewer_sightings import process_sightings
from platform_modules.governance.reconcile import reconcile_contracts
from platform_modules.identity.services import expire_grants
from platform_modules.pam.services import expire_leases
from platform_modules.pam.sessions import reap_connections
from platform_modules.recertification.schedules import process_schedules

WORKER_COUNT = 4
logger = logging.getLogger(__name__)


def deliver(organization):
    close_old_connections()
    try:
        queued_signals = enqueue_periodic_signals(organization)
        notifications = process_events(organization, limit=1)
        campaigns = process_schedules(organization, limit=1)
        creations = process_creations(organization, limit=1)
        changes = process_changes(organization, limit=1)
        collected = process_collectors(organization, limit=1)
        indexed = process_sightings(organization)
        sessions = process_sessions(organization)
        return (
            notifications
            + queued_signals
            + campaigns
            + creations
            + changes
            + collected
            + indexed
            + sessions
            + process_access_observations(organization)
        )
    finally:
        connections.close_all()


def refill(executor, pending, organizations, queue):
    active = {org.pk: org for org in organizations}
    ordered = deque(key for key in queue if key in active)
    known = set(ordered)
    ordered.extend(key for key in active if key not in known)
    for _ in range(len(ordered)):
        if len(pending) >= WORKER_COUNT:
            break
        key = ordered.popleft()
        ordered.append(key)
        if key not in pending:
            pending[key] = executor.submit(deliver, active[key])
    return ordered


class Command(BaseCommand):
    help = "Traiter les expirations durables ; chaque opération est verrouillée dans PostgreSQL."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")

    def handle(self, *args, **options):
        pending = {}
        queue = deque()
        with ThreadPoolExecutor(max_workers=WORKER_COUNT) as executor:
            while True:
                try:
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
                            enqueue_periodic_signals(organization)
                            process_events(organization)
                            process_schedules(organization, limit=10)
                            process_creations(organization)
                            process_changes(organization)
                            process_collectors(organization, limit=1)
                            process_sightings(organization)
                            process_sessions(organization)
                            process_access_observations(organization)
                        return
                    for key, future in list(pending.items()):
                        if future.done():
                            # A failed completed delivery must not remain a
                            # permanently failing future. In-flight work stays
                            # registered and is never submitted a second time.
                            del pending[key]
                            future.result()
                    queue = refill(executor, pending, organizations, queue)
                except (OperationalError, InterfaceError):
                    if options["once"]:
                        raise
                    connections.close_all()
                    # Driver exception text can contain DSNs, SQL or credentials.
                    logger.warning("Database unavailable; durable jobs paused before retry.")
                time.sleep(5)
