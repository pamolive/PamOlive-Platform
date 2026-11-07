import time

from django.core.management.base import BaseCommand
from django.db import close_old_connections

from platform_core.models import Organization
from platform_modules.pam.services import expire_leases


class Command(BaseCommand):
    help = "Traiter les expirations durables ; chaque opération est verrouillée dans PostgreSQL."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")

    def handle(self, *args, **options):
        while True:
            close_old_connections()
            for organization in Organization.objects.filter(active=True):
                expire_leases(organization)
            if options["once"]:
                return
            time.sleep(5)
