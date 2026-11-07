from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from platform_core.models import Organization, OrganizationMembership
from platform_core.services import install_module


class Command(BaseCommand):
    help = "Créer une organisation et activer les modules livrés, sans données de démonstration."

    def add_arguments(self, parser):
        parser.add_argument("--key", required=True)
        parser.add_argument("--name", required=True)
        parser.add_argument("--admin", required=True)

    @transaction.atomic
    def handle(self, *args, **options):
        actor = (
            get_user_model()
            .objects.filter(username=options["admin"], is_superuser=True, is_active=True)
            .first()
        )
        if not actor:
            raise CommandError("Créez d’abord ce compte avec createsuperuser.")
        org, _ = Organization.objects.get_or_create(
            key=options["key"], defaults={"name": options["name"]}
        )
        OrganizationMembership.objects.update_or_create(
            organization=org, account=actor, defaults={"role": "admin", "active": True}
        )
        for key in ["identity", "access", "approvals", "connectors", "recertification", "pam"]:
            install_module(key, actor=actor, organization=org)
        self.stdout.write(self.style.SUCCESS(f"Organisation prête : {org.name} ({org.pk})"))
