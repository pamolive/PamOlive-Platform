from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from platform_core.models import Organization
from platform_core.services import disable_module, install_module, module_catalog


class Command(BaseCommand):
    help = "Liste, active ou désactive les modules PAM-olive."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=("list", "install", "disable"))
        parser.add_argument("module_key", nargs="?")
        parser.add_argument("--organization", required=True)
        parser.add_argument("--actor")

    def handle(self, *args, **options):
        action = options["action"]
        module_key = options["module_key"]
        organization = Organization.objects.filter(key=options["organization"], active=True).first()
        if not organization:
            raise CommandError("Organisation active introuvable.")
        if action == "list":
            for definition, state in module_catalog(organization):
                status = (
                    "enabled" if state and state.enabled else "disabled" if state else "available"
                )
                self.stdout.write(
                    f"{definition.key:24} {definition.version:8} {status:10} {definition.name}"
                )
            return
        if not module_key:
            raise CommandError("module_key est requis pour install ou disable.")
        actor = get_user_model().objects.filter(username=options["actor"], is_active=True).first()
        if not actor:
            raise CommandError("--actor doit désigner un compte administrateur actif.")
        if action == "install":
            install_module(module_key, actor=actor, organization=organization)
            self.stdout.write(self.style.SUCCESS(f"Module {module_key} activé."))
        else:
            disable_module(module_key, actor=actor, organization=organization)
            self.stdout.write(self.style.WARNING(f"Module {module_key} désactivé."))
