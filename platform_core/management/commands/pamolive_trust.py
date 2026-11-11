"""Import independently signed public PAM evidence without possessing signing keys."""

from django.core.management.base import BaseCommand, CommandError

from platform_core.models import Organization
from platform_modules.pam.trust_registry import (
    TrustError,
    publish_registry,
    read_document,
    recognized_registry,
    verify_history,
)


class Command(BaseCommand):
    help = "Importe ou vérifie le registre PAM signé hors portail. Aucune clé privée n’est lue."

    def add_arguments(self, parser):
        parser.add_argument(
            "action", choices=("bootstrap", "publish", "recommission", "verify", "history")
        )
        parser.add_argument("--document")
        parser.add_argument("--organization")

    def handle(self, *args, **options):
        try:
            if options["action"] in ("bootstrap", "publish", "recommission"):
                if not options["document"]:
                    raise CommandError("--document doit désigner une enveloppe JSON signée.")
                row = publish_registry(
                    read_document(options["document"]),
                    bootstrap=options["action"] == "bootstrap",
                    recommission=options["action"] == "recommission",
                )
            else:
                if not options["organization"]:
                    raise CommandError("--organization est requis pour la vérification.")
                organization = Organization.objects.get(pk=options["organization"])
                verifier = recognized_registry if options["action"] == "verify" else verify_history
                row = verifier(organization)
        except (TrustError, Organization.DoesNotExist, ValueError) as error:
            raise CommandError(
                "Registre PAM refusé. Vérifiez les preuves et la configuration."
            ) from error
        self.stdout.write(
            f"Organisation {row.organization_id} · génération {row.generation} · "
            f"révision {row.revision} · empreinte {row.revision_hash}"
        )
