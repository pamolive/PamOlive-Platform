from django.apps import AppConfig


class AccessConfig(AppConfig):
    name = "platform_modules.access"

    def ready(self):
        from platform_core.registry import ModuleDefinition, register_module

        definitions = [
            (
                "access",
                "Gouvernance des accès",
                "Intentions, faits observés et explications",
                ("identity",),
            ),
            (
                "approvals",
                "Approbations",
                "Validation et séparation demandeur / approbateur",
                ("access",),
            ),
            (
                "connectors",
                "Connecteurs",
                "Sources et ingestion authentifiée d’événements",
                ("access",),
            ),
            ("recertification", "Recertification", "Campagnes et revue des droits", ("identity",)),
            (
                "pam",
                "Accès privilégiés",
                "Accès temporaires et suivi des sessions",
                ("access", "approvals"),
            ),
        ]
        for key, name, summary, dependencies in definitions:
            register_module(
                ModuleDefinition(
                    key=key,
                    name=name,
                    summary=summary,
                    version="0.2.0",
                    category="Gouvernance",
                    dependencies=dependencies,
                    url_name=f"{key}-home",
                )
            )
