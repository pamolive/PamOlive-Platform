from django.apps import AppConfig


class GovernanceConfig(AppConfig):
    name = "platform_modules.governance"

    def ready(self):
        from platform_core.registry import ModuleDefinition, register_module

        register_module(
            ModuleDefinition(
                key="governance",
                name="Contrats et politiques",
                version="0.2.0",
                summary="Fournisseurs, périmètres, horaires et séparation des tâches",
                category="Gouvernance",
                dependencies=("access",),
                url_name="governance-home",
            )
        )
