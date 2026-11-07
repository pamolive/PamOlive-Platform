from django.apps import AppConfig


class IntelligenceConfig(AppConfig):
    name = "platform_modules.intelligence"

    def ready(self):
        from platform_core.registry import ModuleDefinition, register_module

        register_module(
            ModuleDefinition(
                key="intelligence",
                name="Graphe et investigations",
                version="0.2.0",
                summary="Relations, chronologie croisée et couverture des sources",
                category="Gouvernance",
                dependencies=("access",),
                url_name="intelligence-home",
            )
        )
