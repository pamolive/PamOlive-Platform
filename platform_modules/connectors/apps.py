from django.apps import AppConfig


class ConnectorsConfig(AppConfig):
    name = "platform_modules.connectors"

    def ready(self):
        from platform_modules.access.observations import register_provider

        from .teamviewer_access import related_events, resolve_observation

        register_provider(
            key="teamviewer",
            module="connectors",
            resolve=resolve_observation,
            related=related_events,
        )
