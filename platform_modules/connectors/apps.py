from django.apps import AppConfig


class ConnectorsConfig(AppConfig):
    name = "platform_modules.connectors"

    def ready(self):
        from platform_modules.access.observations import register_provider
        from platform_modules.identity.business_port import register as register_business_evidence

        from . import business_references
        from .teamviewer_access import related_events, resolve_observation

        register_business_evidence(business_references)
        register_provider(
            key="teamviewer",
            module="connectors",
            resolve=resolve_observation,
            related=related_events,
        )
