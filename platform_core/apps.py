from django.apps import AppConfig


class PlatformCoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "platform_core"
    verbose_name = "PAM-olive Core"

    def ready(self):
        import logging

        from . import signals  # noqa: F401
        from .oidc.logging import OIDCQueryRedactor

        for name in ("uvicorn.access", "django.server"):
            logging.getLogger(name).addFilter(OIDCQueryRedactor())
