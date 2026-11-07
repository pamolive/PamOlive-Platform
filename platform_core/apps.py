from django.apps import AppConfig


class PlatformCoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "platform_core"
    verbose_name = "PAM-olive Core"

    def ready(self):
        from . import signals  # noqa: F401
