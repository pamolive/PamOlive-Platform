from django.apps import AppConfig


class IdentityModuleConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "platform_modules.identity"
    verbose_name = "PAM-olive Identités"

    def ready(self):
        from platform_core.registry import register_module

        from .manifest import definition

        try:
            register_module(definition)
        except RuntimeError:
            pass
