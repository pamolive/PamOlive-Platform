from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from .audit import record


@receiver(user_logged_in)
def audit_login(sender, request, user, **kwargs):
    record(
        action="authentication.login",
        summary=f"Connexion de {user.get_username()}",
        actor=user,
        request=request,
    )
