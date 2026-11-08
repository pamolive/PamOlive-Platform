"""Organization context shared by HTTP and service callers; absent context denies access."""

from contextlib import contextmanager
from contextvars import ContextVar

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models

_organization = ContextVar("pamolive_organization", default=None)
_federated_scope = ContextVar("pamolive_federated_scope", default=None)


@contextmanager
def federation_context(account_id, organization_id):
    token = _federated_scope.set((account_id, organization_id))
    try:
        yield
    finally:
        _federated_scope.reset(token)


def enforce_federated_scope(actor, organization):
    scope = _federated_scope.get()
    if (
        scope
        and scope[1]
        and scope[0] == getattr(actor, "pk", None)
        and scope[1] != organization.pk
    ):
        raise PermissionDenied("La session fédérée est limitée à son organisation.")


def is_platform_administrator(actor):
    """Federation grants organization scope, never installation-global authority."""
    scope = _federated_scope.get()
    return bool(
        actor
        and actor.is_active
        and actor.is_superuser
        and not (scope and scope[0] == actor.pk and scope[1])
    )


def current_organization():
    organization = _organization.get()
    if organization is None:
        raise PermissionDenied("Sélectionnez une organisation.")
    return organization


@contextmanager
def organization_context(organization):
    token = _organization.set(organization)
    try:
        yield organization
    finally:
        _organization.reset(token)


class TenantManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(organization=current_organization())


class OrganizationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from .models import Organization

        request.organization = None
        federated_org = None
        if request.user.is_authenticated:
            if request.session.get("oidc") is not None:
                from django.contrib.auth import logout

                from .oidc.services import federation

                try:
                    federated_org = federation(request.session, request.user)
                except PermissionDenied:
                    logout(request)
                    request.organizations = Organization.objects.none()
                    with organization_context(None):
                        return self.get_response(request)
            available = Organization.objects.filter(active=True)
            if federated_org:
                available = available.filter(pk=federated_org)
            if not request.user.is_superuser:
                available = available.filter(
                    memberships__account=request.user, memberships__active=True
                )
            selected = request.session.get("organization_id")
            request.organization = available.filter(pk=selected).first() if selected else None
            request.organization = request.organization or available.order_by("name").first()
            request.organizations = available
        with (
            organization_context(request.organization),
            federation_context(
                request.user.pk if request.user.is_authenticated else None, federated_org
            ),
        ):
            return self.get_response(request)


class ScopedModel(models.Model):
    organization = models.ForeignKey("platform_core.Organization", on_delete=models.PROTECT)
    objects = TenantManager()
    unscoped = models.Manager()

    class Meta:
        abstract = True
        base_manager_name = "unscoped"

    def clean(self):
        super().clean()
        for field in self._meta.fields:
            if field.is_relation and field.name != "organization" and getattr(self, field.attname):
                related = getattr(self, field.name)
                if hasattr(related, "organization_id"):
                    if related.organization_id != self.organization_id:
                        raise ValidationError({field.name: "Objet d’une autre organisation."})

    def save(self, *args, **kwargs):
        self.clean()
        return super().save(*args, **kwargs)
