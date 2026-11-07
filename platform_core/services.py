from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from .audit import record
from .models import ModuleActivation, Organization, OrganizationMembership
from .registry import all_modules, get_module
from .tenancy import current_organization


def authorize(actor, organization, *, roles=("admin", "operator")):
    if not actor or not actor.is_active or not organization.active:
        raise PermissionDenied
    if actor.is_superuser:
        return
    if not OrganizationMembership.objects.filter(
        organization=organization,
        account=actor,
        active=True,
        role__in=roles,
        organization__active=True,
    ).exists():
        raise PermissionDenied("Droit insuffisant dans cette organisation.")


def require_module(organization, key):
    if not ModuleActivation.objects.filter(
        organization=organization, module_key=key, enabled=True
    ).exists():
        raise PermissionDenied("Ce module n’est pas activé pour cette organisation.")


def module_catalog(organization=None):
    organization = organization or current_organization()
    states = {
        item.module_key: item for item in ModuleActivation.objects.filter(organization=organization)
    }
    return [(definition, states.get(definition.key)) for definition in all_modules()]


@transaction.atomic
def install_module(module_key, *, actor, organization=None, request=None):
    organization = organization or current_organization()
    authorize(actor, organization, roles=("admin",))
    Organization.objects.select_for_update().get(pk=organization.pk)
    definition = get_module(module_key)
    if not definition:
        raise ValidationError("Module inconnu ou paquet absent de ce déploiement.")
    if definition.is_paid:
        raise ValidationError("Une extension commerciale requiert son paquet et son entitlement.")
    for dependency in definition.dependencies:
        require_module(organization, dependency)
    module, _ = ModuleActivation.objects.update_or_create(
        organization=organization,
        module_key=module_key,
        defaults={"version": definition.version, "enabled": True},
    )
    record(
        action="core.module.enabled.v1",
        summary=f"Module {definition.name} activé",
        actor=actor,
        organization=organization,
        target=module,
        request=request,
    )
    return module


@transaction.atomic
def disable_module(module_key, *, actor, organization=None, request=None):
    organization = organization or current_organization()
    authorize(actor, organization, roles=("admin",))
    Organization.objects.select_for_update().get(pk=organization.pk)
    dependents = [
        d.name
        for d in all_modules()
        if module_key in d.dependencies
        and ModuleActivation.objects.filter(
            organization=organization, module_key=d.key, enabled=True
        ).exists()
    ]
    if dependents:
        raise ValidationError("Désactivez les dépendants : " + ", ".join(dependents))
    module = ModuleActivation.objects.get(organization=organization, module_key=module_key)
    module.enabled = False
    module.save(update_fields=["enabled", "updated_at"])
    record(
        action="core.module.disabled.v1",
        summary=f"Module {module_key} désactivé",
        actor=actor,
        organization=organization,
        target=module,
        request=request,
    )
    return module
