from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction

from .audit import record
from .models import ModuleActivation, Organization, OrganizationMembership
from .registry import ModuleDependencyError, all_modules, dependency_closure, get_module
from .tenancy import current_organization, enforce_federated_scope


def authorize(actor, organization, *, roles=("admin", "operator")):
    enforce_federated_scope(actor, organization)
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


def lock_authorized_actor(actor, organization, *, roles=("admin", "operator")):
    """Revalidate mutation authority after the shared membership/activation lock.

    The caller owns the transaction for the entire protected mutation. Returning
    refreshed objects prevents a request's cached account or organization flags
    from retaining authority after a concurrent administrative revocation.
    """
    if not connection.in_atomic_block or current_organization().pk != organization.pk:
        raise PermissionDenied("Cette opération exige une transaction organisationnelle.")
    organization = (
        Organization.objects.select_for_update().filter(pk=organization.pk, active=True).first()
    )
    if organization is None or actor is None:
        raise PermissionDenied
    actor = get_user_model().objects.filter(pk=actor.pk, is_active=True).first()
    if actor is None:
        raise PermissionDenied
    authorize(actor, organization, roles=roles)
    return actor, organization


def require_module(organization, key):
    definition = get_module(key)
    if not definition:
        raise PermissionDenied("Le paquet de ce module est absent du déploiement.")
    # Extension packages have an additional release/version contract, even when
    # they are already present in the process or a stale enabled row exists.
    if definition.metadata.get("extension_release"):
        from .extensions.api import require_delivery

        require_delivery(organization, key)
        return
    try:
        definitions = dependency_closure(key)
    except ModuleDependencyError as error:
        raise PermissionDenied("Les dépendances de ce module ne sont pas disponibles.") from error
    required = {item.key for item in definitions}
    active = set(
        ModuleActivation.objects.filter(
            organization=organization, module_key__in=required, enabled=True
        ).values_list("module_key", flat=True)
    )
    if active != required:
        raise PermissionDenied(
            "Ce module ou ses dépendances ne sont pas activés dans cette organisation."
        )
    for dependency in definitions:
        if dependency.metadata.get("extension_release"):
            from .extensions.api import require_delivery

            require_delivery(organization, dependency.key)


def module_available(organization, key):
    """Noninteractive jobs must honor the same module authority as the UI."""
    try:
        require_module(organization, key)
    except PermissionDenied:
        return False
    return True


def module_catalog(organization=None):
    organization = organization or current_organization()
    states = {
        item.module_key: item for item in ModuleActivation.objects.filter(organization=organization)
    }
    definitions = all_modules()
    extensions = [d for d in definitions if d.metadata.get("extension_release")]
    if extensions:
        from dataclasses import replace

        from .extensions.api import release_for
        from .models import ExtensionDeployment

        deliveries = {
            item.module_key: item
            for item in ExtensionDeployment.objects.filter(
                module_key__in=[d.key for d in extensions]
            )
        }
        annotated = []
        for definition in definitions:
            if definition.metadata.get("extension_release"):
                release = release_for(definition.key)
                delivered = deliveries.get(definition.key)
                ready = bool(
                    release
                    and delivered
                    and delivered.version == release.manifest.version
                    and delivered.release_hash == release.release_hash
                    and delivered.manifest_hash == release.manifest_hash
                    and delivered.wheel_hash == release.wheel_sha256
                )
                definition = replace(
                    definition,
                    metadata={
                        **definition.metadata,
                        "delivery_ready": ready,
                        "activation_current": bool(
                            states.get(definition.key)
                            and states[definition.key].enabled
                            and states[definition.key].version == definition.version
                            and states[definition.key].release_hash == release.release_hash
                        ),
                    },
                )
            annotated.append(definition)
        definitions = annotated
    return [(definition, states.get(definition.key)) for definition in definitions]


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
    activation_hash = ""
    activation_proof = {}
    if definition.metadata.get("extension_release"):
        from .authorization import require_recent_authentication
        from .extensions.api import release_for
        from .models import ExtensionDeployment

        assurance = require_recent_authentication(actor, organization)
        release = release_for(module_key)
        if (
            not release
            or not ExtensionDeployment.objects.filter(
                module_key=module_key,
                release_hash=release.release_hash,
                manifest_hash=release.manifest_hash,
                wheel_hash=release.wheel_sha256,
                version=release.manifest.version,
            ).exists()
        ):
            raise ValidationError(
                "Validez les migrations et la livraison du paquet avant activation."
            )
        from packaging.specifiers import SpecifierSet

        activation_hash = release.release_hash
        activation_proof = {
            "release_hash": release.release_hash,
            "wheel_hash": release.wheel_sha256,
            "manifest_hash": release.manifest_hash,
            "mfa_verified_at": assurance.verified_at,
            "mfa_window_minutes": assurance.freshness_minutes,
        }

        for dependency in release.manifest.dependencies:
            state = ModuleActivation.objects.filter(
                organization=organization, module_key=dependency.key, enabled=True
            ).first()
            if not state or not SpecifierSet(dependency.version_spec).contains(
                state.version, prereleases=True
            ):
                raise ValidationError("Version de dépendance non activée ou incompatible.")
    for dependency in definition.dependencies:
        require_module(organization, dependency)
    module, _ = ModuleActivation.objects.update_or_create(
        organization=organization,
        module_key=module_key,
        defaults={"version": definition.version, "release_hash": activation_hash, "enabled": True},
    )
    record(
        action="core.module.enabled.v1",
        summary=f"Module {definition.name} activé",
        actor=actor,
        organization=organization,
        target=module,
        request=request,
        metadata=activation_proof,
    )
    return module


@transaction.atomic
def disable_module(module_key, *, actor, organization=None, request=None):
    organization = organization or current_organization()
    authorize(actor, organization, roles=("admin",))
    definition = get_module(module_key)
    if definition and definition.metadata.get("extension_release"):
        from .authorization import require_recent_authentication

        require_recent_authentication(actor, organization)
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
