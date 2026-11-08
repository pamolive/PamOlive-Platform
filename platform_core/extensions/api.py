"""Public V1 service facade. A view guard is not a substitute for this service check."""

from django.conf import settings
from django.core.exceptions import PermissionDenied
from packaging.specifiers import SpecifierSet

from platform_core.audit import record
from platform_core.authorization import require_recent_authentication
from platform_core.models import ExtensionDeployment, ModuleActivation
from platform_core.services import authorize as authorize_roles
from platform_core.tenancy import current_organization


def release_for(key):
    return next((item for item in settings.PAMOLIVE_EXTENSIONS if item.manifest.key == key), None)


def require_delivery(organization, key):
    release = release_for(key)
    if not release:
        raise PermissionDenied("Le paquet d’extension est absent du déploiement.")
    manifest = release.manifest
    if not ExtensionDeployment.objects.filter(
        module_key=key,
        version=manifest.version,
        release_hash=release.release_hash,
        manifest_hash=release.manifest_hash,
        wheel_hash=release.wheel_sha256,
    ).exists():
        raise PermissionDenied("La livraison contrôlée de ce paquet doit être validée.")
    state = ModuleActivation.objects.filter(
        organization=organization, module_key=key, enabled=True
    ).first()
    if not state or state.version != manifest.version or state.release_hash != release.release_hash:
        raise PermissionDenied(
            "Cette version de l’extension n’est pas activée dans l’organisation."
        )
    for dependency in manifest.dependencies:
        state = ModuleActivation.objects.filter(
            organization=organization, module_key=dependency.key, enabled=True
        ).first()
        if not state or not SpecifierSet(dependency.version_spec).contains(
            state.version, prereleases=True
        ):
            raise PermissionDenied("Dépendance non activée dans cette organisation.")
        if release_for(dependency.key):
            require_delivery(organization, dependency.key)
    return release


def authorize(actor, organization, permission_code):
    """Enforce tenant membership, technical role, active release and personal MFA."""
    if current_organization().pk != organization.pk:
        raise PermissionDenied("Le service d’extension exige le contexte de l’organisation.")
    key = permission_code.partition(".")[0]
    release = release_for(key)
    permission = (
        next((item for item in release.manifest.permissions if item.code == permission_code), None)
        if release
        else None
    )
    if permission is None:
        raise PermissionDenied("Permission d’extension non déclarée.")
    authorize_roles(actor, organization, roles=permission.roles)
    require_delivery(organization, key)
    if permission.sensitive:
        require_recent_authentication(actor, organization)
    return permission


def audit(*, actor, organization, permission_code, action, summary, target=None, metadata=None):
    authorize(actor, organization, permission_code)
    key = permission_code.partition(".")[0]
    import re

    if not re.fullmatch(
        re.escape(key) + r"\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.v[1-9][0-9]*", action
    ):
        raise ValueError("L’événement d’audit doit appartenir au module et être versionné.")
    if target is not None and getattr(target, "organization_id", None) != organization.pk:
        raise PermissionDenied("La preuve d’extension concerne une autre organisation.")
    return record(
        action=action,
        summary=summary,
        actor=actor,
        organization=organization,
        target=target,
        metadata=metadata,
    )
