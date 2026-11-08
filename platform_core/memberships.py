"""Organization-local portal access, independent of governed IAM identities."""

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from .audit import record
from .authorization import require_recent_authentication
from .models import Organization, OrganizationMembership
from .services import authorize
from .tenancy import current_organization, is_platform_administrator


@transaction.atomic
def set_membership(*, actor, organization, username, role, active=True, password=""):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    organization = (
        Organization.objects.select_for_update().filter(pk=organization.pk, active=True).first()
    )
    if organization is None or actor is None:
        raise PermissionDenied
    actor = get_user_model().objects.filter(pk=actor.pk, is_active=True).first()
    if actor is None:
        raise PermissionDenied
    authorize(actor, organization, roles=("admin",))
    require_recent_authentication(actor, organization)
    choices = {key for key, _ in OrganizationMembership._meta.get_field("role").choices}
    if not isinstance(role, str) or role not in choices or type(active) is not bool:
        raise ValidationError("Rôle ou état d’appartenance invalide.")
    if not isinstance(username, str) or not username or username != username.strip():
        raise ValidationError("Identifiant de compte invalide.")
    account = get_user_model().objects.filter(username=username).first()
    member = (
        OrganizationMembership.objects.select_for_update()
        .filter(organization=organization, account=account)
        .first()
        if account
        else None
    )
    created_account = account is None
    if account is not None and member is None and not is_platform_administrator(actor):
        # Do not infer ownership, link by email, or disclose another tenant's membership.
        raise ValidationError("Ce compte ne peut pas être ajouté depuis cette organisation.")
    if account is not None and member is None and not account.is_active:
        raise ValidationError("Ce compte ne peut pas être ajouté depuis cette organisation.")
    if member and member.active and member.role == "admin" and (not active or role != "admin"):
        if (
            not OrganizationMembership.objects.filter(
                organization=organization, active=True, role="admin", account__is_active=True
            )
            .exclude(pk=member.pk)
            .exists()
        ):
            raise ValidationError("Conservez au moins un administrateur actif dans l’organisation.")
    if created_account:
        account = get_user_model()(username=username, is_superuser=False, is_staff=False)
        if not isinstance(password, str) or not password or len(password) > 4096:
            raise ValidationError("Un mot de passe initial valide est requis.")
        validate_password(password, user=account)
        account.set_password(password)
        account.full_clean()
        account.save()
    previous = {"role": member.role, "active": member.active} if member else None
    member, _ = OrganizationMembership.objects.update_or_create(
        organization=organization, account=account, defaults={"role": role, "active": active}
    )
    record(
        organization=organization,
        actor=actor,
        target=member,
        action="core.membership.changed.v1",
        summary="Appartenance du compte de portail modifiée",
        metadata={
            "account_id": account.pk,
            "created_account": created_account,
            "previous": previous,
            "current": {"role": role, "active": active},
        },
    )
    return member
