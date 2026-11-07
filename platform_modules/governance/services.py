"""Publishing is explicit, organization-scoped, serialized and interactively authorized."""

from datetime import datetime

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from platform_core.audit import record
from platform_core.authorization import require_recent_authentication
from platform_core.models import Organization, OrganizationMembership
from platform_core.services import authorize, require_module
from platform_core.tenancy import organization_context

from .models import (
    ApprovalPolicyRevision,
    ContractParticipant,
    ContractRevision,
    ContractScope,
    SeparationRule,
    Supplier,
    SupplierContract,
)


def _publisher(actor, organization):
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "governance")
    assurance = require_recent_authentication(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk)
    return datetime.fromtimestamp(assurance.verified_at, tz=timezone.get_default_timezone())


def _audit(obj, actor, organization, action):
    record(
        action=f"governance.{action}.v1",
        summary=str(obj),
        actor=actor,
        organization=organization,
        target=obj,
    )
    return obj


@transaction.atomic
def create_supplier(data, *, actor, organization):
    _publisher(actor, organization)
    with organization_context(organization):
        obj = Supplier(
            organization=organization,
            **{k: data[k] for k in ("name", "reference", "contact") if k in data},
        )
        obj.full_clean()
        obj.save()
        return _audit(obj, actor, organization, "supplier.created")


@transaction.atomic
def publish_contract(data, scopes, *, actor, organization, contract_id=None):
    authorized_at = _publisher(actor, organization)
    with organization_context(organization):
        if contract_id:
            contract = SupplierContract.objects.get(pk=contract_id)
            if contract.retired_at:
                raise ValidationError("Un contrat retiré ne peut pas être republié.")
        else:
            contract = SupplierContract(
                organization=organization, **{k: data[k] for k in ("supplier", "name", "reference")}
            )
            contract.full_clean()
            contract.save()
        sponsor = data["sponsor"]
        if (
            not sponsor.is_active
            or not OrganizationMembership.objects.filter(
                organization=organization,
                account=sponsor,
                active=True,
                role__in=("admin", "reviewer"),
            ).exists()
        ):
            raise ValidationError(
                "Le responsable doit être un administrateur ou approbateur actif "
                "de cette organisation."
            )
        if not scopes:
            raise ValidationError("Le contrat doit avoir au moins une ressource autorisée.")
        fields = (
            "starts_at",
            "ends_at",
            "sponsor",
            "timezone_name",
            "weekdays",
            "daily_start",
            "daily_end",
            "allowed_methods",
            "allowed_countries",
            "physical_allowed",
            "require_reference",
        )
        values = {k: data[k] for k in fields}
        values["allowed_methods"] = sorted(
            {v.strip().casefold() for v in values["allowed_methods"]}
        )
        values["allowed_countries"] = sorted({v.upper() for v in values["allowed_countries"]})
        obj = ContractRevision(
            organization=organization,
            contract=contract,
            sequence=(contract.revisions.aggregate(value=Max("sequence"))["value"] or 0) + 1,
            effective_at=timezone.now(),
            published_by=actor,
            authorization_at=authorized_at,
            **values,
        )
        obj.full_clean()
        obj.save()
        for scope in scopes:
            item = ContractScope(
                organization=organization,
                revision=obj,
                **{k: scope[k] for k in ("resource", "privilege", "locations")},
            )
            item.full_clean()
            item.save()
        _audit(obj, actor, organization, "contract.published")
        return contract


@transaction.atomic
def add_participant(data, *, actor, organization):
    _publisher(actor, organization)
    with organization_context(organization):
        obj = ContractParticipant(
            organization=organization,
            registered_by=actor,
            valid_from=timezone.now(),
            **{k: data[k] for k in ("contract", "identity", "valid_until") if k in data},
        )
        if obj.contract.retired_at:
            raise ValidationError("Ce contrat est retiré.")
        if ContractParticipant.objects.filter(
            contract=obj.contract, identity=obj.identity, revoked_at__isnull=True
        ).exists():
            raise ValidationError(
                "Cet intervenant est déjà inscrit. Retirez son inscription précédente "
                "avant de le réinscrire."
            )
        obj.full_clean()
        obj.save()
        return _audit(obj, actor, organization, "participant.added")


@transaction.atomic
def publish_policy(data, *, actor, organization):
    _publisher(actor, organization)
    with organization_context(organization):
        obj = ApprovalPolicyRevision(
            organization=organization,
            published_by=actor,
            sequence=(ApprovalPolicyRevision.objects.aggregate(value=Max("sequence"))["value"] or 0)
            + 1,
            **{
                k: data[k]
                for k in (
                    "min_reviewers",
                    "critical_reviewers",
                    "require_external_contract",
                    "supplier_sponsor_required",
                )
            },
        )
        obj.full_clean()
        obj.save()
        return _audit(obj, actor, organization, "policy.published")


@transaction.atomic
def publish_separation(data, *, actor, organization):
    _publisher(actor, organization)
    with organization_context(organization):
        obj = SeparationRule(
            organization=organization,
            published_by=actor,
            **{
                k: data[k]
                for k in (
                    "name",
                    "left_resource",
                    "left_entitlement",
                    "right_resource",
                    "right_entitlement",
                )
            },
        )
        obj.full_clean()
        obj.save()
        return _audit(obj, actor, organization, "separation.published")


@transaction.atomic
def withdraw(kind, object_id, *, actor, organization):
    _publisher(actor, organization)
    model = {
        "contract": SupplierContract,
        "participant": ContractParticipant,
        "separation": SeparationRule,
    }[kind]
    with organization_context(organization):
        obj = model.objects.select_for_update().get(pk=object_id)
        field = "revoked_at" if kind == "participant" else "retired_at"
        if not getattr(obj, field):
            setattr(obj, field, timezone.now())
            obj.save(update_fields=[field])
            _audit(obj, actor, organization, f"{kind}.withdrawn")
        from .reconcile import reconcile_contracts

        reconcile_contracts(organization)
        return obj
