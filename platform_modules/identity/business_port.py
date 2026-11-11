"""Versioned business-evidence port for IAM mobility. No connector ORM crosses it."""

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError

from platform_core.models import Organization
from platform_core.services import module_available, require_module
from platform_core.tenancy import current_organization

CONTRACT = "identity.mobility-business-evidence/1"
MAX_REFERENCES = 5


@dataclass(frozen=True)
class SourceChoice:
    id: UUID
    name: str
    key: str


class BusinessEvidence(Protocol):
    contract: str

    def source_choices(self, *, organization: Organization) -> tuple[SourceChoice, ...]: ...

    def preview_references(
        self, references: list[tuple[UUID, str]], *, organization: Organization
    ) -> list[dict]: ...

    def capture_references(self, receipt_ids: list, *, organization: Organization) -> dict: ...

    def recheck_references(self, provenance: dict, *, organization: Organization) -> list: ...

    def verify_reference_history(
        self, provenance: dict, checked: list | None, *, organization: Organization
    ) -> None: ...

    def reference_context(
        self,
        provenance: dict,
        checked: list | None,
        *,
        organization: Organization,
        tolerate_invalid_latest: bool = False,
    ) -> dict: ...


_provider: BusinessEvidence | None = None


def register(provider: BusinessEvidence):
    """Bind once at application startup, never from a request or tenant setting."""
    global _provider
    if provider.contract != CONTRACT or _provider is not None:
        raise RuntimeError("Le contrat de preuve métier IAM est incompatible ou déjà déclaré.")
    _provider = provider


def available(organization):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    return _provider is not None and module_available(organization, "connectors")


def active_provider(organization) -> BusinessEvidence:
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    require_module(organization, "connectors")
    if _provider is None:
        raise PermissionDenied("Le fournisseur de preuves métier n’est pas livré.")
    return _provider


def verify_history(provenance, checked, *, organization):
    """Verify signed history even if its provider has since been disabled for the tenant."""
    if _provider is None:
        raise ValidationError("Le fournisseur requis pour vérifier les preuves métier est absent.")
    _provider.verify_reference_history(provenance, checked, organization=organization)
