import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from platform_core.tenancy import ScopedModel


class PublishedModel(ScopedModel):
    class Meta(ScopedModel.Meta):
        abstract = True

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Une publication est immuable ; publiez une nouvelle révision.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Une publication ne peut pas être supprimée.")


class Supplier(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Société fournisseur", max_length=180)
    reference = models.CharField("Référence société", max_length=160, blank=True)
    contact = models.EmailField("Contact", blank=True)

    def __str__(self):
        return self.name


class SupplierContract(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    supplier = models.ForeignKey(Supplier, on_delete=models.PROTECT)
    name = models.CharField("Contrat", max_length=180)
    reference = models.CharField("Référence", max_length=160)
    retired_at = models.DateTimeField(null=True, blank=True, editable=False)
    retired_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "reference"], name="unique_supplier_contract_reference"
            )
        ]

    def __str__(self):
        return f"{self.supplier} · {self.reference} · {self.name}"


class ContractRevision(PublishedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    contract = models.ForeignKey(
        SupplierContract, on_delete=models.PROTECT, related_name="revisions"
    )
    sequence = models.PositiveIntegerField()
    effective_at = models.DateTimeField(default=timezone.now)
    starts_at = models.DateTimeField("Début du contrat")
    ends_at = models.DateTimeField("Fin du contrat")
    sponsor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    timezone_name = models.CharField(
        "Fuseau horaire IANA", max_length=80, default="Europe/Brussels"
    )
    weekdays = models.JSONField(default=list)
    daily_start = models.TimeField("Début de la plage locale")
    daily_end = models.TimeField("Fin de la plage locale")
    allowed_methods = models.JSONField(default=list)
    allowed_countries = models.JSONField(default=list, blank=True)
    physical_allowed = models.BooleanField("Accès physique autorisé", default=False)
    require_reference = models.BooleanField("Référence métier déclarée obligatoire", default=True)
    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="published_contract_revisions",
    )
    authorization_at = models.DateTimeField()

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "contract", "sequence"], name="unique_contract_revision"
            )
        ]

    def clean(self):
        super().clean()
        if self.ends_at and self.starts_at and self.ends_at <= self.starts_at:
            raise ValidationError("La fin doit suivre le début du contrat.")
        try:
            ZoneInfo(self.timezone_name)
        except (ValueError, ZoneInfoNotFoundError):
            raise ValidationError("Fuseau horaire IANA inconnu.") from None
        if (
            not isinstance(self.weekdays, list)
            or not self.weekdays
            or any(type(day) is not int or day not in range(7) for day in self.weekdays)
        ):
            raise ValidationError(
                "Les jours autorisés utilisent les valeurs 0 (lundi) à 6 (dimanche)."
            )
        if (
            not isinstance(self.allowed_methods, list)
            or not self.allowed_methods
            or any(
                not isinstance(m, str) or not m.strip() or len(m) > 80 or m == "*"
                for m in self.allowed_methods
            )
        ):
            raise ValidationError("Indiquez au moins une méthode explicite.")
        if not isinstance(self.allowed_countries, list) or any(
            not isinstance(c, str) or len(c) != 2 or not c.isascii() or not c.isalpha()
            for c in self.allowed_countries
        ):
            raise ValidationError("Utilisez des codes pays à deux lettres.")


class ContractScope(PublishedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    revision = models.ForeignKey(ContractRevision, on_delete=models.PROTECT, related_name="scopes")
    resource = models.ForeignKey("identity.Resource", on_delete=models.PROTECT)
    privilege = models.CharField("Privilège autorisé (vide : tous)", max_length=160, blank=True)
    locations = models.JSONField(default=list, blank=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "revision", "resource", "privilege"],
                name="unique_contract_scope",
            )
        ]

    def clean(self):
        super().clean()
        if not isinstance(self.locations, list) or any(
            not isinstance(v, str) or not v.strip() or len(v) > 255 for v in self.locations
        ):
            raise ValidationError(
                "Les origines autorisées doivent être une liste de lieux explicites."
            )


class ContractParticipant(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    contract = models.ForeignKey(
        SupplierContract, on_delete=models.PROTECT, related_name="participants"
    )
    identity = models.ForeignKey("identity.Identity", on_delete=models.PROTECT)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True, editable=False)
    registered_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)

    def clean(self):
        super().clean()
        if self.valid_until and self.valid_from and self.valid_until <= self.valid_from:
            raise ValidationError("La fin de participation doit suivre son début.")


class ApprovalPolicyRevision(PublishedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sequence = models.PositiveIntegerField()
    effective_at = models.DateTimeField(default=timezone.now)
    min_reviewers = models.PositiveSmallIntegerField(
        "Approbateurs indépendants", default=1, choices=[(1, "1"), (2, "2"), (3, "3")]
    )
    critical_reviewers = models.PositiveSmallIntegerField(
        "Approbateurs pour ressource critique", default=2, choices=[(1, "1"), (2, "2"), (3, "3")]
    )
    require_external_contract = models.BooleanField(
        "Contrat exigé pour les identités prestataires", default=True
    )
    supplier_sponsor_required = models.BooleanField(
        "Validation du responsable du contrat exigée", default=True
    )
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "sequence"], name="unique_approval_policy_revision"
            )
        ]


class SeparationRule(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Règle de séparation des tâches", max_length=180)
    left_resource = models.ForeignKey(
        "identity.Resource", on_delete=models.PROTECT, related_name="left_separation_rules"
    )
    left_entitlement = models.CharField("Premier droit", max_length=160)
    right_resource = models.ForeignKey(
        "identity.Resource", on_delete=models.PROTECT, related_name="right_separation_rules"
    )
    right_entitlement = models.CharField("Droit incompatible", max_length=160)
    effective_at = models.DateTimeField(default=timezone.now)
    retired_at = models.DateTimeField(null=True, blank=True, editable=False)
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)

    def clean(self):
        super().clean()
        if (
            self.left_resource_id == self.right_resource_id
            and self.left_entitlement == self.right_entitlement
        ):
            raise ValidationError("Les deux droits doivent être distincts.")
