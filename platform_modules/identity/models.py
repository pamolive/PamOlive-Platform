import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Now
from django.utils import timezone

from platform_core.tenancy import ScopedModel

from .mover_models import (  # noqa: F401
    MoveAccess,
    MoveDecision,
    MoveGrant,
    MoveProposal,
    RoleRevision,
)


class Identity(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Nom", max_length=180)
    kind = models.CharField(
        "Type",
        max_length=20,
        choices=[
            ("human", "Personne"),
            ("external", "Prestataire"),
            ("machine", "Machine"),
            ("service", "Service"),
            ("workload", "Workload"),
            ("application", "Application"),
            ("api", "Client API"),
        ],
    )
    email = models.EmailField(blank=True)
    owner = models.CharField("Responsable", max_length=180, blank=True)
    department = models.CharField("Équipe", max_length=180, blank=True)
    status = models.CharField(
        max_length=16,
        choices=[("active", "Active"), ("suspended", "Suspendue"), ("departed", "Départ")],
        default="active",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class LoginIdentityBinding(ScopedModel):
    """An administrator-attested link; never inferred from a name or e-mail."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    login_account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    identity = models.ForeignKey(Identity, on_delete=models.PROTECT, related_name="login_bindings")
    verification_reference = models.CharField("Référence de vérification", max_length=255)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="created_identity_bindings"
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    mfa_verified_at = models.DateTimeField(null=True, blank=True, editable=False)
    mfa_window_minutes = models.PositiveSmallIntegerField(default=0, editable=False)
    signature = models.CharField(max_length=64, blank=True, editable=False)
    revoked_at = models.DateTimeField(null=True, blank=True, editable=False)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        editable=False,
        on_delete=models.PROTECT,
        related_name="revoked_identity_bindings",
    )
    revocation_reason = models.TextField(blank=True, editable=False)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "login_account"],
                condition=models.Q(revoked_at__isnull=True),
                name="one_current_login_identity_binding",
            ),
        ]

    def clean(self):
        super().clean()
        if not self.verification_reference.strip():
            raise ValidationError("Une référence de vérification est requise.")
        if self._state.adding:
            from platform_core.models import OrganizationMembership

            if self.identity.status != "active" or self.identity.kind not in ("human", "external"):
                raise ValidationError("Liez une personne ou un intervenant externe actif.")
            if (
                not self.login_account.is_active
                or not OrganizationMembership.objects.filter(
                    organization_id=self.organization_id, account=self.login_account, active=True
                ).exists()
            ):
                raise ValidationError("Le compte doit être membre actif de cette organisation.")
        else:
            previous = type(self).unscoped.get(pk=self.pk)
            immutable = (
                "organization_id",
                "login_account_id",
                "identity_id",
                "verification_reference",
                "created_by_id",
                "created_at",
                "mfa_verified_at",
                "mfa_window_minutes",
                "signature",
            )
            if any(getattr(previous, key) != getattr(self, key) for key in immutable):
                raise ValidationError(
                    "Un lien ne se réattribue pas : révoquez-le puis créez-en un."
                )
            if previous.revoked_at and (
                self.revoked_at != previous.revoked_at
                or self.revoked_by_id != previous.revoked_by_id
                or self.revocation_reason != previous.revocation_reason
            ):
                raise ValidationError("Une révocation de lien est définitive.")
        if self.revoked_at:
            if not self.revoked_by_id or not self.revocation_reason.strip():
                raise ValidationError("Auteur et motif de révocation requis.")
            if self.created_at and self.revoked_at < self.created_at:
                raise ValidationError("La révocation ne peut pas précéder la création.")
        elif self.revoked_by_id or self.revocation_reason:
            raise ValidationError("Une révocation exige sa date.")

    def delete(self, *args, **kwargs):
        raise ValidationError("Les liens historiques se conservent ; utilisez la révocation.")

    def __str__(self):
        return f"{self.login_account} → {self.identity}"


class Resource(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Nom", max_length=180)
    kind = models.CharField(
        "Type",
        max_length=20,
        choices=[
            ("application", "Application"),
            ("server", "Serveur"),
            ("database", "Base de données"),
            ("door", "Porte"),
            ("network", "Réseau"),
            ("api", "API"),
            ("cloud", "Cloud"),
            ("device", "Appareil"),
            ("zone", "Zone physique"),
        ],
    )
    owner = models.CharField("Responsable", max_length=180, blank=True)
    location = models.CharField("Emplacement attendu", max_length=255, blank=True)
    critical = models.BooleanField("Ressource critique", default=False)
    environment = models.CharField(
        "Environnement",
        max_length=20,
        default="unknown",
        choices=[
            ("unknown", "Non classé"),
            ("production", "Production"),
            ("test", "Test"),
            ("development", "Développement"),
        ],
    )

    def __str__(self):
        return self.name


class ExternalAccount(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey(Identity, on_delete=models.PROTECT, related_name="accounts")
    username = models.CharField("Identifiant", max_length=180)
    system = models.CharField("Système", max_length=180)
    kind = models.CharField(
        "Type de compte",
        max_length=16,
        choices=[
            ("standard", "Standard"),
            ("service", "Technique / service"),
            ("privileged", "Privilégié"),
        ],
        default="standard",
    )
    active = models.BooleanField("Actif", default=True)
    state_revision = models.PositiveIntegerField(default=1, editable=False)
    managed_contract = models.ForeignKey(
        "governance.SupplierContract",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        verbose_name="Compte dédié au contrat",
    )

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "system", "username"], name="unique_scoped_external_account"
            )
        ]

    def __str__(self):
        return f"{self.username} · {self.system}"


class Credential(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey(Identity, on_delete=models.PROTECT)
    resource = models.ForeignKey(Resource, null=True, blank=True, on_delete=models.PROTECT)
    name = models.CharField("Nom", max_length=180)
    kind = models.CharField(
        "Type",
        max_length=20,
        choices=[
            ("certificate", "Certificat"),
            ("badge", "Badge"),
            ("ssh_key", "Clé SSH — référence"),
        ],
    )
    fingerprint = models.CharField("Empreinte / identifiant public", max_length=255)
    issuer = models.CharField("Émetteur", max_length=180, blank=True)
    expires_at = models.DateTimeField("Expiration", null=True, blank=True)
    usage = models.CharField("Usage attendu", max_length=180, blank=True)
    registered_at = models.DateTimeField(auto_now_add=True, db_default=Now())

    def __str__(self):
        return self.name


class Grant(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey(Identity, on_delete=models.PROTECT)
    account = models.ForeignKey(ExternalAccount, on_delete=models.PROTECT, null=True, blank=True)
    resource = models.ForeignKey(Resource, on_delete=models.PROTECT)
    entitlement = models.CharField("Droit / rôle", max_length=160)
    justification = models.TextField("Justification")
    expires_at = models.DateTimeField("Expiration", null=True, blank=True)
    status = models.CharField(
        max_length=16, default="active", choices=[("active", "Actif"), ("revoked", "Révoqué")]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    state_revision = models.PositiveIntegerField(default=1, editable=False)
    contract = models.ForeignKey(
        "governance.SupplierContract", null=True, blank=True, on_delete=models.PROTECT
    )
    valid_from = models.DateTimeField(default=timezone.now, db_default=Now())
    revoked_at = models.DateTimeField(null=True, blank=True, editable=False)
    method = models.CharField("Méthode d’accès", max_length=80, blank=True)
    location = models.CharField("Origine déclarée", max_length=255, blank=True)
    country_code = models.CharField("Pays d’origine déclaré (2 lettres)", max_length=2, blank=True)
    reference = models.CharField("Référence métier déclarée", max_length=180, blank=True)

    def clean(self):
        super().clean()
        if self.expires_at and self.valid_from and self.expires_at <= self.valid_from:
            from django.core.exceptions import ValidationError

            raise ValidationError("La fin du droit doit suivre son début.")
        if self.account_id and self.account.identity_id != self.identity_id:
            from django.core.exceptions import ValidationError

            raise ValidationError("Le compte doit appartenir à cette identité.")
        if (
            self.account_id
            and self.account.managed_contract_id
            and self.contract_id != self.account.managed_contract_id
        ):
            from django.core.exceptions import ValidationError

            raise ValidationError("Ce compte est dédié à un autre contrat.")

    def __str__(self):
        return f"{self.identity} → {self.resource} · {self.entitlement}"


class IdentityStateChange(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey(Identity, on_delete=models.PROTECT, related_name="state_changes")
    previous_status = models.CharField(max_length=16)
    next_status = models.CharField(max_length=16)
    effective_at = models.DateTimeField()

    def __str__(self):
        return f"{self.identity} · {self.previous_status} → {self.next_status}"


class IdentityApplication(models.Model):
    name = models.CharField(max_length=160, unique=True)
    key = models.SlugField(max_length=80, unique=True)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="owned_identity_applications",
    )
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "application connectée"
        verbose_name_plural = "applications connectées"
        ordering = ["name"]

    def __str__(self):
        return self.name


class AccessAssignment(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Actif"
        PENDING = "pending", "En attente d'approbation"
        REVOKED = "revoked", "Révoqué"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="identity_access_assignments",
    )
    application = models.ForeignKey(
        IdentityApplication, on_delete=models.CASCADE, related_name="access_assignments"
    )
    role = models.ForeignKey(
        "platform_core.BusinessRole",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="application_assignments",
    )
    entitlement = models.CharField(
        max_length=160, help_text="Droit ou profil cible dans l'application."
    )
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.ACTIVE)
    granted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    justification = models.TextField(blank=True)

    class Meta:
        verbose_name = "attribution d'accès"
        verbose_name_plural = "attributions d'accès"
        constraints = [
            models.UniqueConstraint(
                fields=["user", "application", "entitlement"], name="unique_identity_assignment"
            )
        ]

    def __str__(self):
        return f"{self.user} → {self.application}: {self.entitlement}"
