import uuid

from django.conf import settings
from django.db import models

from platform_core.tenancy import ScopedModel


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

    def clean(self):
        super().clean()
        if self.account_id and self.account.identity_id != self.identity_id:
            from django.core.exceptions import ValidationError

            raise ValidationError("Le compte doit appartenir à cette identité.")

    def __str__(self):
        return f"{self.identity} → {self.resource} · {self.entitlement}"


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
