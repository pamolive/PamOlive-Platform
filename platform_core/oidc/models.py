import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from platform_core.tenancy import ScopedModel, TenantManager


class OIDCQuerySet(models.QuerySet):
    def update(self, **kwargs):
        if set(kwargs) - set(self.model.mutable_fields):
            raise ValidationError("Le périmètre d’une preuve OIDC est immuable.")
        for field in ("encrypted_config", "encrypted_flow"):
            if field in kwargs and kwargs[field] != "":
                raise ValidationError("Une capsule OIDC peut être effacée, jamais remplacée.")
        return super().update(**kwargs)

    def delete(self):
        raise ValidationError("Désactivez le domaine ou révoquez l’association OIDC.")


class OIDCManager(TenantManager.from_queryset(OIDCQuerySet)):
    pass


class OIDCScopedModel(ScopedModel):
    objects = OIDCManager()
    unscoped = OIDCQuerySet.as_manager()
    mutable_fields = ()

    class Meta(ScopedModel.Meta):
        abstract = True

    def save(self, *args, **kwargs):
        if not self._state.adding:
            fields = [
                field.attname
                for field in self._meta.concrete_fields
                if field.name not in self.mutable_fields
            ]
            previous = type(self).unscoped.filter(pk=self.pk).values(*fields).get()
            if any(previous[field] != getattr(self, field) for field in fields):
                raise ValidationError("Le périmètre d’une preuve OIDC est immuable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Désactivez le domaine ou révoquez l’association OIDC.")


class OIDCProvider(OIDCScopedModel):
    mutable_fields = (
        "name",
        "encrypted_secret",
        "algorithm",
        "auth_method",
        "redirect_uri",
        "config_hash",
        "metadata",
        "verified_at",
        "verification_proof",
        "enabled",
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    slug = models.SlugField(max_length=50)
    name = models.CharField(max_length=100)
    issuer = models.URLField(max_length=500)
    client_id = models.CharField(max_length=255)
    encrypted_secret = models.TextField()
    algorithm = models.CharField(max_length=8, default="RS256")
    auth_method = models.CharField(max_length=30, default="client_secret_basic")
    redirect_uri = models.URLField(max_length=700)
    config_hash = models.CharField(max_length=64)
    metadata = models.JSONField(default=dict)
    verified_at = models.DateTimeField()
    verification_proof = models.CharField(max_length=64)
    enabled = models.BooleanField(default=False)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(fields=["organization", "slug"], name="oidc_realm_slug")
        ]


class OIDCDraft(OIDCScopedModel):
    mutable_fields = ("encrypted_config", "encrypted_result", "verified_at", "verification_proof")
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    provider = models.ForeignKey(OIDCProvider, null=True, on_delete=models.PROTECT)
    session_hash = models.CharField(max_length=64)
    encrypted_config = models.TextField()
    config_hash = models.CharField(max_length=64)
    metadata = models.JSONField(default=dict)
    encrypted_result = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(db_index=True)
    verified_at = models.DateTimeField(null=True)
    verification_proof = models.CharField(max_length=64, blank=True)


class OIDCLink(OIDCScopedModel):
    mutable_fields = ("revoked_at",)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    provider = models.ForeignKey(OIDCProvider, on_delete=models.PROTECT)
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    subject = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=timezone.now)
    mfa_verified_at = models.DateTimeField()
    mfa_window_minutes = models.PositiveSmallIntegerField()
    signature = models.CharField(max_length=64)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "provider", "subject"],
                condition=models.Q(revoked_at__isnull=True),
                name="oidc_active_subject",
            ),
            models.UniqueConstraint(
                fields=["organization", "provider", "account"],
                condition=models.Q(revoked_at__isnull=True),
                name="oidc_active_account",
            ),
        ]


class OIDCAttempt(OIDCScopedModel):
    mutable_fields = (
        "encrypted_flow",
        "used_at",
        "pending_link",
        "pending_until",
        "pending_proof",
        "completed_at",
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    provider = models.ForeignKey(OIDCProvider, null=True, on_delete=models.PROTECT)
    draft = models.ForeignKey(OIDCDraft, null=True, on_delete=models.PROTECT)
    requester = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT)
    purpose = models.CharField(max_length=8)
    session_hash = models.CharField(max_length=64)
    state_hash = models.CharField(max_length=64, unique=True)
    config_hash = models.CharField(max_length=64)
    encrypted_flow = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(db_index=True)
    used_at = models.DateTimeField(null=True)
    pending_link = models.ForeignKey(OIDCLink, null=True, on_delete=models.PROTECT)
    pending_until = models.DateTimeField(null=True)
    pending_proof = models.CharField(max_length=64, blank=True)
    completed_at = models.DateTimeField(null=True)
