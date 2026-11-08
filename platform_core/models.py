import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from .tenancy import ScopedModel, TenantManager


class TimestampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Organization(TimestampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.SlugField(unique=True)
    name = models.CharField(max_length=160)
    active = models.BooleanField(default=True)
    audit_sequence = models.PositiveBigIntegerField(default=0, editable=False)
    audit_hash = models.CharField(max_length=64, blank=True, editable=False)

    def __str__(self):
        return self.name


class OrganizationMembership(TimestampedModel):
    organization = models.ForeignKey(
        Organization, on_delete=models.PROTECT, related_name="memberships"
    )
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    role = models.CharField(
        max_length=20,
        choices=[
            ("admin", "Administrateur"),
            ("operator", "Opérateur"),
            ("reviewer", "Approbateur"),
            ("auditor", "Auditeur"),
        ],
        default="auditor",
    )
    active = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "account"], name="unique_organization_membership"
            )
        ]


class ModuleActivation(TimestampedModel):
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    module_key = models.SlugField(max_length=80)
    version = models.CharField(max_length=30)
    release_hash = models.CharField(max_length=64, blank=True, default="")
    enabled = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "module_key"], name="unique_organization_module"
            )
        ]


class AccountSecurity(models.Model):
    account = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    encrypted_secret = models.TextField(blank=True)
    last_counter = models.BigIntegerField(default=-1)
    recovery_hashes = models.JSONField(default=list)
    freshness_minutes = models.PositiveSmallIntegerField(
        default=5,
        choices=[(2, "2 minutes"), (5, "5 minutes"), (10, "10 minutes"), (15, "15 minutes")],
    )
    failures = models.PositiveIntegerField(default=0)
    blocked_until = models.DateTimeField(null=True)


class LoginThrottle(models.Model):
    key = models.CharField(max_length=64, primary_key=True)
    failures = models.PositiveIntegerField(default=0)
    window_started = models.DateTimeField()


class InstalledModule(TimestampedModel):
    module_key = models.SlugField(unique=True, max_length=80)
    version = models.CharField(max_length=30)
    enabled = models.BooleanField(default=True)
    installed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="installed_pamolive_modules",
    )

    class Meta:
        verbose_name = "module installé"
        verbose_name_plural = "modules installés"

    def __str__(self):
        return self.module_key


class ExtensionDeployment(models.Model):
    """Infra delivery of code, separate from an organization's activation of features."""

    module_key = models.SlugField(primary_key=True, max_length=40)
    version = models.CharField(max_length=40)
    release_hash = models.CharField(max_length=64)
    manifest_hash = models.CharField(max_length=64)
    wheel_hash = models.CharField(max_length=64)
    delivered_at = models.DateTimeField()
    delivered_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)


class BusinessRole(TimestampedModel):
    key = models.SlugField(unique=True, max_length=80)
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL, blank=True, related_name="pamolive_business_roles"
    )

    class Meta:
        ordering = ["name"]
        verbose_name = "rôle métier"
        verbose_name_plural = "rôles métier"

    def __str__(self):
        return self.name


class RolePermission(models.Model):
    role = models.ForeignKey(
        BusinessRole, on_delete=models.CASCADE, related_name="permission_grants"
    )
    code = models.CharField(max_length=120)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["role", "code"], name="unique_role_permission")
        ]
        verbose_name = "permission métier"
        verbose_name_plural = "permissions métier"

    def __str__(self):
        return f"{self.role.key}: {self.code}"


class AuditQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError("Les événements d’audit sont immuables.")

    def delete(self):
        raise ValidationError("Les événements d’audit ne peuvent pas être supprimés.")


class AuditEvent(models.Model):
    objects = AuditQuerySet.as_manager()
    organization = models.ForeignKey(Organization, null=True, on_delete=models.PROTECT)
    sequence = models.PositiveBigIntegerField(null=True)
    previous_hash = models.CharField(max_length=64, blank=True)
    event_hash = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="pamolive_audit_events",
    )
    action = models.CharField(max_length=120, db_index=True)
    object_type = models.CharField(max_length=120, blank=True)
    object_id = models.CharField(max_length=120, blank=True)
    summary = models.CharField(max_length=255)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "sequence"], name="unique_organization_audit_sequence"
            )
        ]
        verbose_name = "événement d'audit"
        verbose_name_plural = "événements d'audit"

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M} · {self.action}"

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Les événements d'audit sont immuables.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Les événements d'audit ne peuvent pas être supprimés.")


class ImmutableTenantManager(TenantManager.from_queryset(AuditQuerySet)):
    pass


class ModuleEvent(ScopedModel):
    """A signed notification, never an authorization or executable command."""

    objects = ImmutableTenantManager()
    unscoped = AuditQuerySet.as_manager()
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    emitter = models.CharField(max_length=40)
    emitter_release = models.CharField(max_length=64, blank=True)
    topic = models.CharField(max_length=120)
    occurred_at = models.DateTimeField()
    actor_account_id = models.PositiveBigIntegerField(null=True)
    aggregate_type = models.CharField(max_length=120, blank=True)
    aggregate_id = models.CharField(max_length=120, blank=True)
    correlation_id = models.UUIDField()
    causation_id = models.UUIDField(null=True)
    depth = models.PositiveSmallIntegerField(default=0)
    payload = models.JSONField(default=dict)
    signature = models.CharField(max_length=64)
    audit = models.OneToOneField(AuditEvent, on_delete=models.PROTECT)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Les événements de module sont immuables.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Les événements de module sont immuables.")


class DeliveryQuerySet(models.QuerySet):
    def delete(self):
        raise ValidationError("Les destinataires d’un événement sont conservés.")

    def update(self, **kwargs):
        if set(kwargs) - {"status", "attempts", "available_at", "completed_at"}:
            raise ValidationError("Le périmètre d’une livraison est immuable.")
        return super().update(**kwargs)


class DeliveryManager(TenantManager.from_queryset(DeliveryQuerySet)):
    pass


class EventDelivery(ScopedModel):
    objects = DeliveryManager()
    unscoped = DeliveryQuerySet.as_manager()
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event = models.ForeignKey(ModuleEvent, on_delete=models.PROTECT)
    consumer = models.CharField(max_length=40)
    handler_name = models.CharField(max_length=60)
    contract_hash = models.CharField(max_length=64)
    signature = models.CharField(max_length=64)
    status = models.CharField(max_length=12, default="pending")
    attempts = models.PositiveSmallIntegerField(default=0)
    available_at = models.DateTimeField()
    completed_at = models.DateTimeField(null=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "event", "consumer", "handler_name"],
                name="unique_module_event_recipient",
            )
        ]
        indexes = [models.Index(fields=["organization", "status", "available_at"])]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            fields = (
                "organization_id",
                "event_id",
                "consumer",
                "handler_name",
                "contract_hash",
                "signature",
            )
            previous = type(self).unscoped.filter(pk=self.pk).values(*fields).get()
            if any(previous[field] != getattr(self, field) for field in fields):
                raise ValidationError("Le périmètre d’une livraison est immuable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Les destinataires d’un événement sont conservés.")


class EventAttempt(ScopedModel):
    objects = ImmutableTenantManager()
    unscoped = AuditQuerySet.as_manager()
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    delivery = models.ForeignKey(EventDelivery, on_delete=models.PROTECT)
    number = models.PositiveSmallIntegerField()
    outcome = models.CharField(max_length=12)
    error_code = models.CharField(max_length=80, blank=True)
    consumer_release = models.CharField(max_length=64)
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["delivery", "number"], name="unique_module_event_attempt"
            )
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Les preuves de traitement sont immuables.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Les preuves de traitement sont immuables.")


from .oidc.models import OIDCAttempt, OIDCDraft, OIDCLink, OIDCProvider  # noqa: E402,F401
