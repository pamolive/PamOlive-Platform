"""Business-system assertions are provenance, never local access approval."""

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from platform_core.tenancy import ScopedModel, TenantManager


class BusinessEvidenceQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError("Les preuves métier ne sont pas réécrites.")

    def delete(self):
        raise ValidationError("Les preuves métier sont conservées.")


class BusinessEvidence(ScopedModel):
    objects = TenantManager.from_queryset(BusinessEvidenceQuerySet)()
    unscoped = BusinessEvidenceQuerySet.as_manager()

    class Meta(ScopedModel.Meta):
        abstract = True

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Une preuve métier existante est immuable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Les preuves métier sont conservées.")


class BusinessSourceQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError("La configuration métier passe par une publication auditée.")

    def delete(self):
        raise ValidationError("Désactivez la source ; ses preuves sont conservées.")


class BusinessSource(ScopedModel):
    objects = TenantManager.from_queryset(BusinessSourceQuerySet)()
    unscoped = BusinessSourceQuerySet.as_manager()
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.SlugField(max_length=80)
    name = models.CharField(max_length=180)
    token_hash = models.CharField(max_length=64, unique=True)
    revision = models.PositiveIntegerField(default=1)
    active = models.BooleanField(default=True)
    freshness_seconds = models.PositiveIntegerField(default=900)
    configured_at = models.DateTimeField(default=timezone.now)
    configured_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    mfa_verified_at = models.DateTimeField()
    mfa_window_minutes = models.PositiveSmallIntegerField()
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)
    rate_bucket = models.DateTimeField(null=True, blank=True)
    rate_count = models.PositiveSmallIntegerField(default=0)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(fields=["organization", "key"], name="business_source_key"),
            models.CheckConstraint(condition=models.Q(revision__gte=1), name="business_source_rev"),
            models.CheckConstraint(
                condition=models.Q(freshness_seconds__gte=60, freshness_seconds__lte=86400),
                name="business_source_freshness",
            ),
            models.CheckConstraint(
                condition=models.Q(mfa_window_minutes__in=[2, 5, 10, 15]),
                name="business_source_mfa_window",
            ),
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        from .business import verify_source

        if not self._state.adding:
            old = type(self).unscoped.get(pk=self.pk)
            if (self.organization_id, self.key) != (old.organization_id, old.key):
                raise ValidationError("Le périmètre et la clé de la source sont immuables.")
        if not verify_source(self):
            raise ValidationError("La configuration métier doit être signée et auditée.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Désactivez la source ; ses preuves sont conservées.")


class BusinessRecord(BusinessEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.ForeignKey(BusinessSource, on_delete=models.PROTECT)
    external_id = models.CharField(max_length=180)
    registered_at = models.DateTimeField(default=timezone.now)

    class Meta(BusinessEvidence.Meta):
        abstract = False
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "source", "external_id"], name="business_record_source_id"
            ),
        ]

    def __str__(self):
        return f"{self.source} · {self.external_id}"


class BusinessReceipt(BusinessEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record = models.ForeignKey(BusinessRecord, on_delete=models.PROTECT, related_name="receipts")
    sequence = models.PositiveIntegerField()
    source_revision = models.PositiveIntegerField()
    payload = models.JSONField(default=dict)
    content_hash = models.CharField(max_length=64)
    received_at = models.DateTimeField(default=timezone.now)
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(BusinessEvidence.Meta):
        abstract = False
        constraints = [
            models.UniqueConstraint(
                fields=["record", "sequence"], name="business_receipt_sequence"
            ),
            models.CheckConstraint(
                condition=models.Q(sequence__gte=1, source_revision__gte=1),
                name="business_receipt_positive",
            ),
        ]


class BusinessAssociation(BusinessEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    intent = models.ForeignKey("access.AccessIntent", on_delete=models.PROTECT)
    record = models.ForeignKey(BusinessRecord, on_delete=models.PROTECT)
    receipt = models.ForeignKey(BusinessReceipt, on_delete=models.PROTECT)
    sequence = models.PositiveIntegerField()
    withdrawn = models.BooleanField(default=False)
    rationale = models.CharField(max_length=500)
    intent_scope = models.JSONField(default=dict)
    published_at = models.DateTimeField(default=timezone.now)
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    mfa_verified_at = models.DateTimeField()
    mfa_window_minutes = models.PositiveSmallIntegerField()
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(BusinessEvidence.Meta):
        abstract = False
        constraints = [
            models.UniqueConstraint(
                fields=["intent", "record", "sequence"], name="business_association_sequence"
            ),
            models.CheckConstraint(
                condition=models.Q(sequence__gte=1), name="business_association_positive"
            ),
            models.CheckConstraint(
                condition=models.Q(mfa_window_minutes__in=[2, 5, 10, 15]),
                name="business_association_mfa",
            ),
        ]
