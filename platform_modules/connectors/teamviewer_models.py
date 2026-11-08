"""Tenant-local configuration and immutable, minimized TeamViewer source evidence."""

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from platform_core.tenancy import ScopedModel, TenantManager


class EvidenceQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError("Les preuves TeamViewer sont conservées sans réécriture.")

    def delete(self):
        raise ValidationError("Les preuves TeamViewer ne sont pas supprimées automatiquement.")


class EvidenceManager(TenantManager.from_queryset(EvidenceQuerySet)):
    pass


class CollectorQuerySet(models.QuerySet):
    def update(self, **kwargs):
        if {"id", "pk", "organization", "organization_id", "source", "source_id"} & kwargs.keys():
            raise ValidationError("Le périmètre de la source TeamViewer est immuable.")
        return super().update(**kwargs)

    def delete(self):
        raise ValidationError("Désactivez le collecteur ; son historique est conservé.")


class TeamViewerCollector(ScopedModel):
    objects = TenantManager.from_queryset(CollectorQuerySet)()
    unscoped = CollectorQuerySet.as_manager()
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=180)
    source = models.OneToOneField("connectors.EventSource", on_delete=models.PROTECT)
    encrypted_token = models.TextField()
    start_at = models.DateTimeField()
    collect_notes = models.BooleanField(default=False)
    config_hash = models.CharField(max_length=64)
    config_proof = models.CharField(max_length=64)
    tested_at = models.DateTimeField()
    configured_at = models.DateTimeField(default=timezone.now)
    configured_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    mfa_verified_at = models.DateTimeField()
    mfa_window_minutes = models.PositiveSmallIntegerField()
    revision = models.PositiveIntegerField(default=1)
    enabled = models.BooleanField(default=False)
    activation = models.JSONField(default=dict, blank=True)
    activation_proof = models.CharField(max_length=64, blank=True)
    scan_until = models.DateTimeField(null=True, blank=True)
    next_offset = models.UUIDField(null=True, blank=True)
    scan_last_end = models.DateTimeField(null=True, blank=True)
    scan_proof = models.CharField(max_length=64, blank=True)
    next_run_at = models.DateTimeField(default=timezone.now)
    claim_token = models.UUIDField(null=True, blank=True)
    claim_until = models.DateTimeField(null=True, blank=True)
    last_code = models.CharField(max_length=80, blank=True)

    class Meta(ScopedModel.Meta):
        abstract = False
        constraints = [
            models.CheckConstraint(
                condition=models.Q(mfa_window_minutes__in=[2, 5, 10, 15]), name="tv_mfa_window"
            ),
            models.CheckConstraint(condition=models.Q(revision__gte=1), name="tv_config_revision"),
        ]

    def delete(self, *args, **kwargs):
        raise ValidationError("Désactivez le collecteur ; son historique est conservé.")

    def save(self, *args, **kwargs):
        if not self._state.adding:
            old = type(self).unscoped.values("organization_id", "source_id").get(pk=self.pk)
            if any(old[key] != getattr(self, key) for key in old):
                raise ValidationError("Le périmètre de la source TeamViewer est immuable.")
        return super().save(*args, **kwargs)


class TeamViewerEvidence(ScopedModel):
    objects = EvidenceManager()
    unscoped = EvidenceQuerySet.as_manager()

    class Meta(ScopedModel.Meta):
        abstract = True

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Une preuve TeamViewer est immuable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Les preuves TeamViewer sont conservées.")


class TeamViewerReport(TeamViewerEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    collector = models.ForeignKey(TeamViewerCollector, on_delete=models.PROTECT)
    remote_id = models.UUIDField()
    account_ref = models.CharField(max_length=180, blank=True)
    device_ref = models.CharField(max_length=180, blank=True)
    started_at = models.DateTimeField()
    ended_at = models.DateTimeField()
    encrypted_notes = models.TextField(blank=True)
    notes_included = models.BooleanField(default=False)
    content_hash = models.CharField(max_length=64)
    observed_at = models.DateTimeField(default=timezone.now)
    signature = models.CharField(max_length=64)

    class Meta(TeamViewerEvidence.Meta):
        abstract = False
        constraints = [
            models.CheckConstraint(
                condition=models.Q(ended_at__gte=models.F("started_at")),
                name="tv_report_time_order",
            ),
            models.UniqueConstraint(
                fields=["organization", "collector", "remote_id", "content_hash"],
                name="tv_unique_report_content",
            ),
        ]


class TeamViewerRun(TeamViewerEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    collector = models.ForeignKey(TeamViewerCollector, on_delete=models.PROTECT)
    revision = models.PositiveIntegerField()
    config_hash = models.CharField(max_length=64)
    activation_hash = models.CharField(max_length=64)
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(default=timezone.now)
    since = models.DateTimeField()
    until = models.DateTimeField()
    code = models.CharField(max_length=80)
    status = models.CharField(max_length=16)
    cursor_input = models.UUIDField(null=True, blank=True)
    cursor_output = models.UUIDField(null=True, blank=True)
    report_manifest = models.JSONField(default=list)
    manifest_hash = models.CharField(max_length=64)
    signature = models.CharField(max_length=64)
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)

    class Meta(TeamViewerEvidence.Meta):
        abstract = False
        constraints = [
            models.CheckConstraint(
                condition=models.Q(finished_at__gte=models.F("started_at")),
                name="tv_run_time_order",
            ),
            models.CheckConstraint(
                condition=models.Q(until__gt=models.F("since")), name="tv_run_window"
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=["page", "complete", "failed", "discarded"]),
                name="tv_run_status",
            ),
        ]
