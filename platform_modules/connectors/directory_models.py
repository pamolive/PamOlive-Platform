"""Read-only directory inventory; observations never confer an IAM or PAM right."""

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from platform_core.attestations import ImmutableEvidence
from platform_core.tenancy import ScopedModel


class DirectorySource(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=180)
    provider = models.CharField(max_length=12, choices=[(x, x) for x in ("ad", "ldap", "entra")])
    destination = models.JSONField(default=dict)
    synthetic = models.BooleanField(default=True)
    enabled = models.BooleanField(default=False)
    encrypted_credential = models.TextField()
    credential_seal = models.CharField(max_length=64)
    credential_revision = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    audit = models.ForeignKey("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            old = type(self).unscoped.get(pk=self.pk)
            if any(
                getattr(old, key) != getattr(self, key)
                for key in (
                    "organization_id",
                    "provider",
                    "destination",
                    "synthetic",
                    "created_by_id",
                    "created_at",
                    "audit_id",
                    "signature",
                )
            ):
                raise ValidationError("Une nouvelle destination exige une nouvelle source.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Les sources et leur historique sont conservés.")


class DirectoryRun(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.ForeignKey(DirectorySource, on_delete=models.PROTECT)
    source_revision = models.PositiveIntegerField()
    idempotency_key = models.CharField(max_length=180)
    provenance = models.CharField(max_length=40)
    complete = models.BooleanField(default=False)
    page_count = models.PositiveIntegerField(default=1)
    record_count = models.PositiveIntegerField()
    facts_sha256 = models.CharField(max_length=64)
    transport_identity = models.JSONField(default=dict, blank=True)
    limitations = models.JSONField(default=list, blank=True)
    observed_at = models.DateTimeField(default=timezone.now, editable=False)
    accepted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    audit = models.ForeignKey("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(ImmutableEvidence.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "source", "idempotency_key"],
                name="directory_run_idempotency",
            ),
            models.CheckConstraint(
                condition=models.Q(record_count__lte=1000), name="directory_run_record_bound"
            ),
            models.CheckConstraint(
                condition=models.Q(page_count__gte=1, page_count__lte=20),
                name="directory_run_page_bound",
            ),
        ]


class DirectoryFact(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    run = models.ForeignKey(DirectoryRun, on_delete=models.PROTECT, related_name="facts")
    remote_id = models.UUIDField()
    username = models.CharField(max_length=180)
    enabled = models.BooleanField(null=True)
    groups = models.JSONField(default=list)
    signature = models.CharField(max_length=64)

    class Meta(ImmutableEvidence.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "run", "remote_id"], name="directory_run_remote_unique"
            )
        ]


class DirectoryMapping(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.ForeignKey(DirectorySource, on_delete=models.PROTECT)
    source_revision = models.PositiveIntegerField()
    remote_id = models.UUIDField()
    account = models.ForeignKey("identity.ExternalAccount", on_delete=models.PROTECT)
    sequence = models.PositiveIntegerField()
    kind = models.CharField(max_length=8, choices=[("bind", "bind"), ("revoke", "revoke")])
    previous = models.ForeignKey("self", null=True, blank=True, on_delete=models.PROTECT)
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    decided_at = models.DateTimeField(default=timezone.now, editable=False)
    audit = models.ForeignKey("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(ImmutableEvidence.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "source", "remote_id", "sequence"],
                name="directory_mapping_sequence",
            ),
            models.CheckConstraint(
                condition=models.Q(sequence__gte=1), name="directory_mapping_positive_sequence"
            ),
        ]
