"""Observed configuration scopes and immutable, dated identifier attestations."""

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from .teamviewer_models import TeamViewerEvidence


class TeamViewerSighting(TeamViewerEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    collector = models.ForeignKey("connectors.TeamViewerCollector", on_delete=models.PROTECT)
    run = models.ForeignKey(
        "connectors.TeamViewerRun", on_delete=models.PROTECT, related_name="sightings"
    )
    report = models.ForeignKey(
        "connectors.TeamViewerReport", on_delete=models.PROTECT, related_name="sightings"
    )
    indexed_at = models.DateTimeField(default=timezone.now)
    signature = models.CharField(max_length=64)

    class Meta(TeamViewerEvidence.Meta):
        abstract = False
        constraints = [models.UniqueConstraint(fields=["run", "report"], name="tv_unique_sighting")]


class TeamViewerMapping(TeamViewerEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    collector = models.ForeignKey("connectors.TeamViewerCollector", on_delete=models.PROTECT)
    source_revision = models.PositiveIntegerField()
    source_config_hash = models.CharField(max_length=64)
    kind = models.CharField(
        max_length=16,
        choices=[
            ("account", "Compte opérateur TeamViewer"),
            ("actor", "Identité explicitement attribuée"),
            ("device", "Machine cible"),
        ],
    )
    remote_ref = models.CharField(max_length=180)
    sequence = models.PositiveIntegerField()
    account = models.ForeignKey(
        "identity.ExternalAccount", on_delete=models.PROTECT, null=True, blank=True
    )
    identity = models.ForeignKey(
        "identity.Identity", on_delete=models.PROTECT, null=True, blank=True
    )
    resource = models.ForeignKey(
        "identity.Resource", on_delete=models.PROTECT, null=True, blank=True
    )
    withdrawn = models.BooleanField(default=False)
    target_snapshot = models.JSONField(default=dict, blank=True)
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField(null=True, blank=True)
    verification_reference = models.CharField(max_length=255)
    published_at = models.DateTimeField(default=timezone.now)
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    mfa_verified_at = models.DateTimeField()
    mfa_window_minutes = models.PositiveSmallIntegerField()
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(TeamViewerEvidence.Meta):
        abstract = False
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "collector",
                    "source_revision",
                    "kind",
                    "remote_ref",
                    "sequence",
                ],
                name="tv_unique_mapping_revision",
            ),
            models.CheckConstraint(
                condition=models.Q(source_revision__gte=1, sequence__gte=1),
                name="tv_mapping_revision_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(valid_until__isnull=True)
                | models.Q(valid_until__gt=models.F("valid_from")),
                name="tv_mapping_time_order",
            ),
            models.CheckConstraint(
                condition=models.Q(mfa_window_minutes__in=[2, 5, 10, 15]),
                name="tv_mapping_mfa_window",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        withdrawn=True,
                        account__isnull=True,
                        identity__isnull=True,
                        resource__isnull=True,
                    )
                    | models.Q(
                        withdrawn=False,
                        kind="account",
                        account__isnull=False,
                        identity__isnull=True,
                        resource__isnull=True,
                    )
                    | models.Q(
                        withdrawn=False,
                        kind="actor",
                        account__isnull=True,
                        identity__isnull=False,
                        resource__isnull=True,
                    )
                    | models.Q(
                        withdrawn=False,
                        kind="device",
                        account__isnull=True,
                        identity__isnull=True,
                        resource__isnull=False,
                    )
                )
                & models.Q(kind__in=["account", "actor", "device"]),
                name="tv_mapping_typed_target",
            ),
        ]

    @property
    def target(self):
        return {"account": self.account, "actor": self.identity, "device": self.resource}[self.kind]
