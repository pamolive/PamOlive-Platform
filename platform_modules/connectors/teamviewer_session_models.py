"""A physical session is distinct from each source reading and interpretation."""

import uuid

from django.db import models
from django.utils import timezone

from .teamviewer_models import TeamViewerEvidence


class TeamViewerSession(TeamViewerEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    remote_id = models.UUIDField()
    origin = models.OneToOneField("connectors.TeamViewerSighting", on_delete=models.PROTECT)
    registered_at = models.DateTimeField(default=timezone.now)
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(TeamViewerEvidence.Meta):
        abstract = False
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "remote_id"], name="tv_unique_physical_session"
            )
        ]


class TeamViewerSessionEvidence(TeamViewerEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(
        TeamViewerSession, on_delete=models.PROTECT, related_name="observations"
    )
    sighting = models.OneToOneField(
        "connectors.TeamViewerSighting", on_delete=models.PROTECT, related_name="session_evidence"
    )
    registered_at = models.DateTimeField(default=timezone.now)
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(TeamViewerEvidence.Meta):
        abstract = False
