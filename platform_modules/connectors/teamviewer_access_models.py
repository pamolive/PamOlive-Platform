"""Immutable normalization proof plus a disposable fair-scan cursor."""

import uuid

from django.db import models
from django.utils import timezone

from platform_core.tenancy import ScopedModel

from .teamviewer_models import TeamViewerEvidence


class TeamViewerAccessObservation(TeamViewerEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.OneToOneField("connectors.TeamViewerSession", on_delete=models.PROTECT)
    event = models.OneToOneField("access.AccessEvent", on_delete=models.PROTECT)
    registered_at = models.DateTimeField(default=timezone.now)
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(TeamViewerEvidence.Meta):
        abstract = False


class TeamViewerAccessCursor(ScopedModel):
    """Not source evidence or authorization; corrupt cache resets safely."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.OneToOneField("platform_core.Organization", on_delete=models.PROTECT)
    last_session_id = models.UUIDField(null=True, blank=True)
    checked_at = models.DateTimeField(default=timezone.now)
    signature = models.CharField(max_length=64)
