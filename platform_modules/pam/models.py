import uuid

from django.conf import settings
from django.db import models

from platform_core.tenancy import ScopedModel


class SessionLease(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    intent = models.ForeignKey("access.AccessIntent", on_delete=models.PROTECT)
    opened_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    started_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True)
    status = models.CharField(max_length=16, default="active")
    broker_reference = models.CharField(max_length=180, blank=True)
