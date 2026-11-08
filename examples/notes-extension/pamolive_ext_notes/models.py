import uuid

from django.conf import settings
from django.db import models


class Note(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("platform_core.Organization", on_delete=models.PROTECT)
    title = models.CharField(max_length=160)
    body = models.TextField(max_length=2000)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class EventReceipt(models.Model):
    """Local projection only: a notification never provisions or authorizes access."""

    event_id = models.UUIDField(primary_key=True)
    organization = models.ForeignKey("platform_core.Organization", on_delete=models.PROTECT)
    topic = models.CharField(max_length=120)
    aggregate_id = models.CharField(max_length=120)
    occurred_at = models.DateTimeField()
