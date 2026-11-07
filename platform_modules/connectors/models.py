import uuid

from django.db import models

from platform_core.tenancy import ScopedModel


class EventSource(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Nom de source", max_length=180)
    token_hash = models.CharField(max_length=64, unique=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
