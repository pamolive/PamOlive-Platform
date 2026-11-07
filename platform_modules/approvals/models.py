import uuid

from django.conf import settings
from django.db import models

from platform_core.tenancy import ScopedModel


class ApprovalDecision(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    intent = models.OneToOneField("access.AccessIntent", on_delete=models.PROTECT)
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    approved = models.BooleanField()
    comment = models.TextField()
    decided_at = models.DateTimeField(auto_now_add=True)
