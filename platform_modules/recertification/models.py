import uuid

from django.conf import settings
from django.db import models

from platform_core.tenancy import ScopedModel


class Campaign(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Nom", max_length=180)
    due_at = models.DateTimeField("Échéance")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Review(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    campaign = models.ForeignKey(Campaign, on_delete=models.PROTECT, related_name="reviews")
    grant = models.ForeignKey("identity.Grant", on_delete=models.PROTECT)
    decision = models.CharField(max_length=10, default="pending")
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT)
    comment = models.TextField(blank=True)
    reviewed_at = models.DateTimeField(null=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "campaign", "grant"], name="unique_campaign_grant"
            )
        ]
