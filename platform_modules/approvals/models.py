import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from platform_core.tenancy import ScopedModel


class ApprovalDecision(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    intent = models.ForeignKey(
        "access.AccessIntent", on_delete=models.PROTECT, related_name="decisions"
    )
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    reviewer_binding = models.ForeignKey(
        "identity.LoginIdentityBinding",
        null=True,
        blank=True,
        editable=False,
        on_delete=models.PROTECT,
    )
    reviewer_identity = models.ForeignKey(
        "identity.Identity",
        null=True,
        blank=True,
        editable=False,
        on_delete=models.PROTECT,
    )
    scope_hash = models.CharField(max_length=64, blank=True, editable=False)
    signature = models.CharField(max_length=64, blank=True, editable=False)
    mfa_verified_at = models.DateTimeField(null=True, blank=True, editable=False)
    mfa_window_minutes = models.PositiveSmallIntegerField(default=0, editable=False)
    approved = models.BooleanField()
    comment = models.TextField()
    decided_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "intent", "reviewer"], name="unique_intent_reviewer"
            ),
            models.UniqueConstraint(
                fields=["organization", "intent", "reviewer_identity"],
                condition=models.Q(reviewer_identity__isnull=False),
                name="unique_intent_reviewer_person",
            ),
        ]

    def clean(self):
        super().clean()
        if self.reviewer_binding_id and (
            self.reviewer_binding.identity_id != self.reviewer_identity_id
            or self.reviewer_binding.login_account_id != self.reviewer_id
        ):
            raise ValidationError("L’approbateur et son lien de personne ne concordent pas.")
