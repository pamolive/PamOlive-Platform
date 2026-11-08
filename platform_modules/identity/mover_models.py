"""Tenant-local business role revisions and immutable lifecycle provenance."""

import uuid

from django.db import models

from platform_core.attestations import ImmutableEvidence


class MoverEvidence(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)
    body = models.JSONField()

    class Meta(ImmutableEvidence.Meta):
        abstract = True


class RoleRevision(MoverEvidence):
    key = models.SlugField(max_length=64)
    revision = models.PositiveIntegerField()

    class Meta(MoverEvidence.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=("organization", "key", "revision"), name="identity_mover_role_revision"
            ),
        ]

    def __str__(self):
        return f"{self.body.get('name', self.key)} · r{self.revision}"


class MoveProposal(MoverEvidence):
    identity = models.ForeignKey("identity.Identity", on_delete=models.PROTECT)

    class Meta(MoverEvidence.Meta):
        indexes = [models.Index(fields=("organization", "identity"), name="identity_mover_subject")]


class MoveDecision(MoverEvidence):
    proposal = models.OneToOneField(MoveProposal, on_delete=models.PROTECT)
    identity = models.ForeignKey("identity.Identity", on_delete=models.PROTECT)
    applied = models.BooleanField()
    sequence = models.PositiveBigIntegerField(null=True, blank=True)

    class Meta(MoverEvidence.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=("organization", "identity", "sequence"), name="identity_mover_order"
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(applied=True, sequence__gte=1, sequence__isnull=False)
                    | models.Q(applied=False, sequence__isnull=True)
                ),
                name="identity_mover_applied_order",
            ),
        ]


class MoveAccess(MoverEvidence):
    decision = models.ForeignKey(MoveDecision, on_delete=models.PROTECT)
    role = models.ForeignKey(RoleRevision, on_delete=models.PROTECT)
    intent = models.OneToOneField("access.AccessIntent", on_delete=models.PROTECT)


class MoveGrant(MoverEvidence):
    access = models.OneToOneField(MoveAccess, on_delete=models.PROTECT)
    grant = models.OneToOneField("identity.Grant", on_delete=models.PROTECT)
