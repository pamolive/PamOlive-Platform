from django.core.exceptions import ValidationError

from platform_core.tenancy import current_organization

from .models import EventReceipt


def record_receipt(event):
    organization = current_organization()
    if str(organization.pk) != event.organization_id:
        raise ValidationError("Notification d’une autre organisation.")
    if event.topic not in ("identity.identity.created.v1", "example_notes.note.created.v1"):
        raise ValidationError("Schéma de notification non pris en charge.")
    EventReceipt.objects.get_or_create(
        event_id=event.event_id,
        defaults={
            "organization": organization,
            "topic": event.topic,
            "aggregate_id": event.aggregate_id,
            "occurred_at": event.occurred_at,
        },
    )
