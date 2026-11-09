from django.core.exceptions import ValidationError

from platform_core.tenancy import current_organization

from .models import EventReceipt


def record_receipt(event):
    organization = current_organization()
    if str(organization.pk) != event.organization_id:
        raise ValidationError("Notification d’une autre organisation.")
    if event.topic not in ("identity.identity.created.v1", "example_notes.note.created.v1"):
        raise ValidationError("Schéma de notification non pris en charge.")
    _record(organization, event, event.aggregate_id)


def record_periodic_receipt(event):
    organization = current_organization()
    if (
        str(organization.pk) != event.organization_id
        or event.topic != "core.module_schedule.elapsed.v1"
        or event.emitter != "core"
        or event.actor_account_id is not None
        or event.payload["name"] != "sample_refresh_v1"
    ):
        raise ValidationError("Signal périodique inattendu.")
    _record(organization, event, event.payload["slot_utc"])


def _record(organization, event, aggregate_id):
    EventReceipt.objects.get_or_create(
        event_id=event.event_id,
        organization=organization,
        defaults={
            "topic": event.topic,
            "aggregate_id": aggregate_id,
            "occurred_at": event.occurred_at,
        },
    )
