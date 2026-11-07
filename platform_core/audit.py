import hashlib
import json

from django.db import transaction

from .models import AuditEvent, Organization


def digest(event):
    payload = {
        key: getattr(event, key)
        for key in (
            "sequence",
            "action",
            "object_type",
            "object_id",
            "summary",
            "metadata",
            "previous_hash",
            "actor_id",
        )
    }
    payload["organization_id"] = str(event.organization_id)
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


@transaction.atomic
def record(
    *, action, summary, actor=None, request=None, target=None, metadata=None, organization=None
):
    organization = organization or getattr(request, "organization", None)
    event = AuditEvent(
        organization=organization,
        actor=actor,
        action=action,
        summary=summary,
        object_type=target._meta.label_lower if target else "",
        object_id=str(target.pk) if target else "",
        source_ip=request.META.get("REMOTE_ADDR") if request else None,
        metadata=metadata or {},
    )
    if organization:
        head = Organization.objects.select_for_update().get(pk=organization.pk)
        event.sequence = head.audit_sequence + 1
        event.previous_hash = head.audit_hash
        event.event_hash = digest(event)
        head.audit_sequence, head.audit_hash = event.sequence, event.event_hash
        head.save(update_fields=["audit_sequence", "audit_hash"])
    event.save()
    return event


def verify_chain(organization):
    previous, sequence = "", 0
    for event in AuditEvent.objects.filter(organization=organization).order_by("sequence"):
        sequence += 1
        if (
            event.sequence != sequence
            or event.previous_hash != previous
            or event.event_hash != digest(event)
        ):
            return False
        previous = event.event_hash
    head = Organization.objects.get(pk=organization.pk)
    return (head.audit_sequence, head.audit_hash) == (sequence, previous)
