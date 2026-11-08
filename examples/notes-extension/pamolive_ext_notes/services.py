from django.db import transaction

from platform_core.extensions import api

from .models import Note


def list_notes(*, actor, organization):
    api.authorize(actor, organization, "example_notes.note.view")
    return Note.objects.filter(organization=organization).order_by("-created_at")[:100]


@transaction.atomic
def create_note(*, actor, organization, title, body):
    api.authorize(actor, organization, "example_notes.note.create")
    note = Note(organization=organization, author=actor, title=title, body=body)
    note.full_clean()
    note.save()
    api.audit(
        actor=actor,
        organization=organization,
        permission_code="example_notes.note.create",
        action="example_notes.note.created.v1",
        summary="Note créée dans l’organisation",
        target=note,
    )
    return note
