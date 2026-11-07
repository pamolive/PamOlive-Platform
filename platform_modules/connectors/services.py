import hashlib
import secrets

from django.db import transaction

from platform_core.audit import record
from platform_core.services import authorize, require_module

from .models import EventSource


@transaction.atomic
def create_source(name, *, actor, organization):
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "connectors")
    token = secrets.token_urlsafe(48)
    source = EventSource(
        organization=organization, name=name, token_hash=hashlib.sha256(token.encode()).hexdigest()
    )
    source.full_clean()
    source.save()
    record(
        action="connectors.source.created.v1",
        summary=name,
        actor=actor,
        organization=organization,
        target=source,
    )
    return source, token


def source_from_token(token):
    return (
        EventSource.unscoped.select_related("organization")
        .filter(
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            active=True,
            organization__active=True,
        )
        .first()
    )
