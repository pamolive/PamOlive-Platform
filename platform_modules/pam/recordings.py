"""Authorized, bounded decryption; verify the keyed chain and sealed ending."""

import json
import time

from cryptography.fernet import InvalidToken
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils.crypto import constant_time_compare, salted_hmac

from platform_core.audit import digest
from platform_core.authorization import require_recent_authentication
from platform_core.models import AuditEvent
from platform_core.services import authorize
from platform_core.tenancy import organization_context

from .models import LIVE_CONNECTION_STATES, RecordingChunk, RelayConnection
from .sessions import browser_hash, chunk_digest, recording_seal, session_actor


def _grant_proof(grant):
    content = {key: value for key, value in grant.items() if key != "proof"}
    return salted_hmac(
        "pamolive.recording.grant.v1",
        json.dumps(content, sort_keys=True, separators=(",", ":")),
        algorithm="sha256",
    ).hexdigest()


def issue_recording_grant(item, actor, session_key):
    require_recent_authentication(actor, item.organization)
    if session_actor(session_key).pk != actor.pk:
        raise PermissionDenied
    authorize_recording(item, actor)
    grant = {
        "organization": str(item.organization_id),
        "connection": str(item.pk),
        "account": actor.pk,
        "browser": browser_hash(session_key),
        "expires_at": int(time.time()) + 600,
    }
    return dict(grant, proof=_grant_proof(grant))


def validate_grant(item, actor, session_key, grant):
    if (
        grant.get("organization") != str(item.organization_id)
        or grant.get("connection") != str(item.pk)
        or grant.get("account") != actor.pk
        or grant.get("browser") != browser_hash(session_key)
        or grant.get("expires_at", 0) <= time.time()
        or not constant_time_compare(grant.get("proof", ""), _grant_proof(grant))
    ):
        raise PermissionDenied


def authorize_recording(item, actor):
    authorize(
        actor,
        item.organization,
        roles=(
            ("admin", "operator", "reviewer", "auditor")
            if item.opened_by_id == actor.pk
            else ("admin", "auditor")
        ),
    )
    if item.status in LIVE_CONNECTION_STATES or not item.ended_at:
        raise ValidationError("La capture n’est consultable qu’après la fermeture du relais.")
    with organization_context(item.organization):
        anchor = (
            AuditEvent.objects.filter(
                organization=item.organization,
                action="pam.relay.ended.v1",
                object_type="pam.relayconnection",
                object_id=str(item.pk),
            )
            .order_by("-sequence")
            .first()
        )
    if (
        not anchor
        or anchor.event_hash != digest(anchor)
        or not constant_time_compare(
            anchor.metadata.get("recording_seal", ""), recording_seal(item)
        )
    ):
        raise ValidationError("L’ancrage de l’enregistrement ne peut pas être vérifié.")


def recording_page(connection_id, organization, session_key, grant, sequence, previous):
    from platform_core.security import cipher

    actor = session_actor(session_key)
    with organization_context(organization):
        item = RelayConnection.objects.select_related("organization").get(pk=connection_id)
        validate_grant(item, actor, session_key, grant)
        authorize_recording(item, actor)
        chunks = list(
            RecordingChunk.objects.filter(
                connection=item,
                sequence__gt=sequence,
            ).order_by("sequence")[:16]
        )
        output = []
        for chunk in chunks:
            encrypted = bytes(chunk.encrypted_payload)
            if (
                len(encrypted) > 100000
                or chunk.payload_size > 65536
                or chunk.sequence != sequence + 1
                or chunk.previous_hash != previous
                or not constant_time_compare(
                    chunk.chunk_hash,
                    chunk_digest(
                        item,
                        chunk.sequence,
                        previous,
                        chunk.elapsed_ms,
                        chunk.payload_size,
                        encrypted,
                    ),
                )
            ):
                raise ValidationError("L’intégrité des blocs de capture ne peut pas être établie.")
            try:
                payload = cipher().decrypt(encrypted)
            except InvalidToken:
                raise ValidationError("Le bloc de capture ne peut pas être déchiffré.") from None
            if len(payload) != chunk.payload_size:
                raise ValidationError("Taille de capture incohérente.")
            output.append(payload)
            sequence, previous = chunk.sequence, chunk.chunk_hash
        if not chunks and (sequence != item.recording_chunks or previous != item.recording_hash):
            raise ValidationError("Des blocs de capture sont absents.")
        return output, sequence, previous
