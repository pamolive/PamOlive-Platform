"""Transactional authority and evidence. A Guacamole connection ID is never authority."""

import hashlib
import json
import re
import secrets
import uuid
from copy import copy
from datetime import timedelta

import asyncssh
from cryptography.fernet import InvalidToken
from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY, get_user_model
from django.contrib.sessions.models import Session
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection as database_connection
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac

from platform_core.audit import record
from platform_core.authorization import require_recent_authentication
from platform_core.models import Organization
from platform_core.security import cipher
from platform_core.services import authorize, require_module
from platform_core.tenancy import organization_context
from platform_modules.governance.policy import approval_requirements, enforce_authorization

from .context import network_context
from .destination import TransportFailure, host_port
from .models import LIVE_CONNECTION_STATES, RecordingChunk, RelayConnection, SessionEndpoint
from .probe import certificate_pin, probe_rdp, probe_ssh, ssh_host_key
from .services import open_lease


def browser_hash(key):
    return salted_hmac("pamolive.pam.browser.v1", key, algorithm="sha256").hexdigest()


def session_actor(session_key):
    if not isinstance(session_key, str) or not re.fullmatch(r"[a-z0-9]{32}", session_key):
        raise PermissionDenied
    session = Session.objects.filter(
        session_key=session_key, expire_date__gt=timezone.now()
    ).first()
    if not session:
        raise PermissionDenied
    data = session.get_decoded()
    if data.get(BACKEND_SESSION_KEY) not in settings.AUTHENTICATION_BACKENDS:
        raise PermissionDenied
    try:
        actor = get_user_model().objects.filter(pk=data.get(SESSION_KEY), is_active=True).first()
    except (ValueError, TypeError):
        raise PermissionDenied from None
    if not actor:
        raise PermissionDenied
    hashes = [actor.get_session_auth_hash(), *actor.get_session_auth_fallback_hash()]
    if not any(constant_time_compare(data.get(HASH_SESSION_KEY, ""), value) for value in hashes):
        raise PermissionDenied
    return actor


def _operator(actor, organization):
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "pam")
    require_recent_authentication(actor, organization)


def _secret(auth_method, protocol, password, private_key, passphrase):
    if auth_method == "password":
        if not password or len(password) > 4096 or "\x00" in password:
            raise ValidationError("Un mot de passe initial valide est nécessaire.")
        return {"password": password}
    if auth_method != "private_key" or protocol != "ssh" or not private_key:
        raise ValidationError("Méthode d’authentification incompatible.")
    if len(private_key) > 16384 or len(passphrase) > 1024:
        raise ValidationError("Clé privée trop volumineuse.")
    try:
        key = asyncssh.import_private_key(private_key, passphrase or None)
        return {"private_key": key.export_private_key("openssh").decode()}
    except (ValueError, asyncssh.KeyImportError):
        raise ValidationError("Clé privée ou phrase secrète invalide.") from None


@transaction.atomic
def configure_endpoint(
    *,
    actor,
    organization,
    name,
    resource,
    account,
    protocol,
    hostname,
    port,
    auth_method,
    password="",
    private_key="",
    passphrase="",
    domain="",
    host_key="",
    rdp_pin="",
    endpoint_id=None,
):
    _operator(actor, organization)
    hostname, port = host_port(hostname, port)
    if protocol not in ("ssh", "rdp") or not name.strip():
        raise ValidationError("Nom et protocole requis.")
    if any(ord(char) < 32 for char in domain + account.username) or len(domain) > 180:
        raise ValidationError("Identifiant ou domaine invalide.")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        endpoint = (
            SessionEndpoint.objects.select_for_update().get(pk=endpoint_id)
            if endpoint_id
            else SessionEndpoint(organization=organization)
        )
        if any(value.organization_id != organization.pk for value in (resource, account)):
            raise PermissionDenied
        if not account.active or account.identity.status != "active":
            raise ValidationError("Le compte et son identité doivent être actifs.")
        secret_changed = bool(password or private_key or passphrase)
        if not endpoint_id or endpoint.auth_method != auth_method or secret_changed:
            material = _secret(auth_method, protocol, password, private_key, passphrase)
            endpoint.encrypted_secret = cipher().encrypt(json.dumps(material).encode()).decode()
        endpoint.name, endpoint.resource, endpoint.account = name.strip(), resource, account
        endpoint.protocol, endpoint.hostname, endpoint.port = protocol, hostname, port
        endpoint.domain, endpoint.auth_method = domain, auth_method
        endpoint.ssh_host_key = (
            ssh_host_key(host_key).export_public_key().decode().strip() if protocol == "ssh" else ""
        )
        endpoint.certificate_pin = certificate_pin(rdp_pin) if protocol == "rdp" else ""
        endpoint.revision += int(bool(endpoint_id))
        endpoint.enabled, endpoint.verified_revision = False, None
        endpoint.tested_at, endpoint.test_code = None, ""
        endpoint.full_clean()
        endpoint.save()
        record(
            action="pam.endpoint.configured.v1",
            summary=f"Cible PAM : {endpoint.name}",
            actor=actor,
            organization=organization,
            target=endpoint,
            metadata={"revision": endpoint.revision, "credentials": "encrypted"},
        )
        return endpoint


def probe_endpoint(endpoint_id, *, actor, organization):
    from asgiref.sync import async_to_sync

    _operator(actor, organization)
    with organization_context(organization):
        endpoint = SessionEndpoint.objects.get(pk=endpoint_id)
        revision = endpoint.revision
        try:
            if endpoint.protocol == "ssh":
                result = async_to_sync(probe_ssh)(
                    endpoint.hostname, endpoint.port, endpoint.ssh_host_key
                )
            else:
                result = async_to_sync(probe_rdp)(
                    endpoint.hostname, endpoint.port, endpoint.certificate_pin
                )
            code, verified = "server_identity_verified_credentials_not_tested", True
            observation = {"address": result.address, "fingerprint": result.fingerprint}
        except TransportFailure as error:
            code, verified, observation = str(error), False, {}
        with transaction.atomic():
            Organization.objects.select_for_update().get(pk=organization.pk)
            current = SessionEndpoint.objects.select_for_update().get(pk=endpoint_id)
            if current.revision != revision:
                raise ValidationError("La configuration a changé pendant le test.")
            current.tested_at, current.test_code = timezone.now(), code
            current.verified_revision = revision if verified else None
            if not verified:
                current.enabled = False
            current.save()
            record(
                action="pam.endpoint.tested.v1",
                summary=f"Test de cible PAM : {code}",
                actor=actor,
                organization=organization,
                target=current,
                metadata=observation,
            )
        return verified, code


@transaction.atomic
def set_endpoint_enabled(endpoint_id, *, actor, organization, enabled):
    _operator(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        endpoint = SessionEndpoint.objects.get(pk=endpoint_id)
        if enabled:
            if endpoint.protocol not in settings.PAM_SESSION_PROTOCOLS:
                raise ValidationError("Ce transport n’a pas encore franchi sa porte de validation.")
            if (
                endpoint.verified_revision != endpoint.revision
                or not endpoint.tested_at
                or timezone.now() - endpoint.tested_at > timedelta(minutes=15)
            ):
                raise ValidationError("Testez cette révision avant de l’activer (moins de 15 min).")
            host_port(endpoint.hostname, endpoint.port)
        endpoint.enabled = enabled
        endpoint.save(update_fields=["enabled"])
        record(
            action="pam.endpoint.activation.v1",
            summary=f"Cible active : {enabled}",
            actor=actor,
            organization=organization,
            target=endpoint,
        )
        return endpoint


def endpoint_digest(endpoint):
    content = [
        endpoint.resource_id,
        endpoint.account_id,
        endpoint.protocol,
        endpoint.hostname,
        endpoint.port,
        endpoint.domain,
        endpoint.auth_method,
        endpoint.encrypted_secret,
        endpoint.ssh_host_key,
        endpoint.certificate_pin,
    ]
    return hashlib.sha256(
        json.dumps(content, default=str, separators=(",", ":")).encode()
    ).hexdigest()


def authority_seal(item):
    content = [
        str(item.pk),
        str(item.organization_id),
        item.opened_by_id,
        str(item.lease_id),
        str(item.endpoint_id),
        item.endpoint_revision,
        item.browser_session_hash,
        item.client_ip,
        item.ticket_expires_at.isoformat(),
        item.expires_at.isoformat(),
        item.authority_snapshot,
    ]
    return salted_hmac(
        "pamolive.relay.authority.v1",
        json.dumps(content, sort_keys=True, separators=(",", ":")),
        secret=settings.PAMOLIVE_ENCRYPTION_KEY,
        algorithm="sha256",
    ).hexdigest()


def _check_authority(item, *, session_key, client_ip):
    now, lease, endpoint = timezone.now(), item.lease, item.endpoint
    actor = session_actor(session_key)
    organization = item.organization
    authorize(actor, organization)
    require_module(organization, "pam")
    intent = lease.intent
    if (
        actor.pk != item.opened_by_id
        or actor.pk != lease.opened_by_id
        or not constant_time_compare(item.browser_session_hash, browser_hash(session_key))
        or item.client_ip != client_ip
        or item.stop_requested_at
        or lease.status != "active"
        or now >= min(lease.expires_at, item.expires_at)
        or intent.fulfillment != "pam"
        or intent.status != "approved"
        or not intent.starts_at <= now < intent.ends_at
        or intent.requested_by_id != actor.pk
        or not intent.account_id
        or intent.account.identity_id != intent.identity_id
        or not intent.account.active
        or intent.account.kind != "privileged"
        or intent.identity.status != "active"
        or not intent.approved_at
        or not endpoint.enabled
        or endpoint.revision != item.endpoint_revision
        or endpoint.verified_revision != endpoint.revision
        or endpoint.protocol not in settings.PAM_SESSION_PROTOCOLS
        or endpoint.protocol != intent.method.casefold()
        or endpoint.resource_id != intent.resource_id
        or endpoint.account_id != intent.account_id
        or not constant_time_compare(item.authority_seal, authority_seal(item))
        or item.authority_snapshot.get("intent_id") != str(intent.pk)
        or item.authority_snapshot.get("identity_id") != str(intent.identity_id)
        or item.authority_snapshot.get("account_username") != intent.account.username
        or item.authority_snapshot.get("reason") != intent.reason
        or item.authority_snapshot.get("reference") != intent.reference
        or item.authority_snapshot.get("contract_id") != str(intent.contract_id or "")
        or item.authority_snapshot.get("privilege") != intent.privilege
        or item.authority_snapshot.get("approved_at") != intent.approved_at.isoformat()
        or item.authority_snapshot.get("endpoint_digest") != endpoint_digest(endpoint)
    ):
        raise PermissionDenied("L’autorisation du relais n’est plus applicable.")
    host_port(endpoint.hostname, endpoint.port)
    observed = copy(intent)
    observed.location, observed.country_code = network_context(client_ip)
    enforce_authorization(observed, organization=organization, remaining=True)
    if not approval_requirements(intent, at=intent.approved_at)["complete"]:
        raise PermissionDenied("Les décisions indépendantes d’approbation ne sont pas établies.")
    return actor


def _related(queryset):
    return queryset.select_related(
        "organization",
        "opened_by",
        "endpoint",
        "lease__opened_by",
        "lease__intent__identity",
        "lease__intent__account",
        "lease__intent__resource",
        "lease__intent__contract",
    )


@transaction.atomic
def launch_session(intent_id, *, actor, organization, session_key, client_ip):
    authorize(actor, organization)
    assurance = require_recent_authentication(actor, organization)
    if session_actor(session_key).pk != actor.pk:
        raise PermissionDenied
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        lease = open_lease(intent_id, actor=actor, organization=organization)
        intent = lease.intent
        endpoint = SessionEndpoint.objects.get(
            resource_id=intent.resource_id,
            account_id=intent.account_id,
            protocol=intent.method.casefold(),
        )
        now = timezone.now()
        reap_connections(organization)
        active = RelayConnection.objects.filter(status__in=LIVE_CONNECTION_STATES)
        if (
            active.filter(lease=lease).exists()
            or active.count() >= settings.PAM_MAX_CONNECTIONS_ORG
            or active.filter(opened_by=actor).count() >= settings.PAM_MAX_CONNECTIONS_USER
        ):
            raise ValidationError(
                "Un relais est déjà ouvert ou la limite de sessions est atteinte."
            )
        token = secrets.token_urlsafe(32)
        item = RelayConnection(
            organization=organization,
            lease=lease,
            endpoint=endpoint,
            opened_by=actor,
            endpoint_revision=endpoint.revision,
            browser_session_hash=browser_hash(session_key),
            client_ip=client_ip,
            ticket_hash=hashlib.sha256(token.encode()).hexdigest(),
            ticket_expires_at=now + timedelta(seconds=30),
            expires_at=min(
                lease.expires_at,
                intent.ends_at,
                now + timedelta(seconds=settings.PAM_MAX_SESSION_SECONDS),
            ),
            authority_snapshot={
                "intent_id": str(intent.pk),
                "identity_id": str(intent.identity_id),
                "resource_id": str(intent.resource_id),
                "account_id": str(intent.account_id),
                "account_username": intent.account.username,
                "reason": intent.reason,
                "reference": intent.reference,
                "contract_id": str(intent.contract_id or ""),
                "privilege": intent.privilege,
                "starts_at": intent.starts_at.isoformat(),
                "ends_at": intent.ends_at.isoformat(),
                "method": intent.method,
                "portal_login": actor.get_username(),
                "mfa_verified_at": assurance.verified_at,
                "approved_at": intent.approved_at.isoformat() if intent.approved_at else "",
                "decisions": sorted(
                    str(value)
                    for value in intent.decisions.filter(approved=True).values_list("pk", flat=True)
                ),
                "endpoint_digest": endpoint_digest(endpoint),
            },
        )
        item.authority_seal = authority_seal(item)
        _check_authority(item, session_key=session_key, client_ip=client_ip)
        item.full_clean()
        item.save()
        record(
            action="pam.relay.authorized.v1",
            summary="Ouverture de relais autorisée par MFA",
            actor=actor,
            organization=organization,
            target=item,
            metadata={"endpoint_revision": endpoint.revision, "lease": str(lease.pk)},
        )
        return item, token


@transaction.atomic
def claim_session(connection_id, *, actor, session_key, client_ip, ticket, instance_id):
    candidate = RelayConnection.unscoped.filter(pk=connection_id, opened_by=actor).first()
    if not candidate or not isinstance(ticket, str) or len(ticket) > 128:
        raise PermissionDenied
    organization = Organization.objects.select_for_update().get(pk=candidate.organization_id)
    with organization_context(organization):
        item = _related(RelayConnection.objects.select_for_update(of=("self",))).get(
            pk=connection_id
        )
        if (
            item.status != "pending"
            or timezone.now() >= item.ticket_expires_at
            or not item.ticket_hash
            or not constant_time_compare(
                item.ticket_hash, hashlib.sha256(ticket.encode()).hexdigest()
            )
        ):
            raise PermissionDenied
        _check_authority(item, session_key=session_key, client_ip=client_ip)
        item.ticket_hash, item.status, item.owner_token = "", "connecting", uuid.uuid4()
        item.instance_id, item.heartbeat_at = instance_id[:80], timezone.now()
        item.save(
            update_fields=["ticket_hash", "status", "owner_token", "instance_id", "heartbeat_at"]
        )
        return item.pk, organization.pk, item.owner_token


@transaction.atomic
def check_session(
    connection_id, organization, owner_token, *, session_key, client_ip, target_snapshot=None
):
    # Bound a stuck database check. The async relay also has an overall deadline
    # and closes its native socket if authority cannot be established in time.
    if database_connection.vendor == "postgresql":
        with database_connection.cursor() as cursor:
            cursor.execute("SET LOCAL lock_timeout = '1s'")
            cursor.execute("SET LOCAL statement_timeout = '2s'")
    if target_snapshot is not None:
        Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        item = _related(RelayConnection.objects.select_for_update(of=("self",))).get(
            pk=connection_id
        )
        if item.owner_token != owner_token or item.status not in ("connecting", "active"):
            raise PermissionDenied
        _check_authority(item, session_key=session_key, client_ip=client_ip)
        item.heartbeat_at = timezone.now()
        if target_snapshot is not None:
            item.target_snapshot = target_snapshot
            item.status, item.connected_at = "active", timezone.now()
            record(
                action="pam.relay.opened.v1",
                summary="Relais PAM ouvert ; authentification distante non attestée",
                organization=organization,
                actor=item.opened_by,
                target=item,
                metadata={"target": target_snapshot, "target_authentication_attested": False},
            )
        item.save(update_fields=["heartbeat_at", "target_snapshot", "status", "connected_at"])
        return item


def endpoint_credentials(item):
    try:
        return json.loads(cipher().decrypt(item.endpoint.encrypted_secret.encode()))
    except (InvalidToken, ValueError):
        raise TransportFailure("session_credentials_unavailable") from None


def chunk_digest(item, sequence, previous, elapsed_ms, payload_size, encrypted):
    header = json.dumps(
        [str(item.organization_id), str(item.pk), sequence, previous, elapsed_ms, payload_size],
        separators=(",", ":"),
    ).encode()
    return salted_hmac(
        "pamolive.recording.chunk.v1",
        header + bytes(encrypted),
        secret=settings.PAMOLIVE_ENCRYPTION_KEY,
        algorithm="sha256",
    ).hexdigest()


def recording_seal(item):
    header = json.dumps(
        [
            str(item.organization_id),
            str(item.pk),
            item.opened_by_id,
            item.endpoint_revision,
            item.recording_chunks,
            item.recording_bytes,
            item.recording_hash,
            item.ended_at.isoformat(),
            item.end_reason,
            item.recording_complete,
            item.target_snapshot,
            item.authority_snapshot,
            item.authority_seal,
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return salted_hmac(
        "pamolive.recording.end.v1",
        header,
        secret=settings.PAMOLIVE_ENCRYPTION_KEY,
        algorithm="sha256",
    ).hexdigest()


@transaction.atomic
def append_recording(connection_id, organization, owner_token, payload, elapsed_ms):
    if not isinstance(payload, bytes) or not 0 < len(payload) <= 65536 or elapsed_ms < 0:
        raise ValidationError("Bloc d’enregistrement invalide.")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        item = RelayConnection.objects.select_for_update().get(pk=connection_id)
        if item.owner_token != owner_token or item.status not in ("connecting", "active"):
            raise PermissionDenied
        total = RelayConnection.objects.aggregate(total=Sum("recording_bytes"))["total"] or 0
        if (
            item.recording_bytes + len(payload) > settings.PAM_MAX_RECORDING_BYTES
            or total + len(payload) > settings.PAM_MAX_RECORDING_ORG_BYTES
        ):
            raise TransportFailure("recording_quota_exceeded")
        last = RecordingChunk.objects.filter(connection=item).order_by("-sequence").first()
        if last and elapsed_ms < last.elapsed_ms:
            raise ValidationError("L’horloge monotone de l’enregistrement ne peut pas reculer.")
        encrypted = cipher().encrypt(payload)
        sequence, previous = item.recording_chunks + 1, item.recording_hash
        digest = chunk_digest(item, sequence, previous, elapsed_ms, len(payload), encrypted)
        RecordingChunk.objects.create(
            organization=organization,
            connection=item,
            sequence=sequence,
            previous_hash=previous,
            elapsed_ms=elapsed_ms,
            payload_size=len(payload),
            encrypted_payload=encrypted,
            chunk_hash=digest,
        )
        item.recording_chunks, item.recording_hash = sequence, digest
        item.recording_bytes += len(payload)
        item.save(update_fields=["recording_chunks", "recording_hash", "recording_bytes"])
        return digest


@transaction.atomic
def finish_session(connection_id, organization, owner_token, *, reason, complete):
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        item = RelayConnection.objects.select_for_update().get(pk=connection_id)
        if item.owner_token != owner_token or item.status not in LIVE_CONNECTION_STATES:
            return
        _end(item, reason=reason, complete=complete)


def _end(item, *, reason, complete):
    if item.stop_requested_at and reason == "authority_lost":
        reason = "stop_requested"
    if not reason or len(reason) > 80 or not all(c.isalnum() or c == "_" for c in reason):
        raise ValidationError("Motif de fin invalide.")
    item.status = (
        "ended" if reason in ("client_closed", "native_closed", "stop_requested") else "failed"
    )
    item.end_reason, item.ended_at = reason, timezone.now()
    item.recording_complete, item.ticket_hash = complete, ""
    item.save(
        update_fields=["status", "end_reason", "ended_at", "recording_complete", "ticket_hash"]
    )
    record(
        action="pam.relay.ended.v1",
        summary=f"Relais terminé : {reason}",
        organization=item.organization,
        actor=item.opened_by,
        target=item,
        metadata={
            "recording_hash": item.recording_hash,
            "chunks": item.recording_chunks,
            "bytes": item.recording_bytes,
            "capture_complete": complete,
            "recording_seal": recording_seal(item),
            "target": item.target_snapshot,
            "native_session_logoff_confirmed": False,
        },
    )


@transaction.atomic
def stop_session(connection_id, *, actor, organization):
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        item = RelayConnection.objects.select_for_update().get(pk=connection_id)
        if item.opened_by_id == actor.pk:
            authorize(actor, organization, roles=("admin", "operator", "reviewer", "auditor"))
        else:
            _operator(actor, organization)
        if item.status not in LIVE_CONNECTION_STATES:
            return
        item.stop_requested_at = timezone.now()
        item.save(update_fields=["stop_requested_at"])
        if item.status == "pending":
            _end(item, reason="stop_requested", complete=False)
        record(
            action="pam.relay.stop_requested.v1",
            summary="Fermeture du relais demandée",
            organization=organization,
            actor=actor,
            target=item,
        )


@transaction.atomic
def reap_connections(organization):
    Organization.objects.select_for_update().get(pk=organization.pk)
    now = timezone.now()
    with organization_context(organization):
        for item in RelayConnection.objects.select_for_update().filter(
            status__in=LIVE_CONNECTION_STATES
        ):
            if item.status == "pending" and item.ticket_expires_at <= now:
                _end(item, reason="ticket_expired", complete=False)
            elif item.status != "pending" and (
                not item.heartbeat_at or item.heartbeat_at < now - timedelta(seconds=15)
            ):
                _end(item, reason="relay_owner_lost", complete=False)
