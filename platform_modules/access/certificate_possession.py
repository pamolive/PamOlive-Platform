"""Verify possession at challenge time, independently of access authorization."""

import base64
import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.utils import timezone

from platform_core.audit import digest, record
from platform_core.models import AuditEvent, LoginThrottle, Organization
from platform_core.services import require_module
from platform_core.tenancy import organization_context
from platform_modules.connectors.models import EventSource
from platform_modules.connectors.services import source_from_token
from platform_modules.identity.models import Credential

from .models import AccessEvent
from .observations import sign, source_snapshot

SCHEMA = "pamolive.certificate-possession/1"
SALT = "pamolive.certificate-possession.challenge.v1"
ACTION = "access.certificate.possession_verified.v1"
AGE_SECONDS = 120
MAX_DER = 8192
MAX_SIGNATURE = 512
CALLS_PER_MINUTE = 30


class Unavailable(Exception):
    pass


class Conflict(ValidationError):
    pass


class RateLimited(PermissionDenied):
    pass


def _now():
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT clock_timestamp()")
            return cursor.fetchone()[0]
    return timezone.now()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _message(payload):
    return b"PamOlive certificate possession v1\n" + _canonical(payload)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _encode(data):
    return base64.b64encode(data).decode("ascii")


def _decode(value, maximum):
    if not isinstance(value, str) or not 0 < len(value) <= 4 * ((maximum + 2) // 3):
        raise ValidationError("Preuve encodée invalide.")
    try:
        data = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise ValidationError("Preuve encodée invalide.") from error
    if not 0 < len(data) <= maximum or _encode(data) != value:
        raise ValidationError("Preuve encodée invalide.")
    return data


def _fingerprint(value):
    if value.lower().startswith("sha256:"):
        value = value[7:]
    if re.fullmatch(r"(?:[a-fA-F0-9]{2}:){31}[a-fA-F0-9]{2}", value):
        value = value.replace(":", "")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise Unavailable("Empreinte SHA-256 indisponible.")
    return value.lower()


def _lock(source):
    organization = (
        Organization.objects.select_for_update()
        .filter(pk=source.organization_id, active=True)
        .first()
    )
    if organization is None:
        raise PermissionDenied
    for module in ("access", "connectors"):
        require_module(organization, module)
    if (
        not EventSource.objects.select_for_update()
        .filter(pk=source.pk, active=True, token_hash=source.token_hash)
        .exists()
    ):
        raise PermissionDenied
    return organization


@transaction.atomic
def consume_budget(token):
    if not re.fullmatch(r"[A-Za-z0-9_-]{64}", token):
        raise PermissionDenied
    source = source_from_token(token)
    if source is None:
        raise PermissionDenied
    with organization_context(source.organization):
        _lock(source)
        minute = _now().replace(second=0, microsecond=0)
        key = _sha(b"pamolive.certificate-possession.rate.v1\0" + source.pk.bytes)
        row, _ = LoginThrottle.objects.select_for_update().get_or_create(
            key=key, defaults={"window_started": minute}
        )
        used = row.failures if row.window_started == minute else 0
        if used >= CALLS_PER_MINUTE:
            raise RateLimited
        row.failures = used + 1
        row.window_started = minute
        row.save(update_fields=["window_started", "failures"])
    return source


def _receipts(event, action):
    return list(
        AuditEvent.objects.filter(
            organization_id=event.organization_id,
            action=action,
            object_type=event._meta.label_lower,
            object_id=str(event.pk),
        ).order_by("sequence")[:2]
    )


def _token_ingested(event):
    receipts = _receipts(event, "access.event.received.v1")
    return (
        len(receipts) == 1
        and receipts[0].actor_id is None
        and receipts[0].event_hash == digest(receipts[0])
    )


def _scope(source, event_id, now):
    event = AccessEvent.objects.filter(
        pk=event_id, source=str(source.pk), domain="certificate", credential__isnull=False
    ).first()
    if event is None:
        raise Unavailable
    if not _token_ingested(event):
        raise Unavailable
    credential = (
        Credential.objects.select_for_update()
        .filter(pk=event.credential_id, kind="certificate")
        .first()
    )
    if credential is None or (credential.expires_at is not None and credential.expires_at <= now):
        raise Unavailable
    if _receipts(event, ACTION):
        raise Conflict("Un constat de possession est déjà conservé pour cet événement.")
    return event, {
        "schema": SCHEMA,
        "organization_id": str(event.organization_id),
        "source_id": str(source.pk),
        "event_id": str(event.pk),
        "event_sha256": _sha(_canonical(source_snapshot(event))),
        "credential_id": str(credential.pk),
        "certificate_sha256": _fingerprint(credential.fingerprint),
    }


@transaction.atomic
def issue(source, event_id):
    with organization_context(source.organization):
        _lock(source)
        now = _now()
        _, payload = _scope(source, event_id, now)
        payload.update(issued_at=int(now.timestamp()), nonce=secrets.token_hex(32))
        return {
            "schema": SCHEMA,
            "challenge": signing.dumps(payload, salt=SALT),
            "message_b64": _encode(_message(payload)),
            "certificate_sha256": payload["certificate_sha256"],
            "expires_in_seconds": AGE_SECONDS,
        }


def _verify_key(payload, der, signed, now):
    if not hmac.compare_digest(_sha(der), payload["certificate_sha256"]):
        raise ValidationError("Le certificat ne correspond pas à l’empreinte enregistrée.")
    try:
        cert = x509.load_der_x509_certificate(der)
        if cert.public_bytes(serialization.Encoding.DER) != der:
            raise ValidationError("Le certificat doit être encodé en DER.")
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ValidationError("Le certificat n’est pas valide à la date du contrôle.")
        try:
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            usage = None
        if usage is not None and not usage.digital_signature:
            raise ValidationError("Ce certificat n’autorise pas la signature numérique.")
        key = cert.public_key()
        message = _message(payload)
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signed, message)
            return "Ed25519"
        if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
            key.verify(signed, message, ec.ECDSA(hashes.SHA256()))
            return "ECDSA-P256-SHA256"
        if isinstance(key, rsa.RSAPublicKey) and 2048 <= key.key_size <= 4096:
            key.verify(
                signed,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
            return "RSA-PSS-SHA256"
    except (
        InvalidSignature,
        UnsupportedAlgorithm,
        ValueError,
        x509.DuplicateExtension,
        x509.InvalidVersion,
        x509.UnsupportedGeneralNameType,
    ) as error:
        raise ValidationError("Certificat ou signature invalide.") from error
    raise ValidationError("Algorithme de clé non pris en charge.")


@transaction.atomic
def submit(source, event_id, challenge, certificate, signed):
    if not isinstance(challenge, str) or not re.fullmatch(r"[A-Za-z0-9_:\-]{1,2048}", challenge):
        raise ValidationError("Défi invalide.")
    try:
        payload = signing.loads(challenge, salt=SALT, fallback_keys=[])
    except (signing.BadSignature, TypeError, ValueError) as error:
        raise ValidationError("Défi invalide.") from error
    der = _decode(certificate, MAX_DER)
    signature = _decode(signed, MAX_SIGNATURE)
    with organization_context(source.organization):
        organization = _lock(source)
        now = _now()
        event, scope = _scope(source, event_id, now)
        if (
            not isinstance(payload, dict)
            or set(payload) != set(scope) | {"issued_at", "nonce"}
            or any(payload[key] != value for key, value in scope.items())
            or type(payload["issued_at"]) is not int
            or not 0 <= now.timestamp() - payload["issued_at"] < AGE_SECONDS
            or not isinstance(payload["nonce"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", payload["nonce"])
        ):
            raise ValidationError("Défi expiré ou hors périmètre.")
        algorithm = _verify_key(payload, der, signature, now)
        body = {
            "challenge_payload": payload,
            "verified_at": now.isoformat(),
            "algorithm": algorithm,
            "certificate_der_b64": certificate,
            "signature_b64": signed,
        }
        proof = record(
            action=ACTION,
            summary="Possession de clé vérifiée au moment du défi",
            organization=organization,
            target=event,
            metadata={"proof": body, "seal": sign(body, "certificate-possession")},
        )
        return _summary(proof, body)


def _summary(proof, body):
    return {
        "status": "verified",
        "proof_id": str(proof.pk),
        "verified_at": body["verified_at"],
        "algorithm": body["algorithm"],
        "certificate_sha256": body["challenge_payload"]["certificate_sha256"],
        "historical_access_verified": False,
        "authorization_inferred": False,
    }


def summary(event):
    if event.domain != "certificate" or not event.credential_id:
        return None
    proofs = _receipts(event, ACTION)
    if not proofs:
        return {"status": "not_verified"}
    try:
        if len(proofs) == 1:
            proof = proofs[0]
            body = proof.metadata["proof"]
            payload = body["challenge_payload"]
            verified_at = datetime.fromisoformat(body["verified_at"])
            bound = {
                "schema": SCHEMA,
                "event_id": str(event.pk),
                "source_id": event.source,
                "organization_id": str(event.organization_id),
                "credential_id": str(event.credential_id),
                "event_sha256": _sha(_canonical(source_snapshot(event))),
            }
            if (
                proof.event_hash == digest(proof)
                and hmac.compare_digest(
                    proof.metadata["seal"], sign(body, "certificate-possession")
                )
                and all(payload[key] == value for key, value in bound.items())
                and timezone.is_aware(verified_at)
                and type(payload["issued_at"]) is int
                and 0 <= verified_at.timestamp() - payload["issued_at"] < AGE_SECONDS
                and _token_ingested(event)
                and _verify_key(
                    payload,
                    _decode(body["certificate_der_b64"], MAX_DER),
                    _decode(body["signature_b64"], MAX_SIGNATURE),
                    verified_at,
                )
                == body["algorithm"]
            ):
                return _summary(proof, body)
    except (TypeError, ValueError, KeyError, ValidationError):
        pass
    return {"status": "invalid"}


def verify_restored_proofs():
    """Recheck historical proof bytes, without trusting current source/credential state."""
    count = 0
    for row in AuditEvent.objects.filter(action=ACTION).iterator(chunk_size=100):
        try:
            event = AccessEvent.unscoped.filter(
                pk=row.object_id,
                organization_id=row.organization_id,
            ).first()
        except (ValueError, ValidationError):
            event = None
        result = summary(event) if event is not None else None
        if not result or result["status"] != "verified" or result["proof_id"] != str(row.pk):
            raise ValidationError("Preuve de possession restaurée invalide.")
        count += 1
    return count
