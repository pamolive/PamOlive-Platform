"""WebAuthn proof of possession for independently commissioned PAM identities."""

import base64
import hashlib
import json
import re
import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import timedelta
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import salted_hmac
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import decode_credential_public_key, decoded_public_key_to_cryptography
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from platform_core.attestations import canonical
from platform_core.models import Organization
from platform_core.security import cipher

from .trust_auth_models import PAMTrustAuthorization, PAMTrustChallenge, PAMTrustEnrollment
from .trust_models import PAMAuthenticatorState
from .trust_registry import recognized_registry, registry_person

CEREMONY_SECONDS = 120
_request = ContextVar("pamolive_action_request", default=None)
_ROLES = {
    "request": "requester",
    "approve": "reviewer",
    "refuse": "reviewer",
    "sponsor": "sponsor",
    "launch": "requester",
}
_MUTATIONS = {"registry.change", "policy.change", "recovery", "target.change", "identity.change"}
_ALGORITHMS = [
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.EDDSA,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
]


class PAMActionRequired(PermissionDenied):
    def __init__(self, action, payload):
        self.action, self.payload = action, payload
        super().__init__("Validez cette action avec votre authentificateur PAM.")


def b64encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64decode(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,16384}", value):
        raise ValidationError("Encodage WebAuthn invalide.")
    result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if b64encode(result) != value:
        raise ValidationError("Encodage WebAuthn non canonique.")
    return result


def public_key_fingerprint(public_key):
    decoded = decode_credential_public_key(b64decode(public_key))
    if decoded.alg not in _ALGORITHMS:
        raise ValidationError("Algorithme d’authentificateur non autorisé.")
    key = decoded_public_key_to_cryptography(decoded)
    return hashlib.sha256(
        key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()


def payload_hash(payload):
    if not isinstance(payload, dict):
        raise ValidationError("Périmètre d’action invalide.")
    value = canonical(payload).encode()
    if len(value) > 65536:
        raise ValidationError("Périmètre d’action trop volumineux.")
    return hashlib.sha256(value).hexdigest()


def _configuration():
    rp_id = getattr(settings, "PAM_TRUST_RP_ID", "")
    origin = getattr(settings, "PAM_TRUST_ORIGIN", "")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https" or not rp_id or parsed.hostname != rp_id
        or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password
        or origin != f"https://{parsed.netloc}" or "\\" in origin
    ):
        raise PermissionDenied("Configurez l’origine HTTPS et le RP ID PAM indépendants.")
    return rp_id, origin


def _session_hash(request):
    if not request.session.session_key:
        request.session.create()
    return salted_hmac(
        "pamolive.pam.trust.browser.v1", request.session.session_key, algorithm="sha256"
    ).hexdigest()


def _user_handle(organization_id, person_id):
    return hashlib.sha256(f"pamolive.pam.person.v1/{organization_id}/{person_id}".encode()).digest()


def _person(registry, actor, action):
    if action not in _ROLES and action not in _MUTATIONS and action != "enroll":
        raise PermissionDenied("Action PAM inconnue.")
    person_id, person = registry_person(registry, actor, role=_ROLES.get(action))
    if action in _MUTATIONS:
        custodian = registry.body["custodians"].get(str(person_id), {})
        if not custodian.get("active"):
            raise PermissionDenied("Une habilitation de dépositaire est nécessaire.")
    return str(person_id), person


def _credentials(person):
    rp_id, origin = _configuration()
    return [
        credential for credential in person["authenticators"]
        if credential.get("active") and credential["rp_id"] == rp_id
        and credential["origin"] == origin
    ]


def _binding(challenge):
    return {
        "schema": "pamolive.pam.action-challenge/1",
        "id": str(challenge.pk), "organization": str(challenge.organization_id),
        "account": str(challenge.account_id), "person": str(challenge.person_id),
        "action": challenge.action, "payload_hash": challenge.payload_hash,
        "session_hash": challenge.session_hash, "registry_hash": challenge.registry_hash,
        "registry_generation": str(challenge.registry_generation),
        "registry_revision": challenge.registry_revision, "policy_hash": challenge.policy_hash,
        "credential_id": challenge.credential_id,
        "public_key": challenge.public_key, "rp_id": challenge.rp_id, "origin": challenge.origin,
        "nonce": challenge.nonce, "expires_at": challenge.expires_at,
    }


def challenge_bytes(challenge):
    return hashlib.sha256(canonical(_binding(challenge)).encode()).digest()


def _new_challenge(
    request, registry, person_id, action, digest, credential=None, replay=None, encrypted_form="",
):
    rp_id, origin = _configuration()
    if PAMTrustChallenge.unscoped.filter(
        organization=request.organization, account=request.user,
        used_at__isnull=True, expires_at__gt=timezone.now(),
    ).count() >= 5:
        raise PermissionDenied("Terminez ou laissez expirer les défis PAM déjà ouverts.")
    challenge = PAMTrustChallenge(
        organization=request.organization, account=request.user, person_id=person_id,
        action=action, payload_hash=digest, session_hash=_session_hash(request),
        registry_hash=registry.revision_hash, registry_generation=registry.generation,
        registry_revision=registry.revision,
        policy_hash=payload_hash(registry.body["policy"]), nonce=secrets.token_urlsafe(32),
        rp_id=rp_id, origin=origin,
        credential_id=credential["id"] if credential else "",
        public_key=credential["public_key"] if credential else "",
        encrypted_form=encrypted_form,
        expires_at=timezone.now() + timedelta(seconds=CEREMONY_SECONDS),
    )
    if replay:
        challenge.encrypted_form = cipher().encrypt(canonical(replay).encode()).decode()
    challenge.save()
    return challenge


def _authentication_options(challenge):
    options = generate_authentication_options(
        rp_id=challenge.rp_id, challenge=challenge_bytes(challenge), timeout=120000,
        allow_credentials=[PublicKeyCredentialDescriptor(id=b64decode(challenge.credential_id))],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return {"challenge": str(challenge.pk), "publicKey": json.loads(options_to_json(options))}


@transaction.atomic
def begin_action(request, action, payload, *, credential_id=None, replay=None):
    Organization.objects.select_for_update().get(pk=request.organization.pk, active=True)
    registry = recognized_registry(request.organization, lock=True)
    person_id, person = _person(registry, request.user, action)
    credentials = _credentials(person)
    if credential_id:
        credentials = [item for item in credentials if item["id"] == credential_id]
    if not credentials:
        raise PermissionDenied("Aucun authentificateur PAM indépendant ne permet cette action.")
    challenge = _new_challenge(
        request, registry, person_id, action, payload_hash(payload), credentials[0], replay,
    )
    result = _authentication_options(challenge)
    result["credentials"] = [item["id"] for item in _credentials(person)]
    return result


def _live_challenge(request, challenge_id, *, action=None):
    Organization.objects.select_for_update().get(pk=request.organization.pk, active=True)
    registry = recognized_registry(request.organization, lock=True)
    challenge = PAMTrustChallenge.unscoped.select_for_update().filter(
        pk=challenge_id, organization=request.organization, account=request.user,
    ).first()
    now = timezone.now()
    if (
        not challenge or challenge.used_at or not challenge.created_at <= now < challenge.expires_at
        or challenge.session_hash != _session_hash(request)
        or challenge.registry_hash != registry.revision_hash
        or challenge.registry_generation != registry.generation
        or challenge.registry_revision != registry.revision
        or challenge.policy_hash != payload_hash(registry.body["policy"])
        or (action and challenge.action != action)
        or (challenge.rp_id, challenge.origin) != _configuration()
    ):
        raise PermissionDenied("Défi PAM expiré, utilisé ou périmètre modifié.")
    person_id, person = _person(
        registry, request.user, "enroll" if challenge.action == "enrollment-possession"
        else challenge.action,
    )
    if person_id != str(challenge.person_id):
        raise PermissionDenied("La personne PAM n’est plus habilitée.")
    if challenge.action not in ("enroll", "enrollment-possession") and not any(
        item["id"] == challenge.credential_id and item["public_key"] == challenge.public_key
        for item in _credentials(person)
    ):
        raise PermissionDenied("L’authentificateur PAM n’est plus habilité.")
    return challenge, registry, person


@transaction.atomic
def choose_credential(request, challenge_id, credential_id):
    previous, registry, person = _live_challenge(request, challenge_id)
    if previous.action in ("enroll", "enrollment-possession"):
        raise PermissionDenied
    credential = next((item for item in _credentials(person) if item["id"] == credential_id), None)
    if credential is None:
        raise PermissionDenied
    previous.used_at = timezone.now()
    previous.save(update_fields=["used_at"])
    challenge = _new_challenge(
        request, registry, previous.person_id, previous.action, previous.payload_hash, credential,
        encrypted_form=previous.encrypted_form,
    )
    result = _authentication_options(challenge)
    result["credentials"] = [item["id"] for item in _credentials(person)]
    return result


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _response(value, organization_id, person_id):
    if not isinstance(value, dict) or len(canonical(value).encode()) > 65536:
        raise ValidationError("Réponse WebAuthn invalide.")
    try:
        response = value["response"]
        client = json.loads(b64decode(response["clientDataJSON"]), object_pairs_hook=_unique_object)
        if client.get("crossOrigin", False) is not False or "topOrigin" in client:
            raise ValueError
        handle = response.get("userHandle")
        if handle is not None and b64decode(handle) != _user_handle(organization_id, person_id):
            raise ValueError
        if not 1 <= len(b64decode(value["id"])) <= 1023:
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise ValidationError("Réponse WebAuthn invalide.") from error
    return value


def _verify_assertion(challenge, response, sign_count):
    response = _response(response, challenge.organization_id, challenge.person_id)
    if response["id"] != challenge.credential_id:
        raise PermissionDenied("Autre authentificateur PAM.")
    try:
        result = verify_authentication_response(
            credential=response, expected_challenge=challenge_bytes(challenge),
            expected_rp_id=challenge.rp_id, expected_origin=challenge.origin,
            credential_public_key=b64decode(challenge.public_key),
            credential_current_sign_count=sign_count, require_user_verification=True,
        )
    except (InvalidAuthenticationResponse, ValueError, TypeError, KeyError) as error:
        raise PermissionDenied("La preuve WebAuthn PAM est invalide.") from error
    return result


@transaction.atomic
def finish_action(request, challenge_id, response):
    challenge, _, _ = _live_challenge(request, challenge_id)
    if challenge.action in ("enroll", "enrollment-possession"):
        raise PermissionDenied
    state, _ = PAMAuthenticatorState.unscoped.get_or_create(
        organization=request.organization, credential_id=challenge.credential_id,
    )
    state = PAMAuthenticatorState.unscoped.select_for_update().get(pk=state.pk)
    verification = _verify_assertion(challenge, response, state.sign_count)
    state.sign_count = verification.new_sign_count
    state.save(update_fields=["sign_count"])
    challenge.used_at = timezone.now()
    challenge.save(update_fields=["used_at"])
    token = secrets.token_urlsafe(48)
    proof = PAMTrustAuthorization.unscoped.create(
        organization=request.organization, challenge=challenge,
        token_hash=hashlib.sha256(token.encode()).hexdigest(), response=response,
        sign_count=verification.new_sign_count, verified_at=challenge.used_at,
        expires_at=challenge.expires_at,
    )
    result = {"proof": token, "authorization": str(proof.pk)}
    if challenge.encrypted_form:
        result["resume"] = json.loads(cipher().decrypt(challenge.encrypted_form.encode(), ttl=120))
    return result


@contextmanager
def action_authentication(request):
    token = _request.set(request)
    try:
        yield
    finally:
        _request.reset(token)


@transaction.atomic
def require_action(actor, organization, action, payload):
    request = _request.get()
    if request is None or request.user.pk != actor.pk or request.organization.pk != organization.pk:
        raise PermissionDenied("Une preuve d’action PAM liée au navigateur est nécessaire.")
    token = request.POST.get("_pam_trust_proof", "") or request.headers.get("X-PAM-Trust-Proof", "")
    if not token:
        raise PAMActionRequired(action, payload)
    if not re.fullmatch(r"[A-Za-z0-9_-]{64}", token):
        raise PermissionDenied("Preuve d’action PAM invalide.")
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    registry = recognized_registry(organization, lock=True)
    person_id, person = _person(registry, actor, action)
    proof = PAMTrustAuthorization.unscoped.select_for_update().select_related("challenge").filter(
        organization=organization, token_hash=hashlib.sha256(token.encode()).hexdigest(),
    ).first()
    now = timezone.now()
    if not proof or proof.consumed_at or not proof.verified_at <= now < proof.expires_at:
        raise PermissionDenied("Preuve d’action PAM expirée ou déjà utilisée.")
    challenge = proof.challenge
    if (
        challenge.account_id != actor.pk or str(challenge.person_id) != person_id
        or challenge.action != action or challenge.payload_hash != payload_hash(payload)
        or challenge.session_hash != _session_hash(request)
        or challenge.registry_hash != registry.revision_hash
        or challenge.registry_generation != registry.generation
        or challenge.registry_revision != registry.revision
        or challenge.policy_hash != payload_hash(registry.body["policy"])
        or proof.expires_at != challenge.expires_at or proof.verified_at != challenge.used_at
        or not any(
            item["id"] == challenge.credential_id and item["public_key"] == challenge.public_key
            for item in _credentials(person)
        )
    ):
        raise PermissionDenied("La preuve PAM porte sur un autre périmètre.")
    verification = _verify_assertion(challenge, proof.response, 0)
    if verification.new_sign_count != proof.sign_count:
        raise PermissionDenied("Preuve d’action PAM altérée.")
    proof.consumed_at = now
    proof.save(update_fields=["consumed_at"])
    return proof


def authorization_evidence(proof):
    challenge = proof.challenge
    return {
        "schema": "pamolive.pam.webauthn-action/1", "authorization": str(proof.pk),
        "organization": str(proof.organization_id), "account": str(challenge.account_id),
        "person": str(challenge.person_id), "action": challenge.action,
        "payload_hash": challenge.payload_hash, "registry_hash": challenge.registry_hash,
        "verified_at": proof.verified_at.isoformat(),
    }


def verify_authorization_evidence(
    evidence, *, actor=None, organization=None, action=None, payload=None,
):
    from .trust_registry import historical_registry

    try:
        proof = PAMTrustAuthorization.unscoped.select_related(
            "challenge", "challenge__account",
        ).get(
            pk=evidence["authorization"], consumed_at__isnull=False,
        )
        challenge = proof.challenge
        if (
            evidence != authorization_evidence(proof)
            or (actor is not None and challenge.account_id != actor.pk)
            or (organization is not None and proof.organization_id != organization.pk)
            or (action is not None and challenge.action != action)
            or (payload is not None and challenge.payload_hash != payload_hash(payload))
            or not challenge.created_at <= proof.verified_at <= proof.consumed_at
            or not proof.consumed_at < challenge.expires_at
            or proof.expires_at != challenge.expires_at or proof.verified_at != challenge.used_at
        ):
            return False
        registry = historical_registry(proof.organization, challenge.registry_hash)
        person = registry.body["persons"][str(challenge.person_id)]
        if (
            not person["active"] or str(challenge.account_id) not in person["account_ids"]
            or registry.generation != challenge.registry_generation
            or registry.revision != challenge.registry_revision
            or payload_hash(registry.body["policy"]) != challenge.policy_hash
            or (_ROLES.get(challenge.action) and _ROLES[challenge.action] not in person["roles"])
        ):
            return False
        if not any(
            item["active"] and item["id"] == challenge.credential_id
            and item["public_key"] == challenge.public_key and item["rp_id"] == challenge.rp_id
            and item["origin"] == challenge.origin for item in person["authenticators"]
        ):
            return False
        verification = _verify_assertion(challenge, proof.response, 0)
        return verification.new_sign_count == proof.sign_count
    except (PAMTrustAuthorization.DoesNotExist, PermissionDenied, ValidationError, ValueError,
            TypeError, KeyError, AttributeError):
        return False


@transaction.atomic
def begin_enrollment(request):
    Organization.objects.select_for_update().get(pk=request.organization.pk, active=True)
    registry = recognized_registry(request.organization, lock=True)
    person_id, person = _person(registry, request.user, "enroll")
    challenge = _new_challenge(
        request, registry, person_id, "enroll", payload_hash({"person": person_id}),
    )
    options = generate_registration_options(
        rp_id=challenge.rp_id, rp_name=getattr(settings, "PAM_TRUST_RP_NAME", "PamOlive"),
        user_name=request.user.get_username(),
        user_id=_user_handle(request.organization.pk, person_id),
        challenge=challenge_bytes(challenge), timeout=120000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=b64decode(item["id"]))
            for item in person["authenticators"]
        ], supported_pub_key_algs=_ALGORITHMS,
    )
    return {"challenge": str(challenge.pk), "publicKey": json.loads(options_to_json(options))}


@transaction.atomic
def finish_registration(request, challenge_id, response):
    challenge, registry, _ = _live_challenge(request, challenge_id, action="enroll")
    response = _response(response, challenge.organization_id, challenge.person_id)
    try:
        verification = verify_registration_response(
            credential=response, expected_challenge=challenge_bytes(challenge),
            expected_rp_id=challenge.rp_id, expected_origin=challenge.origin,
            require_user_presence=True, require_user_verification=True,
            supported_pub_key_algs=_ALGORITHMS,
        )
    except (InvalidRegistrationResponse, ValueError, TypeError, KeyError) as error:
        raise PermissionDenied("L’enrôlement WebAuthn PAM est invalide.") from error
    credential_id = b64encode(verification.credential_id)
    public_key = b64encode(verification.credential_public_key)
    fingerprint = public_key_fingerprint(public_key)
    for person in registry.body["persons"].values():
        for credential in person["authenticators"]:
            if credential["id"] == credential_id or public_key_fingerprint(
                credential["public_key"]
            ) == fingerprint:
                raise PermissionDenied("Cet authentificateur PAM est déjà enregistré.")
    challenge.used_at = timezone.now()
    challenge.save(update_fields=["used_at"])
    enrollment = PAMTrustEnrollment.unscoped.create(
        organization=request.organization, registration=challenge, account=request.user,
        person_id=challenge.person_id, credential_id=credential_id, public_key=public_key,
        rp_id=challenge.rp_id, origin=challenge.origin,
        registry_generation=registry.generation, registration_response=response,
        sign_count=verification.sign_count,
    )
    possession = _new_challenge(
        request, registry, challenge.person_id, "enrollment-possession",
        payload_hash({"enrollment": str(enrollment.pk), "public_key": public_key}),
        {"id": credential_id, "public_key": public_key},
    )
    enrollment.possession = possession
    enrollment.save(update_fields=["possession"])
    return {"enrollment": str(enrollment.pk), **_authentication_options(possession)}


@transaction.atomic
def finish_enrollment(request, enrollment_id, response):
    Organization.objects.select_for_update().get(pk=request.organization.pk, active=True)
    enrollment = PAMTrustEnrollment.unscoped.select_for_update().get(
        pk=enrollment_id, organization=request.organization, account=request.user,
    )
    challenge, _, _ = _live_challenge(
        request, enrollment.possession_id, action="enrollment-possession",
    )
    if enrollment.verified_at or enrollment.consumed_at:
        raise PermissionDenied("Cet enrôlement PAM est déjà terminé.")
    verification = _verify_assertion(challenge, response, enrollment.sign_count)
    challenge.used_at = timezone.now()
    challenge.save(update_fields=["used_at"])
    enrollment.verified_at = challenge.used_at
    enrollment.sign_count = verification.new_sign_count
    enrollment.possession_response = response
    enrollment.save(update_fields=["verified_at", "sign_count", "possession_response"])
    return {
        "id": enrollment.credential_id, "public_key": enrollment.public_key,
        "rp_id": enrollment.rp_id, "origin": enrollment.origin, "active": True,
        "enrollment_id": str(enrollment.pk),
    }


@transaction.atomic
def consume_enrollment(organization, person_id, authenticator):
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    enrollment = PAMTrustEnrollment.unscoped.select_for_update(of=("self",)).select_related(
        "account", "possession",
    ).get(pk=authenticator["enrollment_id"], organization=organization, person_id=person_id)
    registry = recognized_registry(organization, lock=True)
    actual_person, _ = registry_person(registry, enrollment.account)
    if (
        str(actual_person) != str(person_id) or enrollment.consumed_at
        or not enrollment.verified_at or enrollment.registry_generation != registry.generation
        or not enrollment.verified_at <= timezone.now()
        or any(authenticator[key] != value for key, value in {
            "id": enrollment.credential_id, "public_key": enrollment.public_key,
            "rp_id": enrollment.rp_id, "origin": enrollment.origin,
        }.items())
    ):
        raise ValidationError("Reçu d’enrôlement PAM invalide ou déjà consommé.")
    verification = _verify_assertion(enrollment.possession, enrollment.possession_response, 0)
    if verification.new_sign_count != enrollment.sign_count:
        raise ValidationError("Reçu d’enrôlement PAM altéré.")
    enrollment.consumed_at = timezone.now()
    enrollment.save(update_fields=["consumed_at"])
    return enrollment
