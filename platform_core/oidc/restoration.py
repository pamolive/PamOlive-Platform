"""Offline cryptographic verification; no DNS, HTTP or current IdP availability required."""

import json

from django.utils.crypto import constant_time_compare

from platform_core.security import cipher

from .models import OIDCAttempt, OIDCDraft, OIDCLink, OIDCProvider
from .services import (
    attempt_binding,
    draft_proof,
    link_signature,
    pending_proof,
    provider_proof,
    tag,
)


def verify_evidence():
    encrypted, signed = 0, 0
    for provider in OIDCProvider.unscoped.select_related("organization").iterator(chunk_size=100):
        config = {
            field: getattr(provider, field)
            for field in (
                "slug",
                "name",
                "issuer",
                "client_id",
                "algorithm",
                "auth_method",
                "redirect_uri",
            )
        }
        config["client_secret"] = cipher().decrypt(provider.encrypted_secret.encode()).decode()
        encrypted += 1
        if not constant_time_compare(
            provider.verification_proof, provider_proof(provider)
        ) or not constant_time_compare(
            provider.config_hash, tag(dict(config=config, metadata=provider.metadata))
        ):
            raise RuntimeError("Restored OIDC provider evidence is invalid.")
        signed += 1
    for link in OIDCLink.unscoped.select_related("provider").iterator(chunk_size=100):
        # Revocation/expiry must not hide damaged historical signatures.
        if not constant_time_compare(link.signature, link_signature(link)):
            raise RuntimeError("Restored OIDC association evidence is invalid.")
        signed += 1
    for draft in OIDCDraft.unscoped.iterator(chunk_size=100):
        if draft.encrypted_config:
            config = json.loads(cipher().decrypt(draft.encrypted_config.encode()))
            encrypted += 1
            if not constant_time_compare(
                draft.config_hash, tag(dict(config=config, metadata=draft.metadata))
            ):
                raise RuntimeError("Restored OIDC draft evidence is invalid.")
            signed += 1
        if draft.encrypted_result:
            json.loads(cipher().decrypt(draft.encrypted_result.encode()))
            encrypted += 1
        if draft.verified_at:
            if not constant_time_compare(draft.verification_proof, draft_proof(draft)):
                raise RuntimeError("Restored OIDC test evidence is invalid.")
            signed += 1
    for attempt in OIDCAttempt.unscoped.iterator(chunk_size=100):
        if attempt.encrypted_flow:
            flow = json.loads(cipher().decrypt(attempt.encrypted_flow.encode()))
            encrypted += 1
            if flow.get("binding") != attempt_binding(attempt):
                raise RuntimeError("Restored OIDC flow evidence is invalid.")
            signed += 1
        if attempt.pending_link_id:
            if not constant_time_compare(attempt.pending_proof, pending_proof(attempt)):
                raise RuntimeError("Restored OIDC pending login evidence is invalid.")
            signed += 1
    return encrypted, signed
