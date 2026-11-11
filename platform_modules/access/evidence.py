"""New evaluations authenticate their exact interpretation, not only a verdict label."""

import hashlib
import hmac
import json

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.crypto import constant_time_compare

from platform_core.audit import digest

from .observations import sign, source_snapshot


def _sign_with_key(value, domain, key):
    """V7's exact wire format, using a historical evidence key for verification."""
    if key == settings.SECRET_KEY:
        return sign(value, domain)
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hmac.new(
        key.encode(),
        ("pamolive.access." + domain + ".v1\0").encode() + payload,
        hashlib.sha256,
    ).hexdigest()


def evaluation_body(evaluation, *, key=None):
    key = settings.SECRET_KEY if key is None else key
    return dict(
        id=str(evaluation.pk),
        organization=str(evaluation.organization_id),
        event=str(evaluation.event_id),
        intent=str(evaluation.intent_id) if evaluation.intent_id else None,
        rule_version=evaluation.rule_version,
        evaluated_at=evaluation.evaluated_at.isoformat(),
        verdict=evaluation.verdict,
        findings=evaluation.findings,
        context=evaluation.context,
        context_hash=evaluation.context_hash,
        event_fact_hash=_sign_with_key(source_snapshot(evaluation.event), "event-facts", key),
    )


def evaluation_signature(evaluation, *, key=None):
    key = settings.SECRET_KEY if key is None else key
    return _sign_with_key(
        dict(
            body=evaluation_body(evaluation, key=key),
            audit_id=evaluation.audit_id,
            audit_hash=evaluation.audit.event_hash,
        ),
        "evaluation",
        key,
    )


def verify_evaluation(evaluation, *, allow_legacy=False):
    try:
        if evaluation.rule_version != "access-context/7":
            # Existing historical rows are preserved, never retroactively signed.
            return bool(
                allow_legacy
                and evaluation.rule_version
                in {f"access-context/{version}" for version in range(1, 7)}
                and not evaluation.context
                and not evaluation.context_hash
                and not evaluation.audit_id
                and not evaluation.signature
            )
        audit = evaluation.audit
        if not (
            evaluation.event.organization_id == evaluation.organization_id
            and (
                not evaluation.intent_id
                or evaluation.intent.organization_id == evaluation.organization_id
            )
            and audit.organization_id == evaluation.organization_id
            and audit.actor_id is None
            and audit.action == "access.event.evaluated.v1"
            and audit.object_type == evaluation._meta.label_lower
            and audit.object_id == str(evaluation.pk)
            and audit.event_hash == digest(audit)
        ):
            return False
        keys = (
            settings.SECRET_KEY,
            *getattr(settings, "PAMOLIVE_EVIDENCE_VERIFICATION_KEYS", ()),
        )
        return any(
            isinstance(key, str)
            and bool(key)
            and audit.metadata.get("body_hash")
            == _sign_with_key(evaluation_body(evaluation, key=key), "evaluation-body", key)
            and evaluation.context_hash
            == _sign_with_key(
                evaluation.context.get("semantic", evaluation.context), "context", key
            )
            and constant_time_compare(
                evaluation.signature, evaluation_signature(evaluation, key=key)
            )
            for key in dict.fromkeys(keys)
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False
