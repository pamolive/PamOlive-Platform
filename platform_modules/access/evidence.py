"""New evaluations authenticate their exact interpretation, not only a verdict label."""

from django.core.exceptions import ValidationError
from django.utils.crypto import constant_time_compare

from platform_core.audit import digest

from .observations import context_hash, sign, source_snapshot


def evaluation_body(evaluation):
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
        event_fact_hash=sign(source_snapshot(evaluation.event), "event-facts"),
    )


def evaluation_signature(evaluation):
    return sign(
        dict(
            body=evaluation_body(evaluation),
            audit_id=evaluation.audit_id,
            audit_hash=evaluation.audit.event_hash,
        ),
        "evaluation",
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
        return bool(
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
            and audit.metadata.get("body_hash")
            == sign(evaluation_body(evaluation), "evaluation-body")
            and evaluation.context_hash == context_hash(evaluation.context)
            and constant_time_compare(evaluation.signature, evaluation_signature(evaluation))
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False
