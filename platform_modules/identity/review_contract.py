"""identity.review/1: typed grant snapshots and narrowly checked review effects."""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.utils import timezone

from platform_core.attestations import canonical
from platform_core.authorization import require_recent_authentication
from platform_core.models import Organization
from platform_core.services import authorize, require_module
from platform_core.tenancy import current_organization

from .models import ExternalAccount, Grant, Identity, Resource

CONTRACT = "identity.review/1"
GRANT_FIELDS = (
    "id",
    "organization_id",
    "identity_id",
    "account_id",
    "resource_id",
    "entitlement",
    "justification",
    "expires_at",
    "valid_from",
    "contract_id",
    "method",
    "location",
    "country_code",
    "reference",
    "created_at",
)


def database_now():
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT clock_timestamp()")
            return cursor.fetchone()[0]
    return timezone.now()


def normalize_scope(data):
    if type(data) is not dict or set(data) - {"resource_ids", "account_kinds", "identity_kinds"}:
        raise ValidationError("Périmètre de revue inconnu.")
    result = {}
    for key in ("resource_ids", "account_kinds", "identity_kinds"):
        values = data.get(key, [])
        if type(values) is not list or len(values) > 100 or any(type(x) is not str for x in values):
            raise ValidationError("Une sélection de 100 éléments maximum est requise.")
        result[key] = sorted(set(values))
    try:
        result["resource_ids"] = sorted({str(UUID(value)) for value in result["resource_ids"]})
    except ValueError:
        raise ValidationError("Identifiant de ressource invalide.") from None
    if Resource.objects.filter(pk__in=result["resource_ids"]).count() != len(
        result["resource_ids"]
    ):
        raise ValidationError("Une ressource ne fait pas partie de cette organisation.")
    for key, model in (("account_kinds", ExternalAccount), ("identity_kinds", Identity)):
        if set(result[key]) - {value for value, _ in model._meta.get_field("kind").choices}:
            raise ValidationError("Type d’identité ou de compte inconnu.")
    return result


def _value(value):
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    return str(value) if isinstance(value, UUID) else value


def grant_snapshot(grant):
    account, identity, resource = grant.account, grant.identity, grant.resource
    return dict(
        contract=CONTRACT,
        authority={name: _value(getattr(grant, name)) for name in GRANT_FIELDS},
        context=dict(
            identity_kind=identity.kind,
            identity_owner=identity.owner,
            department=identity.department,
            account_kind=account.kind if account else None,
            account_username=account.username if account else None,
            account_system=account.system if account else None,
            resource_kind=resource.kind,
            critical=resource.critical,
            environment=resource.environment,
        ),
        labels=dict(identity=identity.name, resource=resource.name),
        state=dict(
            status=grant.status, revision=grant.state_revision, revoked_at=_value(grant.revoked_at)
        ),
    )


@dataclass(frozen=True)
class GrantCapture:
    started_at: datetime
    finished_at: datetime
    items: tuple


def capture_for_review(organization, scope, *, max_items=10000, max_bytes=16777216):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    require_module(organization, "identity")
    scope = normalize_scope(scope)
    query = Grant.objects.filter(status="active").select_related("identity", "account", "resource")
    if scope["resource_ids"]:
        query = query.filter(resource_id__in=scope["resource_ids"])
    if scope["account_kinds"]:
        query = query.filter(account__kind__in=scope["account_kinds"])
    if scope["identity_kinds"]:
        query = query.filter(identity__kind__in=scope["identity_kinds"])
    started, items, size = database_now(), [], 0
    # One SELECT gives one MVCC cohort. Capture bounds, not a fabricated exact
    # historical instant, describe the observation interval even with streaming.
    for grant in query.order_by("id")[: max_items + 1].iterator(chunk_size=100):
        body = grant_snapshot(grant)
        encoded = canonical(body).encode()
        size += len(encoded)
        if len(items) >= max_items or len(encoded) > 65536 or size > max_bytes:
            raise ValidationError(
                "Périmètre trop volumineux : aucune campagne partielle créée.",
                code="review_scope_limit",
            )
        items.append((grant.pk, body))
    finished = database_now()
    if finished < started:
        raise ValidationError("L’horloge de capture a reculé.", code="review_clock_regressed")
    return GrantCapture(started, finished, tuple(items))


@transaction.atomic
def apply_review(organization, grant_id, snapshot, *, actor, keep):
    if current_organization().pk != organization.pk or type(keep) is not bool:
        raise PermissionDenied
    authorize(actor, organization, roles=("admin", "reviewer"))
    require_recent_authentication(actor, organization)
    require_module(organization, "identity")
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    grant = (
        Grant.objects.select_for_update()
        .select_related("identity", "account", "resource")
        .get(pk=grant_id)
    )
    current = grant_snapshot(grant)
    if not keep and grant.status == "revoked":
        return dict(outcome="already_revoked", state=current["state"], external_confirmed=False)
    if (
        grant.status != "active"
        or current["authority"] != snapshot.get("authority")
        or current["context"] != snapshot.get("context")
        or current["state"]["revision"] != snapshot.get("state", {}).get("revision")
    ):
        raise ValidationError("Le droit ou son contexte a changé : ouvrez une nouvelle campagne.")
    if keep:
        from platform_modules.governance.policy import assess_authorization

        if (
            grant.identity.status != "active"
            or (grant.account and not grant.account.active)
            or (grant.expires_at and grant.expires_at <= database_now())
            or assess_authorization(grant, organization=organization, remaining=True).status
            != "allow"
        ):
            raise ValidationError(
                "Ce droit n’est plus applicable ; une confirmation ne le réactive pas."
            )
        outcome = "kept"
    else:
        from .services import revoke_grant

        grant = revoke_grant(
            grant, actor=actor, organization=organization, origin="recertification.revoked"
        )
        outcome = "revoked"
    return dict(outcome=outcome, state=grant_snapshot(grant)["state"], external_confirmed=False)
