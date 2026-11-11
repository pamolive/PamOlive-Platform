"""Point-in-time contract and separation decisions, shared by requests and observations."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils import timezone

from platform_core.tenancy import organization_context
from platform_modules.identity.models import Grant

from .models import ApprovalPolicyRevision, ContractParticipant, ContractRevision, SeparationRule


@dataclass
class Assessment:
    findings: list = field(default_factory=list)

    def add(self, code, state, detail, evidence=""):
        self.findings.append(
            {"code": code, "state": state, "detail": detail, "evidence": str(evidence)}
        )

    @property
    def status(self):
        states = {item["state"] for item in self.findings}
        return "deny" if "deviation" in states else "unknown" if "unknown" in states else "allow"


def policy_at(at):
    return ApprovalPolicyRevision.objects.filter(effective_at__lte=at).order_by("-sequence").first()


def revision_at(contract, at):
    return (
        ContractRevision.objects.filter(contract=contract, effective_at__lte=at)
        .order_by("-sequence")
        .first()
    )


def _boundary(day, wall_time, zone, *, closing):
    naive = datetime.combine(day, wall_time)
    candidates = []
    for fold in (0, 1):
        candidate = naive.replace(tzinfo=zone, fold=fold).astimezone(UTC)
        if candidate.astimezone(zone).replace(tzinfo=None) == naive:
            candidates.append(candidate)
    if not candidates:
        return None  # A nonexistent wall time never expands a permitted window.
    return min(candidates) if closing else max(candidates)


def schedule_allows(revision, start, end):
    if end <= start:
        return False
    if revision.daily_start == revision.daily_end and set(revision.weekdays) == set(range(7)):
        return True
    zone = ZoneInfo(revision.timezone_name)
    first = start.astimezone(zone).date() - timedelta(days=1)
    windows = []
    # A non-24/7 weekly pattern contains a gap within a week. No unbounded calendar scan.
    for offset in range(10):
        day = first + timedelta(days=offset)
        if day.weekday() not in revision.weekdays:
            continue
        overnight = revision.daily_end <= revision.daily_start
        opening = _boundary(day, revision.daily_start, zone, closing=False)
        closing = _boundary(
            day + timedelta(days=int(overnight)), revision.daily_end, zone, closing=True
        )
        if opening is not None and closing is not None and closing > opening:
            windows.append((opening, closing))
    cursor = start.astimezone(UTC)
    for opening, closing in sorted(windows):
        if closing <= cursor:
            continue
        if opening > cursor:
            return False
        cursor = max(cursor, closing)
        if cursor >= end.astimezone(UTC):
            return True
    return False


def assess_contract(
    *,
    contract,
    identity,
    resource,
    method,
    privilege,
    location,
    country_code,
    reference,
    start,
    end=None,
    as_of=None,
):
    result = Assessment()
    as_of = as_of or start
    end = end or start + timedelta(microseconds=1)
    revision = revision_at(contract, as_of)
    if not revision:
        result.add(
            "contract_revision", "unknown", "Aucune révision publiée à cette date.", contract.pk
        )
        return result
    result.add(
        "contract_revision",
        "confirmed",
        f"Contrat {contract.reference}, révision {revision.sequence}.",
        revision.pk,
    )
    if (
        start < revision.starts_at
        or end > revision.ends_at
        or (contract.retired_at and contract.retired_at < end)
    ):
        result.add(
            "contract_period",
            "deviation",
            "Accès hors période du contrat ou après son retrait.",
            revision.pk,
        )
    participant = (
        ContractParticipant.objects.filter(
            contract=contract, identity=identity, valid_from__lte=start
        )
        .filter(Q(valid_until__isnull=True) | Q(valid_until__gte=end))
        .filter(Q(revoked_at__isnull=True) | Q(revoked_at__gte=end))
        .first()
    )
    if not participant:
        result.add(
            "contract_participant",
            "deviation",
            "Cette identité n’est pas autorisée sur toute la période.",
            contract.pk,
        )
    else:
        result.add(
            "contract_participant", "confirmed", "Intervenant inscrit au contrat.", participant.pk
        )
    if method.strip().casefold() not in {m.casefold() for m in revision.allowed_methods}:
        result.add("contract_method", "deviation", "Méthode hors contrat.", revision.pk)
    if resource.kind in ("door", "zone") and not revision.physical_allowed:
        result.add(
            "contract_physical",
            "deviation",
            "Le contrat n’autorise aucun accès physique.",
            revision.pk,
        )
    scopes = list(
        revision.scopes.filter(resource=resource).filter(Q(privilege="") | Q(privilege=privilege))
    )
    if not scopes:
        result.add(
            "contract_resource",
            "deviation",
            "Ressource ou privilège hors périmètre du contrat.",
            revision.pk,
        )
    elif not any(not scope.locations or location in scope.locations for scope in scopes):
        result.add(
            "contract_location",
            "unknown" if not location else "deviation",
            "Origine absente ou hors des lieux autorisés.",
            revision.pk,
        )
    else:
        result.add(
            "contract_scope",
            "confirmed",
            "Ressource, privilège et origine compatibles.",
            revision.pk,
        )
    if not schedule_allows(revision, start, end):
        result.add(
            "contract_schedule",
            "deviation",
            "Accès hors plage autorisée dans le fuseau du contrat.",
            revision.pk,
        )
    if revision.allowed_countries:
        if not country_code:
            result.add(
                "contract_country",
                "unknown",
                "Pays d’origine non fourni ; aucune géolocalisation supposée.",
                revision.pk,
            )
        elif country_code.upper() not in {c.upper() for c in revision.allowed_countries}:
            result.add(
                "contract_country",
                "deviation",
                "Pays hors contrat selon l’information fournie.",
                revision.pk,
            )
        else:
            result.add(
                "contract_country",
                "confirmed",
                "Pays fourni compatible avec le contrat.",
                revision.pk,
            )
    if revision.require_reference:
        result.add(
            "business_reference",
            "confirmed" if reference.strip() else "deviation",
            "Référence métier déclarée : " + reference
            if reference.strip()
            else "Référence métier obligatoire absente.",
            revision.pk,
        )
    return result


def separation_findings(*, identity, resource, entitlement, start, end, as_of):
    result = Assessment()
    rules = SeparationRule.objects.filter(effective_at__lte=as_of).filter(
        Q(retired_at__isnull=True) | Q(retired_at__gt=as_of)
    )
    for rule in rules:
        opposite = None
        if (resource.pk, entitlement) == (rule.left_resource_id, rule.left_entitlement):
            opposite = rule.right_resource_id, rule.right_entitlement
        elif (resource.pk, entitlement) == (rule.right_resource_id, rule.right_entitlement):
            opposite = rule.left_resource_id, rule.left_entitlement
        if not opposite:
            continue
        grants = (
            Grant.objects.filter(
                identity=identity,
                resource_id=opposite[0],
                entitlement=opposite[1],
                valid_from__lt=end,
                created_at__lte=as_of,
            )
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=start))
            .filter(Q(status="active") | Q(status="revoked", revoked_at__gt=start))
        )
        from platform_modules.access.models import AccessIntent

        intents = AccessIntent.objects.filter(
            identity=identity,
            resource_id=opposite[0],
            privilege=opposite[1],
            starts_at__lt=end,
            ends_at__gt=start,
            approved_at__lte=as_of,
        ).filter(Q(status="approved") | Q(status="revoked", revoked_at__gt=start))
        if grants.exists() or intents.exists():
            result.add(
                "separation_of_duties",
                "deviation",
                f"Combinaison interdite : {rule.name}.",
                rule.pk,
            )
    return result


def assess_authorization(obj, *, organization, as_of=None, remaining=False):
    as_of = as_of or timezone.now()
    with organization_context(organization):
        result = Assessment()
        start = getattr(obj, "starts_at", getattr(obj, "valid_from", as_of))
        end = getattr(obj, "ends_at", getattr(obj, "expires_at", None))
        if remaining:
            start = max(start, as_of)
        policy = policy_at(as_of)
        contract = getattr(obj, "contract", None)
        if (
            policy
            and policy.require_external_contract
            and obj.identity.kind == "external"
            and not contract
        ):
            result.add(
                "contract_required",
                "deviation",
                "La politique exige un contrat pour ce prestataire.",
                policy.pk,
            )
        if contract:
            if not end or end <= start:
                result.add(
                    "contract_expiration",
                    "deviation",
                    "Un droit lié au contrat doit être borné dans le temps.",
                    contract.pk,
                )
            else:
                assessment = assess_contract(
                    contract=contract,
                    identity=obj.identity,
                    resource=obj.resource,
                    method=obj.method,
                    privilege=getattr(obj, "privilege", getattr(obj, "entitlement", "")),
                    location=obj.location,
                    country_code=obj.country_code,
                    reference=getattr(obj, "reference", ""),
                    start=start,
                    end=end,
                    as_of=as_of,
                )
                result.findings.extend(assessment.findings)
        if (
            obj.account_id
            and obj.account.managed_contract_id
            and obj.account.managed_contract_id != getattr(obj, "contract_id", None)
        ):
            result.add(
                "dedicated_account_contract", "deviation", "Le compte est dédié à un autre contrat."
            )
        result.findings.extend(
            separation_findings(
                identity=obj.identity,
                resource=obj.resource,
                entitlement=getattr(obj, "privilege", getattr(obj, "entitlement", "")),
                start=start,
                end=end or datetime.max.replace(tzinfo=UTC),
                as_of=as_of,
            ).findings
        )
        return result


def enforce_authorization(obj, *, organization, remaining=False):
    result = assess_authorization(obj, organization=organization, remaining=remaining)
    if result.status != "allow":
        raise ValidationError(
            [
                finding["detail"]
                for finding in result.findings
                if finding["state"] in ("deviation", "unknown")
            ]
        )
    return result


def approval_requirements(intent, *, at=None):
    at = at or timezone.now()
    policy = policy_at(at)
    minimum = 1
    sponsor_id = None
    if policy:
        minimum = max(
            policy.min_reviewers, policy.critical_reviewers if intent.resource.critical else 1
        )
        if intent.contract_id and policy.supplier_sponsor_required:
            revision = revision_at(intent.contract, at)
            sponsor_id = revision.sponsor_id if revision else None
    person_ids = set()
    sponsor_same_person = False
    if intent.fulfillment == "pam":
        from platform_modules.pam.mandates import binding_at, valid_decisions

        decisions = valid_decisions(intent, at)
        approved = {decision.reviewer_id for decision in decisions}
        person_ids = {decision.reviewer_identity_id for decision in decisions}
        sponsor_binding = binding_at(sponsor_id, at) if sponsor_id else None
        sponsor_same_person = bool(
            sponsor_binding
            and (
                sponsor_binding.identity_id == intent.identity_id
                or sponsor_binding.identity_id in person_ids
            )
        )
        count = len(person_ids)
    else:
        approved = set(
            intent.decisions.filter(approved=True, decided_at__lte=at).values_list(
                "reviewer_id", flat=True
            )
        )
        count = len(approved)
    sponsor_satisfied = (
        not sponsor_id
        or sponsor_id == intent.requested_by_id
        or sponsor_id in approved
        or sponsor_same_person
    )
    result = {
        "minimum": minimum,
        "approved": count,
        "unit": "personnes liées" if intent.fulfillment == "pam" else "comptes de connexion",
        "sponsor_id": sponsor_id,
        "sponsor_satisfied": sponsor_satisfied,
        "complete": count >= minimum and sponsor_satisfied,
        "policy_id": str(policy.pk) if policy else "baseline/1",
    }
    if intent.fulfillment == "pam" and intent.pam_trust:
        from platform_modules.pam.trust import trusted_requirements

        return trusted_requirements(intent, at, result)
    return result


def account_contract_live(account, *, at=None):
    at = at or timezone.now()
    if not account.managed_contract_id:
        return True
    contract = account.managed_contract
    revision = revision_at(contract, at)
    if (
        not revision
        or not revision.starts_at <= at < revision.ends_at
        or (contract.retired_at and contract.retired_at <= at)
    ):
        return False
    return (
        ContractParticipant.objects.filter(
            contract=contract, identity=account.identity, valid_from__lte=at
        )
        .filter(Q(valid_until__isnull=True) | Q(valid_until__gt=at))
        .filter(Q(revoked_at__isnull=True) | Q(revoked_at__gt=at))
        .exists()
    )


def contract_withdrawal_required(obj, *, organization, at=None):
    """Withdraw only a contractual right, not an arbitrary side of a new SoD conflict."""
    at = at or timezone.now()
    if not obj.contract_id:
        return False
    end = getattr(obj, "ends_at", getattr(obj, "expires_at", None))
    if not end or end <= at:
        return True
    with organization_context(organization):
        return (
            assess_contract(
                contract=obj.contract,
                identity=obj.identity,
                resource=obj.resource,
                method=obj.method,
                privilege=getattr(obj, "privilege", getattr(obj, "entitlement", "")),
                location=obj.location,
                country_code=obj.country_code,
                reference=obj.reference,
                start=max(at, getattr(obj, "starts_at", getattr(obj, "valid_from", at))),
                end=end,
                as_of=at,
            ).status
            != "allow"
        )
