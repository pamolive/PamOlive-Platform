"""Persistent lab directory observations, without provisioning or implicit identity trust."""

import hashlib
import json
import re
from uuid import UUID

from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils.crypto import constant_time_compare

from platform_core.attestations import canonical, seal, signature, verify_anchor
from platform_core.audit import record
from platform_core.authorization import require_recent_authentication
from platform_core.security import cipher
from platform_core.services import lock_authorized_actor, require_module
from platform_modules.identity.models import ExternalAccount

from .directory_models import DirectoryFact, DirectoryMapping, DirectoryRun, DirectorySource

SCHEMA = "pamolive.directory-inventory/1"
NAMESPACE = "pamolive.directory"
READ_ROLES = ("admin", "operator", "reviewer", "auditor")
MAX_SOURCES = 100
MAX_RUNS = 1000
MAX_FACTS = 100000
MAX_MAPPINGS = 10000


class DirectoryConflict(ValidationError):
    status_code = 409

    def __init__(self):
        super().__init__(
            "Identifiant d’import déjà accepté avec des faits différents.",
            code="idempotency_conflict",
        )


def _guard(actor, organization, *, admin=False, mutate=False):
    actor, organization = lock_authorized_actor(
        actor,
        organization,
        roles=("admin",) if admin else (("admin", "operator") if mutate else READ_ROLES),
    )
    require_module(organization, "identity")
    require_module(organization, "connectors")
    if mutate or admin:
        require_recent_authentication(actor, organization)
    return actor, organization


def _text(value, maximum=180):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(c) < 32 for c in value)
    ):
        raise ValidationError("Texte ou identifiant d’inventaire invalide.")
    return value.strip()


def _uuid(value):
    try:
        return UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise ValidationError("Identifiant UUID d’inventaire invalide.") from None


def _hash(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def source_body(source):
    return dict(
        schema=SCHEMA,
        organization_id=str(source.organization_id),
        source_id=str(source.pk),
        provider=source.provider,
        destination=source.destination,
        synthetic=source.synthetic,
        created_by_id=source.created_by_id,
        created_at=source.created_at,
    )


def verify_directory_source(source):
    try:
        return verify_anchor(
            source,
            NAMESPACE,
            "source.v1",
            source_body(source),
            "directory.source_created",
            source.created_by_id,
        )
    except (ValueError, TypeError, AttributeError, ValidationError):
        return False


def credential_seal(source):
    return signature(
        NAMESPACE,
        "credential-destination.v1",
        dict(
            identity=source_body(source),
            ciphertext=source.encrypted_credential,
            credential_revision=source.credential_revision,
        ),
    )


def _source(source_id, *, enabled=False):
    source = (
        DirectorySource.objects.select_for_update().select_related("audit").get(pk=_uuid(source_id))
    )
    if not verify_directory_source(source):
        raise ValidationError("Identité de source non vérifiable.")
    if enabled and not source.enabled:
        raise PermissionDenied("Source désactivée.")
    return source


def _secret(source):
    if not source.synthetic:
        raise PermissionDenied("Les sources réelles ne sont pas qualifiées.")
    if not constant_time_compare(source.credential_seal, credential_seal(source)):
        raise ValidationError("Justificatif incompatible avec cette destination.")
    try:
        return json.loads(cipher().decrypt(source.encrypted_credential.encode()).decode())
    except Exception:
        # Cipher/decode diagnostics can include supplied credential material.
        raise ValidationError("Justificatif de source illisible.") from None


def _credential(provider, destination, value):
    if type(value) is not dict:
        raise ValidationError("Justificatif d’annuaire invalide.")
    expected = {"token"} if provider == "entra" else {"bind_dn", "password"}
    if set(value) != expected or any(
        not isinstance(item, str)
        or not item
        or len(item) > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in item)
        for item in value.values()
    ):
        raise ValidationError("Justificatif d’annuaire invalide.")
    if provider == "entra" and not re.fullmatch(r"[A-Za-z0-9\-._~+/]+=*", value["token"]):
        raise ValidationError("Format du jeton Bearer invalide.")
    if provider != "entra" and value["bind_dn"] != destination["scope"]["bind_dn"]:
        raise ValidationError("L’identité de bind exige une nouvelle source.")
    return value


@transaction.atomic
def configure_directory_source(
    *,
    actor,
    organization,
    name,
    provider,
    endpoint,
    certificate_sha256,
    scope,
    credential,
    synthetic=True,
):
    from .directory_adapters import normalize_destination

    actor, organization = _guard(actor, organization, admin=True)
    if synthetic is not True:
        raise PermissionDenied("Seules des sources explicitement synthétiques sont autorisées.")
    if DirectorySource.objects.count() >= MAX_SOURCES:
        raise ValidationError("Quota de sources atteint.")
    destination = normalize_destination(provider, endpoint, certificate_sha256, scope)
    credential = _credential(provider, destination, credential)
    source = DirectorySource(
        organization=organization,
        name=_text(name),
        provider=provider,
        destination=destination,
        synthetic=True,
        created_by=actor,
        encrypted_credential=cipher().encrypt(canonical(credential).encode()).decode(),
    )
    source.credential_seal = credential_seal(source)
    return seal(
        source,
        NAMESPACE,
        "source.v1",
        source_body(source),
        "directory.source_created",
        actor=actor,
        summary="Source d’inventaire synthétique créée",
    )


@transaction.atomic
def rotate_directory_credential(source_id, *, credential, actor, organization):
    actor, organization = _guard(actor, organization, admin=True)
    source = _source(source_id)
    credential = _credential(source.provider, source.destination, credential)
    source.encrypted_credential = cipher().encrypt(canonical(credential).encode()).decode()
    source.credential_revision += 1
    source.credential_seal = credential_seal(source)
    source.save(update_fields=["encrypted_credential", "credential_revision", "credential_seal"])
    record(
        action="directory.credential_rotated",
        summary="Justificatif synthétique renouvelé",
        actor=actor,
        organization=organization,
        target=source,
        metadata={"credential_revision": source.credential_revision},
    )
    return source


@transaction.atomic
def set_directory_source_enabled(source_id, *, enabled, actor, organization):
    actor, organization = _guard(actor, organization, admin=True)
    if type(enabled) is not bool:
        raise ValidationError("État de source invalide.")
    source = _source(source_id)
    if enabled:
        _secret(source)
    if source.enabled != enabled:
        source.enabled = enabled
        # A disable/re-enable cycle must invalidate an in-flight authorization too.
        source.credential_revision += 1
        source.credential_seal = credential_seal(source)
        source.save(update_fields=["enabled", "credential_revision", "credential_seal"])
        record(
            action="directory.source_enabled" if enabled else "directory.source_disabled",
            summary="Activation de source synthétique modifiée",
            actor=actor,
            organization=organization,
            target=source,
        )
    return source


def _fact_body(fact):
    return dict(
        remote_id=str(fact.remote_id),
        username=fact.username,
        enabled=fact.enabled,
        groups=fact.groups,
    )


def run_body(run):
    return dict(
        schema=SCHEMA,
        normalization="directory-facts/2",
        organization_id=str(run.organization_id),
        source_id=str(run.source_id),
        run_id=str(run.pk),
        source_revision=run.source_revision,
        idempotency_key=run.idempotency_key,
        provenance=run.provenance,
        complete=run.complete,
        page_count=run.page_count,
        record_count=run.record_count,
        facts_sha256=run.facts_sha256,
        transport_identity=run.transport_identity,
        limitations=run.limitations,
        observed_at=run.observed_at,
        accepted_by_id=run.accepted_by_id,
    )


def verify_directory_run(run):
    try:
        if not verify_directory_source(run.source):
            return False
        if not verify_anchor(
            run,
            NAMESPACE,
            "run.v1",
            run_body(run),
            "directory.inventory_accepted",
            run.accepted_by_id,
        ):
            return False
        facts = list(run.facts.order_by("remote_id")[:1001])
        if len(facts) != run.record_count or len(facts) > 1000:
            return False
        bodies = [_fact_body(fact) for fact in facts]
        return _hash(bodies) == run.facts_sha256 and all(
            fact.organization_id == run.organization_id
            and constant_time_compare(
                fact.signature,
                signature(
                    NAMESPACE,
                    "fact.v1",
                    dict(run_id=str(run.pk), run_signature=run.signature, fact=_fact_body(fact)),
                ),
            )
            for fact in facts
        )
    except (ValueError, TypeError, AttributeError, ValidationError):
        return False


def _accept(
    source,
    records,
    *,
    key,
    complete,
    page_count,
    provenance,
    transport_identity,
    limitations,
    actor,
    organization,
):
    from .directory_adapters import normalize_directory_records

    records = normalize_directory_records(source.provider, records)
    if (
        not isinstance(limitations, (list, tuple))
        or len(limitations) > 32
        or any(
            not isinstance(value, str)
            or not value
            or len(value) > 100
            or not all(c.isalnum() or c == "_" for c in value)
            for value in limitations
        )
    ):
        raise ValidationError("Limites de collecte invalides.")
    if type(complete) is not bool or type(page_count) is not int or not 1 <= page_count <= 20:
        raise ValidationError("Métadonnées d’import invalides.")
    key, digest = _text(key), _hash(records)
    old = (
        DirectoryRun.objects.select_related("audit", "source__audit")
        .filter(source=source, idempotency_key=key)
        .first()
    )
    fingerprint = dict(
        facts_sha256=digest,
        complete=complete,
        provenance=provenance,
        transport_identity=transport_identity,
        page_count=page_count,
        limitations=sorted(set(limitations)),
    )
    if old:
        if not verify_directory_run(old):
            raise ValidationError("Import historique non vérifiable.")
        if any(getattr(old, field) != value for field, value in fingerprint.items()):
            # Repeated conflicts are bounded before creating another audit record.
            if record_count_conflicts(source) >= 1000:
                raise ValidationError("Quota de conflits atteint.")
            record(
                action="directory.import_conflict",
                summary="Conflit d’identifiant d’import",
                actor=actor,
                organization=organization,
                target=old,
                metadata={"incoming_facts_sha256": digest},
            )
            return None
        return old
    if (
        DirectoryRun.objects.filter(source=source).count() >= MAX_RUNS
        or DirectoryFact.objects.count() + len(records) > MAX_FACTS
    ):
        raise ValidationError("Quota d’inventaire atteint ; archivage explicite requis.")
    run = DirectoryRun(
        organization=organization,
        source=source,
        source_revision=source.credential_revision,
        idempotency_key=key,
        record_count=len(records),
        accepted_by=actor,
        **fingerprint,
    )
    seal(
        run,
        NAMESPACE,
        "run.v1",
        run_body(run),
        "directory.inventory_accepted",
        actor=actor,
        summary="Inventaire synthétique accepté, sans attribution de droit",
    )
    for body in records:
        fact = DirectoryFact(organization=organization, run=run, **body)
        fact.signature = signature(
            NAMESPACE, "fact.v1", dict(run_id=str(run.pk), run_signature=run.signature, fact=body)
        )
        fact.save()
    return run


def record_count_conflicts(source):
    from platform_core.models import AuditEvent

    return AuditEvent.objects.filter(action="directory.import_conflict").count()


def import_directory_fixture(
    source_id, *, records, idempotency_key, complete=False, actor, organization
):
    with transaction.atomic():
        actor, organization = _guard(actor, organization, mutate=True)
        source = _source(source_id, enabled=True)
        if not source.synthetic:
            raise PermissionDenied("Les imports réels ne sont pas qualifiés.")
        result = _accept(
            source,
            records,
            key=idempotency_key,
            complete=complete,
            page_count=1,
            provenance="synthetic_fixture",
            transport_identity={},
            limitations=["caller_supplied_synthetic_fixture"],
            actor=actor,
            organization=organization,
        )
    if result is None:
        raise DirectoryConflict()
    return result


def collect_directory_inventory(source_id, *, idempotency_key, actor, organization):
    from .directory_adapters import read_directory

    with transaction.atomic():
        actor, organization = _guard(actor, organization, mutate=True)
        source = _source(source_id, enabled=True)
        secret = _secret(source)
        revision, seal_snapshot = source.credential_revision, source.credential_seal

    def before_auth():
        with transaction.atomic():
            _guard(actor, organization, mutate=True)
            current = _source(source_id, enabled=True)
            if current.credential_revision != revision or current.credential_seal != seal_snapshot:
                raise PermissionDenied("Autorisation modifiée avant émission du justificatif.")

    result = read_directory(
        provider=source.provider,
        destination=source.destination,
        secret=secret,
        synthetic=True,
        before_auth=before_auth,
    )
    with transaction.atomic():
        actor, organization = _guard(actor, organization, mutate=True)
        source = _source(source_id, enabled=True)
        if source.credential_revision != revision or source.credential_seal != seal_snapshot:
            raise PermissionDenied("Autorisation de collecte modifiée pendant la lecture.")
        if result.synthetic is not True:
            raise ValidationError("Résultat non synthétique refusé.")
        expected_identity = {
            key: source.destination[key]
            for key in ("provider", "endpoint", "certificate_sha256", "scope")
        }
        if source.provider == "entra":
            expected_identity["realm_id"] = source.destination["scope"]["tenant_id"]
        else:
            expected_identity.update(source.destination["scope"])
        if result.transport_identity != expected_identity:
            raise ValidationError("Identité de transport incompatible avec la source.")
        accepted = _accept(
            source,
            result.records,
            key=idempotency_key,
            complete=result.complete,
            page_count=result.page_count,
            provenance="authenticated_lab_directory",
            transport_identity=result.transport_identity,
            limitations=result.limitations,
            actor=actor,
            organization=organization,
        )
    if accepted is None:
        raise DirectoryConflict()
    return accepted


def mapping_body(mapping):
    return dict(
        schema=SCHEMA,
        mapping_id=str(mapping.pk),
        organization_id=str(mapping.organization_id),
        source_id=str(mapping.source_id),
        source_revision=mapping.source_revision,
        remote_id=str(mapping.remote_id),
        account_id=str(mapping.account_id),
        sequence=mapping.sequence,
        kind=mapping.kind,
        previous_id=str(mapping.previous_id) if mapping.previous_id else None,
        decided_by_id=mapping.decided_by_id,
        decided_at=mapping.decided_at,
    )


def verify_directory_mapping(mapping):
    try:
        if not verify_directory_source(mapping.source):
            return False
        if not verify_anchor(
            mapping,
            NAMESPACE,
            "mapping.v1",
            mapping_body(mapping),
            "directory.mapping_decided",
            mapping.decided_by_id,
        ):
            return False
        previous = mapping.previous
        return bool(
            mapping.account.organization_id == mapping.organization_id
            and mapping.account.identity.organization_id == mapping.organization_id
            and (
                (mapping.sequence == 1 and previous is None and mapping.kind == "bind")
                or (
                    previous is not None
                    and previous.organization_id == mapping.organization_id
                    and previous.source_id == mapping.source_id
                    and previous.remote_id == mapping.remote_id
                    and previous.sequence + 1 == mapping.sequence
                    and previous.kind != mapping.kind
                    and (mapping.kind != "revoke" or previous.account_id == mapping.account_id)
                )
            )
        )
    except (ValueError, TypeError, AttributeError, ValidationError):
        return False


def _mappings(source):
    rows = (
        DirectoryMapping.objects.filter(source=source)
        .select_related("audit", "source__audit", "account__identity", "previous")
        .order_by("sequence", "pk")
    )
    latest = {}
    for mapping in rows[: MAX_MAPPINGS + 1]:
        if not verify_directory_mapping(mapping):
            raise ValidationError("Correspondance historique non vérifiable.")
        previous = latest.get(mapping.remote_id)
        if mapping.sequence != (
            previous.sequence + 1 if previous else 1
        ) or mapping.previous_id != (previous.pk if previous else None):
            raise ValidationError("Chaîne de correspondances incomplète.")
        latest[mapping.remote_id] = mapping
    if rows.count() > MAX_MAPPINGS:
        raise ValidationError("Quota de correspondances dépassé.")
    return latest


@transaction.atomic
def map_directory_account(source_id, *, remote_id, account_id, actor, organization):
    actor, organization = _guard(actor, organization, admin=True)
    source = _source(source_id, enabled=True)
    remote_id = _uuid(remote_id)
    account = ExternalAccount.objects.select_related("identity").get(pk=_uuid(account_id))
    if account.identity.organization_id != organization.pk:
        raise ValidationError("Identité hors organisation.")
    latest = _mappings(source)
    old = latest.get(remote_id)
    if old and old.kind == "bind":
        if old.account_id == account.pk:
            return old
        raise ValidationError("Révoquer explicitement l’ancienne correspondance.")
    if any(item.kind == "bind" and item.account_id == account.pk for item in latest.values()):
        raise ValidationError("Ce compte est déjà lié à un objet de cette source.")
    active_count = sum(item.kind == "bind" for item in latest.values())
    # Reserve one immutable decision for retiring every active mapping.
    if DirectoryMapping.objects.filter(source=source).count() + active_count + 2 > MAX_MAPPINGS:
        raise ValidationError("Quota de correspondances atteint.")
    mapping = DirectoryMapping(
        organization=organization,
        source=source,
        source_revision=source.credential_revision,
        remote_id=remote_id,
        account=account,
        sequence=old.sequence + 1 if old else 1,
        kind="bind",
        previous=old,
        decided_by=actor,
    )
    return seal(
        mapping,
        NAMESPACE,
        "mapping.v1",
        mapping_body(mapping),
        "directory.mapping_decided",
        actor=actor,
        summary="Correspondance déclarative, sans attestation de personne",
    )


@transaction.atomic
def revoke_directory_mapping(mapping_id, *, actor, organization):
    actor, organization = _guard(actor, organization, admin=True)
    old = DirectoryMapping.objects.select_related("source").get(pk=_uuid(mapping_id))
    source = _source(old.source_id)
    latest = _mappings(source).get(old.remote_id)
    if latest.pk != old.pk or old.kind != "bind":
        raise ValidationError("La correspondance a déjà changé.")
    if DirectoryMapping.objects.filter(source=source).count() >= MAX_MAPPINGS:
        raise ValidationError("Quota de correspondances atteint.")
    mapping = DirectoryMapping(
        organization=organization,
        source=source,
        source_revision=source.credential_revision,
        remote_id=old.remote_id,
        account=old.account,
        sequence=old.sequence + 1,
        kind="revoke",
        previous=old,
        decided_by=actor,
    )
    return seal(
        mapping,
        NAMESPACE,
        "mapping.v1",
        mapping_body(mapping),
        "directory.mapping_decided",
        actor=actor,
        summary="Correspondance révoquée, historique conservé",
    )


def _source_projection(source):
    return dict(
        id=str(source.pk),
        name=source.name,
        provider=source.provider,
        destination=source.destination,
        enabled=source.enabled,
        synthetic=source.synthetic,
        credential_revision=source.credential_revision,
        identity_verified=verify_directory_source(source),
    )


@transaction.atomic
def directory_sources(*, actor, organization):
    _guard(actor, organization)
    rows = DirectorySource.objects.select_related("audit").order_by("created_at", "pk")[:101]
    return dict(
        schema=SCHEMA,
        sources=[_source_projection(row) for row in rows[:100]],
        truncated=len(rows) > 100,
    )


@transaction.atomic
def directory_inventory(*, actor, organization, source_id=None, limit=100, cursor=None):
    _guard(actor, organization)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValidationError("Limite d’inventaire entre1 et100 requise.")
    if source_id is None:
        if cursor:
            raise ValidationError("Le curseur exige une source explicite.")
        return directory_sources(actor=actor, organization=organization)
    source = _source(source_id)
    if cursor:
        if not isinstance(cursor, str) or len(cursor) > 4096:
            raise ValidationError("Curseur d’inventaire trop long ou invalide.")
        try:
            pin = signing.loads(cursor, salt=NAMESPACE + "/cursor.v1", max_age=3600)
            if pin["organization_id"] != str(organization.pk) or pin["source_id"] != str(source.pk):
                raise ValueError
            if pin["phase"] not in ("facts", "absent"):
                raise ValueError
            phase = pin["phase"]
            run = (
                DirectoryRun.objects.select_related("source__audit", "audit").get(
                    pk=_uuid(pin["run_id"]), source=source
                )
                if pin["run_id"] is not None
                else None
            )
            after = _uuid(pin["after"])
        except (signing.BadSignature, KeyError, ValueError, TypeError, DirectoryRun.DoesNotExist):
            raise ValidationError("Curseur d’inventaire invalide ou expiré.") from None
    else:
        run = (
            DirectoryRun.objects.select_related("source__audit", "audit")
            .filter(source=source)
            .order_by("-observed_at", "-pk")
            .first()
        )
        after, phase = None, "facts"
    mappings = _mappings(source)
    if run and not verify_directory_run(run):
        raise ValidationError("Inventaire signé non vérifiable.")
    facts = list(run.facts.order_by("remote_id")) if run else []
    present = {fact.remote_id for fact in facts}
    names = {}
    for fact in facts:
        names.setdefault(fact.username.casefold(), []).append(fact.remote_id)
    page = (
        [fact for fact in facts if after is None or fact.remote_id > after][: limit + 1]
        if phase == "facts"
        else []
    )
    items = []
    for fact in page[:limit]:
        mapping = mappings.get(fact.remote_id)
        active = bool(source.enabled and mapping and mapping.kind == "bind")
        items.append(
            dict(
                **_fact_body(fact),
                account_id=str(mapping.account_id) if active else None,
                mapping_id=str(mapping.pk) if mapping else None,
                state="explicitly_linked" if active else "unlinked_requires_human_review",
                warnings=(
                    ["duplicate_login_requires_human_review"]
                    if len(names[fact.username.casefold()]) > 1
                    else []
                )
                + (["group_observation_incomplete"] if not run.complete else []),
                enabled_assurance="unknown" if fact.enabled is None else "observed_directory_state",
            )
        )
    absent = [
        dict(
            remote_id=str(remote),
            account_id=str(mapping.account_id),
            state="not_observed_requires_review_never_delete",
        )
        for remote, mapping in sorted(mappings.items())
        if mapping.kind == "bind"
        and remote not in present
        and (phase == "facts" or UUID(str(remote)) > after)
    ]
    # Continue facts first, then missing observations. Both phases use the same
    # signed organization/source/run cursor; missing rows never authorize deletion.
    visible_absent = [] if len(page) > limit else absent[:limit]
    continuation = None
    if len(page) > limit:
        continuation = ("facts", str(page[limit - 1].remote_id))
    elif len(absent) > limit:
        continuation = ("absent", visible_absent[-1]["remote_id"])
    next_cursor = (
        signing.dumps(
            dict(
                organization_id=str(organization.pk),
                source_id=str(source.pk),
                run_id=str(run.pk) if run else None,
                phase=continuation[0],
                after=continuation[1],
            ),
            salt=NAMESPACE + "/cursor.v1",
            compress=True,
        )
        if continuation
        else None
    )
    return dict(
        schema=SCHEMA,
        organization_id=str(organization.pk),
        source=_source_projection(source),
        run_id=str(run.pk) if run else None,
        provenance=run.provenance if run else None,
        complete=run.complete if run else False,
        limitations=run.limitations if run else ["no_observation"],
        items=items,
        not_observed=visible_absent,
        not_observed_truncated=len(absent) > len(visible_absent),
        next_cursor=next_cursor,
        read_only=True,
        can_apply=False,
        assurance="directory_observation_not_identity_attestation_or_provisioning_confirmation",
    )
