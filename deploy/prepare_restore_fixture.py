"""Populated CI-only recovery corpus; no network target is contacted."""

import os
import unittest


def teamviewer_corpus(actor, organization):
    """Offline synthetic reports only; no TeamViewer account or API is contacted."""
    import time
    import uuid
    from datetime import timedelta
    from unittest.mock import patch

    from django.test import override_settings
    from django.utils import timezone

    from platform_core.authorization import recent_authentication
    from platform_core.services import install_module
    from platform_modules.connectors.teamviewer import ConnectionReport, ReportBatch, ReportPage
    from platform_modules.connectors.teamviewer_access import normalize_sessions
    from platform_modules.connectors.teamviewer_collection import (
        save_configuration,
        set_enabled,
        test_configuration,
    )
    from platform_modules.connectors.teamviewer_ingestion import process_collectors
    from platform_modules.connectors.teamviewer_mapping import publish_mapping
    from platform_modules.connectors.teamviewer_mapping_models import TeamViewerSighting
    from platform_modules.connectors.teamviewer_sessions import index_sessions
    from platform_modules.identity.models import ExternalAccount, Identity, Resource

    now = timezone.now().replace(microsecond=0)
    with (
        override_settings(CONNECTOR_ALLOWED_HOSTS=["webapi.teamviewer.com:443"]),
        recent_authentication(actor, organization, time.time()),
        patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.fetch_completed",
            return_value=ReportBatch((), 1, True, "pagination_finished"),
        ),
    ):
        install_module("connectors", actor=actor, organization=organization)
        browser = "offline-synthetic-teamviewer-browser"
        capsule, _ = test_configuration(
            actor=actor,
            organization=organization,
            browser_key=browser,
            name="Offline TeamViewer corpus",
            token="not-a-real-teamviewer-token",
            start_at=now - timedelta(days=1),
            collect_notes=True,
        )
        collector = save_configuration(
            capsule, actor=actor, organization=organization, browser_key=browser
        )
        set_enabled(collector.pk, True, actor=actor, organization=organization)
        source = ConnectionReport(
            str(uuid.uuid4()),
            "synthetic-account",
            "synthetic-device",
            now - timedelta(hours=1),
            now - timedelta(minutes=1),
            "Synthetic source note, not a verified ticket",
        )
        with patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.read_page",
            return_value=ReportPage((source,), None, source.ended_at, True),
        ):
            process_collectors(organization)
        sighting = TeamViewerSighting.objects.get(report__remote_id=source.id)
        identity = Identity.objects.create(
            organization=organization, name="Synthetic TeamViewer service", kind="service"
        )
        account = ExternalAccount.objects.create(
            organization=organization,
            identity=identity,
            username="synthetic-tv-operator",
            system="TeamViewer",
            kind="service",
        )
        device = Resource.objects.create(
            organization=organization, name="Synthetic TeamViewer device", kind="device"
        )
        for kind, remote_ref, target in (
            ("actor", "synthetic-account", identity),
            ("account", "synthetic-account", account),
            ("device", "synthetic-device", device),
        ):
            publish_mapping(
                actor=actor,
                organization=organization,
                collector_id=collector.pk,
                kind=kind,
                remote_ref=remote_ref,
                target=target,
                valid_from=source.started_at,
                valid_until=source.ended_at,
                verification_reference="Synthetic offline assignment; not a real provider check",
                sighting_id=sighting.pk,
            )
        index_sessions(organization)
        normalize_sessions(organization)
        set_enabled(collector.pk, False, actor=actor, organization=organization)


def business_corpus(actor, organization, intent_id):
    """Synthetic publisher assertions, not a real GLPI/Jira integration."""
    import time
    from datetime import timedelta

    from django.utils import timezone

    from platform_core.authorization import recent_authentication
    from platform_modules.connectors.business import (
        FORMAT,
        configure_business_source,
        create_business_source,
        ingest_business_record,
    )
    from platform_modules.connectors.business_associations import publish_business_association

    now = timezone.now()
    with recent_authentication(actor, organization, time.time()):
        source, token = create_business_source(
            {"name": "Synthetic business corpus", "key": "restore-business"},
            actor=actor,
            organization=organization,
        )
        receipt, _ = ingest_business_record(
            dict(
                schema=FORMAT,
                external_id="fixture-483",
                sequence=1,
                kind="change",
                reference="CHG-SYNTHETIC-483",
                state="approved",
                source_updated_at=(now - timedelta(hours=1)).isoformat(),
                observed_at=now.isoformat(),
            ),
            token=token,
            organization=organization,
        )
        association = publish_business_association(
            intent_id,
            receipt.pk,
            "Synthetic business reference, not vendor qualification",
            actor=actor,
            organization=organization,
        )
        publish_business_association(
            intent_id,
            receipt.pk,
            "Synthetic withdrawal with history preserved",
            actor=actor,
            organization=organization,
            withdraw_association_id=association.pk,
        )
        publish_business_association(
            intent_id,
            receipt.pk,
            "Synthetic explicit republication",
            actor=actor,
            organization=organization,
        )
        configure_business_source(source.pk, actor=actor, organization=organization, active=False)


def oidc_corpus(actor, organization):
    """Synthetic signed corpus only; deliberately does not contact or impersonate a real IdP."""
    import hashlib
    import json
    import secrets
    from datetime import timedelta

    from django.utils import timezone

    from platform_core.oidc.models import OIDCAttempt, OIDCDraft, OIDCLink, OIDCProvider
    from platform_core.oidc.services import (
        attempt_binding,
        draft_proof,
        link_signature,
        pending_proof,
        provider_proof,
        tag,
    )
    from platform_core.security import cipher

    now = timezone.now()
    issuer = "https://no-network-restore-idp.example.invalid"
    config = dict(
        slug="synthetic-restore",
        name="Offline OIDC corpus",
        issuer=issuer,
        client_id="not-a-real-oidc-client",
        client_secret="not-a-real-oidc-secret",
        algorithm="RS256",
        auth_method="client_secret_basic",
        redirect_uri=f"https://no-network-portal.example.invalid/accounts/oidc/{organization.pk}"
        "/synthetic-restore/callback/",
    )
    metadata = dict(
        issuer=issuer,
        authorization_endpoint=issuer + "/authorize",
        token_endpoint=issuer + "/token",
        jwks_uri=issuer + "/jwks",
    )
    contract = tag(dict(config=config, metadata=metadata))
    provider = OIDCProvider(
        organization=organization,
        metadata=metadata,
        config_hash=contract,
        verified_at=now,
        encrypted_secret=cipher().encrypt(config["client_secret"].encode()).decode(),
        **{field: value for field, value in config.items() if field != "client_secret"},
    )
    provider.verification_proof = provider_proof(provider)
    provider.save()
    link = OIDCLink(
        organization=organization,
        account=actor,
        provider=provider,
        subject="synthetic-explicit-subject",
        created_at=now,
        mfa_verified_at=now - timedelta(seconds=1),
        mfa_window_minutes=5,
    )
    link.signature = link_signature(link)
    link.save()
    browser_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    draft = OIDCDraft(
        organization=organization,
        owner=actor,
        session_hash=browser_hash,
        encrypted_config=cipher().encrypt(json.dumps(config).encode()).decode(),
        config_hash=contract,
        metadata=metadata,
        expires_at=now + timedelta(minutes=15),
        verified_at=now,
        encrypted_result=cipher().encrypt(b'{"subject":"synthetic"}').decode(),
    )
    draft.verification_proof = draft_proof(draft)
    draft.save()
    attempt = OIDCAttempt(
        organization=organization,
        provider=provider,
        purpose="login",
        session_hash=browser_hash,
        state_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        config_hash=contract,
        expires_at=now + timedelta(minutes=5),
    )
    flow = dict(
        config,
        metadata=metadata,
        binding=attempt_binding(attempt),
        nonce=secrets.token_urlsafe(32),
        verifier=secrets.token_urlsafe(32),
    )
    attempt.encrypted_flow = cipher().encrypt(json.dumps(flow).encode()).decode()
    attempt.save()
    pending = OIDCAttempt(
        organization=organization,
        provider=provider,
        purpose="login",
        session_hash=browser_hash,
        state_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        config_hash=contract,
        expires_at=now + timedelta(minutes=5),
        used_at=now,
        encrypted_flow="",
        pending_link=link,
        pending_until=now + timedelta(minutes=2),
    )
    pending.pending_proof = pending_proof(pending)
    pending.save()


def scim_creation_corpus(actor, requester, organization):
    """Synthetic creation effects only; no provider is contacted by this corpus."""
    import time
    from datetime import timedelta
    from unittest.mock import patch

    from django.test import override_settings
    from django.utils import timezone

    from platform_core.authorization import recent_authentication
    from platform_modules.access.services import create_record
    from platform_modules.approvals.services import decide
    from platform_modules.connectors.creation import process_creations, request_creation
    from platform_modules.connectors.outbound import (
        bind_group,
        configure_connector,
        set_connector_enabled,
        test_connector,
    )
    from platform_modules.connectors.scim import ScimAdapter
    from platform_modules.identity.models import ExternalAccount, Identity, Resource

    identity = Identity.objects.create(
        organization=organization, name="Synthetic SCIM joiner", kind="human"
    )
    account = ExternalAccount.objects.create(
        organization=organization,
        identity=identity,
        username="synthetic-scim-joiner",
        system="Offline SCIM corpus",
    )
    resource = Resource.objects.create(
        organization=organization, name="Synthetic SCIM application", kind="application"
    )
    now = timezone.now()
    intent = create_record(
        "intent",
        dict(
            identity=identity,
            account=account,
            resource=resource,
            method="SCIM",
            privilege="synthetic-reader",
            reason="Synthetic initial account corpus",
            fulfillment="iam_group",
            starts_at=now - timedelta(minutes=1),
            ends_at=now + timedelta(hours=1),
        ),
        actor=requester,
        organization=organization,
    )
    with (
        recent_authentication(actor, organization, time.time()),
        override_settings(CONNECTOR_ALLOWED_HOSTS={"unused.example.invalid:443"}),
    ):
        decide(
            intent.pk,
            actor=actor,
            organization=organization,
            approved=True,
            comment="Independent synthetic joiner approval",
        )
        connector = configure_connector(
            actor=actor,
            organization=organization,
            name="Synthetic initial SCIM creation",
            base_url="https://unused.example.invalid/scim/v2",
            token="not-a-real-scim-creation-token",
        )
        with patch.object(ScimAdapter, "test", return_value={}):
            assert test_connector(connector.pk, actor=actor, organization=organization)[0]
        set_connector_enabled(connector.pk, actor=actor, organization=organization, enabled=True)
        bind_group(
            actor=actor,
            organization=organization,
            connector=connector,
            resource=resource,
            entitlement="synthetic-reader",
            remote_identifier="synthetic-group",
        )
        job = request_creation(
            intent.pk,
            connector.pk,
            activate_after_grant=False,
            actor=actor,
            organization=organization,
        )

        def synthetic_creation(adapter, username, external_id):
            adapter.before_write()
            return dict(
                remote_id="synthetic-created-user",
                username=username,
                external_id=external_id,
                active=False,
            )

        with patch.object(ScimAdapter, "create_inactive_user", synthetic_creation):
            assert process_creations(organization) == 1
        job.refresh_from_db()
        assert job.status == "created"
        set_connector_enabled(connector.pk, actor=actor, organization=organization, enabled=False)


def recertification_corpus(actor, organization):
    """Frozen scopes and signed decisions, without any network side effect."""
    import time
    from datetime import timedelta
    from unittest.mock import patch

    from django.utils import timezone

    from platform_core.authorization import recent_authentication
    from platform_core.models import OrganizationMembership
    from platform_core.services import install_module
    from platform_modules.identity.models import Grant, Identity, Resource
    from platform_modules.recertification.evidence import verify_recertification
    from platform_modules.recertification.models import CampaignRun, Review
    from platform_modules.recertification.schedules import (
        process_schedules,
        publish_schedule,
        set_schedule_enabled,
    )
    from platform_modules.recertification.services import review_grant, start_campaign

    install_module("recertification", actor=actor, organization=organization)
    OrganizationMembership.objects.get_or_create(
        organization=organization, account=actor, defaults={"role": "admin"}
    )
    identity = Identity.objects.create(
        organization=organization, name="Review subject", kind="human"
    )
    resource = Resource.objects.create(
        organization=organization, name="Offline review", kind="application"
    )
    grant = Grant.objects.create(
        organization=organization,
        identity=identity,
        resource=resource,
        entitlement="reader",
        justification="Synthetic review corpus",
    )
    with recent_authentication(actor, organization, time.time()):
        campaign = start_campaign(
            actor=actor,
            organization=organization,
            name="Manual restore review",
            due_at=timezone.now() + timedelta(days=1),
        )
        review_grant(
            Review.objects.get(campaign=campaign, grant=grant).pk,
            actor=actor,
            organization=organization,
            keep=False,
            comment="Synthetic withdrawal",
        )
        draft = publish_schedule(
            dict(
                name="Periodic restore review",
                first_at=timezone.now() - timedelta(days=1),
                interval_days=30,
                review_window_days=7,
                scope={},
                owner=actor,
            ),
            key="restore-review",
            actor=actor,
            organization=organization,
        )
        active = set_schedule_enabled(
            draft.schedule_id,
            True,
            expected_revision=draft.revision,
            actor=actor,
            organization=organization,
        )
    clock = active.published_at + timedelta(seconds=1)
    with (
        patch("platform_modules.identity.review_contract.database_now", return_value=clock),
        patch("platform_modules.recertification.schedules.database_now", return_value=clock),
    ):
        assert process_schedules(organization) == 1
    assert CampaignRun.objects.count() == 2
    with recent_authentication(actor, organization, time.time()):
        set_schedule_enabled(
            active.schedule_id,
            False,
            expected_revision=active.revision,
            actor=actor,
            organization=organization,
        )
    assert verify_recertification() >= 7


def mover_corpus(actor, requester, organization):
    """Restore a withdrawn role grant and its full provenance, with no remote calls."""
    import time
    from datetime import timedelta

    from django.utils import timezone

    from platform_core.authorization import recent_authentication
    from platform_modules.access.evidence import verify_evaluation
    from platform_modules.access.mobility_context import candidates, project
    from platform_modules.access.services import ingest_event
    from platform_modules.approvals.services import decide
    from platform_modules.connectors.business import (
        configure_business_source,
        create_business_source,
        ingest_business_record,
    )
    from platform_modules.identity.models import ExternalAccount, Identity, Resource
    from platform_modules.identity.mover import (
        decide_move,
        propose_move,
        publish_role,
        verify_mover,
    )
    from platform_modules.identity.mover_models import MoveAccess, MoveGrant

    person = Identity.objects.create(
        organization=organization, name="Mobility fixture", kind="human"
    )
    account = ExternalAccount.objects.create(
        organization=organization,
        identity=person,
        username="synthetic-mover",
        system="Offline",
    )
    resource = Resource.objects.create(
        organization=organization,
        name="Offline role resource",
        kind="application",
    )
    with recent_authentication(actor, organization, time.time()):
        role = publish_role(
            key="offline-mobility",
            name="Offline mobility",
            enabled=True,
            expected_revision=0,
            entries=[dict(resource=resource.pk, method="SSO", privilege="reader", days=30)],
            actor=actor,
            organization=organization,
        )
        source, token = create_business_source(
            dict(key="offline-hr", name="Synthetic HR source", freshness_seconds=900),
            actor=actor,
            organization=organization,
        )
    modified = (timezone.now() - timedelta(minutes=2)).isoformat()

    def reading(sequence):
        result, _ = ingest_business_record(
            dict(
                schema="pamolive.business-record/1",
                external_id="offline-42",
                sequence=sequence,
                kind="change",
                reference="OFFLINE-HR",
                state="approved",
                title="Synthetic HR dossier",
                source_updated_at=modified,
                observed_at=timezone.now().isoformat(),
            ),
            token=token,
            organization=organization,
        )
        return result

    def propose(department, assignments, receipts=None):
        with recent_authentication(requester, organization, time.time()):
            return propose_move(
                identity_id=person.pk,
                department=department,
                assignments=assignments,
                reason="Synthetic role transfer",
                reference="OFFLINE-HR",
                actor=requester,
                organization=organization,
                business_receipts=receipts,
            )

    first = propose("Support", {role.pk: [account.pk]}, [reading(1).pk])
    latest = reading(2)
    with recent_authentication(actor, organization, time.time()):
        applied = decide_move(
            first.pk,
            approved=True,
            comment="Synthetic approval",
            actor=actor,
            organization=organization,
        )
        intent = MoveAccess.objects.get(decision=applied).intent
        assert applied.body["business_checked"][0]["receipt_id"] == str(latest.pk)
        decide(
            intent.pk,
            approved=True,
            comment="Synthetic IAM approval",
            actor=actor,
            organization=organization,
        )
    event, _ = ingest_event(
        dict(
            source="offline-mobility-observation",
            external_id="offline-access",
            identity=person,
            account=account,
            resource=resource,
            method="SSO",
            privilege="reader",
            action="login",
            occurred_at=timezone.now(),
        ),
        actor=requester,
        organization=organization,
    )
    second = propose("Operations", {})
    with recent_authentication(actor, organization, time.time()):
        decide_move(
            second.pk,
            approved=True,
            comment="Synthetic withdrawal",
            actor=actor,
            organization=organization,
        )
        configure_business_source(source.pk, actor=actor, organization=organization, active=False)
    assert MoveGrant.objects.get(access__intent=intent).grant.status == "revoked"
    assert verify_mover() == 7
    evaluation = event.evaluations.get()
    assert verify_evaluation(evaluation) and evaluation.intent_id == intent.pk
    matches, limited = candidates(event, evaluation, organization)
    context = project(matches, organization=organization, limited=limited)
    (row,) = context["rows"]
    (ref,) = row["references"]
    assert row["matches"][0]["reviewed_provenance_known_at_start"]
    assert ref["reviewed"]["receipt_id"] == str(latest.pk)
    assert not ref["latest"]["current_source_assertion"]


def certificate_possession_corpus(actor, organization):
    """Preserve a real signed challenge with no production key or network peer."""
    import base64
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID
    from django.utils import timezone

    from platform_modules.access import certificate_possession as possession
    from platform_modules.access.services import ingest_event
    from platform_modules.connectors.services import create_source
    from platform_modules.identity.models import Credential, Identity

    now = timezone.now()
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "restore-certificate.example.invalid")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, None)
    )
    machine = Identity.objects.create(
        organization=organization, name="Synthetic certificate machine", kind="machine"
    )
    credential = Credential.objects.create(
        organization=organization,
        identity=machine,
        kind="certificate",
        name="Synthetic Ed25519 certificate",
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
    )
    source, token = create_source(
        "Synthetic certificate source", actor=actor, organization=organization
    )
    event, created = ingest_event(
        {
            "external_id": "offline-certificate-proof",
            "occurred_at": now - timedelta(minutes=1),
            "credential": credential,
            "domain": "certificate",
            "method": "TLS",
            "action": "connect",
        },
        organization=organization,
        source=source,
    )
    assert created
    challenge = possession.issue(possession.consume_budget(token), event.pk)
    message = base64.b64decode(challenge["message_b64"], validate=True)
    result = possession.submit(
        possession.consume_budget(token),
        event.pk,
        challenge["challenge"],
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii"),
        base64.b64encode(key.sign(message)).decode("ascii"),
    )
    assert result["status"] == "verified" and not result["historical_access_verified"]
    # Subsequent inventory changes and source disablement must not erase a
    # historical proof of what was checked at the challenge time.
    credential.fingerprint = "f" * 64
    credential.save(update_fields=["fingerprint"])
    source.active = False
    source.save(update_fields=["active"])
    assert possession.verify_restored_proofs() == 1


def main():
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    django.setup()
    from django.contrib.auth.hashers import make_password
    from django.db import connection
    from django.test import Client, override_settings

    if (
        os.environ.get("PAMOLIVE_RESTORE_FIXTURE") != "1"
        or connection.settings_dict["NAME"] != "test_pamolive_restore_source"
    ):
        raise RuntimeError("A dedicated synthetic restore source is required.")
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database()")
        if cursor.fetchone()[0] != "test_pamolive_restore_source":
            raise RuntimeError("Wrong synthetic database destination.")

    from platform_core.models import AccountSecurity, BusinessRole
    from platform_core.security import cipher
    from platform_modules.connectors.models import ProvisioningConnector
    from platform_modules.pam.sessions import append_recording, finish_session
    from tests.test_pam_sessions import PamSessionFixtureMixin

    class Fixture(PamSessionFixtureMixin, unittest.TestCase):
        pass

    with override_settings(PAM_ALLOWED_HOSTS={"ssh.example.test:22"}):
        Fixture.setUpTestData()
        fixture = Fixture()
        fixture.client = Client()
        try:
            fixture.setUp()
            item, owner = fixture.claimed()
            append_recording(item.pk, fixture.org, owner, b"4.sync,1.1;", 10)
            append_recording(item.pk, fixture.org, owner, b"4.sync,1.2;", 20)
            finish_session(item.pk, fixture.org, owner, reason="client_closed", complete=True)
            ProvisioningConnector.objects.create(
                organization=fixture.org,
                name="Synthetic restore token",
                base_url="https://unused.example.invalid/scim/v2",
                encrypted_token=cipher().encrypt(b"not-a-real-service-token").decode(),
                enabled=False,
            )
            role = BusinessRole.objects.create(key="restore-proof", name="Synthetic M2M proof")
            role.members.add(fixture.operator)
            profile = AccountSecurity.objects.get(account=fixture.operator)
            profile.last_counter = 4242
            profile.freshness_minutes = 10
            profile.recovery_hashes = [make_password("synthetic-not-a-real-recovery-code")]
            profile.save()
            from platform_core.events import publish_domain_event
            from platform_core.tenancy import organization_context

            with organization_context(fixture.org):
                oidc_corpus(fixture.operator, fixture.org)
                teamviewer_corpus(fixture.admin, fixture.org)
                certificate_possession_corpus(fixture.admin, fixture.org)
                business_corpus(fixture.admin, fixture.org, fixture.intent.pk)
                scim_creation_corpus(fixture.admin, fixture.operator, fixture.org)
                recertification_corpus(fixture.admin, fixture.org)
                mover_corpus(fixture.admin, fixture.operator, fixture.org)
                publish_domain_event(
                    organization=fixture.org,
                    emitter="identity",
                    topic="identity.identity.created.v1",
                    payload={"identity_id": str(fixture.identity.pk), "kind": "human"},
                )
        finally:
            fixture.doCleanups()
    print(
        "Synthetic restore corpus prepared: MFA, counter, recovery hash, M2M, "
        "SCIM token, target secret, OIDC secret/link/draft/flow, signed mandate, "
        "signed notification, TeamViewer token/report/run/sighting/mappings/session "
        "certificate key possession and sealed capture."
    )


if __name__ == "__main__":
    main()
