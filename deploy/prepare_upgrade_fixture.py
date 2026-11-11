"""Synthetic a8 schema/data, only in an explicitly opted-in disposable database."""

import os
import re
from datetime import UTC, datetime


def legacy_targets(executor):
    graph = executor.loader.graph
    excluded = set(graph.backwards_plan(("access", "0010_observed_intervals")))
    excluded.update(
        graph.backwards_plan(
            ("connectors", "0004_teamviewercollector_teamviewerrun_teamviewerreport")
        )
    )
    excluded.update(
        graph.backwards_plan(("recertification", "0002_periodic_campaigns_and_review_evidence"))
    )
    excluded.update(graph.backwards_plan(("pam", "0004_credential_destination")))
    excluded.update(graph.backwards_plan(("approvals", "0004_approvaldecision_pam_trust")))
    return [
        key
        for key, node in graph.node_map.items()
        if key not in excluded
        and not any(child.key[0] == key[0] and child.key not in excluded for child in node.children)
    ]


def seed():
    from django.conf import settings
    from django.contrib.auth.hashers import make_password
    from django.core.management.sql import emit_post_migrate_signal
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    from deploy.controlled_upgrade import CATALOGS, current_specs
    from platform_core.audit import record
    from platform_core.models import Organization
    from platform_core.security import cipher

    name = connection.settings_dict["NAME"]
    if (
        os.environ.get("PAMOLIVE_UPGRADE_FIXTURE") != "1"
        or settings.PAMOLIVE_EXTENSIONS
        or connection.vendor != "postgresql"
        or not re.fullmatch(
            r"test_pamolive(?:_[a-z0-9_]+)?|pamolive_restore_check_[a-f0-9]{16}", name
        )
    ):
        raise RuntimeError("Disposable PostgreSQL fixture scope required")
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database()")
        if cursor.fetchone()[0] != name:
            raise RuntimeError("Wrong disposable database")
        tables = set(connection.introspection.table_names(cursor))
        for table in set(current_specs()) & tables - CATALOGS:
            cursor.execute(f"SELECT EXISTS (SELECT 1 FROM {connection.ops.quote_name(table)})")
            if cursor.fetchone()[0]:
                raise RuntimeError("Fixture database must contain no application data")
    executor = MigrationExecutor(connection)
    targets = legacy_targets(executor)
    executor.migrate(targets)
    registry = executor.loader.project_state(targets).apps
    # The guarded disposable scope has no users, groups or business rows yet.
    # Remove only framework-generated catalog rows so its baseline is truly a8,
    # even when Django's test runner initially created the latest catalog.
    registry.get_model("auth", "Permission").objects.all().delete()
    registry.get_model("contenttypes", "ContentType").objects.all().delete()
    emit_post_migrate_signal(0, False, connection.alias, apps=registry, plan=[])
    user_model = registry.get_model(settings.AUTH_USER_MODEL)
    user = user_model.objects.create(
        username="upgrade-fixture-admin",
        password=make_password("synthetic-not-a-real-password"),
        is_active=True,
        is_staff=True,
        is_superuser=True,
    )
    org = registry.get_model("platform_core", "Organization").objects.create(
        key="upgrade-fixture", name="Organisation préexistante — à conserver"
    )
    registry.get_model("platform_core", "OrganizationMembership").objects.create(
        organization_id=org.pk, account_id=user.pk, role="admin", active=True
    )
    registry.get_model("platform_core", "AccountSecurity").objects.create(
        account_id=user.pk,
        encrypted_secret=cipher().encrypt(b"JBSWY3DPEHPK3PXP").decode(),
    )
    person = registry.get_model("identity", "Identity").objects.create(
        organization_id=org.pk, name="Intervenant historique", kind="human"
    )
    owner = registry.get_model("identity", "Identity").objects.create(
        organization_id=org.pk, name="Propriétaire technique distinct", kind="service"
    )
    resource = registry.get_model("identity", "Resource").objects.create(
        organization_id=org.pk, name="Poste conservé", kind="device"
    )
    account = registry.get_model("identity", "ExternalAccount").objects.create(
        organization_id=org.pk,
        identity_id=owner.pk,
        username="synthetic-service",
        system="TeamViewer",
        kind="service",
    )
    for revision in (1, 2):
        registry.get_model("connectors", "ProvisioningConnector").objects.create(
            organization_id=org.pk,
            name=f"Historical SCIM revision {revision}",
            base_url=f"https://synthetic-directory-{revision}.invalid/scim",
            encrypted_token=cipher().encrypt(b"synthetic-historical-scim-token").decode(),
            revision=revision,
        )
    import asyncssh

    registry.get_model("pam", "SessionEndpoint").objects.create(
        organization_id=org.pk,
        resource_id=resource.pk,
        account_id=account.pk,
        name="Historical PAM endpoint",
        protocol="ssh",
        hostname="synthetic-ssh.invalid",
        port=22,
        auth_method="password",
        encrypted_secret=cipher().encrypt(b'{"password":"synthetic-historical-secret"}').decode(),
        ssh_host_key=asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode(),
    )
    registry.get_model("access", "AccessIntent").objects.create(
        organization_id=org.pk,
        identity_id=person.pk,
        account_id=account.pk,
        resource_id=resource.pk,
        requested_by_id=user.pk,
        method="SSH",
        fulfillment="pam",
        reason="Historical logical mandate",
        starts_at=datetime(2026, 1, 1, tzinfo=UTC),
        ends_at=datetime(2026, 1, 2, tzinfo=UTC),
    )
    event = registry.get_model("access", "AccessEvent").objects.create(
        organization_id=org.pk,
        source="synthetic-before-upgrade",
        external_id="history-1",
        occurred_at=datetime(2026, 1, 5, 10, 2, 3, 123456, tzinfo=UTC),
        identity_id=person.pk,
        account_id=account.pk,
        resource_id=resource.pk,
        method="TeamViewer",
        action="remote_session",
        evidence="Référence publique µs — non secrète",
    )
    registry.get_model("access", "AccessEvaluation").objects.create(
        organization_id=org.pk,
        event_id=event.pk,
        verdict="unknown",
        rule_version="access-context/5",
        findings=[
            dict(
                code="why",
                state="unknown",
                detail="Analyse originale conservée",
                evidence="fixture",
            )
        ],
    )
    group = registry.get_model("auth", "Group").objects.create(name="Historical technical group")
    user.groups.add(group)
    record(
        organization=Organization.objects.get(pk=org.pk),
        action="upgrade.fixture.v1",
        summary="Synthetic evidence predating session normalization",
    )
    return dict(database=name, populated=True, source_microsecond=123456)


if __name__ == "__main__":
    import json

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()
    print(json.dumps(seed(), sort_keys=True))
