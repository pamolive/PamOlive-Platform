"""CLI-only fixtures. Never run against an installation or its business database."""

import argparse
import json
import os
import re
import secrets
import sys
import uuid
from datetime import timedelta


def require_test_database():
    from django.db import connection

    if (
        os.environ.get("PAMOLIVE_HA_QUALIFICATION") != "1"
        or connection.vendor != "postgresql"
        or not re.fullmatch(
            r"test_pamolive_ha(?:_[a-z0-9]{1,12})?", str(connection.settings_dict["NAME"])
        )
    ):
        raise RuntimeError("A dedicated PostgreSQL test_pamolive_ha database is required.")
    # Driver OPTIONS/DSN routing must not override the logical Django database name.
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database()")
        actual_name = cursor.fetchone()[0]
    if actual_name != str(connection.settings_dict["NAME"]):
        raise RuntimeError("Qualification refuses a database routing override.")


def database_route():
    from django.db import connection

    require_test_database()
    with connection.cursor() as cursor:
        cursor.execute("SELECT host(inet_client_addr()), host(inet_server_addr())")
        client, server = cursor.fetchone()
    return {"client": client, "server": server}


def partition_probe():
    from deploy.check_active_active import Browser

    if os.environ.get("PAMOLIVE_HA_QUALIFICATION") != "1":
        raise RuntimeError("The loopback probe requires a qualification container.")
    data = json.load(sys.stdin)
    browser = Browser()
    return {
        "health": browser.request(8000, "/health/")[0],
        "ingest": browser.request(
            8000, "/api/v1/events/", payload=data["event"], bearer=data["token"]
        )[0],
    }


def prepare(organization_id=None):
    import pyotp
    from django.contrib.auth import get_user_model
    from django.contrib.auth.hashers import make_password
    from django.db import transaction
    from django.utils import timezone

    from platform_core.models import AccountSecurity, Organization, OrganizationMembership
    from platform_core.security import cipher
    from platform_core.services import install_module
    from platform_core.tenancy import organization_context
    from platform_modules.connectors.services import create_source
    from platform_modules.identity.models import Grant, Identity, Resource

    require_test_database()
    run = uuid.uuid4().hex
    password, secret, recovery = (
        secrets.token_urlsafe(40),
        pyotp.random_base32(),
        secrets.token_hex(16),
    )
    with transaction.atomic():
        user = get_user_model().objects.create_user("ha-" + run, password=password)
        org = Organization.objects.create(
            **({"id": uuid.UUID(organization_id)} if organization_id else {}),
            key="ha-" + run, name="A qualification " + run,
        )
        other = Organization.objects.create(key="hb-" + run, name="B qualification " + run)
        for organization in (org, other):
            membership = OrganizationMembership.objects.create(
                account=user, organization=organization, role="admin"
            )
            for key in ("identity", "access", "connectors", "intelligence"):
                install_module(key, actor=user, organization=organization)
            if organization == other:
                membership.role = "auditor"
                membership.save(update_fields=["role"])
        AccountSecurity.objects.create(
            account=user,
            encrypted_secret=cipher().encrypt(secret.encode()).decode(),
            recovery_hashes=[make_password(recovery)],
        )
        with organization_context(org):
            identity = Identity.objects.create(
                organization=org, name="HA person " + run, kind="human"
            )
            resource = Resource.objects.create(organization=org, name="HA door " + run, kind="door")
            grant = Grant.objects.create(
                organization=org,
                identity=identity,
                resource=resource,
                entitlement="ha-test",
                justification="Disposable active-active qualification",
                valid_from=timezone.now() - timedelta(minutes=2),
                expires_at=timezone.now() + timedelta(hours=1),
            )
            _, token = create_source("HA source " + run, actor=user, organization=org)
    return {
        "run": run,
        "username": user.username,
        "password": password,
        "totp_secret": secret,
        "recovery": recovery,
        "source_token": token,
        "organization": str(org.pk),
        "other_organization": str(other.pk),
        "identity": str(identity.pk),
        "resource": str(resource.pk),
        "grant": str(grant.pk),
    }


def inspect_run(run, action):
    from django.utils import timezone

    from platform_core.audit import verify_chain
    from platform_core.models import AuditEvent, Organization
    from platform_modules.access.models import AccessEvent
    from platform_modules.identity.models import Grant

    require_test_database()
    if not re.fullmatch(r"[0-9a-f]{32}", run):
        raise RuntimeError("Invalid qualification identifier.")
    org = Organization.objects.get(key="ha-" + run)
    other = Organization.objects.get(key="hb-" + run)
    grant = Grant.unscoped.get(organization=org, entitlement="ha-test")
    if action == "arm":
        Grant.unscoped.filter(pk=grant.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        return {"armed": True}
    events = AccessEvent.unscoped.filter(organization=org)
    revocations = AuditEvent.objects.filter(
        organization=org, action="identity.grant.revoked.v1", object_id=str(grant.pk)
    )
    return {
        "events": events.count(),
        "received_audits": AuditEvent.objects.filter(
            organization=org, action="access.event.received.v1"
        ).count(),
        "other_events": AccessEvent.unscoped.filter(organization=other).count(),
        "grant_status": grant.status,
        "grant_revision": grant.state_revision,
        "grant_revocations": revocations.count(),
        "audit_valid": verify_chain(org) and verify_chain(other),
    }


def main():
    import django

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("prepare", "arm", "inspect", "database-route", "partition-probe")
    )
    parser.add_argument("--run", default="")
    parser.add_argument("--organization", default="")
    args = parser.parse_args()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    django.setup()
    fixture = {
        "prepare": lambda: prepare(args.organization or None),
        "database-route": database_route,
        "partition-probe": partition_probe,
    }.get(args.action)
    result = fixture() if fixture else inspect_run(args.run, args.action)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
