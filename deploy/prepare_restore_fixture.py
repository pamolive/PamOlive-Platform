"""Populated CI-only recovery corpus; no network target is contacted."""

import os
import unittest


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
        "SCIM token, target secret, signed mandate, signed notification and sealed capture."
    )


if __name__ == "__main__":
    main()
