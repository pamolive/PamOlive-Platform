"""HA fixture trust uses genuine signatures without bypassing PAM verifiers."""

import io
import json
import os
import re
import time
from copy import deepcopy
from unittest import SkipTest, skipUnless
from unittest.mock import AsyncMock, patch

import asyncssh
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import Client, SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone

from deploy.active_active_trust import (
    CHECKPOINT_TARGET,
    QualificationAuthority,
    RemoteAuthenticator,
    decoded,
    snapshots,
)
from deploy.check_active_active import validate_configuration
from deploy.check_runtime import check_mounts
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.pam.probe import ProbeResult
from platform_modules.pam.trust import _historical_registry
from platform_modules.pam.trust_auth_models import PAMTrustAuthorization

from .test_active_active import configuration


class HostAuthorityTests(SimpleTestCase):
    def setUp(self):
        self.authority = QualificationAuthority()
        self.addCleanup(self.authority.close)
        self.org = next(iter(self.authority.keys))

    def test_only_public_configuration_is_sent_to_application_helpers(self):
        info = self.authority.commissioning(self.org)
        self.assertEqual(set(info), {"generation", "custodians"})
        for value in info["custodians"].values():
            Ed25519PublicKey.from_public_bytes(decoded(value))
        self.assertNotIn("PRIVATE", json.dumps(self.authority.settings()))
        self.assertEqual(RemoteAuthenticator({"account": 42}).document(), {"account": "42"})

    def test_witness_signs_fresh_checkpoint_and_refuses_rollback_or_other_generation(self):
        from deploy.active_active_trust import canonical

        head = {"organization": self.org,
                "generation": self.authority.keys[self.org]["generation"],
                "revision": 2, "registry_hash": "a" * 64}
        document = self.authority.checkpoint(head)
        self.authority.keys[self.org]["witness"].public_key().verify(
            decoded(document["signature"]),
            b"pamolive.pam.trust-checkpoint.v1\0" + canonical(document["body"]),
        )
        changed_body = {**document["body"], "revision": document["body"]["revision"] + 1}
        with self.assertRaises(InvalidSignature):
            self.authority.keys[self.org]["witness"].public_key().verify(
                decoded(document["signature"]),
                b"pamolive.pam.trust-checkpoint.v1\0" + canonical(changed_body),
            )
        for changes in ({"revision": 1}, {"registry_hash": "b" * 64},
                        {"generation": "unexpected"}, {"organization": "unexpected"}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.authority.checkpoint({**head, **changes})

    def test_exact_read_only_public_directory_is_the_only_mount_exception(self):
        config = configuration()
        for service in config["services"].values():
            service["environment"].update(self.authority.settings())
            service["volumes"] = [{"type": "bind", "source": str(self.authority.directory),
                                   "target": CHECKPOINT_TARGET, "read_only": True}]
        validate_configuration(config, checkpoint_directory=self.authority.directory)
        for changes in ({"source": "/existing"}, {"read_only": False},
                        {"target": "/app"}, {"type": "volume"},
                        {"target": "/tmp/pamolive-ha-public-checkpoints"},
                        {"target": CHECKPOINT_TARGET + "/nested"}):
            changed = deepcopy(config)
            changed["services"]["node-a"]["volumes"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                validate_configuration(changed, checkpoint_directory=self.authority.directory)
        with self.assertRaises(RuntimeError):
            validate_configuration(config)

    def test_public_checkpoint_fixture_mount_preserves_private_tmpfs_guard(self):
        self.assertEqual(CHECKPOINT_TARGET, "/run/pamolive-ha-public-checkpoints")
        self.assertEqual(
            self.authority.settings()["PAM_TRUST_CHECKPOINT_DIRECTORY"], CHECKPOINT_TARGET
        )
        baseline = (
            "1 0 0:1 / / ro,relatime - overlay overlay ro\n"
            "2 1 0:2 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw,size=65536k\n"
        )
        # The original probe is unchanged: no /tmp submount is exempted.
        check_mounts(baseline)
        check_mounts(
            baseline + f"3 1 0:3 /checkpoints {CHECKPOINT_TARGET} ro - ext4 /dev/synthetic ro\n"
        )
        with self.assertRaisesRegex(RuntimeError, "^runtime_tmpfs_shadow$"):
            check_mounts(
                baseline + "3 2 0:3 /checkpoints /tmp/pamolive-ha-public-checkpoints "
                "ro - ext4 /dev/synthetic ro\n"
            )


class HostPipe:
    def __init__(self, authority, organization):
        self.output = io.StringIO()
        self.authority, self.organization = authority, organization

    def readline(self, size=-1):
        report = json.loads(self.output.getvalue().splitlines()[-1])
        if report["stage"] == "trust-sign":
            value = self.authority.sign_registry(self.organization, report["body"])
        else:
            value = self.authority.authenticate(self.organization, report)
        return json.dumps(value) + "\n"


@skipUnless(connection.vendor == "postgresql", "HA commissioning requires PostgreSQL")
@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class HACommissioningTests(TransactionTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not re.fullmatch(
            r"test_pamolive_ha(?:_[a-z0-9]{1,12})?", str(connection.settings_dict["NAME"])
        ):
            raise SkipTest("Requires the dedicated test_pamolive_ha_trust CI gate")

    def test_same_fixture_commissions_real_registry_and_personal_actions_without_network(self):
        from deploy.active_active_fixture import prepare as prepare_http
        from deploy.active_active_ssh import FixtureError, launch, prepare
        from platform_modules.pam.models import RelayConnection

        authority = QualificationAuthority()
        self.addCleanup(authority.close)
        organization = next(iter(authority.keys))
        values = authority.settings()
        values["PAM_TRUST_CHECKPOINT_DIRECTORY"] = str(authority.directory)
        for key in ("PAM_TRUST_COMMISSIONING_KEYS", "PAM_TRUST_CHECKPOINT_KEYS"):
            values[key] = json.loads(values[key])
        pipe = HostPipe(authority, organization)
        other_browser = Client()
        wrong_session = False

        def witness(_):
            for head in snapshots([organization]):
                authority.checkpoint(head)

        def http_post(node, path, session, csrf, *, fields=None, json_payload=None):
            if json_payload is not None:
                browser = other_browser if wrong_session else self.client
                response = browser.post(path, data=json.dumps(json_payload),
                                        content_type="application/json")
            else:
                response = self.client.post(path, {"csrfmiddlewaretoken": csrf, **(fields or {})})
            return response.status_code, response.content.decode()

        with (
            patch.dict(os.environ, {"PAMOLIVE_HA_QUALIFICATION": "1"}),
            override_settings(**values, PAM_ALLOWED_HOSTS=("ha-ssh-fixture:22222",),
                              PAM_ALLOWED_NETWORKS=("172.16.0.0/12",)),
        ):
            data = prepare_http(organization)
            actor = get_user_model().objects.get(username=data["username"])
            self.client.force_login(actor)
            other_browser.force_login(actor)
            session = self.client.session
            session["mfa_verified_at"] = time.time()
            session.save()
            key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
            result = ProbeResult("ssh", "ha-ssh-fixture", 22222, "172.20.0.3",
                                 "SHA256:synthetic", timezone.now())
            with (
                patch("sys.stdout", pipe.output), patch("sys.stdin", pipe),
                patch("deploy.active_active_trust.time.sleep", side_effect=witness),
                patch("platform_modules.pam.sessions.probe_ssh", AsyncMock(return_value=result)),
            ):
                org, first, second, device = prepare(
                    data["run"], key, "synthetic-ha-password-only",
                    authority=authority.commissioning(organization),
                    browser_session=session.session_key,
                )
                self.assertEqual(str(org), organization)
                self.assertEqual(AccessIntent.unscoped.filter(
                    pk__in=(first, second), status="approved").count(), 2)
                for intent in AccessIntent.unscoped.filter(pk__in=(first, second)):
                    with organization_context(intent.organization):
                        _historical_registry(intent)
                self.assertEqual(PAMTrustAuthorization.unscoped.filter(
                    consumed_at__isnull=False).count(), 4)
                with patch("deploy.active_active_ssh.post", side_effect=http_post):
                    wrong_session = True
                    with self.assertRaises(FixtureError):
                        launch("ha-web-a", first, session.session_key, "synthetic-csrf",
                               RemoteAuthenticator(device))
                    self.assertFalse(RelayConnection.unscoped.exists())
                    wrong_session = False
                    connection_id, config = launch(
                        "ha-web-a", first, session.session_key, "synthetic-csrf",
                        RemoteAuthenticator(device),
                    )
                self.assertEqual(RelayConnection.unscoped.get(pk=connection_id).status, "pending")
                self.assertIn("ticket", config)
            self.assertEqual(PAMTrustAuthorization.unscoped.filter(
                consumed_at__isnull=False).count(), 5)
