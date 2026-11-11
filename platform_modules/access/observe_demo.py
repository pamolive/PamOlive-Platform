"""One-shot synthetic demonstration. Never imported by an operational endpoint."""

import re
import secrets
import time
from datetime import timedelta
from unittest.mock import patch

import pyotp
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import override_settings
from django.utils import timezone

from platform_core.access_contract import build_access_contract
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity, Organization, OrganizationMembership
from platform_core.security import cipher
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.approvals.services import decide
from platform_modules.connectors import outbound
from platform_modules.connectors.models import ExternalChange
from platform_modules.connectors.scim import IntegrationFailure
from platform_modules.connectors.services import create_source
from platform_modules.identity.services import expire_grants

from .observe import observation_story
from .services import create_record, ingest_event


class SyntheticScim:
    """No socket or HTTP client; confirms only an in-memory synthetic membership."""

    def __init__(self, url, token, before_write=None):
        if not url.startswith("https://observe-demo-") or not url.endswith(".invalid/scim"):
            raise ValidationError("Destination non synthétique refusée.")
        self.before_write = before_write
        self.members = set()

    def test(self):
        return None

    def membership(self, account, group, *, present):
        if self.before_write:
            self.before_write()
        key = (account, group)
        if present:
            self.members.add(key)
        else:
            self.members.discard(key)
        assert (key in self.members) == present
        return {"simulation": True, "transport": "in_memory", "member": present}


@transaction.atomic
def create_observe_demo():
    """Require a fresh synthetic database. No reset, deletion or network fallback."""
    name = str(connection.settings_dict["NAME"])
    if not (
        name == ":memory:" or name.startswith("file:memorydb_")
        or re.fullmatch(r"test_pamolive_[a-z0-9_]{1,50}", name)
    ):
        raise ValidationError("Une base test_pamolive_* neuve est obligatoire.")
    User = get_user_model()
    if Organization.objects.exists() or User.objects.exists():
        raise ValidationError("La base doit être vide de toute organisation et de tout compte.")
    admin = User.objects.create_superuser("observe-demo-admin", password=None)
    AccountSecurity.objects.create(account=admin, encrypted_secret=cipher().encrypt(
        pyotp.random_base32().encode()).decode())
    operator = User.objects.create_user("observe-demo-operator", password=None)
    reviewer = User.objects.create_user("observe-demo-reviewer", password=None)
    AccountSecurity.objects.create(account=reviewer, encrypted_secret=cipher().encrypt(
        pyotp.random_base32().encode()).decode())
    manifest = {"synthetic_only": True, "remote_system_contacted": False,
                "transport": "in_memory", "organizations": []}
    with override_settings(CONNECTOR_ALLOWED_HOSTS=(
        "observe-demo-a.invalid:443", "observe-demo-b.invalid:443"
    )), patch.object(outbound, "ScimAdapter", SyntheticScim):
        for tenant in ("a", "b"):
            org = Organization.objects.create(key=f"observe-demo-{tenant}",
                                              name=f"Observe synthétique {tenant.upper()}")
            for user, role in ((operator, "operator"), (reviewer, "reviewer")):
                OrganizationMembership.objects.create(organization=org, account=user, role=role)
            for key in ("identity", "access", "approvals", "connectors", "intelligence"):
                install_module(key, actor=admin, organization=org)
            if tenant == "a":
                install_module("recertification", actor=admin, organization=org)
            with organization_context(org):
                identity = create_record("identity", {
                    "name": "Cyriel synthétique", "kind": "human"},
                                         actor=operator, organization=org)
                account = create_record("account", {"identity": identity,
                                        "username": "demo-support", "system": "synthetic"},
                                        actor=operator, organization=org)
                resources = {name: create_record("resource", {"name": name, "kind": "device"},
                             actor=operator, organization=org) for name in ("PC-483", "PC-991")}
                with recent_authentication(admin, org, time.time()):
                    connector = outbound.configure_connector(actor=admin, organization=org,
                        name="Annuaire synthétique sans réseau",
                        base_url=f"https://observe-demo-{tenant}.invalid/scim",
                        token=secrets.token_urlsafe(32))
                    outbound.test_connector(connector.pk, actor=admin, organization=org)
                    outbound.set_connector_enabled(connector.pk, actor=admin, organization=org,
                                                   enabled=True)
                    connector.refresh_from_db()
                    outbound.bind_account(actor=admin, organization=org, connector=connector,
                                          account=account, remote_identifier="same-remote-user")
                    outbound.bind_group(actor=admin, organization=org, connector=connector,
                        resource=resources["PC-483"], entitlement="Administrator",
                        remote_identifier="same-remote-group")
                now = timezone.now()
                intent = create_record("intent", {"identity": identity, "account": account,
                    "resource": resources["PC-483"], "method": "TeamViewer",
                    "privilege": "Administrator", "fulfillment": "iam_group",
                    "reason": "Démonstration locale synthétique", "reference": "INC-47294",
                    "starts_at": now - timedelta(minutes=1), "ends_at": now + timedelta(hours=2)},
                    actor=operator, organization=org)
                with recent_authentication(reviewer, org, time.time()):
                    decide(intent.pk, actor=reviewer, organization=org, approved=True,
                           comment="Accord de démonstration synthétique, sans cible réelle")
                pending = build_access_contract(intent.pk, actor=operator, organization=org)
                processed = outbound.process_changes(org, limit=5)
                confirmed = build_access_contract(intent.pk, actor=operator, organization=org)
                source, credential = create_source("Collecteur synthétique Observe",
                                                    actor=admin, organization=org)
                stories = []
                for label, resource, observed_identity in (
                    ("PC-483", resources["PC-483"], identity),
                    ("PC-991", resources["PC-991"], identity),
                    ("identity-unresolved", resources["PC-483"], None),
                ):
                    event, _ = ingest_event({"external_id": label, "identity": observed_identity,
                        "account": account, "resource": resource, "method": "TeamViewer",
                        "privilege": "Administrator", "action": "session.start",
                        "occurred_at": timezone.now(), "evidence": "Synthetic in-memory fixture"},
                        organization=org, source=source, source_token=credential)
                    story = observation_story(event.pk, actor=operator, organization=org,
                                              comparison_intent_id=intent.pk)
                    stories.append({"scenario": label, "event_id": str(event.pk),
                                    "verdict": story["verdict"],
                                    "receipt_id": story["provenance"]["receipt_id"]})
                manual, _ = ingest_event({"source": str(source.pk), "external_id": "PC-483",
                    "identity": identity, "account": account, "resource": resources["PC-483"],
                    "method": "TeamViewer", "privilege": "Administrator",
                    "action": "session.start", "occurred_at": timezone.now()},
                    organization=org, actor=operator)
                # Advance only this isolated fixture's clock; no expiry or real write outside it.
                after_expiry = intent.ends_at + timedelta(seconds=1)
                with patch("platform_modules.identity.services.timezone.now",
                           return_value=after_expiry):
                    expire_grants(org)
                    withdrawing = build_access_contract(intent.pk, actor=operator, organization=org)
                    with patch.object(outbound, "ScimAdapter", side_effect=IntegrationFailure(
                        "synthetic_provider_unavailable", retryable=True
                    )):
                        outbound.process_changes(org, limit=1)
                    retry = ExternalChange.objects.get(kind="remove_membership")
                unavailable = build_access_contract(intent.pk, actor=operator, organization=org)
                with patch("platform_modules.connectors.outbound.timezone.now",
                           return_value=retry.next_attempt_at + timedelta(seconds=1)):
                    outbound.process_changes(org, limit=1)
                recovered = build_access_contract(intent.pk, actor=operator, organization=org)

                def stage(contract):
                    return {"changes": [{"kind": row["kind"], "status": row["status"]}
                                        for row in contract["execution_attempts"]["items"]],
                            "confirmed_effects": [row["kind"] for row in
                                                  contract["confirmed_executions"]["items"]]}

                manifest["organizations"].append({"id": str(org.pk), "key": org.key,
                    "intent_id": str(intent.pk), "processed_changes": processed,
                    "manual_collision_event_id": str(manual.pk),
                    "stages": {"pending": stage(pending), "confirmed": stage(confirmed),
                               "withdrawal_requested": stage(withdrawing),
                               "provider_unavailable": stage(unavailable),
                               "withdrawal_confirmed": stage(recovered)},
                    "observations": stories})
    return manifest
