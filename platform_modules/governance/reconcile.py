"""Reconcile persisted contract withdrawals. Shared accounts are never disabled broadly."""

from django.db import transaction
from django.utils import timezone

from platform_core.audit import record
from platform_core.models import Organization
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.connectors.outbound import queue_account_disable
from platform_modules.identity.models import ExternalAccount, Grant
from platform_modules.identity.services import revoke_grant
from platform_modules.pam.models import SessionLease

from .policy import account_contract_live, contract_withdrawal_required


@transaction.atomic
def reconcile_contracts(organization):
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        now = timezone.now()
        # Policies remain enforceable even when their management UI is disabled.
        for grant in Grant.objects.filter(contract__isnull=False, status="active").select_related(
            "contract", "identity", "resource"
        ):
            if contract_withdrawal_required(grant, organization=organization, at=now):
                revoke_grant(
                    grant, actor=None, organization=organization, origin="contract.withdrawn"
                )
        for account in ExternalAccount.objects.filter(
            managed_contract__isnull=False, active=True
        ).select_related("managed_contract", "identity"):
            if not account_contract_live(account, at=now):
                account.active = False
                account.state_revision += 1
                account.save(update_fields=["active", "state_revision"])
                queue_account_disable(
                    account, actor=None, organization=organization, origin="contract.withdrawn"
                )
                record(
                    action="governance.account.withdrawn.v1",
                    summary=str(account),
                    organization=organization,
                    target=account,
                )
        for intent in AccessIntent.objects.filter(
            contract__isnull=False, status__in=["pending", "approved"]
        ):
            if contract_withdrawal_required(intent, organization=organization, at=now):
                intent.status, intent.revoked_at = "revoked", now
                intent.save(update_fields=["status", "revoked_at"])
                SessionLease.objects.filter(intent=intent, status="active").update(
                    status="revoked", ended_at=now
                )
                record(
                    action="governance.intent.withdrawn.v1",
                    summary=str(intent),
                    organization=organization,
                    target=intent,
                )
