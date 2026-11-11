"""Bind a stored credential and a relay mandate to the actual server identity."""

from django.utils.crypto import constant_time_compare

from platform_core.attestations import signature

from .destination import TransportFailure
from .probe import certificate_pin, ssh_host_key


def target_scope(endpoint, account=None):
    account = account or endpoint.account
    return {
        "organization": str(endpoint.organization_id),
        "endpoint": str(endpoint.pk),
        "epoch": endpoint.destination_epoch,
        "resource": str(endpoint.resource_id),
        "account": str(endpoint.account_id),
        "username": account.username,
        "protocol": endpoint.protocol,
        "hostname": endpoint.hostname,
        "port": endpoint.port,
        "domain": endpoint.domain,
        "auth_method": endpoint.auth_method,
        "fingerprint": (
            ssh_host_key(endpoint.ssh_host_key).get_fingerprint("sha256")
            if endpoint.protocol == "ssh"
            else certificate_pin(endpoint.certificate_pin)
        ),
    }


def credential_seal(endpoint, account=None):
    return signature(
        "pamolive.pam",
        "credential-destination.v1",
        {"target": target_scope(endpoint, account), "ciphertext": endpoint.encrypted_secret},
    )


def credential_verified(endpoint, account=None):
    try:
        return bool(endpoint.credential_seal) and constant_time_compare(
            endpoint.credential_seal, credential_seal(endpoint, account)
        )
    except TransportFailure:
        return False
