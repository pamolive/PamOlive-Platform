"""Authenticate the destination of a SCIM credential without changing its ciphertext."""

from django.utils.crypto import constant_time_compare

from platform_core.attestations import signature
from platform_core.security import cipher

from .scim import IntegrationFailure


def destination_seal(connector):
    return signature(
        "pamolive.scim",
        "credential-destination.v1",
        {
            "organization": str(connector.organization_id),
            "connector": str(connector.pk),
            "url": connector.base_url,
            "ciphertext": connector.encrypted_token,
        },
    )


def destination_verified(connector):
    return bool(connector.destination_seal) and constant_time_compare(
        connector.destination_seal, destination_seal(connector)
    )


def connector_token(connector):
    if not destination_verified(connector):
        raise IntegrationFailure("connector_destination_unverified")
    return cipher().decrypt(connector.encrypted_token.encode()).decode()
