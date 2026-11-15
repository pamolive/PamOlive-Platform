"""Reuse the pinned per-connection DER H11 adapter, without modifying it."""

from pamolive_vault_runtime.transport import configuration, protocol_class, tls_context

__all__ = ["configuration", "protocol_class", "tls_context"]
