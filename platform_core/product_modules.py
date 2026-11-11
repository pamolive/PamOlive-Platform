"""Product vocabulary, not a second activation or authorization registry."""

PRODUCT_MAPPING_VERSION = "pamolive.product-modules/1"

# Technical keys remain authoritative in platform_core.registry. Empty tuples
# deliberately do not manufacture installed capabilities for roadmap products.
PRODUCT_MODULES = (
    ("identity", "Identity", ("identity",), "implemented_partial"),
    ("governance", "Governance", ("governance", "approvals", "recertification"),
     "implemented_partial"),
    ("privilege", "Privilege", ("access", "pam"), "laboratory"),
    ("vault", "Vault", (), "design_only"),
    ("observe", "Observe", ("access", "intelligence"), "implemented_partial"),
    ("connect", "Connect", ("connectors",), "implemented_partial"),
    ("audit", "Audit", (), "shared_core"),
    ("machine", "Machine", ("identity", "intelligence"), "integrated_partial"),
    ("cloud", "Cloud", (), "planned"),
    ("defense", "Defense", (), "planned"),
    ("posture", "Posture", (), "planned"),
)


def product_module_mapping():
    """Return a fresh JSON-safe mapping; it conveys no permissions or entitlements."""
    return {
        "schema": PRODUCT_MAPPING_VERSION,
        "modules": [
            {"key": key, "name": name, "technical_modules": list(modules), "maturity": maturity}
            for key, name, modules, maturity in PRODUCT_MODULES
        ],
    }
