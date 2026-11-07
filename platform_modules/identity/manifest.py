from platform_core.registry import ModuleDefinition

definition = ModuleDefinition(
    key="identity",
    name="Identités",
    version="0.1.0",
    summary="Répertoire d'identités, rôles métier et accès associés.",
    category="Gouvernance des identités",
    permissions=(
        "identity.users.view",
        "identity.roles.manage",
        "identity.applications.manage",
        "identity.assignments.manage",
    ),
    url_name="identity-home",
    icon="users",
)
