from django.db import migrations, models

TABLES = [
    "governance_supplier",
    "governance_suppliercontract",
    "governance_contractrevision",
    "governance_contractscope",
    "governance_contractparticipant",
    "governance_approvalpolicyrevision",
    "governance_separationrule",
    "identity_identitystatechange",
]
RELATIONS = [
    ("governance_suppliercontract", "supplier", "governance_supplier"),
    ("governance_contractrevision", "contract", "governance_suppliercontract"),
    ("governance_contractscope", "revision", "governance_contractrevision"),
    ("governance_contractscope", "resource", "identity_resource"),
    ("governance_contractparticipant", "contract", "governance_suppliercontract"),
    ("governance_contractparticipant", "identity", "identity_identity"),
    ("governance_separationrule", "left_resource", "identity_resource"),
    ("governance_separationrule", "right_resource", "identity_resource"),
    ("identity_identitystatechange", "identity", "identity_identity"),
    ("identity_externalaccount", "managed_contract", "governance_suppliercontract"),
    ("identity_grant", "contract", "governance_suppliercontract"),
    ("access_accessintent", "contract", "governance_suppliercontract"),
    ("access_accessevent", "contract", "governance_suppliercontract"),
]
IMMUTABLE = [
    "governance_contractrevision",
    "governance_contractscope",
    "governance_approvalpolicyrevision",
    "identity_identitystatechange",
]


def backfill(apps, schema_editor):
    Grant = apps.get_model("identity", "Grant")
    Grant._base_manager.update(valid_from=models.F("created_at"))
    Intent = apps.get_model("access", "AccessIntent")
    Decision = apps.get_model("approvals", "ApprovalDecision")
    for decision in Decision._base_manager.filter(approved=True).iterator():
        Intent._base_manager.filter(pk=decision.intent_id, approved_at__isnull=True).update(
            approved_at=decision.decided_at
        )


def install(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for index, table in enumerate(TABLES):
        schema_editor.execute(
            f"CREATE UNIQUE INDEX pamolive_policy_key_{index} ON {table} (organization_id, id)"
        )
    for index, (table, column, target) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT pamolive_policy_relation_{index} "
            f"FOREIGN KEY (organization_id, {column}_id) REFERENCES {target} (organization_id, id)"
        )
    for index, table in enumerate(IMMUTABLE):
        schema_editor.execute(
            f"CREATE TRIGGER pamolive_policy_proof_{index} BEFORE UPDATE OR DELETE "
            f"ON {table} FOR EACH ROW EXECUTE FUNCTION pamolive_audit_guard()"
        )


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for index, table in enumerate(IMMUTABLE):
        schema_editor.execute(f"DROP TRIGGER pamolive_policy_proof_{index} ON {table}")
    for index, (table, _, _) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} DROP CONSTRAINT pamolive_policy_relation_{index}"
        )
    for index, _ in enumerate(TABLES):
        schema_editor.execute(f"DROP INDEX pamolive_policy_key_{index}")


class Migration(migrations.Migration):
    dependencies = [
        ("governance", "0001_initial"),
        ("identity", "0004_externalaccount_managed_contract_grant_contract_and_more"),
        ("access", "0003_accessevent_contract_accessevent_country_code_and_more"),
        ("approvals", "0002_alter_approvaldecision_intent_and_more"),
        ("connectors", "0003_database_boundaries"),
    ]
    operations = [
        migrations.RunPython(backfill, migrations.RunPython.noop),
        migrations.RunPython(install, uninstall),
    ]
