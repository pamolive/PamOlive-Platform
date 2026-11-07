from django.db import migrations


def install(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute("""
            CREATE FUNCTION pamolive_audit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'PAM-olive audit is append-only'; END; $$;
            CREATE TRIGGER pamolive_audit_immutable BEFORE UPDATE OR DELETE
            ON platform_core_auditevent FOR EACH ROW EXECUTE FUNCTION pamolive_audit_guard();
        """)


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute("DROP TRIGGER pamolive_audit_immutable ON platform_core_auditevent")
        schema_editor.execute("DROP FUNCTION pamolive_audit_guard()")


class Migration(migrations.Migration):
    dependencies = [("platform_core", "0002_organization_organizationmembership_and_more")]
    operations = [migrations.RunPython(install, uninstall)]
