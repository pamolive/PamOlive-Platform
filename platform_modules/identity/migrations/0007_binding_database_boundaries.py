"""Tenant/principal references and append-only person attestations under PostgreSQL."""

from django.db import migrations


def install(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        "CREATE UNIQUE INDEX pamolive_binding_key ON identity_loginidentitybinding "
        "(organization_id, id)"
    )
    schema_editor.execute(
        "CREATE UNIQUE INDEX pamolive_binding_principal_key ON identity_loginidentitybinding "
        "(organization_id, id, identity_id, login_account_id)"
    )
    schema_editor.execute(
        "ALTER TABLE identity_loginidentitybinding ADD CONSTRAINT pamolive_binding_identity "
        "FOREIGN KEY (organization_id, identity_id) "
        "REFERENCES identity_identity (organization_id, id)"
    )
    schema_editor.execute(
        "ALTER TABLE access_accessintent ADD CONSTRAINT pamolive_requester_principal "
        "FOREIGN KEY (organization_id, requester_binding_id, identity_id, requested_by_id) "
        "REFERENCES identity_loginidentitybinding "
        "(organization_id, id, identity_id, login_account_id)"
    )
    schema_editor.execute(
        "ALTER TABLE approvals_approvaldecision ADD CONSTRAINT pamolive_reviewer_principal "
        "FOREIGN KEY (organization_id, reviewer_binding_id, reviewer_identity_id, reviewer_id) "
        "REFERENCES identity_loginidentitybinding "
        "(organization_id, id, identity_id, login_account_id)"
    )
    schema_editor.execute(
        "ALTER TABLE approvals_approvaldecision ADD CONSTRAINT pamolive_reviewer_identity "
        "FOREIGN KEY (organization_id, reviewer_identity_id) "
        "REFERENCES identity_identity (organization_id, id)"
    )
    schema_editor.execute("""
        CREATE FUNCTION pamolive_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'PAM-olive person attestations cannot be deleted';
            END IF;
            IF (to_jsonb(NEW) - ARRAY['revoked_at', 'revoked_by_id', 'revocation_reason'])
                IS DISTINCT FROM
                (to_jsonb(OLD) - ARRAY['revoked_at', 'revoked_by_id', 'revocation_reason']) THEN
                RAISE EXCEPTION 'PAM-olive person attestation is immutable';
            END IF;
            IF OLD.revoked_at IS NOT NULL AND
                (NEW.revoked_at, NEW.revoked_by_id, NEW.revocation_reason) IS DISTINCT FROM
                (OLD.revoked_at, OLD.revoked_by_id, OLD.revocation_reason) THEN
                RAISE EXCEPTION 'PAM-olive binding revocation is permanent';
            END IF;
            IF (NEW.revoked_at IS NULL AND
                    (NEW.revoked_by_id IS NOT NULL OR NEW.revocation_reason <> '')) OR
                (NEW.revoked_at IS NOT NULL AND
                    (NEW.revoked_by_id IS NULL OR trim(NEW.revocation_reason) = '' OR
                     NEW.revoked_at < NEW.created_at)) THEN
                RAISE EXCEPTION 'PAM-olive binding revocation is incomplete';
            END IF;
            RETURN NEW;
        END; $$;
        CREATE TRIGGER pamolive_binding_immutable BEFORE UPDATE OR DELETE
        ON identity_loginidentitybinding FOR EACH ROW EXECUTE FUNCTION pamolive_binding_guard();
    """)


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        "DROP TRIGGER pamolive_binding_immutable ON identity_loginidentitybinding"
    )
    schema_editor.execute("DROP FUNCTION pamolive_binding_guard()")
    for table, name in (
        ("approvals_approvaldecision", "pamolive_reviewer_identity"),
        ("approvals_approvaldecision", "pamolive_reviewer_principal"),
        ("access_accessintent", "pamolive_requester_principal"),
        ("identity_loginidentitybinding", "pamolive_binding_identity"),
    ):
        schema_editor.execute(f"ALTER TABLE {table} DROP CONSTRAINT {name}")
    schema_editor.execute("DROP INDEX pamolive_binding_principal_key")
    schema_editor.execute("DROP INDEX pamolive_binding_key")


class Migration(migrations.Migration):
    dependencies = [
        ("identity", "0006_person_bound_pam_mandates"),
        ("access", "0008_person_bound_pam_mandates"),
        ("approvals", "0003_person_bound_pam_mandates"),
        ("platform_core", "0004_tenant_database_boundaries"),
    ]
    operations = [migrations.RunPython(install, uninstall)]
