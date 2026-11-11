"""Tenant references and monotonic, immutable historical action evidence."""

from django.db import migrations

TABLES = (
    "pam_pamtrustrevision",
    "pam_pamtrustchallenge",
    "pam_pamtrustauthorization",
    "pam_pamtrustenrollment",
    "pam_pamauthenticatorstate",
)
RELATIONS = (
    ("pam_pamtrustauthorization", "challenge", "pam_pamtrustchallenge"),
    ("pam_pamtrustenrollment", "registration", "pam_pamtrustchallenge"),
    ("pam_pamtrustenrollment", "possession", "pam_pamtrustchallenge"),
)


def install(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for index, table in enumerate(TABLES):
        schema_editor.execute(
            f"CREATE UNIQUE INDEX pamolive_trust_key_{index} ON {table} (organization_id,id)"
        )
    for index, (table, field, target) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT pamolive_trust_relation_{index} "
            f"FOREIGN KEY (organization_id,{field}_id) REFERENCES {target} (organization_id,id)"
        )
    schema_editor.execute(
        "CREATE UNIQUE INDEX pamolive_trust_registry_hash "
        "ON pam_pamtrustrevision (organization_id,revision_hash)"
    )
    schema_editor.execute(
        "ALTER TABLE pam_pamtrustchallenge ADD CONSTRAINT pamolive_trust_challenge_registry "
        "FOREIGN KEY (organization_id,registry_hash) "
        "REFERENCES pam_pamtrustrevision (organization_id,revision_hash)"
    )
    schema_editor.execute("""
        CREATE FUNCTION pamolive_trust_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE before_doc jsonb; after_doc jsonb; mutable text[]; field text;
        BEGIN
          IF TG_OP = 'DELETE' OR TG_TABLE_NAME = 'pam_pamtrustrevision' THEN
            RAISE EXCEPTION 'PAM trust evidence is immutable';
          END IF;
          before_doc := to_jsonb(OLD); after_doc := to_jsonb(NEW);
          CASE TG_TABLE_NAME
            WHEN 'pam_pamtrustchallenge' THEN mutable := ARRAY['used_at'];
            WHEN 'pam_pamtrustauthorization' THEN mutable := ARRAY['consumed_at'];
            WHEN 'pam_pamtrustenrollment' THEN
              mutable := ARRAY['possession_id','possession_response','sign_count',
                               'verified_at','consumed_at'];
              IF OLD.verified_at IS NOT NULL AND (
                NEW.possession_response IS DISTINCT FROM OLD.possession_response OR
                NEW.sign_count IS DISTINCT FROM OLD.sign_count
              ) THEN RAISE EXCEPTION 'PAM enrollment proof is immutable'; END IF;
            WHEN 'pam_pamauthenticatorstate' THEN
              mutable := ARRAY['sign_count'];
              IF NEW.sign_count < OLD.sign_count THEN
                RAISE EXCEPTION 'PAM authenticator counter cannot decrease';
              END IF;
          END CASE;
          IF (before_doc - mutable) IS DISTINCT FROM (after_doc - mutable) THEN
            RAISE EXCEPTION 'PAM trust evidence is immutable';
          END IF;
          FOREACH field IN ARRAY ARRAY['used_at','consumed_at','verified_at','possession_id'] LOOP
            IF before_doc ? field AND before_doc->field <> 'null'::jsonb
               AND before_doc->field IS DISTINCT FROM after_doc->field THEN
              RAISE EXCEPTION 'PAM proof transition cannot be undone';
            END IF;
          END LOOP;
          RETURN NEW;
        END $$;
    """)
    for index, table in enumerate(TABLES):
        schema_editor.execute(
            f"CREATE TRIGGER pamolive_trust_guard_{index} BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION pamolive_trust_guard()"
        )


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        "ALTER TABLE pam_pamtrustchallenge DROP CONSTRAINT pamolive_trust_challenge_registry"
    )
    schema_editor.execute("DROP INDEX pamolive_trust_registry_hash")
    for index, table in enumerate(TABLES):
        schema_editor.execute(f"DROP TRIGGER pamolive_trust_guard_{index} ON {table}")
    schema_editor.execute("DROP FUNCTION pamolive_trust_guard()")
    for index, (table, _, _) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} DROP CONSTRAINT pamolive_trust_relation_{index}"
        )
    for index, _ in enumerate(TABLES):
        schema_editor.execute(f"DROP INDEX pamolive_trust_key_{index}")


class Migration(migrations.Migration):
    dependencies = [("pam", "0005_pamtrustchallenge_pamtrustauthorization_and_more")]
    operations = [migrations.RunPython(install, uninstall)]
