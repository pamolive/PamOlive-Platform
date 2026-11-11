-- Only the newly initialized, dedicated synthetic database is supported.
-- No password is interpolated into a shell command or SQL source file.
CREATE ROLE pamolive_test LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS;
DO $setup$
DECLARE
    app_password text := trim(trailing E'\n' from pg_read_file('/run/secrets/database_app_password'));
BEGIN
    IF app_password !~ '^[a-f0-9]{64}$' THEN
        RAISE EXCEPTION 'Synthetic application password must be 64 lowercase hexadecimal characters';
    END IF;
    EXECUTE format('ALTER ROLE pamolive_test PASSWORD %L', app_password);
END
$setup$;
ALTER DATABASE test_pamolive_p1 OWNER TO pamolive_test;
REVOKE ALL ON DATABASE test_pamolive_p1 FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO pamolive_test;
