#!/usr/bin/env bash
# Fresh installation from the already loaded release image. GitHub CI only.
set -euo pipefail
umask 077
test "${GITHUB_ACTIONS:-}" = true
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]]
[[ "${PAMOLIVE_TEST_DATABASE_NETWORK:-}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]]
test "$(docker network inspect "$PAMOLIVE_TEST_DATABASE_NETWORK" --format '{{.Name}}')" \
  = "$PAMOLIVE_TEST_DATABASE_NETWORK"

scratch="$(mktemp -d "$RUNNER_TEMP/pamolive-registry-smoke-XXXXXX")"
export ENV_FILE="$scratch/compose.env"
project="pamolive-registry-smoke-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
cat > "$scratch/test-network.yml" <<'YAML'
networks:
  default:
    external: true
    name: ${PAMOLIVE_TEST_DATABASE_NETWORK:?Missing CI PostgreSQL network}
YAML

python - <<'PY'
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
from psycopg import sql

source = os.environ["DATABASE_URL"]
parsed = urlsplit(source)
assert parsed.hostname == "127.0.0.1" and parsed.path == "/pamolive" and not parsed.query
role, database = "pamolive_registry_ci", "test_pamolive_registry_install"
password = secrets.token_hex(32)
with psycopg.connect(source, autocommit=True) as connection:
    connection.execute(
        sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB PASSWORD {}").format(
            sql.Identifier(role), sql.Literal(password)
        )
    )
    connection.execute(
        sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(database), sql.Identifier(role))
    )
    connection.execute(
        sql.SQL("REVOKE CONNECT, TEMPORARY ON DATABASE {} FROM PUBLIC").format(
            sql.Identifier(database)
        )
    )
Path(os.environ["ENV_FILE"]).write_text(
    f"PAMOLIVE_IMAGE=pamolive-platform:ci\nSECRET_KEY={secrets.token_hex(48)}\n"
    f"DATABASE_URL=postgresql://{role}:{password}@postgres:5432/{database}\n"
    "PAMOLIVE_PORT=127.0.0.1:39491\nDEBUG=false\nSECURE_COOKIES=false\n",
    encoding="utf-8",
)
PY

# The runner-level DATABASE_URL/SECRET_KEY must not override the fixture env file.
unset DATABASE_URL SECRET_KEY PAMOLIVE_PORT PAMOLIVE_IMAGE
compose() {
  docker compose --env-file "$ENV_FILE" --project-name "$project" \
    -f compose.registry.yml -f "$scratch/test-network.yml" "$@"
}
trap 'compose down --timeout 10' EXIT
test "$(compose config --services)" = web
compose run --rm --no-deps web python manage.py migrate --noinput
DJANGO_SUPERUSER_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(32))')" \
  compose run --rm --no-deps -e DJANGO_SUPERUSER_PASSWORD web python manage.py createsuperuser \
    --noinput --username registry-ci --email registry-ci@example.invalid
compose run --rm --no-deps web python manage.py setup_organization \
  --key registry-ci --name 'Registry CI' --admin registry-ci
compose up --no-build --pull never --wait --wait-timeout 90 -d web
node="$(compose ps --all --quiet)"
[[ "$node" =~ ^[a-f0-9]{12,64}$ ]]
test "$(docker inspect "$node" --format '{{.Image}}')" \
  = "$(docker image inspect pamolive-platform:ci --format '{{.Id}}')"
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:39491/health/ >/dev/null
curl --fail --silent --show-error --max-time 5 \
  http://127.0.0.1:39491/accounts/login/ --output "$scratch/login.html"
grep -q 'name="csrfmiddlewaretoken"' "$scratch/login.html"
compose exec -T web python -m deploy.check_runtime
compose exec -T web python manage.py shell <<'PY'
from django.contrib.auth import get_user_model
from django.db import connection
from platform_core.audit import verify_chain
from platform_core.models import Organization

with connection.cursor() as cursor:
    cursor.execute("SELECT current_database(), current_user, rolsuper, rolcreatedb, rolcreaterole "
                   "FROM pg_roles WHERE rolname = current_user")
    assert cursor.fetchone() == (
        "test_pamolive_registry_install", "pamolive_registry_ci", False, False, False
    )
admin = get_user_model().objects.get(username="registry-ci", is_superuser=True, is_active=True)
org = Organization.objects.get(key="registry-ci", active=True)
assert org.memberships.filter(account=admin, active=True, role="admin").exists()
assert verify_chain(org)
PY
echo 'Single-container Compose installation passed on fresh PostgreSQL without building.'
