import json
import os
import re
import socket
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured

from platform_core.extensions.releases import load_catalog, load_trust_keys

BASE_DIR = Path(__file__).resolve().parent.parent


def _positive_env_limit(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return default
    if not re.fullmatch(r"[1-9][0-9]{0,7}", raw):
        raise ImproperlyConfigured(f"{name} doit être un entier positif inférieur à 100000000.")
    return int(raw)


SECRET_KEY = os.environ.get("SECRET_KEY", "insecure-development-key-change-me")
if not SECRET_KEY.strip() or not SECRET_KEY.isprintable():
    raise ImproperlyConfigured("SECRET_KEY doit être une valeur non vide et imprimable.")


def _evidence_verification_keys():
    name = "PAMOLIVE_EVIDENCE_VERIFICATION_KEYS"
    raw = os.environ.get(name)
    if raw is None:
        return ()
    try:
        keys = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise ImproperlyConfigured(
            f"{name} doit être un tableau JSON de clés historiques."
        ) from error
    if not isinstance(keys, list) or any(
        not isinstance(key, str)
        or not key.strip()
        or not key.isprintable()
        or key == SECRET_KEY
        for key in keys
    ) or len(set(keys)) != len(keys):
        raise ImproperlyConfigured(
            f"{name} doit contenir uniquement des clés historiques distinctes et valides."
        )
    return tuple(keys)


PAMOLIVE_EVIDENCE_VERIFICATION_KEYS = _evidence_verification_keys()

PAMOLIVE_ENCRYPTION_KEY = os.environ.get("PAMOLIVE_ENCRYPTION_KEY")
if PAMOLIVE_ENCRYPTION_KEY is None:
    PAMOLIVE_ENCRYPTION_KEY = SECRET_KEY
elif (
    len(PAMOLIVE_ENCRYPTION_KEY) < 40
    or not PAMOLIVE_ENCRYPTION_KEY.strip()
    or not PAMOLIVE_ENCRYPTION_KEY.isprintable()
):
    raise ImproperlyConfigured(
        "PAMOLIVE_ENCRYPTION_KEY doit contenir au moins 40 caractères imprimables "
        "et ne peut pas être composée uniquement d’espaces."
    )
CONNECTOR_ALLOWED_HOSTS = frozenset(
    filter(
        None,
        (
            value.strip().lower()
            for value in os.environ.get("PAMOLIVE_CONNECTOR_HOSTS", "").split(",")
        ),
    )
)
CONNECTOR_ALLOWED_NETWORKS = tuple(
    filter(
        None,
        (value.strip() for value in os.environ.get("PAMOLIVE_CONNECTOR_NETWORKS", "").split(",")),
    )
)
CONNECTOR_CA_BUNDLE = os.environ.get("PAMOLIVE_CONNECTOR_CA_BUNDLE", "")
# A PAM destination must match BOTH a host:port entry and an IP network.
# Empty deployment allowlists intentionally deny all session probes/targets.
PAM_ALLOWED_HOSTS = frozenset(
    value.strip().lower()
    for value in os.environ.get("PAMOLIVE_TARGET_HOSTS", "").split(",")
    if value.strip()
)
PAM_ALLOWED_NETWORKS = tuple(
    value.strip()
    for value in os.environ.get("PAMOLIVE_TARGET_NETWORKS", "").split(",")
    if value.strip()
)
PAM_TRUSTED_PROXY_NETWORKS = tuple(
    filter(
        None,
        (
            value.strip()
            for value in os.environ.get("PAMOLIVE_TRUSTED_PROXY_NETWORKS", "").split(",")
        ),
    )
)
PAM_NETWORK_CONTEXT = json.loads(os.environ.get("PAMOLIVE_NETWORK_CONTEXT", "[]"))
PAM_PUBLIC_ORIGIN = os.environ.get("PAMOLIVE_PUBLIC_ORIGIN", "").rstrip("/")
OIDC_PUBLIC_ORIGIN = os.environ.get("PAMOLIVE_OIDC_PUBLIC_ORIGIN", "").rstrip("/")
OIDC_ALLOWED_HOSTS = frozenset(
    value.strip().lower()
    for value in os.environ.get("PAMOLIVE_OIDC_HOSTS", "").split(",")
    if value.strip()
)
OIDC_ALLOWED_NETWORKS = tuple(
    value.strip()
    for value in os.environ.get("PAMOLIVE_OIDC_NETWORKS", "").split(",")
    if value.strip()
)
OIDC_CA_BUNDLE = os.environ.get("PAMOLIVE_OIDC_CA_BUNDLE", "")
# Both transports have mandatory native/ASGI release gates in the test image.
PAM_SESSION_PROTOCOLS = frozenset({"ssh", "rdp"})
PAM_MAX_CONNECTIONS_USER = 4
PAM_MAX_CONNECTIONS_ORG = 16
PAM_MAX_SESSION_SECONDS = 4 * 60 * 60
PAM_MAX_RECORDING_BYTES = 64 * 1024 * 1024
PAM_MAX_RECORDING_ORG_BYTES = 1024 * 1024 * 1024
PAM_GUACD_PORT = 4822
PAM_INSTANCE_ID = os.environ.get("PAMOLIVE_INSTANCE_ID", socket.gethostname())
# Independent deployment anchors; no private signing material belongs on the portal.
PAM_TRUST_INSTALLATION_ID = os.environ.get("PAM_TRUST_INSTALLATION_ID", "")
PAM_TRUST_COMMISSIONING_KEYS = json.loads(os.environ.get("PAM_TRUST_COMMISSIONING_KEYS", "{}"))
PAM_TRUST_CHECKPOINT_KEYS = json.loads(os.environ.get("PAM_TRUST_CHECKPOINT_KEYS", "{}"))
PAM_TRUST_CHECKPOINT_DIRECTORY = os.environ.get("PAM_TRUST_CHECKPOINT_DIRECTORY", "")
PAM_TRUST_RP_ID = os.environ.get("PAM_TRUST_RP_ID", "")
PAM_TRUST_ORIGIN = os.environ.get("PAM_TRUST_ORIGIN", "")
PAM_TRUST_RP_NAME = "PamOlive"
PAM_TRUST_CHALLENGE_SECONDS = 120
PAM_TRUST_REGISTRY_MAX_SECONDS = 86400
PAM_TRUST_CHECKPOINT_MAX_SECONDS = 60
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if host.strip()
]
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]
TIME_ZONE = os.environ.get("TIME_ZONE", "Europe/Brussels")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "platform_core.apps.PlatformCoreConfig",
    "platform_modules.identity.apps.IdentityModuleConfig",
    "platform_modules.access.apps.AccessConfig",
    "platform_modules.approvals",
    "platform_modules.connectors",
    "platform_modules.recertification",
    "platform_modules.pam",
    "platform_modules.governance.apps.GovernanceConfig",
    "platform_modules.intelligence.apps.IntelligenceConfig",
]
# Deployment configuration only. No request, database field or uploaded code can add an app.
PAMOLIVE_EXTENSIONS = load_catalog(
    os.environ.get("PAMOLIVE_EXTENSION_CATALOG", ""),
    load_trust_keys(
        os.environ.get("PAMOLIVE_EXTENSION_TRUST_KEYS", ""),
        os.environ.get("PAMOLIVE_EXTENSION_TRUST_KEYS_FILE", ""),
    ),
)
INSTALLED_APPS.extend(release.manifest.django_app for release in PAMOLIVE_EXTENSIONS)
INSTALLED_APPS.append("platform_core.extensions.apps.ExtensionRegistryConfig")
MIDDLEWARE = [
    "platform_core.middleware.TrustedProxyMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "platform_core.tenancy.OrganizationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "platform_core.middleware.ResponseSecurityMiddleware",
]
ROOT_URLCONF = "config.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "platform_core.context_processors.navigation_modules",
            ]
        },
    }
]
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

database_url = os.environ.get("DATABASE_URL")
if database_url:
    DATABASES = {
        "default": dj_database_url.parse(database_url, conn_max_age=0, conn_health_checks=True)
    }
else:
    DATABASES = {
        "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}
    }

test_database_name = os.environ.get("PAMOLIVE_TEST_DATABASE_NAME", "")
if test_database_name:
    if not re.fullmatch(r"test_pamolive_[a-z0-9_]{1,50}", test_database_name):
        raise ValueError("Le nom de base de tests doit être explicitement préfixé test_pamolive_.")
    DATABASES["default"]["TEST"] = {"NAME": test_database_name}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LANGUAGE_CODE = "fr"
USE_I18N = True
USE_TZ = True
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
DATA_UPLOAD_MAX_MEMORY_SIZE = 65536
DATA_UPLOAD_MAX_NUMBER_FIELDS = 100
RECERTIFICATION_MAX_GRANTS = int(os.environ.get("PAMOLIVE_RECERTIFICATION_MAX_GRANTS", "10000"))
RECERTIFICATION_MAX_BYTES = int(os.environ.get("PAMOLIVE_RECERTIFICATION_MAX_BYTES", "16777216"))
PAMOLIVE_EVENT_MANUAL_DAILY_LIMIT = _positive_env_limit(
    "PAMOLIVE_EVENT_MANUAL_DAILY_LIMIT", 5000
)
PAMOLIVE_EVENT_COLLECTOR_DAILY_LIMIT = _positive_env_limit(
    "PAMOLIVE_EVENT_COLLECTOR_DAILY_LIMIT", 50000
)
PAMOLIVE_EVENT_INTERNAL_DAILY_LIMIT = _positive_env_limit(
    "PAMOLIVE_EVENT_INTERNAL_DAILY_LIMIT", 50000
)
PAMOLIVE_EVENT_ORG_DAILY_LIMIT = _positive_env_limit(
    "PAMOLIVE_EVENT_ORG_DAILY_LIMIT", 250000
)
PAMOLIVE_EVENT_MANUAL_DAILY_ATTEMPT_LIMIT = _positive_env_limit(
    "PAMOLIVE_EVENT_MANUAL_DAILY_ATTEMPT_LIMIT", 20000
)
PAMOLIVE_EVENT_COLLECTOR_DAILY_ATTEMPT_LIMIT = _positive_env_limit(
    "PAMOLIVE_EVENT_COLLECTOR_DAILY_ATTEMPT_LIMIT", 200000
)
PAMOLIVE_EVENT_INTERNAL_DAILY_ATTEMPT_LIMIT = _positive_env_limit(
    "PAMOLIVE_EVENT_INTERNAL_DAILY_ATTEMPT_LIMIT", 200000
)
PAMOLIVE_EVENT_ORG_DAILY_ATTEMPT_LIMIT = _positive_env_limit(
    "PAMOLIVE_EVENT_ORG_DAILY_ATTEMPT_LIMIT", 1000000
)
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = os.environ.get("SECURE_SSL_REDIRECT", "false").lower() == "true"
SESSION_COOKIE_SECURE = os.environ.get("SECURE_COOKIES", str(not DEBUG)).lower() == "true"
SESSION_COOKIE_NAME = "pamolive_platform_session"
CSRF_COOKIE_NAME = "pamolive_platform_csrftoken"
CSRF_COOKIE_SECURE = SESSION_COOKIE_SECURE
SECURE_HSTS_SECONDS = 31_536_000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
