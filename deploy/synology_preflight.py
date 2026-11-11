"""Validate the dedicated N0 Compose plan without starting a container."""

import argparse
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


def validate(plan, *, application_env):
    """Fail closed on an unexpected topology; never return environment values."""
    services = plan.get("services", {})
    if set(services) != {"web", "postgres", "gateway"}:
        raise ValueError("Unexpected service topology.")
    definitions = plan.get("secrets", {})
    if set(definitions) != {
        "database_owner_password", "database_app_password", "tls_certificate", "tls_private_key"
    }:
        raise ValueError("Exactly four dedicated file secrets are required.")
    paths = []
    for definition in definitions.values():
        if (not isinstance(definition.get("file"), str) or not definition["file"]
                or definition.get("external") or definition.get("environment")):
            raise ValueError("Only private file secrets are permitted.")
        paths.append(Path(definition["file"]).resolve())
    if not application_env or not Path(application_env).is_absolute():
        raise ValueError("The application environment file must be identified.")
    paths.extend((Path(application_env).resolve(),
                  (Path(__file__).parent / "synology-test" / "nginx.conf").resolve()))
    # Symlinks are resolved, and existing hardlinks also count as one file.
    # No secret content is opened or returned by this check.
    for index, path in enumerate(paths):
        for other in paths[:index]:
            if path == other or (path.exists() and other.exists() and path.samefile(other)):
                raise ValueError(
                    "Secrets, application environment and gateway config must be distinct files."
                )
    networks = plan.get("networks", {})
    if set(networks) != {"frontend", "database", "ingress"} or any(
        networks[name].get("internal") is not True for name in ("frontend", "database")
    ):
        raise ValueError("An isolated internal network is required.")
    if any(network.get("external") for network in networks.values()):
        raise ValueError("Existing networks are forbidden.")
    if networks["ingress"].get("internal"):
        raise ValueError("The dedicated gateway ingress network must support loopback publishing.")
    volumes = plan.get("volumes", {})
    if set(volumes) != {"postgres_test"} or volumes["postgres_test"].get("external"):
        raise ValueError("A new dedicated database volume is required.")
    project = plan.get("name", "")
    if not project.startswith("pamolive-p1-"):
        raise ValueError("An explicit synthetic project prefix is required.")
    if volumes["postgres_test"].get("name") != project + "_postgres_test":
        raise ValueError("Unexpected existing volume name.")
    if any(networks[name].get("name") != project + "_" + name for name in networks):
        raise ValueError("Unexpected existing network name.")
    for name, service in services.items():
        if not re.fullmatch(r"[\w./:-]+@sha256:[a-f0-9]{64}", service.get("image", "")):
            raise ValueError("Images must be pinned by digest.")
        if any(service.get(key) for key in ("privileged", "network_mode", "container_name")):
            raise ValueError("Host privileges or existing container names are forbidden.")
        if any(service.get(key) for key in (
            "pid", "ipc", "uts", "devices", "device_cgroup_rules", "volumes_from",
            "use_api_socket", "gpus", "group_add", "entrypoint", "userns_mode",
        )):
            raise ValueError("Host namespaces, devices or alternate entrypoints are forbidden.")
        expected_caps = {
            "web": {"SETUID", "SETGID", "KILL"},
            "postgres": {"CHOWN", "FOWNER", "DAC_OVERRIDE", "SETUID", "SETGID"},
            "gateway": set(),
        }[name]
        if (set(service.get("cap_add", [])) != expected_caps
                or set(service.get("cap_drop", [])) != {"ALL"}
                or set(service.get("security_opt", [])) != {"no-new-privileges:true"}):
            raise ValueError("Only the reviewed minimal capabilities are permitted.")
        if service.get("restart") != "no" or not service.get("read_only"):
            raise ValueError("Read-only containers without automatic restart are required.")
        expected_networks = {
            "web": {"frontend", "database"},
            "gateway": {"frontend", "ingress"},
            "postgres": {"database"},
        }[name]
        if set(service.get("networks", {})) != expected_networks:
            raise ValueError("Unexpected service network.")
        if not service.get("cpus") or not service.get("mem_limit"):
            raise ValueError("Explicit CPU and memory ceilings are required.")
        if service.get("memswap_limit") != service["mem_limit"]:
            raise ValueError("Additional swap is forbidden.")
        if not service.get("healthcheck") or not service.get("pids_limit"):
            raise ValueError("Healthchecks and PID ceilings are required.")
        for mount in service.get("volumes", []):
            if name == "gateway":
                expected = Path(__file__).parent / "synology-test" / "nginx.conf"
                if (mount.get("type") != "bind" or not mount.get("read_only")
                        or mount.get("target") != "/etc/nginx/nginx.conf"
                        or Path(mount.get("source", "")).resolve() != expected.resolve()):
                    raise ValueError("Only the reviewed gateway configuration may be mounted.")
                continue
            if name == "web" or mount.get("target") not in {
                "/var/lib/postgresql/data", "/docker-entrypoint-initdb.d/10-pamolive-test.sql"
            }:
                raise ValueError("Unexpected host or data mount.")
            if mount["target"] == "/var/lib/postgresql/data":
                if mount.get("type") != "volume" or mount.get("source") != "postgres_test":
                    raise ValueError("Database data must use the dedicated volume.")
            else:
                expected = Path(__file__).parent / "synology-test" / "init-test-db.sql"
                if (mount.get("type") != "bind" or not mount.get("read_only")
                        or Path(mount.get("source", "")).resolve() != expected.resolve()):
                    raise ValueError("Only the reviewed initialization script is permitted.")
        if name != "gateway" and service.get("ports"):
            raise ValueError("Application and database ports must not be published.")
    ports = services["gateway"].get("ports", [])
    if len(ports) != 1 or ports[0].get("host_ip") != "127.0.0.1" or ports[0].get("target") != 8443:
        raise ValueError("Only the loopback TLS endpoint is permitted.")
    gateway = services["gateway"]
    if gateway.get("user") != "101:101" or gateway.get("environment"):
        raise ValueError("The gateway must be non-root and receive no application environment.")
    if gateway.get("command") != ["nginx", "-g", "daemon off;"]:
        raise ValueError("Unexpected gateway command.")
    if len(gateway.get("volumes", [])) != 1:
        raise ValueError("The reviewed gateway configuration is required.")
    if {secret.get("source") for secret in gateway.get("secrets", [])} != {
        "tls_certificate", "tls_private_key"
    }:
        raise ValueError("Only TLS secrets may enter the gateway.")
    if services["web"].get("secrets"):
        raise ValueError("Database owner and TLS secrets must not enter the application.")
    if {secret.get("source") for secret in services["postgres"].get("secrets", [])} != {
        "database_owner_password", "database_app_password"
    }:
        raise ValueError("Unexpected database secrets.")
    environment = services["web"].get("environment", {})
    if environment.get("DEBUG") != "false" or environment.get("SECURE_COOKIES") != "true":
        raise ValueError("TLS packaging requires production-mode secure cookies.")
    proxy_peer = environment.get("PAMOLIVE_TRUSTED_PROXY_NETWORKS", "")
    if proxy_peer:
        try:
            peer = ipaddress.ip_network(proxy_peer, strict=True)
        except ValueError:
            raise ValueError("A single exact proxy peer is required.") from None
        if peer.prefixlen != peer.max_prefixlen:
            raise ValueError("Proxy trust must never include a subnet.")
    destination = urlsplit(environment.get("DATABASE_URL", ""))
    if (destination.scheme != "postgresql" or destination.hostname != "postgres"
            or destination.username != "pamolive_test" or destination.path != "/test_pamolive_p1"
            or destination.port not in (None, 5432)):
        raise ValueError("Only the dedicated synthetic application database is permitted.")
    for key in ("SECRET_KEY", "PAMOLIVE_ENCRYPTION_KEY"):
        value = environment.get(key, "")
        if len(value) < 40 or not value.strip() or not value.isprintable():
            raise ValueError("Explicit valid synthetic application keys are required.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--application-env", type=Path, required=True)
    args = parser.parse_args()
    if not args.application_env.is_absolute():
        raise SystemExit("An absolute private application environment path is required.")
    application_env = args.application_env.resolve()
    compose = Path(__file__).parent / "synology-test" / "compose.yml"
    # Compose 2.20 has no `config --environment`. Force the same explicit file
    # into interpolation and alias validation instead of parsing dotenv here.
    environment = dict(os.environ, PAMOLIVE_TEST_APP_ENV=str(application_env))
    result = subprocess.run(
        ["docker", "compose", "--env-file", args.env_file, "-f", str(compose),
         "config", "--format", "json"], capture_output=True, text=True, check=False,
        env=environment,
    )
    # Compose diagnostics may quote user-supplied values; never print them.
    try:
        if result.returncode:
            raise ValueError
        validate(json.loads(result.stdout), application_env=application_env)
    except (ValueError, KeyError, TypeError, OSError):
        raise SystemExit(
            "N0 Compose validation failed; inspect private configuration locally."
        ) from None
    print("N0 Compose topology validated; no container started and no NAS contacted.")


if __name__ == "__main__":
    main()
