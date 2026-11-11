"""Validate the dedicated N0 Compose plan without starting a container."""

import argparse
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


def validate(plan):
    """Fail closed on an unexpected topology; never return environment values."""
    services = plan.get("services", {})
    if set(services) != {"web", "postgres"}:
        raise ValueError("Unexpected service topology.")
    networks = plan.get("networks", {})
    if set(networks) != {"isolated"} or networks["isolated"].get("internal") is not True:
        raise ValueError("An isolated internal network is required.")
    if networks["isolated"].get("external"):
        raise ValueError("Existing networks are forbidden.")
    volumes = plan.get("volumes", {})
    if set(volumes) != {"postgres_test"} or volumes["postgres_test"].get("external"):
        raise ValueError("A new dedicated database volume is required.")
    project = plan.get("name", "")
    if not project.startswith("pamolive-p1-"):
        raise ValueError("An explicit synthetic project prefix is required.")
    if volumes["postgres_test"].get("name") != project + "_postgres_test":
        raise ValueError("Unexpected existing volume name.")
    if networks["isolated"].get("name") != project + "_isolated":
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
        expected_caps = {"SETUID", "SETGID", "KILL"} if name == "web" else {
            "CHOWN", "FOWNER", "DAC_OVERRIDE", "SETUID", "SETGID"
        }
        if (set(service.get("cap_add", [])) != expected_caps
                or set(service.get("cap_drop", [])) != {"ALL"}
                or set(service.get("security_opt", [])) != {"no-new-privileges:true"}):
            raise ValueError("Only the reviewed minimal capabilities are permitted.")
        if service.get("restart") != "no" or not service.get("read_only"):
            raise ValueError("Read-only containers without automatic restart are required.")
        if set(service.get("networks", {})) != {"isolated"}:
            raise ValueError("Unexpected service network.")
        if not service.get("cpus") or not service.get("mem_limit"):
            raise ValueError("Explicit CPU and memory ceilings are required.")
        if service.get("memswap_limit") != service["mem_limit"]:
            raise ValueError("Additional swap is forbidden.")
        if not service.get("healthcheck") or not service.get("pids_limit"):
            raise ValueError("Healthchecks and PID ceilings are required.")
        for mount in service.get("volumes", []):
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
        if name == "postgres" and service.get("ports"):
            raise ValueError("Database ports must not be published.")
    ports = services["web"].get("ports", [])
    if len(ports) != 1 or ports[0].get("host_ip") != "127.0.0.1" or ports[0].get("target") != 8000:
        raise ValueError("Only the loopback web endpoint is permitted.")
    environment = services["web"].get("environment", {})
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
    args = parser.parse_args()
    compose = Path(__file__).parent / "synology-test" / "compose.yml"
    result = subprocess.run(
        ["docker", "compose", "--env-file", args.env_file, "-f", str(compose),
         "config", "--format", "json"], capture_output=True, text=True, check=False,
    )
    # Compose diagnostics may quote user-supplied values; never print them.
    try:
        if result.returncode:
            raise ValueError
        validate(json.loads(result.stdout))
    except (ValueError, KeyError, TypeError):
        raise SystemExit(
            "N0 Compose validation failed; inspect private configuration locally."
        ) from None
    print("N0 Compose topology validated; no container started and no NAS contacted.")


if __name__ == "__main__":
    main()
