"""Validate the dedicated N0 Compose plan without starting a container."""

import argparse
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

try:
    from deploy.runtime import NATIVE_LIBRARIES, validate_launch_environment
except ModuleNotFoundError:
    from runtime import NATIVE_LIBRARIES, validate_launch_environment


def validate_image_runtime(config):
    """Pure check of the qualified image Config; no Engine/network is contacted."""
    if (
        type(config) is not dict
        or config.get("Cmd") != ["python", "deploy/runtime.py"]
        or config.get("Entrypoint") not in (None, [])
        or config.get("User", "") not in ("", "root", "0", "0:0")
        or config.get("WorkingDir") != "/app"
    ):
        raise ValueError("The qualified image must run the reviewed root supervisor.")
    declared = config.get("Env")
    if type(declared) is not list or any(
        type(item) is not str or "=" not in item for item in declared
    ):
        raise ValueError("The qualified image environment must be explicit.")
    environment = {}
    for item in declared:
        name, _, value = item.partition("=")
        if name in environment:
            raise ValueError("Duplicate image environment names are forbidden.")
        environment[name] = value
    # The supervisor inherits the base image's root HOME and system PATH. These
    # differ from the fixed child values but must never select writable paths.
    image_path = environment.get("PATH", "").split(":")
    if image_path[0] != "/usr/local/bin" or not set(image_path) <= {
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    }:
        raise ValueError("The qualified image must use reviewed system executable paths.")
    if environment.get("HOME", "/root") != "/root":
        raise ValueError("The qualified supervisor must use the root image home.")
    validate_launch_environment(
        {name: value for name, value in environment.items() if name not in {"PATH", "HOME"}}
    )
    if environment.get("LANG") != "C.UTF-8":
        raise ValueError("The qualified image must retain the reviewed locale.")
    if environment.get("LD_LIBRARY_PATH") != NATIVE_LIBRARIES:
        raise ValueError("The qualified image must retain both reviewed native prefixes.")


def validate_tmpfs(name, entries):
    expected = {
        "web": {"/tmp": (64 * 1024**2, 0o1777, None)},
        "gateway": {"/tmp": (16 * 1024**2, 0o1777, None)},
        "postgres": {
            "/tmp": (32 * 1024**2, 0o1777, None),
            "/var/run/postgresql": (8 * 1024**2, 0o775, "999"),
        },
    }[name]
    if type(entries) is not list or len(entries) != len(expected):
        raise ValueError("Only reviewed bounded tmpfs mounts are permitted.")
    seen = set()
    for entry in entries:
        if type(entry) is not str or len(entry) > 256 or entry.count(":") != 1:
            raise ValueError("Invalid tmpfs mount format.")
        target, raw_options = entry.split(":")
        if target not in expected or target in seen:
            raise ValueError("Tmpfs must not shadow code, libraries or font configuration.")
        seen.add(target)
        options = {}
        for raw in raw_options.split(","):
            key, _, value = raw.partition("=")
            if key in options or key not in {
                "size",
                "mode",
                "uid",
                "gid",
                "rw",
                "noexec",
                "nosuid",
                "nodev",
            }:
                raise ValueError("Unknown or duplicate tmpfs option.")
            if key in {"rw", "noexec", "nosuid", "nodev"} and "=" in raw:
                raise ValueError("Invalid tmpfs flag.")
            options[key] = value
        limit, mode, owner = expected[target]
        size = re.fullmatch(r"([1-9][0-9]*)([kKmMgG]?)", options.get("size", ""))
        if size is None or len(size[1]) > 12:
            raise ValueError("Explicit bounded tmpfs size is required.")
        amount = int(size[1]) * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[size[2].lower()]
        declared_mode = options.get("mode", "")
        if (
            amount > limit
            or not re.fullmatch(r"0?[0-7]{3,4}", declared_mode)
            or int(declared_mode, 8) != mode
        ):
            raise ValueError("Unapproved tmpfs size or permissions.")
        if owner is None:
            if any(key in options for key in ("uid", "gid")):
                raise ValueError("Unexpected tmpfs owner override.")
        elif options.get("uid") != owner or options.get("gid") != owner:
            raise ValueError("The dedicated PostgreSQL socket owner is required.")


def validate(plan, *, application_env, image_config=None):
    """Fail closed on an unexpected topology; never return environment values."""
    services = plan.get("services", {})
    if set(services) != {"web", "postgres", "gateway"}:
        raise ValueError("Unexpected service topology.")
    if image_config is not None:
        validate_image_runtime(image_config)
    definitions = plan.get("secrets", {})
    if set(definitions) != {
        "database_owner_password",
        "database_app_password",
        "tls_certificate",
        "tls_private_key",
    }:
        raise ValueError("Exactly four dedicated file secrets are required.")
    paths = []
    for definition in definitions.values():
        if (
            not isinstance(definition.get("file"), str)
            or not definition["file"]
            or definition.get("external")
            or definition.get("environment")
        ):
            raise ValueError("Only private file secrets are permitted.")
        paths.append(Path(definition["file"]).resolve())
    if not application_env or not Path(application_env).is_absolute():
        raise ValueError("The application environment file must be identified.")
    paths.extend(
        (
            Path(application_env).resolve(),
            (Path(__file__).parent / "synology-test" / "nginx.conf").resolve(),
        )
    )
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
        validate_tmpfs(name, service.get("tmpfs"))
        if not re.fullmatch(r"[\w./:-]+@sha256:[a-f0-9]{64}", service.get("image", "")):
            raise ValueError("Images must be pinned by digest.")
        if any(service.get(key) for key in ("privileged", "network_mode", "container_name")):
            raise ValueError("Host privileges or existing container names are forbidden.")
        if any(
            service.get(key)
            for key in (
                "pid",
                "ipc",
                "uts",
                "devices",
                "device_cgroup_rules",
                "volumes_from",
                "use_api_socket",
                "gpus",
                "group_add",
                "userns_mode",
            )
        ):
            raise ValueError("Host namespaces, devices or alternate entrypoints are forbidden.")
        if "entrypoint" in service and service["entrypoint"] is not None:
            raise ValueError("Alternate entrypoints are forbidden.")
        if name == "web" and (
            service.get("command") not in (None, ["python", "deploy/runtime.py"])
            or service.get("user") not in (None, "root", "0", "0:0")
            or service.get("working_dir") not in (None, "/app")
            or service.get("configs")
        ):
            raise ValueError("The application must retain the reviewed root supervisor.")
        expected_caps = {
            "web": {"SETUID", "SETGID", "KILL"},
            "postgres": {"CHOWN", "FOWNER", "DAC_OVERRIDE", "SETUID", "SETGID"},
            "gateway": set(),
        }[name]
        if (
            set(service.get("cap_add", [])) != expected_caps
            or set(service.get("cap_drop", [])) != {"ALL"}
            or set(service.get("security_opt", [])) != {"no-new-privileges:true"}
        ):
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
                if (
                    mount.get("type") != "bind"
                    or not mount.get("read_only")
                    or mount.get("target") != "/etc/nginx/nginx.conf"
                    or Path(mount.get("source", "")).resolve() != expected.resolve()
                ):
                    raise ValueError("Only the reviewed gateway configuration may be mounted.")
                continue
            if name == "web" or mount.get("target") not in {
                "/var/lib/postgresql/data",
                "/docker-entrypoint-initdb.d/10-pamolive-test.sql",
            }:
                raise ValueError("Unexpected host or data mount.")
            if mount["target"] == "/var/lib/postgresql/data":
                if mount.get("type") != "volume" or mount.get("source") != "postgres_test":
                    raise ValueError("Database data must use the dedicated volume.")
            else:
                expected = Path(__file__).parent / "synology-test" / "init-test-db.sql"
                if (
                    mount.get("type") != "bind"
                    or not mount.get("read_only")
                    or Path(mount.get("source", "")).resolve() != expected.resolve()
                ):
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
        "tls_certificate",
        "tls_private_key",
    }:
        raise ValueError("Only TLS secrets may enter the gateway.")
    if services["web"].get("secrets"):
        raise ValueError("Database owner and TLS secrets must not enter the application.")
    if {secret.get("source") for secret in services["postgres"].get("secrets", [])} != {
        "database_owner_password",
        "database_app_password",
    }:
        raise ValueError("Unexpected database secrets.")
    environment = services["web"].get("environment", {})
    validate_launch_environment(environment)
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
    if (
        destination.scheme != "postgresql"
        or destination.hostname != "postgres"
        or destination.username != "pamolive_test"
        or destination.path != "/test_pamolive_p1"
        or destination.port not in (None, 5432)
    ):
        raise ValueError("Only the dedicated synthetic application database is permitted.")
    for key in ("SECRET_KEY", "PAMOLIVE_ENCRYPTION_KEY"):
        value = environment.get(key, "")
        if len(value) < 40 or not value.strip() or not value.isprintable():
            raise ValueError("Explicit valid synthetic application keys are required.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--application-env", type=Path, required=True)
    parser.add_argument(
        "--image-config",
        type=Path,
        help="Optional qualified image Config JSON object, supplied without contacting Docker.",
    )
    args = parser.parse_args()
    if not args.application_env.is_absolute():
        raise SystemExit("An absolute private application environment path is required.")
    application_env = args.application_env.resolve()
    compose = Path(__file__).parent / "synology-test" / "compose.yml"
    # Compose 2.20 has no `config --environment`. Force the same explicit file
    # into interpolation and alias validation instead of parsing dotenv here.
    environment = dict(os.environ, PAMOLIVE_TEST_APP_ENV=str(application_env))
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            args.env_file,
            "-f",
            str(compose),
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    # Compose diagnostics may quote user-supplied values; never print them.
    try:
        if result.returncode:
            raise ValueError
        image_config = None
        if args.image_config is not None:
            with args.image_config.open("rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("Image Config exceeds the review budget.")
            image_config = json.loads(raw)
            validate_image_runtime(image_config)
        validate(
            json.loads(result.stdout), application_env=application_env, image_config=image_config
        )
    except (ValueError, KeyError, TypeError, OSError, UnicodeError):
        raise SystemExit(
            "N0 Compose validation failed; inspect private configuration locally."
        ) from None
    print("N0 Compose topology validated; no container started and no NAS contacted.")
    if image_config is None:
        print(
            "Image Config was not supplied: inherited image command and environment are unverified."
        )
    else:
        print(
            "Supplied image Config validated; "
            "image identity and effective runtime remain separate checks."
        )


if __name__ == "__main__":
    main()
