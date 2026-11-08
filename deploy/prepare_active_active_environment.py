"""Generate a private disposable qualification environment; never modify a database."""

import argparse
import os
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit


def environment(database_url, *, image, network, host=None):
    if any(character in database_url for character in "\r\n'\\"):
        raise ValueError("Unsupported source URL.")
    parsed = urlsplit(database_url)
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname:
        raise ValueError("A PostgreSQL source URL is required.")
    if {key.lower() for key, _ in parse_qsl(parsed.query)} & {
        "dbname",
        "database",
        "service",
        "servicefile",
    }:
        raise ValueError("Database routing overrides are forbidden in qualification.")
    if host:
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
            raise ValueError("Invalid Docker database host.")
        userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
        parsed = parsed._replace(
            netloc=userinfo + host + (":" + str(parsed.port) if parsed.port else "")
        )
    result = {
        "PAMOLIVE_HA_DATABASE_URL": urlunsplit(parsed._replace(path="/test_pamolive_ha")),
        "PAMOLIVE_HA_IMAGE": image,
        "PAMOLIVE_HA_DATABASE_NETWORK": network,
    }
    for value in result.values():
        if not value or any(character in value for character in "\r\n'\\"):
            raise ValueError("Unsupported private environment value.")
    # Single-quoted Compose values are literal, including $ in percent-encoded credentials.
    return "".join(f"{key}='{value}'\n" for key, value in result.items())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--host")
    args = parser.parse_args()
    content = environment(
        os.environ.get("DATABASE_URL", ""), image=args.image, network=args.network, host=args.host
    )
    # No overwrite of a pre-existing credential file; only a generated local artifact.
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    print("Private HA qualification environment created; no database was changed.")


if __name__ == "__main__":
    main()
