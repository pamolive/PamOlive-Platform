"""Create the disposable Docker build context used to qualify the extension template."""

import argparse
from pathlib import Path

from platform_core.extensions.releases import canonical
from tests.extension_fixtures import signed_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    options = parser.parse_args()
    target = Path(options.directory)
    target.mkdir(exist_ok=False)
    wheelhouse = target / "wheels"
    wheelhouse.mkdir()
    wheel, _, _, envelope, trust, catalog = signed_fixture(wheelhouse)
    (target / "catalog.json").write_bytes(catalog.read_bytes())
    (target / "public-keys.json").write_bytes(canonical(trust))
    lock = (
        f"{envelope['payload']['distribution']}=={envelope['payload']['version']} "
        f"--hash=sha256:{envelope['payload']['wheel_sha256']}\n"
    )
    (target / "requirements.lock").write_text(lock, encoding="utf8")
    (target / "Dockerfile").write_bytes(Path("deploy/Dockerfile.extensions").read_bytes())
    # These deliberately do not match any COPY instruction in the derived image.
    (target / "publisher-private.pem").write_text("must-not-enter-the-image", encoding="utf8")
    (target / ".env").write_text("must-not-enter-the-image", encoding="utf8")
    print(
        f"Disposable extension context prepared with {wheel.name}; no real signing key was written."
    )


if __name__ == "__main__":
    main()
