"""Separate CycloneDX inventory of verified local Debian Kerberos libraries.

Offline export in the isolated security toolchain, never runtime capture.
This does not amend scanner findings or merge with the compiled-native SBOM.
"""

import argparse
import json
import os
import re
import uuid
from urllib.parse import quote

try:
    from deploy import krb5_inventory as inventory
    from deploy import native_sbom as standard
except ModuleNotFoundError:
    import krb5_inventory as inventory
    import native_sbom as standard

PREFIX = "urn:pamolive:krb5:"
IMAGE_KIND = "image_config"


def require(value, code):
    if not value:
        raise standard.SbomError(code)


def properties(values):
    return [
        {"name": "pamolive:krb5:" + key, "value": str(value)}
        for key, value in sorted(values.items())
    ]


def export(manifest, report, *, image_digest, image_digest_kind, input_hashes):
    inventory.validate_manifest(manifest)
    require(
        isinstance(report, dict)
        and report.get("schema") == inventory.SCHEMA
        and report.get("verified") is True
        and report.get("compilation_proof") is False,
        "krb5_verification_required",
    )
    require(report.get("inventory") == manifest, "krb5_report_mismatch")
    require(image_digest_kind == IMAGE_KIND, "image_digest_kind")
    require(
        isinstance(image_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest),
        "image_digest",
    )
    require(
        set(input_hashes) == {"manifest", "report"}
        and all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
            for value in input_hashes.values()
        ),
        "input_hashes",
    )
    standard.bounded(manifest)
    standard.bounded(report)
    source_ref = PREFIX + "source:mit-krb5:1.21.3"
    patch_url = "https://github.com/krb5/krb5/commit/" + inventory.COMMIT + ".patch"
    source = {
        "type": "library",
        "name": "mit-krb5",
        "version": "1.21.3",
        "bom-ref": source_ref,
        "purl": "pkg:generic/mit-krb5@1.21.3",
        "description": "MIT Kerberos 1.21.3 plus local Debian backport; not upstream 1.22.3.",
        "externalReferences": [
            {
                "type": "distribution",
                "url": "https://security.debian.org/debian-security/pool/updates/main/k/krb5/"
                + name,
                "hashes": [{"alg": "SHA-256", "content": sha}],
            }
            for name, sha in sorted(inventory.SOURCES.items())
        ]
        + [
            {
                "type": "source-distribution",
                "url": patch_url,
                "comment": "Upstream patch backported locally; no upstream version change.",
                "hashes": [{"alg": "SHA-256", "content": inventory.PATCH}],
            }
        ],
        "pedigree": {"patches": [{"type": "backport", "diff": {"url": patch_url}}]},
        "properties": properties(
            {
                "patch-sha256": inventory.PATCH,
                "upstream-backport-commit": inventory.COMMIT,
                "decoder-original-sha256": inventory.DECODER_SOURCE["before"],
                "decoder-patched-sha256": inventory.DECODER_SOURCE["after"],
            }
        ),
    }
    components, dependencies, roots = [source], [{"ref": source_ref, "dependsOn": []}], []
    for row in sorted(manifest["libraries"], key=lambda item: item["package"]):
        name = row["package"]
        package_ref = PREFIX + "package:" + name
        file_ref = PREFIX + "elf:" + name
        roots.append(package_ref)
        # Debian vendor namespace describes format/source heritage, not an
        # assertion that Debian distributes PamOlive's local package revision.
        package = {
            "type": "library",
            "group": "debian",
            "name": name,
            "version": inventory.VERSION,
            "publisher": "PamOlive local build",
            "bom-ref": package_ref,
            "purl": "pkg:deb/debian/"
            + name
            + "@"
            + quote(inventory.VERSION, safe="")
            + "?arch=amd64&distro=debian-13",
            "description": "Local trixie rebuild; this revision is not distributed by Debian.",
            "externalReferences": [
                {
                    "type": "license",
                    "url": "file:///usr/share/doc/" + name + "/copyright",
                    "comment": "Copyright reference only; no SPDX or verified file hash asserted.",
                }
            ],
            "properties": properties(
                {
                    "source-component": source_ref,
                    "base-debian-version": inventory.BASE_VERSION,
                    "abi-sha256": row["abi_sha256"],
                    "soname": row["soname"],
                    "local-backport": "true",
                }
            ),
        }
        elf = {
            "type": "file",
            "name": row["path"],
            "bom-ref": file_ref,
            "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
            "properties": properties({"package": name, "elf-class": "64"}),
        }
        components.extend([package, elf])
        dependencies.extend(
            [
                {"ref": package_ref, "dependsOn": [source_ref, file_ref]},
                {"ref": file_ref, "dependsOn": []},
            ]
        )
    image_ref = PREFIX + IMAGE_KIND + ":" + image_digest
    image = {
        "type": "container",
        "name": "pamolive-platform",
        "version": IMAGE_KIND + ":" + image_digest,
        "bom-ref": image_ref,
        "properties": properties({"image-digest": image_digest, "image-digest-kind": IMAGE_KIND}),
    }
    dependencies.append({"ref": image_ref, "dependsOn": sorted(roots)})
    identity = {
        "manifest-canonical-sha256": standard.digest(manifest),
        "manifest-input-sha256": input_hashes["manifest"],
        "report-input-sha256": input_hashes["report"],
        "image-digest": image_digest,
        "image-digest-kind": IMAGE_KIND,
        "provenance-sha256": manifest["provenance_sha256"],
        "coverage": "four local Kerberos packages and source/files; OS archive scan required",
        "compilation-proof": "false",
        "debian-test-status": manifest["debian_tests"]["status"],
    }
    if manifest["debian_tests"]["status"] == "passed_with_capability_skips":
        # The inventory validator above fixes the exact capability, reason,
        # test names, phase counts and evidence. Preserve its qualification
        # limit visibly rather than presenting skipped tests as passed.
        skipped = manifest["debian_tests"]["capability_skips"][0]
        identity["unqualified-capability"] = skipped["capability"]
        identity["capability-skip-count"] = skipped["count"]
    result = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "serialNumber": "urn:uuid:"
        + str(uuid.uuid5(uuid.NAMESPACE_URL, "pamolive-krb5-sbom:" + standard.digest(identity))),
        "metadata": {"component": image, "properties": properties(identity)},
        "components": components,
        "dependencies": dependencies,
    }
    standard.references(result)
    standard.validate_schema(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "report", "image-digest", "image-digest-kind", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    fd = None
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        manifest, manifest_sha = standard.load(args.manifest)
        report, report_sha = standard.load(args.report)
        result = export(
            manifest,
            report,
            image_digest=args.image_digest,
            image_digest_kind=args.image_digest_kind,
            input_hashes={"manifest": manifest_sha, "report": report_sha},
        )
        raw = standard.canonical(result)
        require(len(raw.encode()) <= standard.MAX_INPUT, "output_budget")
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            stream.write(raw + "\n")
    except Exception as error:
        if fd is not None:
            os.close(fd)
        code = str(error) if isinstance(error, standard.SbomError) else "krb5_sbom_failed"
        print(json.dumps({"verified": False, "error": code}))
        return 1
    print(json.dumps({"verified": True, "coverage": "local-krb5-backport-only", "components": 9}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
