"""Enrich an application CycloneDX SBOM with a verified native inventory.

No network or ELF execution. Requires the isolated security toolchain, including
CycloneDX's bundled strict JSON schemas. This is not an OS package inventory.
"""

import argparse
import copy
import hashlib
import json
import os
import re
import uuid
from pathlib import Path

try:
    from deploy.native_inventory import (
        COMPAT_PATCH_SHA,
        COMPAT_UPSTREAM_COMMIT,
        CONFIGURATION_PROBES,
        GUAC_FLAGS,
        OPTIONS,
        PATCH_SHA,
        PREFIXES,
        RUNTIME_OPTIONS,
        SCHEMA,
        SIGNER,
        SOURCES,
    )
except ModuleNotFoundError:  # Direct invocation: python deploy/native_sbom.py
    from native_inventory import (
        COMPAT_PATCH_SHA,
        COMPAT_UPSTREAM_COMMIT,
        CONFIGURATION_PROBES,
        GUAC_FLAGS,
        OPTIONS,
        PATCH_SHA,
        PREFIXES,
        RUNTIME_OPTIONS,
        SCHEMA,
        SIGNER,
        SOURCES,
    )

SOURCE_URLS = {
    "freerdp": "https://pub.freerdp.com/releases/freerdp-3.33.1.tar.gz",
    "guacd": "https://dlcdn.apache.org/guacamole/1.6.0/source/guacamole-server-1.6.0.tar.gz",
}
# Vendor/product tuples verified against these official NVD configurations.
# Generic PURLs alone failed the deliberately vulnerable scanner control.
CPE_EVIDENCE = {
    "freerdp": ("freerdp", "freerdp", "CVE-2026-45700"),
    "guacd": ("apache", "guacamole", "CVE-2024-35164"),
}
MAX_INPUT = 4 * 1024 * 1024
PREFIX = "urn:pamolive:native:"


class SbomError(ValueError):
    """Non-sensitive qualification error code."""


def require(condition, code):
    if not condition:
        raise SbomError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def bounded(value, depth=0, counter=None):
    counter = counter if counter is not None else [0]
    counter[0] += 1
    require(depth <= 32 and counter[0] <= 100000, "structure_budget")
    if isinstance(value, dict):
        require("$ref" not in value, "embedded_schema_reference")
        for child in value.values():
            bounded(child, depth + 1, counter)
    elif isinstance(value, list):
        for child in value:
            bounded(child, depth + 1, counter)
    elif isinstance(value, str):
        require(len(value) <= 131072 and "\x00" not in value, "string_budget")


def load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    require(len(raw) <= MAX_INPUT, "input_budget")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, RecursionError) as exc:
        raise SbomError("invalid_json") from exc
    bounded(value)
    return value, hashlib.sha256(raw).hexdigest()


def validate_schema(bom):
    require(isinstance(bom, dict), "cyclonedx_object")
    require(bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion") in
            ("1.4", "1.5", "1.6"), "cyclonedx_version")
    version = bom["specVersion"]
    require(bom.get("$schema") in (None,
            f"http://cyclonedx.org/schema/bom-{version}.schema.json",
            f"https://cyclonedx.org/schema/bom-{version}.schema.json"), "schema_location")
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
        validator = JsonStrictValidator(getattr(SchemaVersion, "V" + version.replace(".", "_")))
        error = validator.validate_str(canonical(bom))
    except ImportError as exc:
        raise SbomError("schema_validator_unavailable") from exc
    except Exception as exc:
        raise SbomError("schema_validation_failed") from exc
    require(error is None, "cyclonedx_schema")


def references(bom):
    refs = set()
    def walk(value):
        if isinstance(value, dict):
            if "bom-ref" in value:
                ref = value["bom-ref"]
                require(isinstance(ref, str) and ref and ref not in refs, "duplicate_bom_ref")
                require(not ref.startswith(PREFIX), "reserved_bom_ref")
                refs.add(ref)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(bom)
    seen = set()
    for dependency in bom.get("dependencies", []):
        ref = dependency.get("ref")
        require(ref in refs and ref not in seen, "dependency_ref")
        seen.add(ref)
        require(all(item in refs for item in dependency.get("dependsOn", [])), "dependency_target")
    return refs


def native_components(manifest, report):
    require(isinstance(manifest, dict) and manifest.get("schema") == SCHEMA, "native_schema")
    require(isinstance(report, dict) and report.get("schema") == SCHEMA and
            report.get("verified") is True and report.get("live_link_probe") is True,
            "native_verification_required")
    require(report.get("inventory") == manifest, "native_report_mismatch")
    require(manifest.get("runtime_versions") == {
        "freerdp": SOURCES["freerdp"][0], "winpr": SOURCES["freerdp"][0],
        "guacd": SOURCES["guacd"][0], "freerdp_build_options": RUNTIME_OPTIONS},
        "native_runtime_identity")
    components = manifest.get("components")
    require(isinstance(components, list) and len(components) == 2, "native_components")
    by_name = {}
    result, deps = [], []
    for component in components:
        require(isinstance(component, dict), "native_component_object")
        name = component.get("name")
        require(name in SOURCES and name not in by_name, "native_component_identity")
        require((component.get("version"), component.get("source_sha256")) == SOURCES[name]
                and component.get("prefix") == PREFIXES[name], "native_source_identity")
        allowed = {"name", "prefix", "version", "source_sha256", "build_options"}
        allowed |= {"signer_fingerprint", "transformations", "compile_policy"} if (
            name == "freerdp") else {"patch_sha256", "compat_patch_sha256",
                                      "compat_upstream_commit"}
        require(set(component).issubset(allowed), "native_metadata_fields")
        if "build_options" in component:
            require(component["build_options"] == (OPTIONS if name == "freerdp" else
                                                    sorted(GUAC_FLAGS)), "native_build_options")
        if "signer_fingerprint" in component:
            require(component["signer_fingerprint"] == SIGNER, "native_signer")
        if "patch_sha256" in component:
            require(component["patch_sha256"] == PATCH_SHA, "native_patch")
        if name == "guacd":
            require(component.get("compat_patch_sha256") == COMPAT_PATCH_SHA and
                    component.get("compat_upstream_commit") == COMPAT_UPSTREAM_COMMIT,
                    "native_compat_patch")
        if "transformations" in component:
            transforms = component["transformations"]
            require(isinstance(transforms, list) and len(transforms) == 1 and
                    isinstance(transforms[0], dict) and
                    set(transforms[0]) == {"tool", "operation", "value"}, "native_transform")
            require(re.fullmatch(r"patchelf \d+(?:\.\d+){1,3}", str(transforms[0]["tool"]))
                    and transforms[0]["operation"] == "--set-rpath" and
                    transforms[0]["value"] == PREFIXES[name] + "/lib", "native_transform")
        if "compile_policy" in component:
            policy = component["compile_policy"]
            expected = {"schema": "pamolive.native-compile-policy.v1", "verified": True,
                        "prohibited_flag_prefixes": ["-flto", "-mavx"],
                        "allowed_march": ["-march=x86-64"],
                        "excluded_configuration_probe_roots": CONFIGURATION_PROBES}
            require(isinstance(policy, dict) and set(policy) == set(expected) | {
                "compile_commands_sha256", "compilation_commands", "link_command_files"},
                "native_compile_policy")
            require(all(policy[key] == value for key, value in expected.items()) and
                    policy["verified"] is True and re.fullmatch(r"[0-9a-f]{64}", str(
                        policy["compile_commands_sha256"])) and
                    all(type(policy[key]) is int and 0 < policy[key] <= 100000 for key in (
                        "compilation_commands", "link_command_files")), "native_compile_policy")
        ref = PREFIX + name + ":" + SOURCES[name][0]
        by_name[name] = ref
        properties = [{"name": "pamolive:native:" + key, "value": canonical(component[key])}
                      for key in sorted(component) if key not in ("name", "version")]
        vendor, product, evidence = CPE_EVIDENCE[name]
        properties.append({"name": "pamolive:native:cpe-evidence", "value":
                           "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + evidence})
        result.append({"type": "library", "name": "freerdp" if name == "freerdp" else
                       "guacamole-server", "version": component["version"], "bom-ref": ref,
                       "cpe": f"cpe:2.3:a:{vendor}:{product}:{component['version']}:*:*:*:*:*:*:*",
                       "purl": "pkg:generic/" + ("freerdp" if name == "freerdp" else
                                                 "guacamole-server") + "@" + component["version"],
                       "properties": properties,
                       "externalReferences": [{"type": "distribution", "url": SOURCE_URLS[name],
                           "hashes": [{"alg": "SHA-256", "content": component["source_sha256"]}]}]})
    files = manifest.get("files")
    aliases = manifest.get("aliases")
    require(isinstance(files, list) and 1 <= len(files) <= 256 and isinstance(aliases, dict),
            "native_files")
    paths, file_refs = {}, {name: [] for name in SOURCES}
    for item in files:
        require(isinstance(item, dict), "native_file_object")
        name, path, sha = item.get("component"), item.get("path"), item.get("sha256")
        require(name in SOURCES and isinstance(path, str) and
                path.startswith(PREFIXES[name] + "/") and ".." not in path.split("/") and
                "\\" not in path and "//" not in path and path not in paths, "native_file_path")
        require(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha), "native_file_hash")
        ref = PREFIX + "elf:" + hashlib.sha256((path + ":" + sha).encode()).hexdigest()
        paths[path] = (ref, name)
        file_refs[name].append(ref)
        result.append({"type": "file", "name": path.rsplit("/", 1)[-1], "bom-ref": ref,
                       "hashes": [{"alg": "SHA-256", "content": sha}], "properties": [
                           {"name": "pamolive:native:path", "value": path},
                           {"name": "pamolive:native:aliases", "value": canonical(sorted(
                               alias for alias, target in aliases.items() if target == path))}]})
    for alias, target in aliases.items():
        require(isinstance(alias, str) and isinstance(target, str) and target in paths and
                alias.startswith(PREFIXES[paths[target][1]] + "/") and
                ".." not in alias.split("/") and "\\" not in alias and "//" not in alias,
                "native_alias")
    for name in SOURCES:
        require(bool(file_refs[name]), "native_component_files_missing")
        deps.append({"ref": by_name[name], "dependsOn": sorted(file_refs[name] +
                     ([by_name["freerdp"]] if name == "guacd" else []))})
    deps.extend({"ref": ref} for ref, _ in paths.values())
    return result, deps, list(by_name.values())


def merge(app, manifest, report, *, image_digest, input_hashes, image_digest_kind="oci_manifest"):
    for value in (app, manifest, report):
        bounded(value)
    require(isinstance(image_digest, str) and
            re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is not None, "image_digest")
    require(image_digest_kind in ("oci_manifest", "image_config"), "image_digest_kind")
    require(isinstance(input_hashes, dict) and set(input_hashes) == {"app", "manifest", "report"}
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in input_hashes.values()),
            "input_hashes")
    validate_schema(app)
    references(app)
    components, deps, roots = native_components(manifest, report)
    result = copy.deepcopy(app)
    original = result.setdefault("components", [])
    require(len(original) <= 2000, "component_budget")
    identities = set()
    refs = set()
    pending = list(original)
    if "component" in result.get("metadata", {}):
        pending.append(result["metadata"]["component"])
    count = 0
    while pending:
        item = pending.pop()
        count += 1
        require(count <= 2000, "component_budget")
        pending.extend(item.get("components", []))
        if "bom-ref" in item:
            refs.add(item["bom-ref"])
        name = re.sub(r"[-_.]+", "-", item["name"]).lower()
        key = (item.get("group", ""), name)
        require(key not in identities and name not in ("freerdp", "guacd", "guacamole-server"),
                "component_identity_conflict")
        identities.add(key)
        algorithms = [value["alg"] for value in item.get("hashes", [])]
        require(len(algorithms) == len(set(algorithms)), "conflicting_hash_algorithm")
    image_ref = PREFIX + "image:" + image_digest_kind + ":" + image_digest
    image = {"type": "container", "name": "pamolive-platform",
             "version": image_digest_kind + ":" + image_digest, "bom-ref": image_ref,
             "properties": [{"name": "pamolive:image:digest-kind", "value": image_digest_kind},
                            {"name": "pamolive:image:digest", "value": image_digest}]}
    # Only a registry/OCI manifest digest identifies the distributed image here.
    # A configuration hash is retained explicitly, without claiming it hashes
    # the complete container artifact or can be used as a registry pull digest.
    if image_digest_kind == "oci_manifest":
        image["hashes"] = [{"alg": "SHA-256", "content": image_digest[7:]}]
    original.extend([image, *components])
    result.setdefault("dependencies", []).extend([
        {"ref": image_ref, "dependsOn": sorted(refs | set(roots))}, *deps])
    properties = result.setdefault("metadata", {}).setdefault("properties", [])
    require(not any(p["name"].startswith("pamolive:sbom:") for p in properties),
            "reserved_property")
    provenance = {"image-digest": image_digest, "image-digest-kind": image_digest_kind,
                  "manifest-canonical-sha256": digest(manifest),
                  **{name + "-input-sha256": value for name, value in input_hashes.items()},
                  "coverage": "application-and-compiled-native; OS archive scan required"}
    properties.extend({"name": "pamolive:sbom:" + key, "value": value}
                      for key, value in sorted(provenance.items()))
    result["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL,
                                                       "pamolive-sbom:" + digest(provenance)))
    validate_schema(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("app-sbom", "native-manifest", "native-report", "image-digest", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--image-digest-kind", choices=("oci_manifest", "image_config"),
                        default="oci_manifest")
    args = parser.parse_args(argv)
    fd = None
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        app, app_sha = load(args.app_sbom)
        manifest, manifest_sha = load(args.native_manifest)
        report, report_sha = load(args.native_report)
        result = merge(app, manifest, report, image_digest=args.image_digest,
                       image_digest_kind=args.image_digest_kind,
                       input_hashes={"app": app_sha, "manifest": manifest_sha,
                                     "report": report_sha})
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            stream.write(canonical(result) + "\n")
    except (SbomError, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        if fd is not None:
            os.close(fd)
        code = str(exc) if isinstance(exc, SbomError) else "sbom_enrichment_failed"
        print(json.dumps({"verified": False, "error": code}))
        return 1
    print(json.dumps({"verified": True, "components": len(result["components"]),
                      "coverage": "application-and-native; OS scan separate"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
