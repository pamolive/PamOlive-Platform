"""Fail-closed, offline policy gate for exact qualified-image Grype artifacts.

This verifies evidence consistency; it never invokes Docker, downloads data, or
claims that scanner coverage is exhaustive. Policy exceptions need independent
review and executable archive conditions, not a global scanner ignore list.
"""

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import re
import tarfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

try:
    from deploy import qualified_image
except ModuleNotFoundError:
    import qualified_image

SCHEMA = "pamolive.image-scan-policy.v1"
TOOL_VERSION = "0.121.3"
TOOL_SHA256 = "e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85"
EXPECTED_CONTROL = {("freerdp", "3.15.0", "CVE-2026-45700"),
                    ("guacamole-server", "1.5.5", "CVE-2024-35164")}
SEVERITIES = {"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
MAX_JSON = 32 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")


class ScanPolicyError(ValueError):
    """A bounded failure code, without raw scanner/configuration contents."""


def require(condition, code):
    if not condition:
        raise ScanPolicyError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def hash_file(path, maximum=2 * 1024**3):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            "artifact_file")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def bounded(value, depth=0, nodes=None):
    nodes = nodes if nodes is not None else [0]
    nodes[0] += 1
    require(depth <= 40 and nodes[0] <= 500000, "json_structure_budget")
    if isinstance(value, dict):
        for item in value.values():
            bounded(item, depth + 1, nodes)
    elif isinstance(value, list):
        for item in value:
            bounded(item, depth + 1, nodes)
    elif isinstance(value, str):
        require(len(value) <= 2 * 1024 * 1024 and "\x00" not in value, "json_string_budget")


def read_json(path, maximum=MAX_JSON):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "json_file")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "json_byte_budget")
    value = json.loads(raw, object_pairs_hook=pairs)
    bounded(value)
    return value


def instant(value):
    require(isinstance(value, str) and len(value) <= 40, "timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "timestamp_timezone")
    return result.astimezone(UTC)


def validate_report(report, *, expected_from, now):
    require(isinstance(report, dict) and not report.get("error") and not report.get("errors"),
            "scanner_error")
    descriptor = report.get("descriptor", {})
    require(not descriptor.get("error") and not descriptor.get("errors") and
            not report.get("source", {}).get("error"), "scanner_error")
    require(descriptor.get("name") == "grype" and descriptor.get("version") == TOOL_VERSION,
            "scanner_identity")
    scan_time = instant(descriptor.get("timestamp"))
    require(timedelta(minutes=-5) <= now - scan_time <= timedelta(hours=24), "stale_scan")
    config = descriptor.get("configuration", {})
    require(config.get("from") == [expected_from], "scan_source_mode")
    for name in ("ignore", "exclude", "vex-documents", "vex-add"):
        require(config.get(name) == [], "scanner_filter_" + name)
    for name in ("only-fixed", "only-notfixed"):
        require(config.get(name) is False, "scanner_filter_" + name)
    require(config.get("ignore-wontfix") in ("", False) and
            config.get("match-upstream-kernel-headers") is True and
            config.get("include-matcher-suppressions") is True, "scanner_hidden_suppression")
    require(config.get("match", {}).get("stock", {}).get("using-cpes") is True,
            "cpe_matching_disabled")
    require(config.get("externalSources", {}).get("enable") is False, "external_enrichment")
    db_config = config.get("db", {})
    require(db_config.get("auto-update") is False and db_config.get("validate-age") is True
            and db_config.get("validate-by-hash-on-start") is True, "database_validation")
    status = descriptor.get("db", {}).get("status", {})
    require(status.get("valid") is True and re.fullmatch(r"v6\.\d+\.\d+", str(
        status.get("schemaVersion"))) is not None, "database_status")
    built = instant(status.get("built"))
    require(timedelta(minutes=-5) <= now - built <= timedelta(hours=48)
            and built <= scan_time + timedelta(minutes=5), "stale_database")
    matches = report.get("matches")
    require(isinstance(matches, list) and len(matches) <= 50000, "matches_budget")
    # Grype's pinned JSON presenter uses omitempty for an empty ignored list.
    # Explicit null/invalid types still fail; strict config was checked above.
    ignored = report.get("ignoredMatches", [])
    require(isinstance(ignored, list) and len(ignored) <= 50000, "ignored_matches_missing")
    for match in matches:
        require(isinstance(match, dict) and isinstance(match.get("artifact"), dict)
                and isinstance(match.get("vulnerability"), dict), "match_object")
        vulnerability = match["vulnerability"]
        require(vulnerability.get("severity") in SEVERITIES, "unknown_severity")
        require(isinstance(vulnerability.get("id"), str) and
                1 <= len(vulnerability["id"]) <= 100, "vulnerability_identity")
        fix = vulnerability.get("fix", {})
        require(fix.get("state") in ("fixed", "not-fixed", "wont-fix", "unknown") and
                isinstance(fix.get("versions"), list), "fix_metadata")
    return {"schema": status["schemaVersion"], "built": status["built"]}


def high_groups(report, scope):
    groups = {}
    distro = report.get("distro", {})
    for match in report["matches"]:
        vulnerability, artifact = match["vulnerability"], match["artifact"]
        if vulnerability["severity"] != "High":
            continue
        upstreams = artifact.get("upstreams") or [{"name": artifact.get("name")}]
        require(len(upstreams) == 1 and isinstance(upstreams[0].get("name"), str),
                "ambiguous_package_source")
        finding = {"scope": scope, "source_package": upstreams[0]["name"],
                   "vulnerability_id": vulnerability["id"], "severity": "High",
                   "fix_state": vulnerability["fix"]["state"],
                   "namespace": vulnerability.get("namespace", ""),
                   "data_source": vulnerability.get("dataSource", ""),
                   "distro": {key: distro.get(key, "") for key in ("name", "version")}}
        key = canonical(finding)
        group = groups.setdefault(key, {**finding, "packages": []})
        package = {key: artifact.get(key, "") for key in ("name", "version", "type", "purl")}
        require(all(isinstance(value, str) for value in package.values()), "package_identity")
        if package not in group["packages"]:
            group["packages"].append(package)
    result = {}
    for group in groups.values():
        group["packages"].sort(key=canonical)
        result[fingerprint(group)] = group
    return result


def checked_path(value):
    require(isinstance(value, str) and 1 <= len(value) <= 512 and "\\" not in value,
            "condition_path")
    path = PurePosixPath(value)
    require(path.is_absolute() and ".." not in path.parts and str(path) == value,
            "condition_path")
    return value


def archive_facts(archive, conditions):
    """Bounded streaming inspection, no extraction/execution, no symlink following."""
    requested = {checked_path(item["path"]) for item in conditions if item.get("kind") == "elf"}
    names, elves = set(), {}
    ancestors = {str(parent) for path in requested for parent in PurePosixPath(path).parents}
    non_directories = set()
    def invalidate(path):
        for existing in list(elves):
            if existing == path or existing.startswith(path.rstrip("/") + "/"):
                del elves[existing]

    total = count = 0
    with tarfile.open(archive) as outer:
        manifest = json.loads(qualified_image.tar_metadata(outer, "manifest.json", 262144))
        layers = manifest[0]["Layers"]
        require(isinstance(layers, list) and len(layers) <= 128, "layer_budget")
        for layer in layers:
            with outer.extractfile(layer) as stream, tarfile.open(
                    fileobj=stream, mode="r|*") as inner:
                for member in inner:
                    count += 1
                    total += member.size
                    require(count <= 100000 and total <= 4 * 1024**3, "layer_content_budget")
                    require("\\" not in member.name and
                            ".." not in PurePosixPath(member.name).parts, "layer_path")
                    normalized = str(PurePosixPath(member.name)).lstrip("/")
                    name = checked_path("/" if normalized == "." else "/" + normalized)
                    names.add(name)
                    pure = PurePosixPath(name)
                    if pure.name == ".wh..wh..opq":
                        invalidate(str(pure.parent))
                    elif pure.name.startswith(".wh."):
                        target = str(pure.with_name(pure.name[4:]))
                        invalidate(target)
                        non_directories = {path for path in non_directories if path != target
                                           and not path.startswith(target.rstrip("/") + "/")}
                    elif member.isdir():
                        elves.pop(name, None)
                        non_directories.discard(name)
                    else:
                        # A directory replaced by a file, hardlink or symlink
                        # makes all previously selected descendants inaccessible.
                        invalidate(name)
                        if name in ancestors:
                            non_directories.add(name)
                        blocked = any(str(parent) in non_directories
                                      for parent in pure.parents)
                        if name in requested and member.isfile() and not blocked:
                            require(member.size <= 64 * 1024**2, "elf_budget")
                            data = inner.extractfile(member)
                            header, sha = b"", hashlib.sha256()
                            while block := data.read(1024 * 1024):
                                if not header:
                                    header = block[:6]
                                sha.update(block)
                            elves[name] = {"sha256": sha.hexdigest(), "class":
                                           {1: 32, 2: 64}.get(header[4]) if
                                           header[:4] == b"\x7fELF" and len(header) >= 6 else None}
    return names, elves


def conditions_hold(conditions, facts):
    require(isinstance(conditions, list) and 1 <= len(conditions) <= 32, "conditions_missing")
    names, elves = facts
    for item in conditions:
        kind = item.get("kind")
        if kind == "absent_basename_glob":
            pattern = item.get("pattern")
            require(isinstance(pattern, str) and 1 <= len(pattern) <= 128 and
                    "/" not in pattern and "\\" not in pattern, "condition_pattern")
            if any(fnmatch.fnmatchcase(PurePosixPath(name).name, pattern) for name in names):
                return False
        elif kind == "absent_path_suffix":
            suffix = checked_path(item.get("suffix"))
            if any(name.endswith(suffix) for name in names):
                return False
        elif kind == "elf":
            path = checked_path(item.get("path"))
            require(item.get("class") in (32, 64) and SHA.fullmatch(str(item.get("sha256"))),
                    "condition_elf")
            if elves.get(path) != {"class": item["class"], "sha256": item["sha256"]}:
                return False
        else:
            raise ScanPolicyError("unknown_condition")
    return True


def reviewed_exception(entry, finding, *, facts, repo, now):
    require(entry.get("fingerprint") == fingerprint(entry.get("finding")), "policy_fingerprint")
    require(entry["finding"] == finding, "policy_finding_changed")
    if entry.get("disposition") == "untriaged":
        return False
    require(entry.get("disposition") == "not_reachable", "unknown_disposition")
    analyst, reviewers = entry.get("analyst"), entry.get("reviewers")
    require(isinstance(analyst, str) and analyst.strip() and isinstance(reviewers, list)
            and len(set(reviewers)) >= 2 and analyst not in reviewers and
            all(isinstance(item, str) and item.strip() for item in reviewers), "independent_review")
    require(isinstance(entry.get("analysis"), str) and len(entry["analysis"].strip()) >= 80,
            "exposure_analysis_missing")
    reviewed, expires = instant(entry.get("reviewed_at")), instant(entry.get("expires"))
    require(reviewed <= now + timedelta(minutes=5) and
            now < expires <= reviewed + timedelta(days=30),
            "review_expired")
    vendor = entry.get("vendor_evidence")
    require(isinstance(vendor, list) and bool(vendor), "vendor_evidence_missing")
    for value in vendor:
        url = urlsplit(value)
        require(url.scheme == "https" and url.hostname and not url.username and not url.password
                and not url.fragment and url.port in (None, 443), "vendor_evidence_url")
    proofs = entry.get("local_evidence")
    require(isinstance(proofs, list) and 1 <= len(proofs) <= 8, "local_evidence_missing")
    for proof in proofs:
        name = proof.get("path")
        require(isinstance(name, str) and not PurePosixPath(name).is_absolute() and
                ".." not in PurePosixPath(name).parts and "\\" not in name and
                name.startswith(("docs/", "deploy/", ".github/qualification/")), "proof_path")
        candidate = repo / name
        require(not candidate.is_symlink(), "proof_symlink")
        path = candidate.resolve(strict=True)
        require(path.is_relative_to(repo) and hash_file(path, 2 * 1024 * 1024) ==
                proof.get("sha256"), "proof_changed")
    return conditions_hold(entry.get("conditions"), facts)


def check_positive(report):
    found = {(item["artifact"].get("name"), item["artifact"].get("version"),
              item["vulnerability"]["id"]) for item in report["matches"]}
    require(EXPECTED_CONTROL <= found, "positive_control_not_detected")


def check_fixture(fixture):
    expected = {("freerdp", "3.15.0", "pkg:generic/freerdp@3.15.0",
                 "cpe:2.3:a:freerdp:freerdp:3.15.0:*:*:*:*:*:*:*"),
                ("guacamole-server", "1.5.5", "pkg:generic/guacamole-server@1.5.5",
                 "cpe:2.3:a:apache:guacamole:1.5.5:*:*:*:*:*:*:*")}
    components = fixture.get("components")
    require(fixture.get("bomFormat") == "CycloneDX" and fixture.get("specVersion") == "1.4"
            and isinstance(components, list) and len(components) == 2,
            "positive_fixture_schema")
    require({tuple(item.get(key) for key in ("name", "version", "purl", "cpe"))
             for item in components} == expected, "positive_fixture_components")
    require(fixture.get("metadata", {}).get("properties") == [
        {"name": "pamolive:synthetic-positive-control", "value": "true; not an installed image"}],
        "positive_fixture_identity")


def qualify(os_report, compiled_report, positive_report, compiled_sbom, policy, *,
            config_id, config_bytes, facts, repo, now=None):
    """Pure policy evaluation after files/archive identities have been checked."""
    now = now or datetime.now(UTC)
    require(policy.get("schema") == SCHEMA and policy.get("version") == 1, "policy_version")
    databases = [validate_report(report, expected_from=source, now=now) for report, source in (
        (os_report, "docker-archive"), (compiled_report, "sbom"), (positive_report, "sbom"))]
    require(databases[0] == databases[1] == databases[2], "database_mismatch")
    check_positive(positive_report)
    target = os_report.get("source", {}).get("target")
    require(os_report.get("source", {}).get("type") == "image" and isinstance(target, dict)
            and target.get("imageID") == config_id and target.get("os") == "linux"
            and target.get("architecture") == "amd64", "os_image_identity")
    require(base64.b64decode(target.get("config", ""), validate=True) == config_bytes,
            "os_configuration_bytes")
    for report in (compiled_report, positive_report):
        require(report.get("source", {}).get("type") == "sbom-file", "sbom_source")
    properties = compiled_sbom.get("metadata", {}).get("properties", [])
    require(len({item["name"] for item in properties}) == len(properties), "duplicate_property")
    props = {item["name"]: item["value"] for item in properties}
    require(props.get("pamolive:sbom:image-digest-kind") == "image_config" and
            props.get("pamolive:sbom:image-digest") == config_id, "sbom_image_identity")
    expected_cpes = {"cpe:2.3:a:freerdp:freerdp:3.33.1:*:*:*:*:*:*:*",
                     "cpe:2.3:a:apache:guacamole:1.6.0:*:*:*:*:*:*:*"}
    require(expected_cpes <= {item.get("cpe") for item in compiled_sbom.get("components", [])},
            "compiled_inventory_missing")
    entries = policy.get("findings")
    require(isinstance(entries, list) and len(entries) <= 1000, "policy_findings")
    indexed = {}
    for entry in entries:
        key = entry.get("fingerprint")
        require(key == fingerprint(entry.get("finding")) and key not in indexed,
                "policy_fingerprint")
        require(entry.get("disposition") in ("untriaged", "not_reachable"), "unknown_disposition")
        indexed[key] = entry
    blockers, groups = [], {}
    summaries = {}
    for scope, report in (("os", os_report), ("compiled", compiled_report)):
        summaries[scope] = {"severities": dict(Counter(
            item["vulnerability"]["severity"] for item in report["matches"])),
            "matches": len(report["matches"]),
            "ignored_matches": len(report.get("ignoredMatches", []))}
        if report.get("ignoredMatches", []):
            blockers.append({"code": "unreviewed_suppressed_matches", "scope": scope,
                             "count": len(report["ignoredMatches"])})
        for item in report["matches"]:
            vulnerability = item["vulnerability"]
            if vulnerability["severity"] == "Critical":
                blockers.append({"code": "critical", "scope": scope,
                                 "id": vulnerability["id"]})
            elif vulnerability["severity"] == "High" and (
                    vulnerability["fix"]["state"] == "fixed" or
                    vulnerability["fix"]["versions"]):
                blockers.append({"code": "high_fix_available", "scope": scope,
                                 "id": vulnerability["id"]})
        groups.update(high_groups(report, scope))
    for key, finding in groups.items():
        entry = indexed.get(key)
        if entry is None or not reviewed_exception(entry, finding, facts=facts, repo=repo, now=now):
            blockers.append({"code": "untriaged_high", "fingerprint": key, "finding": finding})
    return {"schema": "pamolive.image-scan-result.v1", "passed": not blockers,
            "all_findings_clear": all(not report["matches"] and not report.get("ignoredMatches", [])
                                      for report in (
                os_report, compiled_report)), "config_id": config_id,
            "scanner_version": TOOL_VERSION, "database": databases[0], "summary": summaries,
            "high_finding_groups": len(groups), "blockers": blockers,
            "coverage": "OS archive plus declared compiled/application SBOM; not exhaustive SCA",
            "decisions": [{"fingerprint": key, "disposition": indexed[key]["disposition"]}
                          for key in groups if key in indexed]}


def referenced(policy_path, item):
    name = item.get("file")
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", name), "reference_path")
    path = policy_path.parent / name
    require(hash_file(path, 1024 * 1024) == item.get("sha256"), "reference_hash")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "revision", "os-report", "compiled-sbom", "compiled-report",
                 "positive-report", "scanner-archive", "policy", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    fd = None
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        policy_path = Path(args.policy).resolve(strict=True)
        require(policy_path.parent.name == "qualification" and
                policy_path.parent.parent.name == ".github", "policy_location")
        repo = policy_path.parent.parent.parent.resolve(strict=True)
        policy = read_json(policy_path, 1024 * 1024)
        tool_path = referenced(policy_path, policy["scanner_pin"])
        tool = read_json(tool_path, 65536)
        require(tool.get("schema") == "pamolive.grype-release-pin.v1" and
                tool.get("version") == TOOL_VERSION and tool.get("archive_sha256") == TOOL_SHA256,
                "scanner_pin")
        require(hash_file(args.scanner_archive, 128 * 1024 * 1024) == TOOL_SHA256,
                "scanner_archive_hash")
        control_path = referenced(policy_path, policy["positive_control"])
        check_fixture(read_json(control_path))
        bundle = Path(args.bundle).resolve(strict=True)
        # Read duplicate keys ourselves before reusing the existing read-only verifier.
        metadata = read_json(bundle / qualified_image.METADATA, 8192)
        require(metadata == qualified_image.verify_bundle(bundle, args.revision), "bundle_identity")
        archive = bundle / qualified_image.ARCHIVE
        with tarfile.open(archive) as outer:
            manifest = json.loads(qualified_image.tar_metadata(outer, "manifest.json", 262144))
            config = qualified_image.tar_metadata(outer, manifest[0]["Config"], 2 * 1024 * 1024)
        conditions = [condition for entry in policy["findings"]
                      if entry.get("disposition") == "not_reachable"
                      for condition in entry.get("conditions", [])]
        facts = archive_facts(archive, conditions) if conditions else (set(), {})
        os_report, compiled, positive, sbom = (read_json(path) for path in (
            args.os_report, args.compiled_report, args.positive_report, args.compiled_sbom))
        compiled_target = compiled["source"]["target"]
        positive_target = positive["source"]["target"]
        require(compiled_target == "/combined.cdx.json" or Path(compiled_target).resolve() ==
                Path(args.compiled_sbom).resolve(), "compiled_sbom_source")
        require(positive_target == "/control.cdx.json" or Path(positive_target).resolve() ==
                control_path.resolve(), "positive_control_source")
        result = qualify(os_report, compiled, positive, sbom, policy,
                         config_id=metadata["image_id"], config_bytes=config, facts=facts,
                         repo=repo)
        result["input_sha256"] = {name: hash_file(path) for name, path in (
            ("qualified_image", bundle / qualified_image.METADATA), ("archive", archive),
            ("os_report", args.os_report), ("compiled_report", args.compiled_report),
            ("positive_report", args.positive_report), ("compiled_sbom", args.compiled_sbom),
            ("positive_fixture", control_path), ("policy", policy_path),
            ("scanner_pin", tool_path))}
        result["source_targets"] = {"compiled": compiled_target, "positive": positive_target,
                                    "binding": "fixed read-only CI mounts or identical host paths"}
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            stream.write(canonical(result) + "\n")
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError,
            tarfile.TarError) as exc:
        if fd is not None:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(canonical({"passed": False, "error": str(exc) if isinstance(
                    exc, ScanPolicyError) else "qualification_failed"}) + "\n")
        print(json.dumps({"passed": False, "error": str(exc) if isinstance(
            exc, ScanPolicyError) else "qualification_failed"}))
        return 1
    print(json.dumps({"passed": result["passed"], "high_groups": result["high_finding_groups"],
                      "blockers": len(result["blockers"]), "all_findings_clear":
                      result["all_findings_clear"]}))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
