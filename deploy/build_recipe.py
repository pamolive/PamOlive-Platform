"""Reviewed inputs, distinct from per-build output hashes (ADR-021).

Capture creates an UNAPPROVED candidate. Verification checks local bytes, not
signatures or compiler execution. CI origin/attestation is a separate gate.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

try:
    from deploy import krb5_inventory as krb
except ModuleNotFoundError:
    import krb5_inventory as krb

SCHEMA = "pamolive.build-recipe.v1"
PROFILE = "pamolive-linux-amd64-krb5-backport-v1"
MAX_FILES = 5000
MAX_FILE = 32 * 1024**2
MAX_TOTAL = 128 * 1024**2
EXCLUDED = frozenset({
    ".github/qualification/build-recipe.v1.json",
    ".github/qualification/image-scan-policy.v1.json",
    ".secrets.baseline",
})
FORBIDDEN_TRACKED = frozenset({".github/workflows/diagnose-partition.yml",
                               "deploy/Dockerfile.partition-probe"})
REQUIRED = frozenset({"Dockerfile", ".dockerignore", ".gitignore"})
SHA = re.compile(r"[a-f0-9]{64}\Z")
ASSET_SUFFIXES = frozenset({".css", ".js", ".svg", ".woff", ".woff2", ".ttf", ".otf", ".eot"})


class RecipeError(ValueError):
    """Static error codes; never source contents or credentials."""


def require(value, code):
    if not value:
        raise RecipeError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked_path(value):
    require(isinstance(value, str) and 0 < len(value) <= 512 and
            "\\" not in value and "\0" not in value, "recipe_path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and str(path) == value and
            all(part not in ("", ".") for part in path.parts), "recipe_path")
    return value


def exclusions(extra=()):
    require(isinstance(extra, (list, tuple)) and len(extra) <= 64 and
            len(extra) == len(set(extra)), "recipe_exclusions")
    for name in extra:
        checked_path(name)
        path = PurePosixPath(name)
        require(str(path.parent) == ".github/qualification/evidence" and
                path.suffix in (".json", ".md"), "recipe_external_evidence")
    return sorted(EXCLUDED | set(extra))


def source_inventory(root, *, excluded):
    """Tracked Git source set; future/private untracked work is not read."""
    root = Path(root).resolve(strict=True)
    require(root.is_dir(), "recipe_root")
    result = subprocess.run(
        ["git", "-c", "safe.directory=" + root.as_posix(), "-C", str(root),
         "ls-files", "--stage", "-z"],
        capture_output=True, check=False, timeout=15,
    )
    require(result.returncode == 0 and len(result.stdout) <= 2 * 1024**2,
            "recipe_git_inventory")
    records = result.stdout.decode("utf-8").split("\0")
    if records and records[-1] == "":
        records.pop()
    names = []
    for record in records:
        metadata, separator, name = record.partition("\t")
        fields = metadata.split()
        require(separator and len(fields) == 3 and fields[0] in ("100644", "100755")
                and fields[2] == "0", "recipe_git_file_mode")
        names.append(name)
    require(0 < len(names) <= MAX_FILES and len(names) == len(set(names)) and
            len({name.casefold() for name in names}) == len(names), "recipe_source_set")
    require(not set(names) & FORBIDDEN_TRACKED, "recipe_private_diagnostic_tracked")
    files, total = {}, 0
    for name in sorted(names):
        checked_path(name)
        if name in excluded:
            continue
        path = root / name
        require(not path.is_symlink() and all(not parent.is_symlink()
                for parent in path.parents if parent != root and parent.is_relative_to(root)),
                "recipe_symlink")
        require(path.is_file() and path.resolve(strict=True).is_relative_to(root) and
                path.stat().st_size <= MAX_FILE, "recipe_source_file")
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE + 1)
        require(len(raw) <= MAX_FILE, "recipe_source_file")
        total += len(raw)
        require(total <= MAX_TOTAL, "recipe_source_budget")
        files[name] = sha(raw)
    require(REQUIRED <= set(files), "recipe_required_inputs")
    return files


def elf_reference(entries):
    require(isinstance(entries, list) and 0 < len(entries) <= 5000, "recipe_elf_reference")
    paths = set()
    for item in entries:
        require(isinstance(item, dict), "recipe_elf_record")
        path = item.get("path")
        require(isinstance(path, str) and path.startswith("/") and
                "\\" not in path and ".." not in PurePosixPath(path).parts and
                str(PurePosixPath(path)) == path and len(path) <= 512 and path not in paths,
                "recipe_elf_path")
        paths.add(path)
        kind = item.get("type")
        keys = {"path", "type", "target"} if kind == "symlink" else (
            {"path", "type", "target", "sha256", "class", "machine"} if kind == "hardlink"
            else {"path", "type", "sha256", "class", "machine"})
        require(kind in ("elf", "symlink", "hardlink") and set(item) == keys,
                "recipe_elf_record")
        if kind in ("elf", "hardlink"):
            require(SHA.fullmatch(str(item.get("sha256"))) and
                    ((item.get("class") in (32, 64) and
                      type(item.get("machine")) is int and 0 <= item["machine"] <= 65535) or
                     (kind == "hardlink" and item.get("class") is None and
                      item.get("machine") is None)), "recipe_elf_identity")
        if kind in ("symlink", "hardlink"):
            require(isinstance(item["target"], str) and 0 < len(item["target"]) <= 4096 and
                    "\\" not in item["target"] and "\0" not in item["target"], "recipe_elf_alias")
    required = {"/usr/lib/x86_64-linux-gnu/" + name for name, _ in krb.LIBRARIES.values()}
    table = {item["path"]: item for item in entries}
    require(required <= paths and all(table[name]["type"] == "elf" and
            table[name]["class"] == 64 and table[name]["machine"] == 62 for name in required),
            "recipe_kerberos_paths")
    return sorted(entries, key=lambda row: row["path"])


def generated_assets(value):
    require(isinstance(value, dict) and len(value) <= 10000, "recipe_generated_assets")
    for path, checksum in value.items():
        require(isinstance(path, str) and path.startswith("/app/staticfiles/") and
                str(PurePosixPath(path)) == path and ".." not in PurePosixPath(path).parts and
                "\\" not in path and len(path) <= 512, "recipe_generated_path")
        suffix = PurePosixPath(path).suffix
        if suffix in (".gz", ".br"):
            suffix = PurePosixPath(path[:-len(suffix)]).suffix
        require(suffix in ASSET_SUFFIXES and SHA.fullmatch(str(checksum)),
                "recipe_generated_type")
    return value


def capture(root, *, backport_manifest, elf_entries, external_evidence=(), assets=None):
    """Candidate only: caller must review and pin this file independently."""
    krb.validate_manifest(backport_manifest)
    names = exclusions(external_evidence)
    files = source_inventory(root, excluded=names)
    provenance = backport_manifest["provenance"]
    outputs = provenance["test_outputs"]
    fixed = {name: provenance["evidence"][name] for name in (
        "upstream.patch", outputs["harness"], outputs["wrapper"],
        provenance["apt_chain"]["keyring_file"])}
    for name in ("test-keyring-compat.patch", "keyctl-probe.py"):
        if name in provenance["evidence"]:
            fixed[name] = provenance["evidence"][name]
    return validate({"schema": SCHEMA, "profile": PROFILE, "excluded_exact_paths": names,
        "files": files, "backport": {"baseline": backport_manifest["baseline"],
            "proof_names": sorted(provenance["evidence"]), "fixed_evidence": fixed,
            "test_outputs": outputs, "apt_chain": provenance["apt_chain"]},
        "elf_reference": elf_reference(elf_entries),
        "generated_assets": generated_assets(assets or {})})


def validate(recipe):
    require(isinstance(recipe, dict) and set(recipe) == {"schema", "profile",
            "excluded_exact_paths", "files", "backport", "elf_reference", "generated_assets"} and
            recipe["schema"] == SCHEMA and recipe["profile"] == PROFILE, "recipe_schema")
    names = recipe["excluded_exact_paths"]
    require(isinstance(names, list) and names == exclusions([
        name for name in names if name not in EXCLUDED]), "recipe_exclusions")
    files = recipe["files"]
    require(isinstance(files, dict) and 0 < len(files) <= MAX_FILES and
            REQUIRED <= set(files) and not set(files) & set(names), "recipe_files")
    for name, value in files.items():
        checked_path(name)
        require(SHA.fullmatch(str(value)), "recipe_file_hash")
    data = recipe["backport"]
    require(isinstance(data, dict) and set(data) == {"baseline", "proof_names", "fixed_evidence",
            "test_outputs", "apt_chain"}, "recipe_backport")
    baseline = data["baseline"]
    require(isinstance(baseline, dict) and baseline.get("schema") == krb.BASE_SCHEMA and
            baseline.get("packages") == dict.fromkeys(krb.LIBRARIES, krb.BASE_VERSION) and
            isinstance(baseline.get("libraries"), list) and len(baseline["libraries"]) == 4,
            "recipe_baseline")
    require({row.get("package") for row in baseline["libraries"]} == set(krb.LIBRARIES),
            "recipe_baseline")
    for row in baseline["libraries"]:
        filename, soname = krb.LIBRARIES[row["package"]]
        require(row.get("path") == "/usr/lib/x86_64-linux-gnu/" + filename and
                row.get("version") == krb.BASE_VERSION and row.get("soname") == soname and
                type(row.get("class")) is int and row["class"] == 64 and
                type(row.get("exported_symbols")) is int and
                0 < row["exported_symbols"] <= 100000 and
                SHA.fullmatch(str(row.get("sha256"))) and
                SHA.fullmatch(str(row.get("abi_sha256"))), "recipe_baseline")
    require(isinstance(data["proof_names"], list) and 5 <= len(data["proof_names"]) <= 20 and
            data["proof_names"] == sorted(set(data["proof_names"])), "recipe_proof_set")
    for name in data["proof_names"]:
        krb.evidence_name(name)
    require(isinstance(data["fixed_evidence"], dict) and data["fixed_evidence"].get(
            "upstream.patch") == krb.PATCH and set(data["fixed_evidence"]) <=
            set(data["proof_names"]), "recipe_fixed_evidence")
    for value in data["fixed_evidence"].values():
        require(SHA.fullmatch(str(value)), "recipe_fixed_evidence")
    outputs = data["test_outputs"]
    require(isinstance(outputs, dict) and set(outputs) == {
        "debian", "asn1", "before", "after", "harness", "wrapper"} and
        len(set(outputs.values())) == 6 and set(outputs.values()) <= set(data["proof_names"]),
        "recipe_test_outputs")
    source_proofs = {"upstream.patch": "deploy/krb5-asn1-sequence.patch",
        outputs["harness"]: "tests/fixtures/krb5_asn1_regression.c",
        outputs["wrapper"]: "deploy/check_krb5_asn1.sh"}
    if "test-keyring-compat.patch" in data["proof_names"]:
        source_proofs["test-keyring-compat.patch"] = "deploy/krb5-test-keyring-seccomp.patch"
        require(data["fixed_evidence"].get("test-keyring-compat.patch") == krb.TEST_COMPAT_PATCH,
                "recipe_test_patch")
    require(all(files.get(path) == data["fixed_evidence"].get(name)
                for name, path in source_proofs.items()) and all(
                name in data["fixed_evidence"] for name in source_proofs),
            "recipe_proof_source")
    chain = data["apt_chain"]
    fields = {"status_file", "inrelease_file", "release_file", "index_file",
              "source_record_file", "keyring_file", "dsc_file"}
    require(isinstance(chain, dict) and set(chain) == fields | {
        "index_release_path", "signer_fingerprints"}, "recipe_apt_chain")
    chain_names = [chain[key] for key in fields]
    require(len(set(chain_names)) == len(fields) and set(chain_names) <=
            set(data["proof_names"]) and re.fullmatch(r"main/source/Sources\.(?:xz|gz)",
            str(chain["index_release_path"])), "recipe_apt_chain")
    fixed_names = {"upstream.patch", outputs["harness"], outputs["wrapper"],
                   chain["keyring_file"]} | ({"test-keyring-compat.patch", "keyctl-probe.py"} &
                                              set(data["proof_names"]))
    require(set(data["fixed_evidence"]) == fixed_names, "recipe_fixed_evidence")
    signers = chain["signer_fingerprints"]
    require(isinstance(signers, list) and 1 <= len(signers) <= 8 and
            len(set(signers)) == len(signers) and all(isinstance(value, str) and
            re.fullmatch(r"(?:[A-F0-9]{40}|[A-F0-9]{64})", value) for value in signers),
            "recipe_apt_signers")
    require(recipe["elf_reference"] == elf_reference(recipe["elf_reference"]),
            "recipe_elf_order")
    generated_assets(recipe["generated_assets"])
    return recipe


def verify(recipe, root):
    validate(recipe)
    require(source_inventory(root, excluded=recipe["excluded_exact_paths"]) == recipe["files"],
            "recipe_source_changed")
    return {"schema": SCHEMA, "verified": True, "recipe_sha256": sha(canonical(recipe).encode()),
            "source_files": len(recipe["files"]), "cryptographic_attestation_verified": False,
            "build_verified": False, "compilation_proof": False}


def read_json(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024**2,
            "recipe_json_file")
    with path.open("rb") as stream:
        raw = stream.read(2 * 1024**2 + 1)
    require(len(raw) <= 2 * 1024**2, "recipe_json_file")
    value = json.loads(raw, object_pairs_hook=krb.pairs)
    # Reuse the bounded JSON walker without filesystem extraction.
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        require(depth <= 24 and count <= 100000, "recipe_json_budget")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            require(len(item) <= 65536 and "\0" not in item, "recipe_json_budget")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("capture", "verify", "verify-archive"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--recipe", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--backport-manifest", type=Path)
    parser.add_argument("--elf-reference", type=Path)
    parser.add_argument("--generated-assets", type=Path)
    parser.add_argument("--external-evidence", action="append", default=[])
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    fd = None
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        require((args.operation == "capture" and args.backport_manifest is not None and
                 args.elf_reference is not None and args.recipe is None and args.archive is None) or
                (args.operation in ("verify", "verify-archive") and args.recipe is not None and
                 args.backport_manifest is None and args.elf_reference is None and
                 args.generated_assets is None and not args.external_evidence and
                 (args.archive is not None) == (args.operation == "verify-archive")),
                "recipe_cli_arguments")
        value = (capture(args.root, backport_manifest=read_json(args.backport_manifest),
                         elf_entries=read_json(args.elf_reference),
                         external_evidence=args.external_evidence,
                         assets=read_json(args.generated_assets) if args.generated_assets else {})
                 if args.operation == "capture"
                 else verify(read_json(args.recipe), args.root))
        if args.operation == "verify-archive":
            try:
                from deploy.qualify_image_scan import verify_archive_backport
            except ModuleNotFoundError:
                from qualify_image_scan import verify_archive_backport
            _, value = verify_archive_backport(args.archive, read_json(args.recipe), args.root)
        with os.fdopen(fd, "w", encoding="utf8", newline="\n") as stream:
            fd = None
            stream.write(canonical(value) + "\n")
    except (ValueError, OSError, TypeError, AttributeError, KeyError, RecursionError,
            subprocess.SubprocessError, tarfile.TarError, EOFError) as exc:
        if fd is not None:
            with os.fdopen(fd, "w", encoding="utf8") as stream:
                stream.write(canonical({"verified": False, "error": str(exc) if isinstance(
                    exc, RecipeError) else "recipe_failed"}) + "\n")
        print('{"verified":false,"error":"recipe_failed"}')
        return 1
    print(canonical({"verified": args.operation != "capture", "candidate_created":
                     args.operation == "capture", "cryptographic_attestation_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
