"""One expat-prepared APT boundary. Data codecs only; no install or process here."""

import hashlib
import io
import json
import re
from datetime import UTC, datetime

BASE = "sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
MANIFEST = "sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177"
CONFIG = "sha256:78976a69c067520ef8be34cde307ef9f6fea6dcefa50edb57039773d241ca0db"
STAGE = "expat-prepared"
REQUESTS = (
    "build-essential",
    "binutils",
    "patch",
    "gpg=2.4.7-21+deb13u1+b5",
    "dpkg-dev",
    "debhelper",
    "autoconf",
    "automake",
    "libtool",
    "pkg-config",
    "docbook-to-man",
    "docbook2x",
    "libexpat1-dev=2.9.0-1~deb13u1",
    "ca-certificates",
)
REPOSITORIES = {
    "trixie": "https://deb.debian.org/debian/",
    "trixie-updates": "https://deb.debian.org/debian/",
    "trixie-security": "https://deb.debian.org/debian-security/",
}
SQV_SHA = "bdc0f58c70414dea8beddfc98df608d78ce232cd7f22a55d3755956fd3bc93d2"
KEYRING_SHA = "506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017"
HEX = re.compile(r"[a-f0-9]{64}\Z")
FPR = re.compile(r"[A-F0-9]{40}\Z")
SCHEMA = "pamolive.expat-prepared.material-set/2"
META_LIMIT = 256 * 1024**2


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def scalar_fields(fields, names):
    """Never clean up folded scalar values or case aliases into identities."""
    known = {name.casefold(): name for name in names}
    for name, value in fields.items():
        if name.casefold() in known:
            need(
                name == known[name.casefold()]
                and type(value) is str
                and "\n" not in value
                and "\r" not in value,
                "scalar_field_framing",
            )


class Gate:
    def __init__(self, codecs):
        self.m = codecs  # The runtime loads only hash-pinned reviewed materials.py.

    def policy(self, raw, expected_sha):
        need(
            type(expected_sha) is str
            and HEX.fullmatch(expected_sha)
            and type(raw) is bytes
            and len(raw) <= 1024**2
            and sha(raw) == expected_sha,
            "external_policy_pin_required",
        )
        value = self.m.json_data(raw)
        need(
            type(value) is dict
            and set(value)
            == {
                "schema",
                "stage",
                "parent",
                "requests",
                "repositories",
                "bootstrap",
                "maintainer_scripts_tcb",
                "base_supplier_tcb",
            }
            and value["schema"] == "pamolive.expat-prepared.apt-policy/1"
            and value["stage"] == STAGE
            and value["parent"] == BASE
            and value["base_supplier_tcb"]
            == "Docker-Official-python-Root-pinned-OCI-digest-TLS-bootstrap-not-build-attestation"
            and value["requests"] == list(REQUESTS)
            and value["maintainer_scripts_tcb"]
            == "signed-reviewed-Debian-DEBs-root-hooks-no-global-output-proof",
            "policy_scope",
        )
        need(
            value["bootstrap"]
            == {
                "verifier_sha256": SQV_SHA,
                "verifier_bytes": 1935072,
                "keyring_sha256": KEYRING_SHA,
                "supplier_tcb": (
                    "Debian-official-HTTPS-plus-Root-approved-SHA-not-tool-build-attestation"
                ),
            },
            "bootstrap_supplier_policy",
        )
        repos = value["repositories"]
        need(type(repos) is dict and set(repos) == set(REPOSITORIES), "repository_set")
        for suite, rule in repos.items():
            need(
                type(rule) is dict
                and set(rule)
                == {
                    "uri",
                    "allowed_certificates",
                    "required_any_current",
                    "max_age_days",
                    "valid_until_required",
                }
                and rule["uri"] == REPOSITORIES[suite]
                and type(rule["max_age_days"]) is int
                and 1 <= rule["max_age_days"] <= 90
                and type(rule["valid_until_required"]) is bool
                and (suite == "trixie" or rule["valid_until_required"] is True),
                "repository_policy",
            )
            for key in ("allowed_certificates", "required_any_current"):
                rows = rule[key]
                need(
                    type(rows) is list
                    and 1 <= len(rows) <= 8
                    and all(type(item) is str and FPR.fullmatch(item) for item in rows)
                    and len(set(rows)) == len(rows),
                    "certificate_policy",
                )
            need(
                set(rule["required_any_current"]) <= set(rule["allowed_certificates"]),
                "certificate_policy",
            )
        return value

    def status(self, raw):
        need(type(raw) is bytes and 0 < len(raw) <= 4 * 1024**2, "status_budget")
        rows = {}
        for fields in self.m.controls(io.BytesIO(raw), maximum=4 * 1024**2, max_line=128 * 1024):
            scalar_fields(fields, ("Package", "Version", "Architecture", "Status"))
            name, version, arch = self.m.package_identity(fields)
            need(
                name not in rows
                and fields.get("Status")
                in {
                    "install ok installed",
                    "deinstall ok config-files",
                },
                "package_state",
            )
            rows[name] = {"version": version, "architecture": arch, "status": fields["Status"]}
        need(rows, "status_empty")
        return rows

    def parent(self, base):
        need(
            base["root_digest"] == BASE
            and base["linux_manifest_digest"] == MANIFEST
            and base["config_digest"] == CONFIG
            and len(base["layers"]) == len(base["diff_ids"]) == 4,
            "parent_identity",
        )
        return {
            key: base[key]
            for key in (
                "root_digest",
                "linux_manifest_digest",
                "config_digest",
                "layers",
                "diff_ids",
            )
        }

    def approval(self, raw, expected_sha, policy_sha):
        need(
            type(expected_sha) is str
            and HEX.fullmatch(expected_sha)
            and type(raw) is bytes
            and len(raw) <= 4 * 1024**2
            and sha(raw) == expected_sha,
            "external_material_set_pin_required",
        )
        value = self.m.json_data(raw)
        need(
            type(value) is dict
            and set(value)
            == {
                "schema",
                "stage",
                "operation",
                "parent",
                "policy_sha256",
                "requests",
                "prestate_sha256",
                "metadata",
                "packages",
                "expected_after_state",
                "transitions",
                "build_verified",
                "materials_complete",
                "cryptographic_build_attestation_verified",
                "other_builder_boundaries_closed",
                "compiler_SDK_generated_state_closed",
            }
            and value["schema"] == SCHEMA
            and value["stage"] == STAGE
            and value["operation"] == "install-with-exact-reviewed-transitions"
            and value["policy_sha256"] == policy_sha
            and value["requests"] == list(REQUESTS)
            and value["parent"].get("root_digest") == BASE
            and type(value["packages"]) is list
            and 0 <= len(value["packages"]) <= 512
            and all(
                value[key] is False
                for key in (
                    "build_verified",
                    "materials_complete",
                    "cryptographic_build_attestation_verified",
                    "other_builder_boundaries_closed",
                    "compiler_SDK_generated_state_closed",
                )
            )
            and canonical(value) == raw,
            "material_set_scope",
        )
        return value

    def capture(
        self,
        policy_raw,
        policy_sha,
        spec_raw,
        read,
        verify_release,
        base,
        before_raw,
        now,
        approved=None,
    ):
        """Capture/authenticate data, never approve the selected solver set or execute a DEB."""
        policy = self.policy(policy_raw, policy_sha)
        parent = self.parent(base)
        _, key = self.m.resolve(
            base["files"], "usr/share/keyrings/debian-archive-keyring.pgp", with_path=True
        )
        need(key["type"] == "file" and key["sha256"] == KEYRING_SHA, "base_keyring_binding")
        _, status_row = self.m.resolve(base["files"], "var/lib/dpkg/status", with_path=True)
        need(
            status_row["type"] == "file" and sha(before_raw) == status_row["sha256"],
            "exact_base_prestate",
        )
        before = self.status(before_raw)
        spec = self.m.json_data(spec_raw)
        need(
            type(spec) is dict
            and set(spec) == {"schema", "metadata", "selection"}
            and spec["schema"] == "pamolive.expat-prepared.spool/1"
            and type(spec["metadata"]) is dict
            and set(spec["metadata"]) == set(REPOSITORIES)
            and type(spec["selection"]) is list
            and 0 <= len(spec["selection"]) <= 512,
            "spool_shape",
        )
        selection, files, keys = [], set(), set()
        for row in spec["selection"]:
            need(
                type(row) is dict
                and set(row) == {"suite", "package", "version", "architecture", "deb"}
                and row["suite"] in REPOSITORIES,
                "selected_record",
            )
            key = self.m.package_identity(
                {
                    "Package": row["package"],
                    "Version": row["version"],
                    "Architecture": row["architecture"],
                }
            )
            self.m.relative(row["deb"])
            need(
                re.fullmatch(r"debs/[a-f0-9]{64}\.deb", row["deb"])
                and key not in keys
                and row["package"] not in {item["package"] for item in selection}
                and row["deb"] not in files,
                "selected_duplicate_or_path",
            )
            prior = before.get(row["package"])
            need(
                prior is None or prior["architecture"] == row["architecture"],
                "architecture_transition_requires_new_policy",
            )
            keys.add(key)
            files.add(row["deb"])
            selection.append(row)
        records, metadata, releases, total_meta = {}, [], [], 0
        for suite in sorted(REPOSITORIES):
            value = spec["metadata"][suite]
            need(
                value
                == {
                    "inrelease": "metadata/" + suite + ".InRelease",
                    "index": "metadata/" + suite + ".Packages",
                },
                "metadata_paths",
            )
            signed = read(value["inrelease"], 1024**2)
            need(
                signed.startswith(
                    (
                        b"-----BEGIN PGP SIGNED MESSAGE-----\n",
                        b"-----BEGIN PGP SIGNED MESSAGE-----\r\n",
                    )
                ),
                "clearsigned_only",
            )
            # Native maintained verifier returns only normal verified plaintext + full certificates.
            cleartext, certificates = verify_release(signed, suite, policy["repositories"][suite])
            need(
                type(cleartext) is bytes
                and 0 < len(cleartext) <= 1024**2
                and type(certificates) is tuple
                and certificates
                and len(set(certificates)) == len(certificates)
                and all(type(item) is str and FPR.fullmatch(item) for item in certificates),
                "signature_result",
            )
            rule = policy["repositories"][suite]
            need(
                set(certificates) <= set(rule["allowed_certificates"])
                and set(certificates) & set(rule["required_any_current"]),
                "certificate_purpose",
            )
            fields = self.m.one_control(cleartext)
            scalar_fields(fields, ("Origin", "Codename", "Date", "Valid-Until"))
            checks = self.m.release(
                cleartext,
                codename=suite,
                max_age_days=rule["max_age_days"],
                valid_until_required=rule["valid_until_required"],
                now=datetime.fromtimestamp(now, UTC),
            )
            index = read(value["index"], self.m.MAX_INDEX)
            total_meta += len(signed) + len(cleartext) + len(index)
            need(
                total_meta <= META_LIMIT
                and checks.get("main/binary-amd64/Packages")
                == {"sha256": sha(index), "size": len(index)},
                "signed_index_binding",
            )
            wanted = {
                (item["package"], item["version"], item["architecture"])
                for item in selection
                if item["suite"] == suite
            }
            count = 0
            for fields in self.m.controls(
                io.BytesIO(index), maximum=self.m.MAX_INDEX, max_line=128 * 1024
            ):
                count += 1
                need(count <= 300000, "index_stanza_budget")
                scalar_fields(
                    fields,
                    ("Package", "Version", "Architecture", "Filename", "Size", "SHA256", "Source"),
                )
                key = self.m.package_identity(fields)
                if key not in wanted:
                    continue
                need(
                    (suite, key) not in records
                    and HEX.fullmatch(fields.get("SHA256", ""))
                    and re.fullmatch(r"[1-9][0-9]{0,9}", fields.get("Size", ""))
                    and int(fields["Size"]) <= self.m.MAX_DEB,
                    "index_selected_record",
                )
                self.m.relative(fields.get("Filename", ""))
                need(fields["Filename"].startswith("pool/"), "package_origin_path")
                records[suite, key] = fields
            metadata.append(
                {
                    "suite": suite,
                    "uri": rule["uri"],
                    "inrelease_sha256": sha(signed),
                    "release_sha256": sha(cleartext),
                    "index_sha256": sha(index),
                    "index_bytes": len(index),
                    "certificates": list(certificates),
                }
            )
            releases.append((suite, cleartext, rule))
            files.update(value.values())
        expected_after, packages, total_debs = dict(before), [], 0
        retained_debs = []
        for row in sorted(selection, key=lambda item: item["package"]):
            key = (row["package"], row["version"], row["architecture"])
            need((row["suite"], key) in records, "package_record_missing")
            fields = records[row["suite"], key]
            raw = read(row["deb"], self.m.MAX_DEB)
            total_debs += len(raw)
            need(
                total_debs <= self.m.MAX_SPOOL
                and sha(raw) == fields["SHA256"]
                and len(raw) == int(fields["Size"])
                and row["deb"] == "debs/" + sha(raw) + ".deb",
                "DEB_signed_record_binding",
            )
            if approved is not None:
                expected = [item for item in approved["packages"] if item.get("package") == key[0]]
                need(
                    len(expected) == 1
                    and all(
                        expected[0].get(name) == value
                        for name, value in {
                            "suite": row["suite"],
                            "package": key[0],
                            "version": key[1],
                            "architecture": key[2],
                            "filename": fields["Filename"],
                            "deb": row["deb"],
                            "sha256": sha(raw),
                            "bytes": len(raw),
                        }.items()
                    ),
                    "DEB_not_in_external_material_set",
                )
            # No TAR/parser/executable content use until both signed-record digest and size pass.
            control, payload = self.m.deb(raw, payload=True)
            scalar_fields(control, ("Package", "Version", "Architecture", "Source"))
            need(self.m.package_identity(control) == key, "DEB_control_identity")
            expected_after[key[0]] = {
                "version": key[1],
                "architecture": key[2],
                "status": "install ok installed",
            }
            packages.append(
                {
                    "suite": row["suite"],
                    "package": key[0],
                    "version": key[1],
                    "architecture": key[2],
                    "filename": fields["Filename"],
                    "deb": row["deb"],
                    "sha256": sha(raw),
                    "bytes": len(raw),
                    "control_sha256": sha(canonical(control)),
                    "payload_map_sha256": sha(canonical(payload)),
                }
            )
            retained_debs.append((row["deb"], raw))
        for request in REQUESTS:
            name, _, version = request.partition("=")
            value = expected_after.get(name)
            need(
                value is not None
                and value["status"] == "install ok installed"
                and (not version or value["version"] == version),
                "direct_request_unsatisfied",
            )
        material = {
            "schema": SCHEMA,
            "stage": STAGE,
            "operation": "install-with-exact-reviewed-transitions",
            "parent": parent,
            "policy_sha256": policy_sha,
            "requests": list(REQUESTS),
            "prestate_sha256": sha(before_raw),
            "metadata": metadata,
            "packages": packages,
            "expected_after_state": expected_after,
            "transitions": [
                {"package": name, "before": before.get(name), "after": value}
                for name, value in sorted(expected_after.items())
                if before.get(name) != value
            ],
            "build_verified": False,
            "materials_complete": False,
            "cryptographic_build_attestation_verified": False,
            "other_builder_boundaries_closed": False,
            "compiler_SDK_generated_state_closed": False,
        }
        return material, tuple(retained_debs), tuple(releases), frozenset(files)

    def admit(self, material, expected_sha):
        need(
            type(expected_sha) is str
            and HEX.fullmatch(expected_sha)
            and sha(canonical(material)) == expected_sha,
            "external_material_set_pin_required",
        )
        return canonical(material)

    def freshness(self, releases, now):
        for suite, raw, rule in releases:
            self.m.release(
                raw,
                codename=suite,
                max_age_days=rule["max_age_days"],
                valid_until_required=rule["valid_until_required"],
                now=datetime.fromtimestamp(now, UTC),
            )
