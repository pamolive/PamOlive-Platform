#!/usr/bin/env bash
# Exact-image qualification on an ephemeral Linux runner; no registry push.
set -euo pipefail
[[ "${GITHUB_SHA:?}" =~ ^[a-f0-9]{40}$ ]]
test -n "${RUNNER_TEMP:?}"
proof="$RUNNER_TEMP/pamolive-image-security"
bundle="$RUNNER_TEMP/pamolive-qualified-image"
tools_dir="$RUNNER_TEMP/pamolive-scan-tools"
test -d "$proof" && test ! -e "$tools_dir"
mkdir -m 700 "$tools_dir"
mkdir -m 700 "$proof/reports"
scanner_archive="$tools_dir/grype-linux-amd64.tar.gz"
curl --proto '=https' --proto-redir '=https' --fail --silent --show-error --location \
  --max-time 120 --retry 2 \
  --output "$scanner_archive" \
  https://github.com/anchore/grype/releases/download/v0.121.3/grype_0.121.3_linux_amd64.tar.gz
PAMOLIVE_SCAN_TOOLS="$tools_dir" python - <<'PY'
import hashlib
import json
import os
import shutil
import tarfile
from pathlib import Path

tools = Path(os.environ["PAMOLIVE_SCAN_TOOLS"])
archive = tools / "grype-linux-amd64.tar.gz"
pin = json.loads(Path(".github/qualification/grype-0.121.3-linux-amd64.json").read_text())
expected = "e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85"
with archive.open("rb") as stream:
    assert hashlib.file_digest(stream, "sha256").hexdigest() == pin["archive_sha256"] == expected
with tarfile.open(archive, "r:gz") as source:
    members = [item for item in source.getmembers() if item.name == "grype"]
    assert len(members) == 1 and members[0].isfile() and 0 < members[0].size <= 256 * 1024**2
    with source.extractfile(members[0]) as stream, (tools / "grype").open("xb") as output:
        shutil.copyfileobj(stream, output, 1024**2)
(tools / "grype").chmod(0o700)
common = {"check-for-app-update": False, "external-sources": {"enable": False},
          "ignore": [], "exclude": [], "only-fixed": False, "only-notfixed": False,
          "match-upstream-kernel-headers": True, "include-matcher-suppressions": True}
for name, cache in (("host", str(tools / "db")), ("container", "/scanner/db")):
    config = dict(common, db={"cache-dir": cache, "auto-update": False,
                             "validate-by-hash-on-start": True, "validate-age": True})
    with (tools / ("grype-" + name + ".json")).open("x") as output:
        json.dump(config, output)
PY
# The only online scanner operation downloads its public vulnerability database.
# Neither source archives, SBOMs nor application credentials are sent to it.
timeout 300 env -i PATH="$PATH" TMPDIR="$tools_dir" GOMAXPROCS=1 GOMEMLIMIT=192MiB \
  "$tools_dir/grype" -c "$tools_dir/grype-host.json" db update
image_ref=$(docker image inspect pamolive-platform:ci --format '{{.Id}}')
scan() {
  local label="$1" kind="$2" target="$3" status=0
  timeout --signal=TERM --kill-after=15s 240s docker run --rm \
    --user "$(id -u):$(id -g)" --pull never --network none \
    --cpus 1 --memory 256m --memory-swap 256m --pids-limit 128 \
    --cap-drop ALL --security-opt no-new-privileges --read-only --no-healthcheck \
    --tmpfs /tmp:size=64m,mode=1777 --entrypoint /scanner/grype \
    --env LD_LIBRARY_PATH= --env LD_PRELOAD= --env GOMAXPROCS=1 --env GOMEMLIMIT=192MiB \
    --env TMPDIR=/tmp \
    --mount "type=bind,src=$tools_dir,dst=/scanner,readonly" \
    --mount "type=bind,src=$proof/reports,dst=/reports" \
    --mount "type=bind,src=$proof/combined.cdx.json,dst=/combined.cdx.json,readonly" \
    --mount "type=bind,src=$bundle/pamolive-linux-amd64.tar,dst=/image.tar,readonly" \
    --mount "type=bind,src=$PWD/.github/qualification/native-positive-control.cdx.json,dst=/control.cdx.json,readonly" \
    "$image_ref" -c /scanner/grype-container.json --from "$kind" "$target" \
    --scope squashed --fail-on high -o json --file "/reports/$label.json" \
    > "$proof/$label.stdout.log" 2> "$proof/$label.stderr.log" || status=$?
  # 2 means that the documented scanner threshold is exceeded, not success.
  # Preserve the complete JSON and let the stricter reviewed policy decide.
  case "$status" in 0|2) ;; *) return "$status" ;; esac
  printf '%s\n' "$status" > "$proof/$label.exit-code.txt"
}
scan os docker-archive /image.tar
scan compiled sbom /combined.cdx.json
scan positive sbom /control.cdx.json
python -m deploy.qualify_image_scan --bundle "$bundle" --revision "$GITHUB_SHA" \
  --os-report "$proof/reports/os.json" --compiled-sbom "$proof/combined.cdx.json" \
  --compiled-report "$proof/reports/compiled.json" --positive-report "$proof/reports/positive.json" \
  --scanner-archive "$scanner_archive" --policy .github/qualification/image-scan-policy.v1.json \
  --output "$proof/policy-result.json"
