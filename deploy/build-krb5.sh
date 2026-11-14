#!/bin/sh
# Build-stage only. Fetch and compilation are deliberately separate RUNs.
set -eu
umask 022
export LC_ALL=C LANG=C DEB_BUILD_OPTIONS=parallel=1 DEB_BUILD_MAINT_OPTIONS=hardening=+all
unset DEB_BUILD_PROFILES
base_version=1.21.3-5+deb13u1
version=$base_version+pamolive1
work=/build
proof=/usr/share/pamolive/krb5-backport
phase=${1-}
test "$phase" = fetch || test "$phase" = build
test "$(dpkg --print-architecture)" = amd64
run_logged() {
  logfile=$1
  shift
  if "$@" > "$logfile" 2>&1; then
    return 0
  else
    code=$?
    # Public source and synthetic test data only. Preserve the actual failure.
    tail -n 80 "$logfile" >&2
    exit "$code"
  fi
}

if test "$phase" = fetch; then
  test ! -e "$work/krb5-input"
  mkdir -p "$work/krb5-input" "$proof"
  cd "$work/krb5-input"
  fetch() { curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 120 --max-filesize 33554432 --output "$2" "$1"; }
  cp /usr/share/keyrings/debian-archive-keyring.gpg "$proof/debian-archive-keyring.gpg"
  fetch https://security.debian.org/debian-security/dists/trixie-security/InRelease "$proof/InRelease"
  # APT may use sqv. This is an additional REAL gpgv operation, not invented status.
  gpgv --keyring "$proof/debian-archive-keyring.gpg" --status-fd 3 \
    --output "$proof/Release" "$proof/InRelease" 3> "$proof/gpgv.status"
  fetch https://security.debian.org/debian-security/dists/trixie-security/main/source/Sources.xz "$proof/Sources.xz"
  python - <<'PYCHECK'
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import lzma
from pathlib import Path
import re
p = Path('/usr/share/pamolive/krb5-backport')
release = (p/'Release').read_text()
def fields(text):
    result = {}; key = None
    for line in text.splitlines():
        if line.startswith((' ', '\t')) and key:
            result[key] += '\n' + line[1:]
        elif ': ' in line:
            key, value = line.split(': ', 1)
            if key in result: raise ValueError('duplicate_control_field')
            result[key] = value
        elif line.endswith(':'):
            key = line[:-1]
            if key in result: raise ValueError('duplicate_control_field')
            result[key] = ''
        elif line: raise ValueError('invalid_control_field')
    return result
r = fields(release)
now = datetime.now(timezone.utc)
assert r['Codename'] == 'trixie-security' and r['Origin'] == 'Debian'
assert parsedate_to_datetime(r['Date']) <= now < parsedate_to_datetime(r['Valid-Until'])
status = (p/'gpgv.status').read_text()
assert '[GNUPG:] VALIDSIG ' in status
assert not re.search(r'\[GNUPG:\] (?:BADSIG|ERRSIG|EXPKEYSIG|EXPSIG|REVKEYSIG|NO_PUBKEY|FAILURE) ', status)
data = (p/'Sources.xz').read_bytes()
matches = [line.split() for line in r['SHA256'].splitlines()
           if line.split() and line.split()[-1] == 'main/source/Sources.xz']
assert len(matches) == 1 and matches[0][0] == hashlib.sha256(data).hexdigest()
assert int(matches[0][1]) == len(data)
# Decompression is bounded even if a future signed repository grows unexpectedly.
decoder = lzma.LZMADecompressor()
raw = decoder.decompress(data, max_length=32*1024*1024+1)
assert len(raw) <= 32*1024*1024 and decoder.eof and not decoder.unused_data
records = [record for record in raw.decode().split('\n\n')
           if fields(record).get('Package') == 'krb5'
           and fields(record).get('Version') == '1.21.3-5+deb13u1']
assert len(records) == 1
record = fields(records[0]); assert record['Directory'] == 'pool/updates/main/k/krb5'
(p/'source-record.txt').write_text(records[0]+'\n')
expected = {
 'krb5_1.21.3.orig.tar.gz':'b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35',
 'krb5_1.21.3-5+deb13u1.debian.tar.xz':'02b873b239fbe7ddf016dfe44deba4130673f4606c18c93da0622e2bc8500fb4'}
rows = [line.split() for line in record['Checksums-Sha256'].splitlines() if line.strip()]
assert len({row[2] for row in rows}) == len(rows)
for name, sha in expected.items():
    assert sum(row[2] == name and row[0] == sha for row in rows) == 1
dsc = 'krb5_1.21.3-5+deb13u1.dsc'
assert sum(row[2] == dsc for row in rows) == 1
assert {row[2] for row in rows} == {*expected, dsc, 'krb5_1.21.3.orig.tar.gz.asc'}
assert all(re.fullmatch(r'[0-9a-f]{64}', row[0]) for row in rows)
Path('/build/krb5-input/downloads.sha256').write_text(''.join(row[0]+'  '+row[2]+'\n' for row in rows))
PYCHECK
  for file in krb5_1.21.3.orig.tar.gz krb5_1.21.3.orig.tar.gz.asc krb5_1.21.3-5+deb13u1.debian.tar.xz krb5_1.21.3-5+deb13u1.dsc; do
    fetch "https://security.debian.org/debian-security/pool/updates/main/k/krb5/$file" "$file"
  done
  sha256sum -c downloads.sha256
  cp "krb5_$base_version.dsc" "$proof/"
  cp /build-fixtures/krb5-asn1-sequence.patch "$proof/upstream.patch"
  printf '%s  %s\n' e676f3727b3c984aa5a7baaafdb39394c8774c913ace0c3ce302e9b81aaa19ee "$proof/upstream.patch" | sha256sum -c -
  cp /build-fixtures/krb5-test-keyring-seccomp.patch "$proof/test-keyring-compat.patch"
  printf '%s  %s\n' 1227fc24b76e62371bd94346e1a653906e2e964d39ac25f095c32ccbe8a9cd27 "$proof/test-keyring-compat.patch" | sha256sum -c -
  # New build stage only. Never add sid or change the host's APT configuration.
  printf '%s\n' 'Types: deb-src' 'URIs: https://security.debian.org/debian-security' \
    'Suites: trixie-security' 'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' > /etc/apt/sources.list.d/pamolive-krb5.sources
  apt-get update
  apt-get build-dep --yes --arch-only --no-install-recommends "krb5=$base_version"
  # No uploader-signature claim: the .dsc bytes are authenticated by signed APT.
  dpkg-source -x "krb5_$base_version.dsc" "$work/krb5-baseline"
  cp -a "$work/krb5-baseline" "$work/krb5-patched"
  exit 0
fi

# Dockerfile MUST call this phase with RUN --network=none. No fetch occurs here.
test -d "$work/krb5-baseline/debian"
test -d "$work/krb5-patched/debian"
test ! -e "$proof/debian-tests.json"
test -f "$proof/baseline.json"  # Actual stock four-library baseline, captured by independent gate.
printf '%s  %s\n' e676f3727b3c984aa5a7baaafdb39394c8774c913ace0c3ce302e9b81aaa19ee "$proof/upstream.patch" | sha256sum -c -
printf '%s  %s\n' 1227fc24b76e62371bd94346e1a653906e2e964d39ac25f095c32ccbe8a9cd27 "$proof/test-keyring-compat.patch" | sha256sum -c -
cat > "$proof/keyctl-probe.py" <<'PYKEYRING'
"""Build-only synthetic syscall probe. Never opens an existing key or keyring."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys

command = ['/usr/bin/keyctl', 'add', 'user', 'pamolive-krb5-probe', 'synthetic', '@p']
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
              if ':' in line)
assert sys.platform == 'linux' and int(status['Seccomp']) == 2
assert {name for _, name in socket.if_nameindex()} == {'lo'}
result = subprocess.run(command, capture_output=True, timeout=5)
# This qualification profile is deliberately limited to the observed refusal.
# Other errors, or a host allowing keys, require their own capability qualification.
assert result.returncode == 1 and not result.stdout
assert result.stderr == b'add_key: Operation not permitted\n'
value = {'schema':'pamolive.krb5-keyring-probe.v1', 'exit_code':result.returncode,
         'errno':'EPERM', 'stderr_sha256':hashlib.sha256(result.stderr).hexdigest(),
         'probe_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'seccomp_mode':int(status['Seccomp']), 'command':command,
         'network':'none', 'supported':False}
with Path(__file__).with_suffix('.json').open('x') as stream:
    stream.write(json.dumps(value, sort_keys=True)+'\n')
PYKEYRING
python "$proof/keyctl-probe.py"
# Debian declares these test dependencies for its own interpreter. Keep the app
# and metadata helpers on Python3.12; only configure/makecheck use Debian Python.
export PYTHON=/usr/bin/python3
"$PYTHON" -c 'import kdcproxy, pyrad'
export QUILT_PATCHES=debian/patches
for tree in "$work/krb5-baseline" "$work/krb5-patched"; do
  cd "$tree"
  quilt import -P pamolive-test-keyring-seccomp.patch "$proof/test-keyring-compat.patch"
  patch --dry-run -p1 --fuzz=0 < "$proof/test-keyring-compat.patch" > "$work/krb5-test-patch-dry-run.log"
  if grep -Eiq 'offset|fuzz' "$work/krb5-test-patch-dry-run.log"; then exit 1; fi
  QUILT_PATCH_OPTS='--fuzz=0' quilt push
done
cd "$work/krb5-baseline"
# Debian's normal build target configures, compiles and checks the unmodified source.
run_logged "$work/krb5-baseline-build.log" debian/rules build-arch
sh /build-fixtures/check_krb5_asn1.sh --source "$PWD/src" --build "$PWD/build" \
  --phase baseline --output "$work/asn1-baseline.json"
cd "$work/krb5-patched"
# Quilt preserves the existing Debian series; -F0 rejects fuzzy application.
export QUILT_PATCHES=debian/patches
quilt import -P pamolive-asn1-sequence.patch "$proof/upstream.patch"
patch --dry-run -p1 --fuzz=0 < "$proof/upstream.patch" > "$work/krb5-patch-dry-run.log"
if grep -Eiq 'offset|fuzz' "$work/krb5-patch-dry-run.log"; then exit 1; fi
QUILT_PATCH_OPTS='--fuzz=0' quilt push
DEBFULLNAME='PamOlive build' DEBEMAIL='build@pamolive.invalid' \
  dch --newversion "$version" --distribution trixie-security \
  'Backport MIT 205832663330da308d9d031a17326b68a16715fd (CVE-2026-119079); retain upstream 1.21.3 ABI.'
# No nocheck, no -d, no parallel tests, no synthetic upstream version.
run_logged "$proof/debian-build.log" dpkg-buildpackage -B -us -uc -j1
sh /build-fixtures/check_krb5_asn1.sh --source "$PWD/src" --build "$PWD/build" \
  --phase patched --output "$work/asn1-patched.json"
mkdir -p /packages/runtime /packages/sdk /packages/build-records
for name in libkrb5-3 libk5crypto3 libkrb5support0 libgssapi-krb5-2; do
  file="$work/${name}_${version}_amd64.deb"
  test "$(dpkg-deb -f "$file" Package)" = "$name"
  test "$(dpkg-deb -f "$file" Version)" = "$version"
  cp "$file" /packages/runtime/
done
for name in libkrb5-dev krb5-multidev libkadm5clnt-mit12 libkadm5srv-mit12 libkdb5-10t64 libgssrpc4t64; do
  file="$work/${name}_${version}_amd64.deb"
  test "$(dpkg-deb -f "$file" Package)" = "$name"
  test "$(dpkg-deb -f "$file" Version)" = "$version"
  cp "$file" /packages/sdk/
done
cp "$work"/*.buildinfo "$work"/*.changes /packages/build-records/
cp "$work/krb5-baseline-build.log" /packages/build-records/
cp "$work/krb5-baseline-build.log" "$proof/baseline-build.log"
cp "$work/asn1-baseline.json" "$proof/baseline-asn1.json"
cp "$work/asn1-patched.json" "$proof/patched-asn1.json"
cp /build-fixtures/krb5_asn1_regression.c /build-fixtures/check_krb5_asn1.sh "$proof/"
python - <<'PYPROOF'
import hashlib
import json
from pathlib import Path
p = Path('/usr/share/pamolive/krb5-backport')
def sha(path):
    with path.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()
before = json.loads(Path('/build/asn1-baseline.json').read_text())
after = json.loads(Path('/build/asn1-patched.json').read_text())
assert before['verified'] and after['verified'] and before['source_file_sha256'] != after['source_file_sha256']
regression = {'schema':'pamolive.krb5-asn1-regression.v1',
 'patch_sha256':'e676f3727b3c984aa5a7baaafdb39394c8774c913ace0c3ce302e9b81aaa19ee',
 'source_original_sha256':before['source_file_sha256'], 'source_patched_sha256':after['source_file_sha256'],
 'before':before, 'after':after}
(p/'asn1-regression.json').write_text(json.dumps(regression, sort_keys=True)+'\n')
tests = ['keyring collection tests', 'keyring ccache tests']
phase_logs = {'baseline':'baseline-build.log', 'patched':'debian-build.log'}
phase_counts = {}
for phase, name in phase_logs.items():
    lines = (p/name).read_text().splitlines()
    phase_counts[phase] = {test:lines.count('*** Skipping: '+test+': keyring support not built')
                           for test in tests}
    assert all(1 <= count <= 64 for count in phase_counts[phase].values())
(p/'debian-tests.json').write_text(json.dumps({'schema':'pamolive.krb5-debian-tests.v1',
 'status':'passed_with_capability_skips','tests_enabled':True,'exit_code':0,'jobs':1,
 'command':'dpkg-buildpackage -B -us -uc -j1','log_sha256':sha(p/'debian-build.log'),
 'capability_skips':[{'capability':'kernel_keyring','reason':'docker_seccomp_eperm',
 'probe_file':'keyctl-probe.json','probe_script_file':'keyctl-probe.py',
 'test_patch_file':'test-keyring-compat.patch','tests':tests,
 'phase_logs':phase_logs,'phase_counts':phase_counts,
 'count':sum(sum(counts.values()) for counts in phase_counts.values()),
 'historical_test_message':'keyring support not built'}],
 'test_python':'/usr/bin/python3'})+'\n')
files = sorted(path for path in p.iterdir() if path.is_file())
assert len(files) <= 20 and all(f.stat().st_size <= 32*1024*1024 for f in files)
assert sum(f.stat().st_size for f in files) <= 128*1024*1024
signers = sorted({line.split()[2] for line in (p/'gpgv.status').read_text().splitlines()
                  if line.startswith('[GNUPG:] VALIDSIG ')})
assert signers
value = {'schema':'pamolive.krb5-backport-provenance.v1',
 'base_version':'1.21.3-5+deb13u1','version':'1.21.3-5+deb13u1+pamolive1',
 'upstream_commit':'205832663330da308d9d031a17326b68a16715fd',
 'patch_sha256':regression['patch_sha256'],
 'sources':{'krb5_1.21.3.orig.tar.gz':'b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35',
 'krb5_1.21.3-5+deb13u1.debian.tar.xz':'02b873b239fbe7ddf016dfe44deba4130673f4606c18c93da0622e2bc8500fb4'},
 'evidence':{f.name:sha(f) for f in files},
 'test_outputs':{'debian':'debian-tests.json','asn1':'asn1-regression.json',
 'before':'baseline-asn1.json','after':'patched-asn1.json',
 'harness':'krb5_asn1_regression.c','wrapper':'check_krb5_asn1.sh'},
 'apt_chain':{'status_file':'gpgv.status','signer_fingerprints':signers,
 'inrelease_file':'InRelease','release_file':'Release','index_file':'Sources.xz',
 'index_release_path':'main/source/Sources.xz','source_record_file':'source-record.txt',
 'keyring_file':'debian-archive-keyring.gpg','dsc_file':'krb5_1.21.3-5+deb13u1.dsc'},
 'build':{'jobs':1,'tests_enabled':True}}
(p/'provenance.json').write_text(json.dumps(value, sort_keys=True)+'\n')
PYPROOF
# Public build evidence contains no credentials and must be readable by runtime UID.
find "$proof" -type d -exec chmod 0555 {} +
find "$proof" -type f -exec chmod 0444 {} +
