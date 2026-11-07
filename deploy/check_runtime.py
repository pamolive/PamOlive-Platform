"""Container-only privilege separation check. Never prints environment values."""

import json
import subprocess
import sys
import urllib.request
from pathlib import Path

web, native = [], []
for directory in Path("/proc").iterdir():
    if not directory.name.isdecimal():
        continue
    try:
        status = (directory / "status").read_text()
        command = (directory / "cmdline").read_bytes()
    except (OSError, ProcessLookupError):
        continue
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    uid = tuple(map(int, fields["Uid"].split()))
    if b"config.asgi:application" in command or b"manage.py\x00runjobs" in command:
        assert uid == (1000, 1000, 1000, 1000), "Application role is not UID 1000"
        assert int(fields["CapEff"].strip(), 16) == 0, "Application retained capabilities"
        web.append(directory.name)
    if b"/opt/pamolive-guac/sbin/guacd" in command:
        assert uid == (1001, 1001, 1001, 1001), "Native role is not UID 1001"
        assert int(fields["CapEff"].strip(), 16) == 0, "Native role retained capabilities"
        native.append(directory.name)
assert web and native, "The application or private engine is not running"
probe = """
import pathlib,sys,json,stat
web,native=json.loads(sys.argv[1])
for pid in web:
    try:
        pathlib.Path('/proc/'+pid+'/environ').read_bytes()
    except (PermissionError,ProcessLookupError):
        pass
    else:
        raise AssertionError('Native role can read application environment')
for pid in native:
    content=pathlib.Path('/proc/'+pid+'/environ').read_bytes()
    names={part.split(b'=',1)[0] for part in content.split(b'\\0') if part}
    assert not names & {b'DATABASE_URL', b'SECRET_KEY', b'PAMOLIVE_ENCRYPTION_KEY'}
"""
subprocess.run(
    [sys.executable, "-c", probe, json.dumps([web, native])],
    check=True,
    user=1001,
    group=1001,
    extra_groups=[],
    env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
)
with urllib.request.urlopen("http://127.0.0.1:8000/health/", timeout=5) as response:
    assert response.status == 200
print("Web/jobs UID 1000; native UID 1001; children have no effective capabilities.")
print("Native environment has no application secrets and cannot read web/job environments.")
print("ASGI HTTP health is available through the single application port.")
