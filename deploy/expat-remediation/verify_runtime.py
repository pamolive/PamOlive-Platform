"""Check final active paths/packages and run bounded fresh Python children."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, command, need, read, record, sha
from python_cases import CASES


def package_version(text):
    found = []
    for stanza in text.split("\n\n"):
        if "Package: libexpat1" not in stanza.splitlines():
            continue
        fields = {}
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")):
                continue
            key, sep, value = line.partition(": ")
            need(sep and key not in fields, "dpkg_field_duplicate")
            fields[key] = value
        found.append(fields)
    need(len(found) == 1, "package_count")
    row = found[0]
    need(
        row.get("Version") == "2.10.0-1+pamolive1"
        and row.get("Architecture") == "amd64"
        and row.get("Status") == "install ok installed",
        "package_version_or_state",
    )
    return row["Version"]


def main(output):
    output = Path(output)
    output.mkdir(mode=0o700)
    proof = json.loads(read("/usr/share/pamolive/expat4/after/ABI.json", 4 * 1024**2))
    for item in proof.values():
        target = Path(item["alias"]).resolve(strict=True)
        need(
            str(target) == item["target"] and sha(read(target, 4 * 1024**2)) == item["sha256"],
            "final_active_file_changed",
        )
    for prefix in ("/opt/pamolive-freerdp/lib", "/opt/pamolive-guac/lib"):
        need(not (Path(prefix) / "libexpat.so.1").exists(), "alternate_loader_provider")
    version = package_version(read("/var/lib/dpkg/status", 16 * 1024**2).decode())
    for case in CASES:
        command(
            ["/usr/local/bin/python3.12", "-I", "-B", "-S", str(HERE / "run_python_case.py"), case],
            output,
            output / case,
            seconds=5,
            cap=65536,
        )
    record(
        output / "RUNTIME.json",
        {
            "package_version": version,
            "cases": list(CASES),
            "fixed4_admitted": False,
            "exact_image_scan_pending": True,
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 2, "usage_new_output")
    main(sys.argv[1])
