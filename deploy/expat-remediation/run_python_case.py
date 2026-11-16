"""LINUX ONLY: one short-lived actual parser test; do not execute on preparation PC."""

import hashlib
import importlib
import json
import resource
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from python_cases import CASES, OUTPUT_CAP, payload


def main(name):
    if name not in CASES:
        raise ValueError("case_name")
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024**2, 128 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if name == "capsule-first":
        import _elementtree  # noqa: F401
    import pyexpat

    if pyexpat.EXPAT_VERSION != "expat_2.10.0" or sys.version_info[:3] != (3, 12, 16):
        raise ValueError("runtime_declaration")
    if Path(pyexpat.__file__) != Path(
        "/usr/local/lib/python3.12/lib-dynload/pyexpat.cpython-312-x86_64-linux-gnu.so"
    ):
        raise ValueError("module_path")
    features = dict(pyexpat.features)
    if not {"XML_DTD", "XML_NS", "XML_GE"} <= features.keys():
        raise ValueError("runtime_features")
    proof = json.loads(Path("/usr/share/pamolive/expat4/after/ABI.json").read_text())
    module_hash = hashlib.sha256(Path(pyexpat.__file__).read_bytes()).hexdigest()
    if module_hash != proof["pyexpat"]["sha256"]:
        raise ValueError("module_hash")
    provider = proof["libexpat.so.1"]
    # Filter the current process map in memory; publish no ASLR addresses or unrelated paths.
    with Path("/proc/self/maps").open("rb") as stream:
        maps = stream.read(512 * 1024 + 1)
    if len(maps) > 512 * 1024:
        raise ValueError("maps_cap")
    selected = {line.split()[-1].decode() for line in maps.splitlines() if b"/libexpat.so." in line}
    if (
        selected != {provider["target"]}
        or hashlib.sha256(Path(provider["target"]).read_bytes()).hexdigest() != provider["sha256"]
    ):
        raise ValueError("loaded_provider")
    output = 0

    def text(value):
        nonlocal output
        output += len(value.encode("utf-8"))
        if output > OUTPUT_CAP:
            raise ValueError("expanded_output_cap")

    if name.startswith("capsule-"):
        import _elementtree  # noqa: F401
        import xml.etree.ElementTree as ET

        expected_elementtree = proof["_elementtree"]
        if (
            str(Path(_elementtree.__file__).resolve()) != expected_elementtree["target"]
            or hashlib.sha256(Path(_elementtree.__file__).read_bytes()).hexdigest()
            != expected_elementtree["sha256"]
        ):
            raise ValueError("elementtree_module_hash")

        before = pyexpat.expat_CAPI
        importlib.reload(pyexpat)
        # Exercise the existing C accelerator against the new producer in BOTH fresh import orders.
        if not hasattr(pyexpat, "expat_CAPI") or type(before).__name__ != "PyCapsule":
            raise ValueError("capsule_missing")
        for _ in range(16):
            root = ET.fromstring("<!DOCTYPE r [<!ENTITY x 'ok'>]><r xmlns='urn:test'>&x;</r>")
            if root.tag != "{urn:test}r" or root.text != "ok":
                raise ValueError("elementtree_capsule_behavior")
    elif name == "external":
        parent = pyexpat.ParserCreate()
        for context, content in ((None, b"<!ELEMENT x EMPTY>"), ("", b"<x/>")):
            child = parent.ExternalEntityParserCreate(context)
            child.Parse(b"", False)
            child.Parse(content, True)
    else:
        parser = pyexpat.ParserCreate(namespace_separator="|")
        parser.CharacterDataHandler = text
        parser.SetReparseDeferralEnabled(True)
        raw = payload(name)
        chunk = 32 if name == "quadratic" else 4096
        for offset in range(0, len(raw), chunk):
            parser.Parse(raw[offset : offset + chunk], False)
        parser.Parse(b"", True)
    print(
        json.dumps(
            {
                "case": name,
                "PASS": True,
                "output_bytes": output,
                "runtime_declaration": pyexpat.EXPAT_VERSION,
                "features": features,
                "module_sha256": module_hash,
                "provider_sha256": provider["sha256"],
                "not_build_attestation": True,
            }
        )
    )


if __name__ == "__main__":
    main(sys.argv[1])
