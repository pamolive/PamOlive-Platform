"""Strict three-wheel PEP427 mapping and installed RECORD; data reads only."""

import base64
import csv
import io
import json
import posixpath
from pathlib import PurePosixPath

from support import need, read_regular, sha


def canonical_url(wheel):
    need(wheel.is_absolute() and wheel == wheel.resolve(strict=True))
    return wheel.as_uri()


def expected_direct_url(wheel, digest):
    return {
        "archive_info": {"hash": "sha256=" + digest, "hashes": {"sha256": digest}},
        "url": canonical_url(wheel),
    }


def wheel_mapping(inventory):
    module, version, info = inventory["module"], inventory["version"], inventory["info"]
    stem = inventory["name"].replace("-", "_")
    need(info == stem + "-" + version + ".dist-info")
    result = {}
    for name, row in inventory["files"].items():
        need(type(name) is str and not name.startswith("/") and "\\" not in name)
        need(all(part not in ("", ".", "..") for part in name.split("/")))
        if name.startswith(stem + "-" + version + ".data/"):
            need(module == "pamolive_vault_runtime")
            need(
                name
                == stem + "-" + version + ".data/data/share/pamolive/vault-reservation/schema.sql"
            )
            installed = "share/pamolive/vault-reservation/schema.sql"
        else:
            need(name.startswith(module + "/") or name.startswith(info + "/"))
            installed = "lib/python3.12/site-packages/" + name
        need(installed not in result)
        result[installed] = row
    return result


def check(prefix, inventory, wheel):
    need(prefix.is_absolute() and prefix == prefix.resolve(strict=True))
    site = prefix / "lib/python3.12/site-packages"
    info = inventory["info"]
    mapping = wheel_mapping(inventory)
    generated = {
        "lib/python3.12/site-packages/" + info + "/INSTALLER": b"pip\n",
        "lib/python3.12/site-packages/" + info + "/REQUESTED": b"",
        "lib/python3.12/site-packages/" + info + "/direct_url.json": json.dumps(
            expected_direct_url(wheel, inventory["wheel_sha256"]), sort_keys=True
        ).encode(),
    }
    need(not set(generated) & set(mapping))
    expected = {
        **mapping,
        **{name: {"sha256": sha(raw), "bytes": len(raw)} for name, raw in generated.items()},
    }
    record_name = "lib/python3.12/site-packages/" + info + "/RECORD"
    record_path = prefix / record_name
    raw_record = read_regular(record_path, 65536)
    rows = list(csv.reader(io.StringIO(raw_record.decode("utf-8"), newline="")))
    need(len(rows) == len(expected) + 1 and all(len(row) == 3 for row in rows))
    seen, actual = set(), {}
    for name, digest, size in rows:
        need(type(name) is str and name not in seen and len(name) <= 4096 and "\\" not in name)
        seen.add(name)
        if name.startswith("../"):
            need(name == "../../../share/pamolive/vault-reservation/schema.sql")
            need(inventory["module"] == "pamolive_vault_runtime")
        else:
            need(
                not PurePosixPath(name).is_absolute()
                and all(part not in ("", ".", "..") for part in name.split("/"))
            )
        relative = posixpath.normpath("lib/python3.12/site-packages/" + name)
        need(not relative.startswith("../") and relative not in actual)
        path = prefix / relative
        need(path.resolve(strict=True) == path and path.is_relative_to(prefix))
        if relative == record_name:
            need(digest == size == "")
            actual[relative] = {"bytes": len(raw_record), "sha256": sha(raw_record)}
            continue
        need(relative in expected)
        raw = read_regular(path, 1024**2)
        observed = {"sha256": sha(raw), "bytes": len(raw)}
        need(observed == expected[relative])
        encoded = base64.urlsafe_b64encode(bytes.fromhex(observed["sha256"])).rstrip(b"=").decode()
        need(digest == "sha256=" + encoded and size == str(len(raw)))
        actual[relative] = observed
    need(set(actual) == set(expected) | {record_name})
    for directory in (site / inventory["module"], site / info):
        names = set()
        for path in directory.rglob("*"):
            need(not path.is_symlink())
            if path.is_file():
                names.add(path.relative_to(prefix).as_posix())
        wanted = {
            name
            for name in actual
            if name.startswith(directory.relative_to(prefix).as_posix() + "/")
        }
        need(names == wanted)
    need(not list(site.rglob("*.pth")) and not list(site.rglob("*.pyc")))
    return {
        "name": inventory["name"],
        "version": inventory["version"],
        "RECORD_sha256": sha(raw_record),
        "files_checked": len(actual),
        "wheel_source_notice_and_metadata_bound": True,
        "generated_pip_files_exact": ["INSTALLER", "REQUESTED", "direct_url.json"],
        "SQL_only_known_data_relocation": inventory["module"] == "pamolive_vault_runtime",
    }
