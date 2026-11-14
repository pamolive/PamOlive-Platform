"""Check portability of the committed review metadata, without scanning secrets."""

import argparse
import json
from pathlib import Path, PurePosixPath


def require(condition):
    if not condition:
        raise ValueError("invalid_public_secret_baseline_metadata")


def relative_path(name):
    require(type(name) is str and 0 < len(name) <= 512 and "\\" not in name and ":" not in name)
    path = PurePosixPath(name)
    require(
        not path.is_absolute()
        and str(path) == name
        and ".." not in path.parts
        and "\0" not in name
        and name != "."
    )


def validate(value):
    require(
        type(value) is dict
        and type(value.get("filters_used")) is list
        and type(value.get("results")) is dict
    )
    for setting in value["filters_used"]:
        require(type(setting) is dict and type(setting.get("path")) is str)
        # This is a transient CLI filter: persisting it leaks a machine-specific
        # temporary path and makes future checks depend on another checkout.
        require(setting["path"] != "detect_secrets.filters.common.is_baseline_file")
        if "filename" in setting:
            relative_path(setting["filename"])
    for name, entries in value["results"].items():
        relative_path(name)
        require(type(entries) is list)
        for entry in entries:
            require(
                type(entry) is dict
                and entry.get("filename") == name
                and type(entry.get("line_number")) is int
                and entry["line_number"] > 0
            )
    return {
        "portable": True,
        "review_decisions_checked": sum(map(len, value["results"].values())),
        "secret_scan_performed": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    args = parser.parse_args()
    try:
        require(args.baseline.is_file() and not args.baseline.is_symlink())
        with args.baseline.open("rb") as stream:
            raw = stream.read(2 * 1024**2 + 1)
        require(len(raw) <= 2 * 1024**2)
        report = validate(json.loads(raw))
    except (ValueError, TypeError, OSError, RecursionError):
        print('{"portable":false,"error":"invalid_public_secret_baseline_metadata"}')
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
