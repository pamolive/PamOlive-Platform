"""Finite pinned public-source download; NEVER run implicitly during offline build."""

import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ENV, command, material_rows, need, record, sha, write_new


class Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, url):
        parsed = urllib.parse.urlsplit(url)
        self.count += 1
        need(
            self.count == 1
            and req.host == "github.com"
            and code == 302
            and parsed.scheme == "https"
            and parsed.hostname == "release-assets.githubusercontent.com"
            and parsed.username is None
            and parsed.password is None
            and parsed.port is None,
            "redirect_refused",
        )
        return urllib.request.Request(url, headers={"User-Agent": "PamOlive-public-source"})


def worker(folder):
    # DNS/TLS/header/body all remain inside the parent's owned-session deadline.
    context = ssl.create_default_context()
    facts, total = [], 0
    for row in material_rows():
        redirect = Redirect()
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), redirect, urllib.request.HTTPSHandler(context=context)
        )
        request = urllib.request.Request(
            row["URL"], headers={"User-Agent": "PamOlive-public-source"}
        )
        with opener.open(request, timeout=15) as response:
            need(response.status == 200, "http_status")
            raw = response.read(row["bytes"] + 1)
            need(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "download_bytes")
        total += len(raw)
        need(total <= 32 * 1024**2, "total_download_budget")
        write_new(folder / row["name"], raw, 0o444)
        facts.append(
            {
                "name": row["name"],
                "bytes": len(raw),
                "sha256": sha(raw),
                "redirects": redirect.count,
            }
        )
    record(
        folder / "DOWNLOAD.json",
        {
            "files": facts,
            "initial_application_GETs": 10,
            "TLS_peer_verified": True,
            "proxy_credentials_retry": False,
            "PGP_verified": False,
        },
    )


def main(folder):
    folder = Path(folder).resolve()
    folder.mkdir(mode=0o700)
    # Closed env; no existing GitHub, registry, proxy or loader variables copied.
    command(
        [
            str(Path(sys.executable).resolve()),
            "-I",
            "-B",
            "-S",
            str(Path(__file__).resolve()),
            "--worker",
            str(folder),
        ],
        folder,
        folder / "supervisor",
        seconds=180,
        cap=65536,
        env=ENV,
    )


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--worker":
            worker(Path(sys.argv[2]))
        else:
            need(len(sys.argv) == 2, "usage_new_folder")
            main(sys.argv[1])
    except BaseException:
        # No free-form transport errors or ephemeral signed URLs in public logs.
        print('{"state":"DOWNLOAD_REFUSED_OR_UNKNOWN"}')
        raise SystemExit(42) from None
