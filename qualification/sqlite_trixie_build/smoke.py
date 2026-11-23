import json
import re
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

EXPECTED_VERSIONS = {"baseline": "3.46.1", "candidate": "3.54.1"}
EXPECTED_ROWS = [(1, "copper lantern"), (2, "glass lantern"), (3, "paper map")]
EXPECTED_MATCHES = [(1,), (2,)]


def read_rows(connection: sqlite3.Connection) -> list[tuple[int, str]]:
    return connection.execute("SELECT id, body FROM documents ORDER BY id").fetchall()


def read_matches(connection: sqlite3.Connection) -> list[tuple[int]]:
    return connection.execute(
        "SELECT rowid FROM document_search WHERE document_search MATCH ? ORDER BY rowid",
        ("lantern",),
    ).fetchall()


def exercise_transactions(connection: sqlite3.Connection) -> None:
    connection.execute("CREATE TABLE documents (id INTEGER PRIMARY KEY, body TEXT NOT NULL)")
    connection.execute("CREATE VIRTUAL TABLE document_search USING fts5(body)")
    with connection:
        connection.executemany("INSERT INTO documents VALUES (?, ?)", EXPECTED_ROWS)
        connection.execute(
            "INSERT INTO document_search(rowid, body) SELECT id, body FROM documents"
        )

    connection.execute("BEGIN")
    connection.execute("INSERT INTO documents VALUES (4, 'spare lantern')")
    connection.execute("INSERT INTO document_search(rowid, body) VALUES (4, 'spare lantern')")
    connection.rollback()


def write_fixture(path: Path) -> None:
    path.touch(exist_ok=False)
    try:
        with closing(sqlite3.connect(path)) as connection:
            exercise_transactions(connection)
            with connection:
                connection.execute("CREATE TABLE transaction_result (rows_json TEXT NOT NULL)")
                connection.execute(
                    "INSERT INTO transaction_result VALUES (?)",
                    (json.dumps(read_rows(connection), separators=(",", ":")),),
                )
    except sqlite3.Error:
        path.unlink(missing_ok=True)
        raise


def qualify(mode: str, path: Path, report: dict[str, str | bool]) -> None:
    report["version_ok"] = sqlite3.sqlite_version == EXPECTED_VERSIONS[mode]
    with closing(sqlite3.connect(":memory:")) as memory:
        fts5_enabled, session_enabled = memory.execute(
            "SELECT sqlite_compileoption_used('ENABLE_FTS5'), "
            "sqlite_compileoption_used('ENABLE_SESSION')"
        ).fetchone()
        report["fts5_enabled"] = bool(fts5_enabled)
        report["session_enabled"] = bool(session_enabled)
        if not (report["version_ok"] and report["fts5_enabled"] and report["session_enabled"]):
            return

        memory_ok = True
        if mode == "baseline":
            write_fixture(path)
        else:
            exercise_transactions(memory)
            memory_ok = (
                read_rows(memory) == EXPECTED_ROWS and read_matches(memory) == EXPECTED_MATCHES
            )

    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as fixture:
        report["rows_ok"] = read_rows(fixture) == EXPECTED_ROWS
        report["search_ok"] = read_matches(fixture) == EXPECTED_MATCHES
        report["integrity_ok"] = fixture.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        expected_export = json.dumps(EXPECTED_ROWS, separators=(",", ":"))
        report["transactions_ok"] = memory_ok and fixture.execute(
            "SELECT rows_json FROM transaction_result"
        ).fetchall() == [(expected_export,)]


def main() -> int:
    version = sqlite3.sqlite_version
    report: dict[str, str | bool] = {
        "sqlite_version": version if re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){2}", version) else "",
        "version_ok": False,
        "fts5_enabled": False,
        "session_enabled": False,
        "rows_ok": False,
        "search_ok": False,
        "integrity_ok": False,
        "transactions_ok": False,
    }
    if len(sys.argv) == 3 and sys.argv[1] in EXPECTED_VERSIONS:
        try:
            qualify(sys.argv[1], Path(sys.argv[2]), report)
        except (OSError, ValueError, sqlite3.Error):
            report["transactions_ok"] = False

    print(json.dumps(report, separators=(",", ":")))
    return 0 if all(report.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
