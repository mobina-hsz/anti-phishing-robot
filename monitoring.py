"""Small SQLite event history and cumulative counters for private admin commands."""

import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from analyzer.models import ScanResult


class Monitor:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                host TEXT NOT NULL,
                status TEXT NOT NULL,
                phishing TEXT NOT NULL,
                keylogger TEXT NOT NULL,
                elapsed_ms INTEGER NOT NULL,
                errors TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS counters (
                name TEXT PRIMARY KEY, value INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS scans_created ON scans(created_at);
        """)
        self.db.commit()

    def record(self, result: ScanResult):
        try:
            host = (urlsplit(result.url).hostname or "invalid")[:253]
        except ValueError:
            host = "invalid"
        with self.db:
            self.db.execute(
                "INSERT INTO scans (host, status, phishing, keylogger, elapsed_ms, errors) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    host,
                    result.status.value,
                    result.phishing.status.value,
                    result.keylogger.status.value,
                    result.elapsed_ms,
                    ",".join(result.errors),
                ),
            )
            for name, amount in (
                ("total", 1),
                (result.status.value, 1),
                ("elapsed_ms", result.elapsed_ms),
                ("errors", int(bool(result.errors))),
            ):
                self.db.execute(
                    "INSERT INTO counters VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
                    (name, amount),
                )
            self.db.execute(
                "DELETE FROM scans WHERE id <= (SELECT COALESCE(MAX(id), 0) - 10000 FROM scans)"
            )

    def summary(self) -> dict:
        values = dict(self.db.execute("SELECT name, value FROM counters").fetchall())
        for key in ("total", "suspicious", "not_detected", "inconclusive", "errors", "elapsed_ms"):
            values.setdefault(key, 0)
        values["average_ms"] = values["elapsed_ms"] // max(values["total"], 1)
        values["retained"] = self.db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        return values

    def recent(self, errors_only: bool = False) -> list[dict]:
        where = "WHERE errors <> ''" if errors_only else ""
        rows = self.db.execute(f"SELECT * FROM scans {where} ORDER BY id DESC LIMIT 10").fetchall()
        return [dict(row) for row in rows]

    def close(self):
        self.db.close()
