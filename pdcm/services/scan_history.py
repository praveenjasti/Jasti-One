from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import sqlite3

from ..engines.cleaner_engine import CleanerScanResult


@dataclass(frozen=True)
class ScanHistoryEntry:
    scanned_at: str
    files_scanned: int
    directories_scanned: int
    bytes_scanned: int
    duplicate_groups: int
    duplicate_potential_bytes: int
    elapsed_seconds: float
    inaccessible_entries: int


def default_history_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / "JastiOne" / "scan_history.sqlite3"


class ScanHistory:
    """Persists aggregate scan metrics only; no file names or paths are stored."""

    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = Path(path) if path is not None else default_history_path()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY,
                scanned_at TEXT NOT NULL,
                files_scanned INTEGER NOT NULL,
                directories_scanned INTEGER NOT NULL,
                bytes_scanned INTEGER NOT NULL,
                duplicate_groups INTEGER NOT NULL,
                duplicate_potential_bytes INTEGER NOT NULL,
                elapsed_seconds REAL NOT NULL,
                inaccessible_entries INTEGER NOT NULL
            )
            """
        )
        return connection

    def record(self, result: CleanerScanResult) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scan_history (
                    scanned_at, files_scanned, directories_scanned, bytes_scanned,
                    duplicate_groups, duplicate_potential_bytes, elapsed_seconds,
                    inaccessible_entries
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now().astimezone().isoformat(timespec="seconds"),
                    result.files_scanned,
                    result.directories_scanned,
                    result.bytes_scanned,
                    len(result.duplicates),
                    result.duplicate_potential_bytes,
                    result.elapsed_seconds,
                    result.inaccessible_entries,
                ),
            )

    def recent(self, limit: int = 50) -> list[ScanHistoryEntry]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT scanned_at, files_scanned, directories_scanned, bytes_scanned,
                       duplicate_groups, duplicate_potential_bytes, elapsed_seconds,
                       inaccessible_entries
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(0, min(limit, 500)),),
            ).fetchall()
        return [ScanHistoryEntry(*row) for row in rows]
