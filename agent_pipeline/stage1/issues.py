"""A restart-safe ``IssueTracker``: one local issue per gap key (07 §3)."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from ..contracts import GapRef
from ..data import canonical_json


class SqliteIssueTracker:
    """Keeps the gap-to-issue mapping across Controller restarts.

    Issues are local references (``gap-N``); filing them in an external
    tracker is a separate integration.
    """

    def __init__(self, path: Path | str) -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), isolation_level=None,
                                   check_same_thread=False, timeout=30)
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS issues (
                n INTEGER PRIMARY KEY AUTOINCREMENT,
                gap TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'open');
            CREATE TABLE IF NOT EXISTS links (
                n INTEGER NOT NULL, job_id TEXT NOT NULL,
                PRIMARY KEY (n, job_id));
        """)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def open_or_link(self, gap: GapRef, job_id: str) -> str:
        key = canonical_json(gap).decode()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT n FROM issues WHERE gap = ? AND status = 'open'",
                    (key,)).fetchone()
                if row is None:
                    # A resolved gap that comes back opens a new issue.
                    self._db.execute("DELETE FROM issues WHERE gap = ?", (key,))
                    n = self._db.execute(
                        "INSERT INTO issues (gap) VALUES (?)", (key,)).lastrowid
                else:
                    n = row[0]
                self._db.execute("INSERT OR IGNORE INTO links VALUES (?, ?)",
                                 (n, job_id))
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")
        return f"gap-{n}"

    def resolve(self, gap: GapRef) -> None:
        with self._lock:
            self._db.execute("UPDATE issues SET status = 'resolved' WHERE gap = ?",
                             (canonical_json(gap).decode(),))
