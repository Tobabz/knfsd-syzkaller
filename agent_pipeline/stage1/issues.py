"""A restart-safe ``IssueTracker``: one local issue per gap key (07 §3).

Status changes (``change``) are recorded as events.  The service passes
each undelivered event to ``Controller.on_issue`` and then marks it
delivered, so a change recorded by a one-shot command reaches a running
service, and one recorded before a crash is applied after restart.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from ..contracts import GapRef
from ..data import canonical_json

#: Statuses that close an issue; the gap appearing again opens a new one.
CLOSING = ("resolved", "wont_fix")
STATUSES = ("resolved", "deferred", "reopened", "wont_fix")


class UnknownIssue(KeyError):
    pass


class SqliteIssueTracker:
    """Keeps the gap-to-issue mapping and status events across restarts.

    Issues are local references (``gap-N``); filing them in an external
    tracker is a separate integration.
    """

    def __init__(self, path: Path | str) -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), isolation_level=None,
                                   check_same_thread=False, timeout=30)
        self._db.execute("PRAGMA busy_timeout = 30000")
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS issues (
                n INTEGER PRIMARY KEY AUTOINCREMENT,
                gap TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open');
            CREATE INDEX IF NOT EXISTS issues_gap ON issues (gap, status);
            CREATE TABLE IF NOT EXISTS links (
                n INTEGER NOT NULL, job_id TEXT NOT NULL,
                PRIMARY KEY (n, job_id));
            CREATE TABLE IF NOT EXISTS issue_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                n INTEGER NOT NULL,
                status TEXT NOT NULL,
                resolution TEXT NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0);
        """)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _tx(self, body):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = body()
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")
            return result

    def open_or_link(self, gap: GapRef, job_id: str) -> str:
        key = canonical_json(gap).decode()

        def body() -> int:
            row = self._db.execute(
                "SELECT n FROM issues WHERE gap = ? AND status NOT IN "
                "('resolved', 'wont_fix')", (key,)).fetchone()
            n = row[0] if row is not None else self._db.execute(
                "INSERT INTO issues (gap) VALUES (?)", (key,)).lastrowid
            self._db.execute("INSERT OR IGNORE INTO links VALUES (?, ?)",
                             (n, job_id))
            return n

        return f"gap-{self._tx(body)}"

    @staticmethod
    def _number(issue: str) -> int:
        if not issue.startswith("gap-") or not issue[4:].isdigit():
            raise UnknownIssue(issue)
        return int(issue[4:])

    def change(self, issue: str, status: str, resolution: str = "") -> GapRef:
        """Record a status change of ``gap-N`` for delivery to the jobs."""
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        n = self._number(issue)

        def body() -> str:
            row = self._db.execute("SELECT gap FROM issues WHERE n = ?",
                                   (n,)).fetchone()
            if row is None:
                raise UnknownIssue(issue)
            self._db.execute("UPDATE issues SET status = ? WHERE n = ?",
                             (status if status in CLOSING else "open", n))
            self._db.execute(
                "INSERT INTO issue_events (n, status, resolution) "
                "VALUES (?, ?, ?)", (n, status, resolution))
            return row[0]

        return GapRef.model_validate_json(self._tx(body))

    def pending_events(self) -> list[tuple[int, GapRef, str, str]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT e.id, i.gap, e.status, e.resolution FROM issue_events e "
                "JOIN issues i ON i.n = e.n WHERE e.delivered = 0 "
                "ORDER BY e.id").fetchall()
        return [(row[0], GapRef.model_validate_json(row[1]), row[2], row[3])
                for row in rows]

    def mark_delivered(self, event_id: int) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE issue_events SET delivered = 1 WHERE id = ?",
                (event_id,))

    def issues(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT n, gap, status FROM issues ORDER BY n").fetchall()
            links = self._db.execute("SELECT n, job_id FROM links").fetchall()
        jobs: dict[int, list[str]] = {}
        for n, job_id in links:
            jobs.setdefault(n, []).append(job_id)
        return [{"issue": f"gap-{n}", "gap": GapRef.model_validate_json(gap)
                 .model_dump(mode="json"), "status": status,
                 "jobs": sorted(jobs.get(n, []))} for n, gap, status in rows]
