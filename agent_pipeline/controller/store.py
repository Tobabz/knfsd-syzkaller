"""SQLite job store (09 §8).

One transition is one SQLite transaction: the Transition row, the Job row
and any verdicts it consumed commit together, and the job's sequence number
must still be the one the transition was computed from (a lost update is
refused, not merged).  Tasks are sent only after commit, by the service.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterator

from ..contracts import GapRef, JobPolicy, Q1Result, VulnerabilityCandidate
from .records import AgentAttempt, Job, JobState, Transition

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY, state TEXT NOT NULL, seq INTEGER NOT NULL,
    body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS transitions (
    job_id TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL,
    PRIMARY KEY (job_id, seq));
CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attempts (
    task_id TEXT NOT NULL, attempt INTEGER NOT NULL, job_id TEXT NOT NULL,
    body TEXT NOT NULL, PRIMARY KEY (task_id, attempt));
CREATE TABLE IF NOT EXISTS candidates (
    candidate_id TEXT PRIMARY KEY, target TEXT NOT NULL UNIQUE,
    body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS gap_issues (
    gap_class TEXT NOT NULL, missing_capability_id TEXT NOT NULL,
    issue_ref TEXT NOT NULL, PRIMARY KEY (gap_class, missing_capability_id));
CREATE TABLE IF NOT EXISTS gap_links (
    job_id TEXT NOT NULL, gap_class TEXT NOT NULL,
    missing_capability_id TEXT NOT NULL,
    PRIMARY KEY (job_id, gap_class, missing_capability_id));
CREATE TABLE IF NOT EXISTS effect_failures (
    job_id TEXT NOT NULL, effect TEXT NOT NULL, error TEXT NOT NULL,
    at TEXT NOT NULL);
"""


class StaleJob(Exception):
    """The job changed after the transition was computed."""


class Store:
    def __init__(self, path: Path | str) -> None:
        self.db = sqlite3.connect(str(path), isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def _tx(self):
        return _Tx(self.db)

    # ---------------------------------------------------------- policies

    def save_policy(self, policy: JobPolicy) -> None:
        with self._tx():
            row = self.db.execute("SELECT body FROM policies WHERE "
                                  "policy_id = ?",
                                  (policy.policy_id,)).fetchone()
            body = policy.model_dump_json()
            if row and row[0] != body:
                # A policy identity names one policy forever (01 §11.1).
                raise ValueError(f"policy {policy.policy_id} already exists "
                                 f"with other values")
            self.db.execute("INSERT OR IGNORE INTO policies VALUES (?, ?)",
                            (policy.policy_id, body))

    def policy(self, policy_id: str) -> JobPolicy:
        row = self.db.execute("SELECT body FROM policies WHERE policy_id = ?",
                              (policy_id,)).fetchone()
        if row is None:
            raise KeyError(policy_id)
        return JobPolicy.model_validate_json(row[0])

    # ---------------------------------------------------------- candidates

    def register_candidate(self, c: VulnerabilityCandidate
                           ) -> VulnerabilityCandidate:
        """Store an accepted candidate, or return the one already stored for
        the same target.  A candidate is immutable and one candidate can have
        many jobs, e.g. one per sanitizer (02 §7)."""
        target = c.model_dump_json(exclude={"candidate_id"})
        with self._tx():
            row = self.db.execute("SELECT body FROM candidates WHERE "
                                  "target = ?", (target,)).fetchone()
            if row:
                return VulnerabilityCandidate.model_validate_json(row[0])
            self.db.execute("INSERT INTO candidates VALUES (?, ?, ?)",
                            (c.candidate_id, target, c.model_dump_json()))
        return c

    def candidate(self, candidate_id: str) -> VulnerabilityCandidate:
        row = self.db.execute("SELECT body FROM candidates WHERE "
                              "candidate_id = ?", (candidate_id,)).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        return VulnerabilityCandidate.model_validate_json(row[0])

    def jobs_for(self, candidate_id: str) -> list[Job]:
        return [j for j in self.jobs()
                if j.candidate and j.candidate.candidate_id == candidate_id]

    # ---------------------------------------------------------- jobs

    def create(self, job: Job, transition: Transition) -> None:
        with self._tx():
            self.db.execute("INSERT INTO jobs VALUES (?, ?, ?, ?)",
                            (job.job_id, job.state.value, job.seq,
                             job.model_dump_json()))
            self._append(transition)

    def commit(self, prev_seq: int, job: Job, transition: Transition,
               verdicts: list[Q1Result] = ()) -> None:
        with self._tx():
            cur = self.db.execute("UPDATE jobs SET state = ?, seq = ?, "
                                  "body = ? WHERE job_id = ? AND seq = ?",
                                  (job.state.value, job.seq,
                                   job.model_dump_json(), job.job_id,
                                   prev_seq))
            if cur.rowcount != 1:
                raise StaleJob(job.job_id)
            # A job's issue link lasts while it waits on that gap; the same
            # gap later is a new wait that is linked again (07 §2).
            waiting = job.state in (JobState.BLOCKED_HARNESS_GAP,
                                    JobState.PARKED) and job.gap is not None
            self.db.execute(
                "DELETE FROM gap_links WHERE job_id = ? AND NOT "
                "(? AND gap_class = ? AND missing_capability_id = ?)",
                (job.job_id, waiting,
                 job.gap.gap_class.value if waiting else "",
                 job.gap.missing_capability_id if waiting else ""))
            self._append(transition)
            for v in verdicts:
                self.db.execute("INSERT OR IGNORE INTO verdicts VALUES "
                                "(?, ?, ?)", (v.verdict_id, job.job_id,
                                              v.model_dump_json()))

    def _append(self, t: Transition) -> None:
        self.db.execute("INSERT INTO transitions VALUES (?, ?, ?)",
                        (t.job_id, t.seq, t.model_dump_json()))

    def job(self, job_id: str) -> Job:
        row = self.db.execute("SELECT body FROM jobs WHERE job_id = ?",
                              (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        return Job.model_validate_json(row[0])

    def jobs(self, states: set[JobState] | None = None) -> Iterator[Job]:
        rows = self.db.execute("SELECT body FROM jobs ORDER BY job_id"
                               ).fetchall()
        for (body,) in rows:
            j = Job.model_validate_json(body)
            if states is None or j.state in states:
                yield j

    def transitions(self, job_id: str) -> list[Transition]:
        rows = self.db.execute("SELECT body FROM transitions WHERE "
                               "job_id = ? ORDER BY seq",
                               (job_id,)).fetchall()
        return [Transition.model_validate_json(b) for (b,) in rows]

    def verdicts(self, job_id: str) -> list[Q1Result]:
        rows = self.db.execute("SELECT body FROM verdicts WHERE job_id = ? "
                               "ORDER BY rowid", (job_id,)).fetchall()
        return [Q1Result.model_validate_json(b) for (b,) in rows]

    # ---------------------------------------------------------- attempts

    def save_attempt(self, a: AgentAttempt) -> None:
        with self._tx():
            self.db.execute("INSERT OR REPLACE INTO attempts VALUES "
                            "(?, ?, ?, ?)", (a.task_id, a.attempt, a.job_id,
                                             a.model_dump_json()))

    def attempt(self, task_id: str, attempt: int) -> AgentAttempt | None:
        row = self.db.execute("SELECT body FROM attempts WHERE task_id = ? "
                              "AND attempt = ?", (task_id, attempt)
                              ).fetchone()
        return AgentAttempt.model_validate_json(row[0]) if row else None

    def attempts(self, job_id: str) -> list[AgentAttempt]:
        rows = self.db.execute("SELECT body FROM attempts WHERE job_id = ? "
                               "ORDER BY rowid", (job_id,)).fetchall()
        return [AgentAttempt.model_validate_json(b) for (b,) in rows]

    # ---------------------------------------------------------- gap issues

    def link_issue(self, gap: GapRef, issue_ref: str,
                   job_id: str | None = None) -> None:
        """The gap's issue, and that `job_id` is linked to it."""
        with self._tx():
            self.db.execute("INSERT OR REPLACE INTO gap_issues VALUES "
                            "(?, ?, ?)", (gap.gap_class.value,
                                          gap.missing_capability_id,
                                          issue_ref))
            if job_id is not None:
                self.db.execute("INSERT OR IGNORE INTO gap_links VALUES "
                                "(?, ?, ?)", (job_id, gap.gap_class.value,
                                              gap.missing_capability_id))

    def record_failure(self, job_id: str, effect: str, error: str,
                       at: str) -> None:
        """A side effect sent after commit failed; it stays due and is sent
        again by poll() or recover()."""
        with self._tx():
            self.db.execute("INSERT INTO effect_failures (job_id, effect, "
                            "error, at) VALUES (?, ?, ?, ?)",
                            (job_id, effect, error, at))

    def effect_failures(self, job_id: str | None = None
                        ) -> list[tuple[str, str, str, str]]:
        q = "SELECT job_id, effect, error, at FROM effect_failures"
        args: tuple = ()
        if job_id is not None:
            q += " WHERE job_id = ?"
            args = (job_id,)
        return self.db.execute(q + " ORDER BY rowid", args).fetchall()

    def is_linked(self, job_id: str, gap: GapRef) -> bool:
        return self.db.execute(
            "SELECT 1 FROM gap_links WHERE job_id = ? AND gap_class = ? AND "
            "missing_capability_id = ?", (job_id, gap.gap_class.value,
                                          gap.missing_capability_id)
        ).fetchone() is not None

    def issue_ref(self, gap: GapRef) -> str | None:
        row = self.db.execute("SELECT issue_ref FROM gap_issues WHERE "
                              "gap_class = ? AND missing_capability_id = ?",
                              (gap.gap_class.value,
                               gap.missing_capability_id)).fetchone()
        return row[0] if row else None


class _Tx:
    """BEGIN IMMEDIATE ... COMMIT, rolled back on any exception."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    def __enter__(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    def __exit__(self, exc_type, exc, tb):
        self.db.execute("ROLLBACK" if exc_type else "COMMIT")
        return False
