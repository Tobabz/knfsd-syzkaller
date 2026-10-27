"""SQLite job store (09 §8).

One transition is one SQLite transaction: the Transition row, the Job row
and any verdicts it consumed commit together, and the job's sequence number
must still be the one the transition was computed from (a lost update is
refused, not merged).  Tasks are sent only after commit, by the service.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterator

from ..contracts import (GapRef, JobPolicy, JudgeVersions, Q1Result,
                         Sanitizer, VulnerabilityCandidate)
from .generation import (GenerationState, GenerationTransition,
                         HarnessGeneration)
from .promotion import (HarnessPromotion, PromotionState,
                        PromotionTransition)
from .records import (GAP_STATES, AgentAttempt, Job, JobState,
                      Transition)

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
CREATE TABLE IF NOT EXISTS job_issues (
    job_id TEXT PRIMARY KEY, issue_ref TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS issue_marks (
    job_id TEXT PRIMARY KEY, event_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS controller_settings (
    key TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS generations (
    generation_id TEXT PRIMARY KEY, gap_class TEXT NOT NULL,
    missing_capability_id TEXT NOT NULL, kernel_commit TEXT NOT NULL,
    sanitizer TEXT NOT NULL, state TEXT NOT NULL, seq INTEGER NOT NULL,
    body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS generation_transitions (
    generation_id TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL,
    PRIMARY KEY (generation_id, seq));
CREATE TABLE IF NOT EXISTS promotions (
    promotion_id TEXT PRIMARY KEY, generation_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS promotion_transitions (
    promotion_id TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL,
    PRIMARY KEY (promotion_id, seq));
CREATE TABLE IF NOT EXISTS effect_failures (
    job_id TEXT NOT NULL, effect TEXT NOT NULL, error TEXT NOT NULL,
    at TEXT NOT NULL);
"""


class StaleJob(Exception):
    """The job changed after the transition was computed."""


class StaleIssueEvent(StaleJob):
    """The job already took this issue event or a later one."""


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
            # Compared as values: a policy stored before a field with a
            # default existed is still the same policy (01 §11.1).  One
            # stored before Harness Generation keeps it off (_load_policy),
            # also when the same policy is given again without the field.
            if row and _legacy_generation(row[0]) and \
                    "harness_generation_budget" not in policy.model_fields_set:
                policy = policy.model_copy(
                    update={"harness_generation_budget": 0})
            if row and _load_policy(row[0]) != policy:
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
        return _load_policy(row[0])

    # ---------------------------------------------------------- judge

    def save_judge_versions(self, versions: JudgeVersions) -> None:
        """The fallback Q1 authorities the Controller adopted (09 §5)."""
        with self._tx():
            self.db.execute(
                "INSERT OR REPLACE INTO controller_settings VALUES (?, ?)",
                ("judge_versions", versions.model_dump_json()))

    def judge_versions(self) -> JudgeVersions | None:
        row = self.db.execute("SELECT body FROM controller_settings WHERE "
                              "key = 'judge_versions'").fetchone()
        return None if row is None else \
            JudgeVersions.model_validate_json(row[0])

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
               verdicts: list[Q1Result] = (),
               issue_event: int | None = None) -> None:
        """``issue_event``: the issue event this transition applies.  It is
        recorded with the transition, and refused when the job already took
        it or a later one, so concurrent deliverers apply it once, in order."""
        with self._tx():
            if issue_event is not None:
                mark = self._issue_mark(job.job_id)
                if mark is not None and mark >= issue_event:
                    raise StaleIssueEvent(job.job_id)
                self.db.execute("INSERT OR REPLACE INTO issue_marks VALUES "
                                "(?, ?)", (job.job_id, issue_event))
            cur = self.db.execute("UPDATE jobs SET state = ?, seq = ?, "
                                  "body = ? WHERE job_id = ? AND seq = ?",
                                  (job.state.value, job.seq,
                                   job.model_dump_json(), job.job_id,
                                   prev_seq))
            if cur.rowcount != 1:
                raise StaleJob(job.job_id)
            # A job's issue link lasts while it waits on that gap; the same
            # gap later is a new wait that is linked again (07 §2).
            waiting = job.state in GAP_STATES and job.gap is not None
            self.db.execute(
                "DELETE FROM gap_links WHERE job_id = ? AND NOT "
                "(? AND gap_class = ? AND missing_capability_id = ?)",
                (job.job_id, waiting,
                 job.gap.gap_class.value if waiting else "",
                 job.gap.missing_capability_id if waiting else ""))
            self.db.execute(
                "DELETE FROM job_issues WHERE job_id = ? AND NOT EXISTS "
                "(SELECT 1 FROM gap_links WHERE job_id = ?)",
                (job.job_id, job.job_id))
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

    # ---------------------------------------------------------- generations

    def create_generation(self, g: HarnessGeneration,
                          transition: GenerationTransition,
                          after: str | None) -> HarnessGeneration:
        """Store `g` as the latest generation of its key, only while the
        latest one is still `after` (None: there is none).  Otherwise the
        latest one is returned: another job started it first (09 §3.2)."""
        with self._tx():
            latest = self._latest_generation(g.gap, g.kernel_commit,
                                             g.sanitizer)
            if (latest.generation_id if latest else None) != after:
                return latest
            self.db.execute(
                "INSERT INTO generations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (g.generation_id, g.gap.gap_class.value,
                 g.gap.missing_capability_id, g.kernel_commit,
                 g.sanitizer.value, g.state.value, g.seq,
                 g.model_dump_json()))
            self._append_generation(transition)
        return g

    def commit_generation(self, prev_seq: int, g: HarnessGeneration,
                          transition: GenerationTransition) -> None:
        with self._tx():
            cur = self.db.execute(
                "UPDATE generations SET state = ?, seq = ?, body = ? "
                "WHERE generation_id = ? AND seq = ?",
                (g.state.value, g.seq, g.model_dump_json(),
                 g.generation_id, prev_seq))
            if cur.rowcount != 1:
                raise StaleJob(g.generation_id)
            self._append_generation(transition)

    def _append_generation(self, t: GenerationTransition) -> None:
        self.db.execute("INSERT INTO generation_transitions VALUES "
                        "(?, ?, ?)", (t.generation_id, t.seq,
                                      t.model_dump_json()))

    def generation(self, generation_id: str) -> HarnessGeneration:
        row = self.db.execute("SELECT body FROM generations WHERE "
                              "generation_id = ?",
                              (generation_id,)).fetchone()
        if row is None:
            raise KeyError(generation_id)
        return HarnessGeneration.model_validate_json(row[0])

    def _latest_generation(self, gap: GapRef, kernel_commit: str,
                           sanitizer: Sanitizer
                           ) -> HarnessGeneration | None:
        row = self.db.execute(
            "SELECT body FROM generations WHERE gap_class = ? AND "
            "missing_capability_id = ? AND kernel_commit = ? AND "
            "sanitizer = ? ORDER BY rowid DESC LIMIT 1",
            (gap.gap_class.value, gap.missing_capability_id, kernel_commit,
             sanitizer.value)).fetchone()
        return HarnessGeneration.model_validate_json(row[0]) if row else None

    def latest_generation(self, gap: GapRef, kernel_commit: str,
                          sanitizer: Sanitizer) -> HarnessGeneration | None:
        """The gap key's latest generation for that build key."""
        return self._latest_generation(gap, kernel_commit, sanitizer)

    def generations(self, states: set[GenerationState] | None = None
                    ) -> list[HarnessGeneration]:
        rows = self.db.execute("SELECT body FROM generations ORDER BY rowid"
                               ).fetchall()
        out = [HarnessGeneration.model_validate_json(b) for (b,) in rows]
        return [g for g in out if states is None or g.state in states]

    def generation_transitions(self, generation_id: str
                               ) -> list[GenerationTransition]:
        rows = self.db.execute("SELECT body FROM generation_transitions "
                               "WHERE generation_id = ? ORDER BY seq",
                               (generation_id,)).fetchall()
        return [GenerationTransition.model_validate_json(b) for (b,) in rows]

    # ---------------------------------------------------------- promotions

    def create_promotion(self, p: HarnessPromotion,
                         transition: PromotionTransition) -> HarnessPromotion:
        """Store `p` unless its generation has a promotion; returns the
        stored one."""
        with self._tx():
            cur = self.db.execute(
                "INSERT OR IGNORE INTO promotions VALUES (?, ?, ?, ?, ?)",
                (p.promotion_id, p.generation_id, p.state.value, p.seq,
                 p.model_dump_json()))
            if cur.rowcount == 1:
                self._append_promotion(transition)
        return self.promotion_for(p.generation_id)

    def commit_promotion(self, prev_seq: int, p: HarnessPromotion,
                         transition: PromotionTransition) -> None:
        with self._tx():
            cur = self.db.execute(
                "UPDATE promotions SET state = ?, seq = ?, body = ? "
                "WHERE promotion_id = ? AND seq = ?",
                (p.state.value, p.seq, p.model_dump_json(), p.promotion_id,
                 prev_seq))
            if cur.rowcount != 1:
                raise StaleJob(p.promotion_id)
            self._append_promotion(transition)

    def _append_promotion(self, t: PromotionTransition) -> None:
        self.db.execute("INSERT INTO promotion_transitions VALUES (?, ?, ?)",
                        (t.promotion_id, t.seq, t.model_dump_json()))

    def promotion(self, promotion_id: str) -> HarnessPromotion:
        row = self.db.execute("SELECT body FROM promotions WHERE "
                              "promotion_id = ?", (promotion_id,)).fetchone()
        if row is None:
            raise KeyError(promotion_id)
        return HarnessPromotion.model_validate_json(row[0])

    def promotion_for(self, generation_id: str) -> HarnessPromotion | None:
        row = self.db.execute("SELECT body FROM promotions WHERE "
                              "generation_id = ?", (generation_id,)).fetchone()
        return HarnessPromotion.model_validate_json(row[0]) if row else None

    def promotions(self, states: set[PromotionState] | None = None
                   ) -> list[HarnessPromotion]:
        rows = self.db.execute("SELECT body FROM promotions ORDER BY rowid"
                               ).fetchall()
        out = [HarnessPromotion.model_validate_json(b) for (b,) in rows]
        return [p for p in out if states is None or p.state in states]

    def promotion_transitions(self, promotion_id: str
                              ) -> list[PromotionTransition]:
        rows = self.db.execute("SELECT body FROM promotion_transitions "
                               "WHERE promotion_id = ? ORDER BY seq",
                               (promotion_id,)).fetchall()
        return [PromotionTransition.model_validate_json(b) for (b,) in rows]

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
                self.db.execute("INSERT OR REPLACE INTO job_issues VALUES "
                                "(?, ?)", (job_id, issue_ref))

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

    def job_issue(self, job_id: str) -> str | None:
        """The issue of the job's current gap wait, or None when the wait is
        not linked yet.  A link stored before per-job issues existed falls
        back to the gap's issue."""
        row = self.db.execute("SELECT issue_ref FROM job_issues WHERE "
                              "job_id = ?", (job_id,)).fetchone()
        if row is not None:
            return row[0]
        row = self.db.execute(
            "SELECT i.issue_ref FROM gap_links l JOIN gap_issues i ON "
            "i.gap_class = l.gap_class AND "
            "i.missing_capability_id = l.missing_capability_id "
            "WHERE l.job_id = ?", (job_id,)).fetchone()
        return row[0] if row else None

    def _issue_mark(self, job_id: str) -> int | None:
        row = self.db.execute("SELECT event_id FROM issue_marks WHERE "
                              "job_id = ?", (job_id,)).fetchone()
        return row[0] if row else None

    def issue_mark(self, job_id: str) -> int | None:
        """The last issue event the job took, if any."""
        return self._issue_mark(job_id)

    def issue_ref(self, gap: GapRef) -> str | None:
        row = self.db.execute("SELECT issue_ref FROM gap_issues WHERE "
                              "gap_class = ? AND missing_capability_id = ?",
                              (gap.gap_class.value,
                               gap.missing_capability_id)).fetchone()
        return row[0] if row else None


def _legacy_generation(body: str) -> bool:
    return "harness_generation_budget" not in json.loads(body)


def _load_policy(body: str) -> JobPolicy:
    """A policy stored before harness_generation_budget existed keeps
    Harness Generation off, so its jobs replay the transitions they made
    (09 §3.2, §8).  A policy stored since carries the field."""
    policy = JobPolicy.model_validate_json(body)
    if _legacy_generation(body):
        policy = policy.model_copy(update={"harness_generation_budget": 0})
    return policy


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
