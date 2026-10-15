"""SQLite-backed implementation of the Controller's Runner protocol.

This module owns durable orchestration only.  It does not execute programs,
seal evidence, or produce Q1/Q2 verdicts.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from ..controller.tasks import (CLEANUP_UNCONFIRMED, RunnerInput, RunnerStatus, SubmitRefused,
                                runner_input_digest)
from ..data import canonical_json, parse_json
from .models import (
    AttemptFact,
    BackendResult,
    CompletionReceipt,
    RecoverableTask,
    TaskBinding,
    TaskFacts,
    WorkLease,
)


EXECUTOR_ENDED_UNSEALED = "executor_ended_without_bundle"
BACKEND_ERROR = "backend_error"
#: 09 §8: an execution whose worker stopped renewing its lease is not run
#: again; the Controller charges the Runner retry budget for it.
RUNNER_RESTART = "runner_restart"
CANCELLED = "cancelled"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runner_tasks (
    submission_order INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL UNIQUE,
    input_json BLOB,
    input_sha256 TEXT,
    job_id TEXT,
    harness_ref TEXT,
    execution_harness_id TEXT,
    lifecycle TEXT NOT NULL CHECK (
        lifecycle IN ('queued', 'leased', 'sealed', 'ended_unsealed')),
    lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_worker_id TEXT,
    lease_token TEXT,
    lease_claimed_at_ns INTEGER,
    lease_expires_at_ns INTEGER,
    cancel_requested_at_ns INTEGER,
    cancel_completed_at_ns INTEGER,
    cancel_disposition TEXT CHECK (
        cancel_disposition IS NULL OR cancel_disposition IN
        ('cancelled', 'already_sealed', 'already_ended_unsealed')),
    final_bundle_ref TEXT,
    final_reason TEXT,
    receipt_json BLOB,
    receipt_sha256 TEXT,
    created_at_ns INTEGER NOT NULL,
    updated_at_ns INTEGER NOT NULL,
    CHECK ((lifecycle = 'sealed' AND final_bundle_ref IS NOT NULL
            AND final_reason IS NULL)
           OR lifecycle != 'sealed'),
    CHECK ((lifecycle = 'ended_unsealed' AND final_bundle_ref IS NULL
            AND final_reason IS NOT NULL)
           OR lifecycle != 'ended_unsealed'),
    CHECK ((lifecycle IN ('queued', 'leased') AND final_bundle_ref IS NULL
            AND final_reason IS NULL AND receipt_json IS NULL
            AND receipt_sha256 IS NULL)
           OR lifecycle NOT IN ('queued', 'leased')),
    CHECK ((lifecycle = 'leased' AND lease_worker_id IS NOT NULL
            AND lease_token IS NOT NULL AND lease_claimed_at_ns IS NOT NULL
            AND lease_expires_at_ns IS NOT NULL)
           OR lifecycle != 'leased')
);
CREATE TABLE IF NOT EXISTS runner_attempts (
    task_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    worker_id TEXT NOT NULL,
    token TEXT NOT NULL,
    claimed_at_ns INTEGER NOT NULL,
    expires_at_ns INTEGER NOT NULL,
    finished_at_ns INTEGER,
    outcome TEXT NOT NULL CHECK (outcome IN
        ('active', 'lease_expired', 'sealed', 'ended_unsealed', 'cancelled')),
    bundle_ref TEXT,
    reason TEXT,
    PRIMARY KEY (task_id, generation),
    FOREIGN KEY (task_id) REFERENCES runner_tasks(task_id)
);
CREATE INDEX IF NOT EXISTS runner_claimable
    ON runner_tasks(lifecycle, lease_expires_at_ns, submission_order);
"""


class LeaseLost(RuntimeError):
    """A worker no longer owns the task generation it tried to update."""


class RunnerDataError(RuntimeError):
    """Durable Runner data failed an internal integrity check."""


class DurableRunner:
    """Restart-safe Runner and work queue backed by one SQLite database.

    ``submit``, ``cancel``, claims, renewals, and completions acknowledge only
    after their ``BEGIN IMMEDIATE`` transaction commits.  Multiple instances
    may point at the same database; SQLite serializes competing transitions.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        clock: Callable[[], int] = time.time_ns,
        lease_duration_ns: int = 60_000_000_000,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        if type(lease_duration_ns) is not int or lease_duration_ns < 1:
            raise ValueError("lease_duration_ns must be a positive integer")
        self._clock = clock
        self._lease_duration_ns = lease_duration_ns
        self._token_factory = token_factory or (lambda: secrets.token_hex(32))
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            str(path),
            isolation_level=None,
            check_same_thread=False,
            timeout=30,
        )
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA busy_timeout = 30000")
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise ValueError("clock must return a non-negative signed 64-bit integer")
        return value

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    @staticmethod
    def _task_id(value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError("invalid task_id")
        if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("invalid task_id")
        return value

    @staticmethod
    def _worker_id(value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError("invalid worker_id")
        if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("invalid worker_id")
        return value

    @staticmethod
    def _canonical_input(task_input: RunnerInput) -> tuple[RunnerInput, bytes, str]:
        value = RunnerInput.model_validate(task_input)
        raw = canonical_json(value)
        return value, raw, runner_input_digest(value)

    @staticmethod
    def _load_input(row: sqlite3.Row) -> RunnerInput:
        raw_value = row["input_json"]
        if raw_value is None:
            raise RunnerDataError("cancel-before-submit tombstone has no task input")
        raw = bytes(raw_value)
        try:
            parse_json(raw)
            value = RunnerInput.model_validate_json(raw)
        except (ValueError, TypeError, UnicodeError) as exc:
            raise RunnerDataError("stored task input is invalid") from exc
        if canonical_json(value) != raw:
            raise RunnerDataError("stored task input is not canonical")
        if runner_input_digest(value) != row["input_sha256"]:
            raise RunnerDataError("stored task input digest mismatch")
        if (
            value.job_id != row["job_id"]
            or value.harness_ref != row["harness_ref"]
            or value.execution_harness_id != row["execution_harness_id"]
        ):
            raise RunnerDataError("stored task input binding mismatch")
        return value

    @staticmethod
    def _status(row: sqlite3.Row | None) -> RunnerStatus:
        if row is None:
            return RunnerStatus(state="unknown")
        lifecycle = row["lifecycle"]
        if lifecycle in ("queued", "leased"):
            return RunnerStatus(state="running")
        if lifecycle == "sealed":
            bundle = row["final_bundle_ref"]
            if not bundle:
                raise RunnerDataError("sealed task has no bundle reference")
            return RunnerStatus(state="sealed", bundles=(bundle,))
        if lifecycle == "ended_unsealed":
            reason = row["final_reason"]
            if not reason:
                raise RunnerDataError("unsealed task has no reason")
            return RunnerStatus(state="ended_unsealed", reason=reason)
        raise RunnerDataError(f"unknown task lifecycle: {lifecycle!r}")

    @staticmethod
    def _binding(row: sqlite3.Row) -> TaskBinding:
        return TaskBinding(
            task_id=row["task_id"],
            job_id=row["job_id"],
            harness_ref=row["harness_ref"],
            execution_harness_id=row["execution_harness_id"],
        )

    def _row(self, task_id: str) -> sqlite3.Row | None:
        return self._db.execute(
            "SELECT * FROM runner_tasks WHERE task_id = ?", (task_id,)
        ).fetchone()

    # ------------------------------------------------ Controller protocol

    def submit(self, task_id: str, task_input: RunnerInput) -> RunnerStatus:
        task_id = self._task_id(task_id)
        task_input, raw, digest = self._canonical_input(task_input)
        # RunnerInput predates this production boundary and intentionally has
        # unconstrained strings.  Validate every persisted execution binding
        # before opening the transaction so an unclaimable row is never
        # admitted to the queue.
        binding = TaskBinding(
            task_id=task_id,
            job_id=task_input.job_id,
            harness_ref=task_input.harness_ref,
            execution_harness_id=task_input.execution_harness_id,
        )
        with self._transaction():
            now = self._now()
            row = self._row(task_id)
            if row is None:
                self._db.execute(
                    """INSERT INTO runner_tasks (
                        task_id, input_json, input_sha256, job_id, harness_ref,
                        execution_harness_id, lifecycle, created_at_ns,
                        updated_at_ns) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)""",
                    (
                        task_id,
                        raw,
                        digest,
                        binding.job_id,
                        binding.harness_ref,
                        binding.execution_harness_id,
                        now,
                        now,
                    ),
                )
                row = self._row(task_id)
            else:
                stored = row["input_json"]
                if stored is None:
                    raise SubmitRefused(f"task {task_id} was cancelled before submit")
                if bytes(stored) != raw:
                    raise SubmitRefused(f"task {task_id} already has different input")
                self._load_input(row)
                if row["cancel_disposition"] == "cancelled":
                    raise SubmitRefused(f"task {task_id} was cancelled")
            status = self._status(row)
        return status

    def status(self, task_id: str) -> RunnerStatus:
        task_id = self._task_id(task_id)
        with self._lock:
            row = self._row(task_id)
            if row is not None and row["lifecycle"] == "leased" and \
                    row["lease_expires_at_ns"] <= self._now():
                with self._transaction():
                    self._end_expired_leases(self._now())
                    row = self._row(task_id)
            return self._status(row)

    def cancel(self, task_id: str) -> RunnerStatus:
        task_id = self._task_id(task_id)
        with self._transaction():
            now = self._now()
            self._end_expired_leases(now)
            row = self._row(task_id)
            if row is None:
                self._db.execute(
                    """INSERT INTO runner_tasks (
                        task_id, lifecycle, cancel_requested_at_ns,
                        cancel_completed_at_ns, cancel_disposition,
                        final_reason, created_at_ns, updated_at_ns)
                       VALUES (?, 'ended_unsealed', ?, ?, 'cancelled',
                               'cancelled', ?, ?)""",
                    (task_id, now, now, now, now),
                )
                row = self._row(task_id)
            elif row["cancel_requested_at_ns"] is None:
                lifecycle = row["lifecycle"]
                if lifecycle == "leased":
                    # 09 §8: cancel answers a final status only once the
                    # execution stopped.  The worker sees the request through
                    # stop_requested() and completes as cancelled.
                    self._db.execute(
                        """UPDATE runner_tasks SET cancel_requested_at_ns = ?,
                            updated_at_ns = ? WHERE task_id = ?""",
                        (now, now, task_id),
                    )
                elif lifecycle == "queued":
                    self._db.execute(
                        """UPDATE runner_tasks SET cancel_requested_at_ns = ?
                           WHERE task_id = ?""", (now, task_id))
                    self._end_unsealed(self._row(task_id), CANCELLED, now)
                else:
                    disposition = (
                        "already_sealed"
                        if lifecycle == "sealed"
                        else "already_ended_unsealed"
                    )
                    self._db.execute(
                        """UPDATE runner_tasks SET cancel_requested_at_ns = ?,
                            cancel_completed_at_ns = ?, cancel_disposition = ?,
                            updated_at_ns = ? WHERE task_id = ?""",
                        (now, now, disposition, now, task_id),
                    )
                row = self._row(task_id)
            status = self._status(row)
        return status

    # ------------------------------------------------ worker queue

    def recoverable(self) -> tuple[RecoverableTask, ...]:
        """Return tasks claimable now in stable submission order."""

        with self._lock:
            rows = self._db.execute(
                """SELECT task_id, submission_order, lifecycle,
                          lease_generation
                   FROM runner_tasks
                   WHERE cancel_requested_at_ns IS NULL AND
                       lifecycle = 'queued'
                   ORDER BY submission_order""",
            ).fetchall()
        return tuple(
            RecoverableTask(
                task_id=row["task_id"],
                submission_order=row["submission_order"],
                next_generation=row["lease_generation"] + 1,
                reclaiming_expired_lease=row["lifecycle"] == "leased",
            )
            for row in rows
        )

    def claim(self, worker_id: str) -> WorkLease | None:
        worker_id = self._worker_id(worker_id)
        with self._transaction():
            # Lock contention can outlast a lease. Take all lease timestamps
            # only once both the process lock and SQLite write lock are held.
            now = self._now()
            expires = now + self._lease_duration_ns
            if expires > 2**63 - 1:
                raise ValueError("lease expiry exceeds signed 64-bit range")
            self._end_expired_leases(now)
            row = self._db.execute(
                """SELECT * FROM runner_tasks
                   WHERE cancel_requested_at_ns IS NULL AND
                       lifecycle = 'queued'
                   ORDER BY submission_order LIMIT 1""",
            ).fetchone()
            if row is None:
                return None
            task_input = self._load_input(row)
            generation = row["lease_generation"] + 1
            token = self._token_factory()
            # HostRecord performs the authoritative token validation before
            # any value is committed.
            lease = WorkLease(
                binding=self._binding(row),
                task_input=task_input,
                generation=generation,
                worker_id=worker_id,
                token=token,
                claimed_at_ns=now,
                expires_at_ns=expires,
            )
            self._db.execute(
                """UPDATE runner_tasks SET lifecycle = 'leased',
                    lease_generation = ?, lease_worker_id = ?, lease_token = ?,
                    lease_claimed_at_ns = ?, lease_expires_at_ns = ?,
                    updated_at_ns = ? WHERE task_id = ?""",
                (
                    generation,
                    worker_id,
                    token,
                    now,
                    expires,
                    now,
                    row["task_id"],
                ),
            )
            self._db.execute(
                """INSERT INTO runner_attempts (
                    task_id, generation, worker_id, token, claimed_at_ns,
                    expires_at_ns, outcome) VALUES (?, ?, ?, ?, ?, ?, 'active')""",
                (
                    row["task_id"],
                    generation,
                    worker_id,
                    token,
                    now,
                    expires,
                ),
            )
        return lease

    def renew(self, lease: WorkLease) -> WorkLease:
        lease = WorkLease.model_validate(lease)
        with self._transaction():
            now = self._now()
            row = self._row(lease.binding.task_id)
            self._require_current_lease(row, lease, now)
            # A heartbeat guarantees one lease window from "now" without
            # letting rapid renewals accumulate an arbitrarily distant expiry.
            expires = max(
                row["lease_expires_at_ns"], now + self._lease_duration_ns
            )
            if expires > 2**63 - 1:
                raise ValueError("lease expiry exceeds signed 64-bit range")
            self._db.execute(
                """UPDATE runner_tasks SET lease_expires_at_ns = ?,
                    updated_at_ns = ? WHERE task_id = ?""",
                (expires, now, lease.binding.task_id),
            )
            self._db.execute(
                """UPDATE runner_attempts SET expires_at_ns = ?
                   WHERE task_id = ? AND generation = ?""",
                (expires, lease.binding.task_id, lease.generation),
            )
        return lease.model_copy(update={"expires_at_ns": expires})

    def stop_unconfirmed(self, lease: WorkLease) -> None:
        """Record that this lease's execution could not be confirmed
        stopped.  The task then ends ``cleanup_unconfirmed`` at lease
        expiry, not ``cancelled`` or ``runner_restart``."""

        lease = WorkLease.model_validate(lease)
        with self._transaction():
            now = self._now()
            row = self._row(lease.binding.task_id)
            self._require_current_lease(row, lease, now, allow_cancel=True)
            self._db.execute(
                """UPDATE runner_attempts SET reason = ?
                   WHERE task_id = ? AND generation = ?
                     AND outcome = 'active'""",
                (CLEANUP_UNCONFIRMED, lease.binding.task_id, lease.generation),
            )

    def stop_requested(self, lease: WorkLease) -> bool:
        """True for cancellation, expiry, reclaim, or any lost ownership."""

        lease = WorkLease.model_validate(lease)
        with self._lock:
            now = self._now()
            row = self._row(lease.binding.task_id)
            try:
                self._require_current_lease(row, lease, now)
            except LeaseLost:
                return True
            return False

    def complete(self, lease: WorkLease, result: BackendResult) -> RunnerStatus:
        lease = WorkLease.model_validate(lease)
        result = BackendResult.model_validate(result)
        with self._transaction():
            now = self._now()
            row = self._row(lease.binding.task_id)
            self._require_current_lease(row, lease, now, allow_cancel=True)
            if row["cancel_requested_at_ns"] is not None:
                # The execution stopped after cancel(): settle the cancel.
                self._end_unsealed(row, CANCELLED, now)
                return self._status(self._row(lease.binding.task_id))
            if result.bundle_ref is not None:
                lifecycle = "sealed"
                bundle_ref = result.bundle_ref
                reason = None
            else:
                lifecycle = "ended_unsealed"
                bundle_ref = None
                reason = result.reason
            receipt, receipt_sha = self._completion_receipt(
                row,
                generation=lease.generation,
                state=lifecycle,
                bundle_ref=bundle_ref,
                reason=reason,
                completed_at_ns=now,
            )
            self._db.execute(
                """UPDATE runner_tasks SET lifecycle = ?, final_bundle_ref = ?,
                    final_reason = ?, lease_worker_id = NULL, lease_token = NULL,
                    lease_claimed_at_ns = NULL, lease_expires_at_ns = NULL,
                    receipt_json = ?, receipt_sha256 = ?, updated_at_ns = ?
                   WHERE task_id = ?""",
                (
                    lifecycle,
                    bundle_ref,
                    reason,
                    receipt,
                    receipt_sha,
                    now,
                    lease.binding.task_id,
                ),
            )
            self._db.execute(
                """UPDATE runner_attempts SET finished_at_ns = ?, outcome = ?,
                    bundle_ref = ?, reason = ?
                   WHERE task_id = ? AND generation = ? AND outcome = 'active'""",
                (
                    now,
                    lifecycle,
                    bundle_ref,
                    reason,
                    lease.binding.task_id,
                    lease.generation,
                ),
            )
            row = self._row(lease.binding.task_id)
            status = self._status(row)
        return status

    def _require_current_lease(
        self, row: sqlite3.Row | None, lease: WorkLease, now: int, *,
        allow_cancel: bool = False,
    ) -> None:
        if row is None or row["lifecycle"] != "leased":
            raise LeaseLost(lease.binding.task_id)
        if row["cancel_requested_at_ns"] is not None and not allow_cancel:
            raise LeaseLost(lease.binding.task_id)
        if (
            row["lease_generation"] != lease.generation
            or row["lease_worker_id"] != lease.worker_id
            or row["lease_token"] != lease.token
            or row["lease_expires_at_ns"] <= now
        ):
            raise LeaseLost(lease.binding.task_id)
        if self._binding(row) != lease.binding or self._load_input(row) != lease.task_input:
            raise LeaseLost(lease.binding.task_id)

    def _end_expired_leases(self, now: int) -> None:
        """End every expired lease: ``cleanup_unconfirmed`` if the worker
        reported its execution not confirmed stopped, else ``cancelled`` if
        a cancel waits for it, otherwise ``runner_restart``.  An expired
        execution is never claimed again, so the Controller decides what
        follows (09 §8)."""

        rows = self._db.execute(
            """SELECT t.*, a.reason AS attempt_reason
               FROM runner_tasks t LEFT JOIN runner_attempts a
                 ON a.task_id = t.task_id AND a.generation = t.lease_generation
               WHERE t.lifecycle = 'leased' AND t.lease_expires_at_ns <= ?""",
            (now,),
        ).fetchall()
        for row in rows:
            if row["attempt_reason"] == CLEANUP_UNCONFIRMED:
                reason = CLEANUP_UNCONFIRMED
            elif row["cancel_requested_at_ns"] is not None:
                reason = CANCELLED
            else:
                reason = RUNNER_RESTART
            self._end_unsealed(row, reason, now)

    def _end_unsealed(self, row: sqlite3.Row, reason: str, now: int) -> None:
        """Finish a queued or leased row without a bundle, inside the
        caller's transaction."""

        task_id = row["task_id"]
        cancelled = row["cancel_requested_at_ns"] is not None
        if row["lifecycle"] == "leased":
            outcome = "cancelled" if cancelled else "lease_expired"
            self._db.execute(
                """UPDATE runner_attempts SET finished_at_ns = ?,
                    outcome = ?, reason = ?
                   WHERE task_id = ? AND generation = ?
                     AND outcome = 'active'""",
                (now, outcome, reason, task_id, row["lease_generation"]),
            )
        receipt, receipt_sha = self._completion_receipt(
            row, generation=row["lease_generation"],
            state="ended_unsealed", bundle_ref=None,
            reason=reason, completed_at_ns=now,
        )
        self._db.execute(
            """UPDATE runner_tasks SET
                lifecycle = 'ended_unsealed', final_reason = ?,
                cancel_completed_at_ns = CASE WHEN ? THEN ? END,
                cancel_disposition = CASE WHEN ? THEN 'cancelled' END,
                lease_worker_id = NULL, lease_token = NULL,
                lease_claimed_at_ns = NULL, lease_expires_at_ns = NULL,
                receipt_json = ?, receipt_sha256 = ?, updated_at_ns = ?
               WHERE task_id = ?""",
            (reason, cancelled, now, cancelled, receipt, receipt_sha, now,
             task_id),
        )

    def _completion_receipt(
        self,
        row: sqlite3.Row,
        *,
        generation: int,
        state: str,
        bundle_ref: str | None,
        reason: str | None,
        completed_at_ns: int,
    ) -> tuple[bytes, str]:
        receipt = CompletionReceipt(
            binding=self._binding(row),
            generation=generation,
            final_state=state,
            bundle_ref=bundle_ref,
            reason=reason,
            completed_at_ns=completed_at_ns,
        )
        raw = canonical_json(receipt)
        return raw, hashlib.sha256(raw).hexdigest()

    # ------------------------------------------------ audit views

    def receipt(self, task_id: str) -> CompletionReceipt | None:
        task_id = self._task_id(task_id)
        with self._lock:
            row = self._row(task_id)
            if row is None or row["receipt_json"] is None:
                return None
            raw = bytes(row["receipt_json"])
            try:
                parse_json(raw)
                receipt = CompletionReceipt.model_validate_json(raw)
            except (ValueError, TypeError, UnicodeError) as exc:
                raise RunnerDataError("stored completion receipt is invalid") from exc
            if canonical_json(receipt) != raw:
                raise RunnerDataError("stored completion receipt is not canonical")
            if hashlib.sha256(raw).hexdigest() != row["receipt_sha256"]:
                raise RunnerDataError("stored completion receipt digest mismatch")
            try:
                binding = self._binding(row)
            except (TypeError, ValueError) as exc:
                raise RunnerDataError("stored task binding is invalid") from exc
            if (
                receipt.binding != binding
                or receipt.generation != row["lease_generation"]
                or receipt.final_state != row["lifecycle"]
                or receipt.bundle_ref != row["final_bundle_ref"]
                or receipt.reason != row["final_reason"]
            ):
                raise RunnerDataError("completion receipt conflicts with task state")
            return receipt

    def attempts(self, task_id: str) -> tuple[AttemptFact, ...]:
        task_id = self._task_id(task_id)
        with self._lock:
            rows = self._db.execute(
                """SELECT * FROM runner_attempts WHERE task_id = ?
                   ORDER BY generation""",
                (task_id,),
            ).fetchall()
        return tuple(
            AttemptFact(
                task_id=row["task_id"],
                generation=row["generation"],
                worker_id=row["worker_id"],
                token_sha256=hashlib.sha256(row["token"].encode()).hexdigest(),
                claimed_at_ns=row["claimed_at_ns"],
                expires_at_ns=row["expires_at_ns"],
                finished_at_ns=row["finished_at_ns"],
                outcome=row["outcome"],
                bundle_ref=row["bundle_ref"],
                reason=row["reason"],
            )
            for row in rows
        )

    def facts(self, task_id: str) -> TaskFacts | None:
        task_id = self._task_id(task_id)
        with self._lock:
            row = self._row(task_id)
            if row is None:
                return None
            task_input = None if row["input_json"] is None else self._load_input(row)
            return TaskFacts(
                task_id=row["task_id"],
                submission_order=row["submission_order"],
                task_input=task_input,
                input_sha256=row["input_sha256"],
                lifecycle=row["lifecycle"],
                lease_generation=row["lease_generation"],
                cancel_requested_at_ns=row["cancel_requested_at_ns"],
                cancel_completed_at_ns=row["cancel_completed_at_ns"],
                cancel_disposition=row["cancel_disposition"],
                final_bundle_ref=row["final_bundle_ref"],
                final_reason=row["final_reason"],
                receipt_sha256=row["receipt_sha256"],
            )
