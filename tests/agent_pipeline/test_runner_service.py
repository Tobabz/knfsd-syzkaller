"""Host tests for the durable Runner orchestration slice (01 §11, 09 §8)."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_pipeline.controller.tasks import (RunnerInput, SubmitRefused,
                                             runner_input_digest)
from agent_pipeline.data import canonical_json
from agent_pipeline.runner import (
    BACKEND_ERROR,
    EXECUTOR_ENDED_UNSEALED,
    BackendResult,
    DurableRunner,
    LeaseLost,
    RunnerDataError,
    RunnerWorker,
)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def runner_input(job: str = "job-1", harness: str = "harness-1") -> RunnerInput:
    return RunnerInput(
        job_id=job,
        harness_ref=sha(harness),
        execution_harness_id=sha(f"execution:{harness}"),
    )


class FakeClock:
    def __init__(self, value: int = 1_000) -> None:
        self.value = value
        self.lock = threading.Lock()

    def __call__(self) -> int:
        with self.lock:
            return self.value

    def set(self, value: int) -> None:
        with self.lock:
            self.value = value

    def advance(self, amount: int) -> None:
        with self.lock:
            self.value += amount


def make_runner(path, clock, *, duration=100) -> DurableRunner:
    return DurableRunner(path, clock=clock, lease_duration_ns=duration)


def test_submit_is_canonical_idempotent_durable_and_fail_closed(tmp_path):
    path = tmp_path / "runner.sqlite"
    clock = FakeClock()
    task_input = runner_input()
    runner = make_runner(path, clock)

    first = runner.submit("job-1.t1", task_input)
    second = runner.submit("job-1.t1", RunnerInput(**task_input.model_dump()))
    facts = runner.facts("job-1.t1")
    assert first == second
    assert first.state == "running"
    assert facts.task_input == task_input
    assert facts.input_sha256 == runner_input_digest(task_input)
    assert facts.lifecycle == "queued"

    with pytest.raises(SubmitRefused, match="different input"):
        runner.submit("job-1.t1", runner_input(harness="other"))
    runner.close()

    restarted = make_runner(path, clock)
    assert restarted.status("job-1.t1").state == "running"
    assert [task.task_id for task in restarted.recoverable()] == ["job-1.t1"]
    restarted.close()


@pytest.mark.parametrize(
    "task_input",
    [
        RunnerInput(
            job_id="", harness_ref=sha("h"), execution_harness_id=sha("e")
        ),
        RunnerInput(
            job_id="job-1", harness_ref="not-a-digest",
            execution_harness_id=sha("e"),
        ),
        RunnerInput(
            job_id="job-1", harness_ref=sha("h"),
            execution_harness_id="not-a-digest",
        ),
    ],
)
def test_invalid_binding_is_rejected_without_poisoning_queue(tmp_path, task_input):
    runner = make_runner(tmp_path / "runner.sqlite", FakeClock())
    with pytest.raises(ValueError):
        runner.submit("job-1.t1", task_input)
    assert runner.status("job-1.t1").state == "unknown"
    assert runner.facts("job-1.t1") is None
    assert runner.recoverable() == ()
    runner.close()


def test_cancel_before_submit_is_a_durable_tombstone(tmp_path):
    path = tmp_path / "runner.sqlite"
    clock = FakeClock()
    runner = make_runner(path, clock)

    first = runner.cancel("job-1.t1")
    second = runner.cancel("job-1.t1")
    assert first == second
    assert (first.state, first.reason, first.bundles) == (
        "ended_unsealed",
        "cancelled",
        (),
    )
    facts = runner.facts("job-1.t1")
    assert facts.task_input is None
    assert facts.cancel_disposition == "cancelled"
    requested_at = facts.cancel_requested_at_ns
    runner.close()

    restarted = make_runner(path, clock)
    assert restarted.status("job-1.t1") == first
    assert restarted.facts("job-1.t1").cancel_requested_at_ns == requested_at
    with pytest.raises(SubmitRefused, match="cancelled before submit"):
        restarted.submit("job-1.t1", runner_input())
    assert restarted.recoverable() == ()
    restarted.close()


def test_claim_order_and_concurrent_claim_are_single_owner(tmp_path):
    path = tmp_path / "runner.sqlite"
    clock = FakeClock()
    first = make_runner(path, clock)
    second = make_runner(path, clock)
    first.submit("job-1.t2", runner_input())
    first.submit("job-1.t1", runner_input())
    assert [work.task_id for work in second.recoverable()] == [
        "job-1.t2",
        "job-1.t1",
    ]

    barrier = threading.Barrier(3)

    def claim(runner, worker):
        barrier.wait()
        return runner.claim(worker)

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(claim, first, "worker-a")
        b = pool.submit(claim, second, "worker-b")
        barrier.wait()
        leases = [lease for lease in (a.result(), b.result()) if lease is not None]

    # There are two pending tasks, so both workers claim one; each task has
    # exactly one active generation despite the simultaneous transactions.
    assert {lease.binding.task_id for lease in leases} == {"job-1.t1", "job-1.t2"}
    for task_id in ("job-1.t1", "job-1.t2"):
        attempts = first.attempts(task_id)
        assert len(attempts) == 1
        assert attempts[0].outcome == "active"
        assert attempts[0].generation == 1
    first.close()
    second.close()


def test_concurrent_duplicate_submit_creates_one_task(tmp_path):
    path = tmp_path / "runner.sqlite"
    clock = FakeClock()
    first = make_runner(path, clock)
    second = make_runner(path, clock)
    barrier = threading.Barrier(3)

    def submit(runner):
        barrier.wait()
        return runner.submit("job-1.t1", runner_input())

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(submit, first)
        b = pool.submit(submit, second)
        barrier.wait()
        assert a.result().state == b.result().state == "running"

    recoverable = first.recoverable()
    assert len(recoverable) == 1
    assert recoverable[0].task_id == "job-1.t1"
    first.close()
    second.close()


def test_restart_reclaims_only_after_expiry_and_rejects_old_worker(tmp_path):
    path = tmp_path / "runner.sqlite"
    clock = FakeClock(100)
    runner = make_runner(path, clock, duration=10)
    task_input = runner_input()
    runner.submit("job-1.t1", task_input)
    old = runner.claim("worker-old")
    assert old.generation == 1
    runner.close()

    restarted = make_runner(path, clock, duration=10)
    clock.set(109)
    assert restarted.recoverable() == ()
    assert restarted.claim("worker-new") is None

    clock.set(110)
    pending = restarted.recoverable()
    assert len(pending) == 1
    assert pending[0].reclaiming_expired_lease
    assert pending[0].next_generation == 2
    new = restarted.claim("worker-new")
    assert new.generation == 2
    attempts = restarted.attempts("job-1.t1")
    assert [attempt.outcome for attempt in attempts] == ["lease_expired", "active"]

    with pytest.raises(LeaseLost):
        restarted.complete(old, BackendResult(bundle_ref=sha("stale")))
    sealed = restarted.complete(new, BackendResult(bundle_ref=sha("accepted")))
    assert sealed.bundles == (sha("accepted"),)
    receipt = restarted.receipt("job-1.t1")
    assert receipt.binding.task_id == "job-1.t1"
    assert receipt.binding.job_id == task_input.job_id
    assert receipt.binding.harness_ref == task_input.harness_ref
    assert receipt.binding.execution_harness_id == task_input.execution_harness_id
    assert receipt.generation == 2
    restarted.close()

    final = make_runner(path, clock, duration=10)
    assert final.status("job-1.t1") == sealed
    assert final.attempts("job-1.t1")[-1].outcome == "sealed"
    final.close()


def test_attempt_audit_redacts_bearer_token(tmp_path):
    runner = make_runner(tmp_path / "runner.sqlite", FakeClock())
    runner.submit("job-1.t1", runner_input())
    lease = runner.claim("worker")

    attempt = runner.attempts("job-1.t1")[0]
    assert not hasattr(attempt, "token")
    assert attempt.token_sha256 == sha(lease.token)
    assert lease.token.encode() not in canonical_json(attempt)
    assert lease.token not in runner.facts("job-1.t1").model_dump_json()
    runner.close()


def test_lease_can_be_renewed_without_changing_generation(tmp_path):
    clock = FakeClock(100)
    runner = make_runner(tmp_path / "runner.sqlite", clock, duration=10)
    runner.submit("job-1.t1", runner_input())
    lease = runner.claim("worker")
    clock.set(105)
    renewed = runner.renew(lease)
    assert renewed.generation == lease.generation == 1
    assert renewed.token == lease.token
    assert renewed.expires_at_ns == 115
    clock.set(110)
    assert not runner.stop_requested(renewed)
    assert runner.complete(
        renewed, BackendResult(bundle_ref=sha("bundle"))
    ).state == "sealed"
    runner.close()


def test_cancel_wins_over_a_late_backend_result(tmp_path):
    path = tmp_path / "runner.sqlite"
    clock = FakeClock()
    runner = make_runner(path, clock)
    observer = make_runner(path, clock)
    runner.submit("job-1.t1", runner_input())
    lease = runner.claim("worker")

    status = observer.cancel("job-1.t1")
    assert (status.state, status.reason) == ("ended_unsealed", "cancelled")
    with pytest.raises(LeaseLost):
        runner.complete(lease, BackendResult(bundle_ref=sha("too-late")))
    assert runner.status("job-1.t1") == status
    facts = runner.facts("job-1.t1")
    assert facts.cancel_requested_at_ns is not None
    assert facts.cancel_completed_at_ns is not None
    assert facts.cancel_disposition == "cancelled"
    assert runner.attempts("job-1.t1")[0].outcome == "cancelled"
    assert runner.receipt("job-1.t1").reason == "cancelled"
    runner.close()
    observer.close()


def test_complete_and_cancel_race_has_one_monotone_winner(tmp_path):
    path = tmp_path / "runner.sqlite"
    clock = FakeClock()
    runner = make_runner(path, clock)
    canceller = make_runner(path, clock)

    for number in range(12):
        task_id = f"job-1.t{number}"
        runner.submit(task_id, runner_input())
        lease = runner.claim(f"worker-{number}")
        barrier = threading.Barrier(3)

        def complete():
            barrier.wait()
            try:
                return runner.complete(
                    lease, BackendResult(bundle_ref=sha(f"bundle-{number}"))
                )
            except LeaseLost:
                return "lease_lost"

        def cancel():
            barrier.wait()
            return canceller.cancel(task_id)

        with ThreadPoolExecutor(max_workers=2) as pool:
            completed = pool.submit(complete)
            cancelled = pool.submit(cancel)
            barrier.wait()
            completed_result = completed.result()
            cancel_result = cancelled.result()

        final = runner.status(task_id)
        if final.state == "sealed":
            assert completed_result.state == "sealed"
            assert cancel_result == final
            assert runner.facts(task_id).cancel_disposition == "already_sealed"
        else:
            assert (final.state, final.reason) == ("ended_unsealed", "cancelled")
            assert completed_result == "lease_lost"
            assert cancel_result == final
            assert runner.facts(task_id).cancel_disposition == "cancelled"

    runner.close()
    canceller.close()


class EmptyBackend:
    def execute(self, lease, control):
        return None


class RaisingBackend:
    def execute(self, lease, control):
        raise RuntimeError("untrusted backend detail")


@pytest.mark.parametrize(
    ("backend", "reason"),
    [
        (EmptyBackend(), EXECUTOR_ENDED_UNSEALED),
        (RaisingBackend(), BACKEND_ERROR),
    ],
)
def test_worker_end_without_bundle_is_ended_unsealed(tmp_path, backend, reason):
    runner = make_runner(tmp_path / f"{reason}.sqlite", FakeClock())
    runner.submit("job-1.t1", runner_input())
    run = RunnerWorker(runner, backend, worker_id="worker").run_once()
    assert run.disposition == "completed"
    assert (run.status.state, run.status.reason, run.status.bundles) == (
        "ended_unsealed",
        reason,
        (),
    )
    assert runner.attempts("job-1.t1")[0].outcome == "ended_unsealed"
    assert runner.receipt("job-1.t1").bundle_ref is None
    runner.close()


def test_backend_in_flight_cancel_cannot_publish_late_success(tmp_path):
    path = tmp_path / "runner.sqlite"
    clock = FakeClock()
    runner = make_runner(path, clock)
    canceller = make_runner(path, clock)
    entered = threading.Event()
    release = threading.Event()

    class BlockingBackend:
        def execute(self, lease, control):
            entered.set()
            assert release.wait(timeout=5)
            assert control.stop_requested()
            return BackendResult(bundle_ref=sha("late"))

    runner.submit("job-1.t1", runner_input())
    worker = RunnerWorker(runner, BlockingBackend(), worker_id="worker")
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(worker.run_once)
        assert entered.wait(timeout=5)
        cancelled = canceller.cancel("job-1.t1")
        release.set()
        run = future.result(timeout=5)

    assert (cancelled.state, cancelled.reason) == ("ended_unsealed", "cancelled")
    assert run.disposition == "lease_lost"
    assert run.status == cancelled
    assert runner.status("job-1.t1") == cancelled
    runner.close()
    canceller.close()


def test_forged_binding_cannot_complete_an_owned_lease(tmp_path):
    runner = make_runner(tmp_path / "runner.sqlite", FakeClock())
    runner.submit("job-1.t1", runner_input())
    lease = runner.claim("worker")
    forged = lease.model_copy(
        update={
            "binding": lease.binding.model_copy(update={"job_id": "job-other"})
        }
    )
    with pytest.raises(LeaseLost):
        runner.complete(forged, BackendResult(bundle_ref=sha("bundle")))
    assert runner.status("job-1.t1").state == "running"
    runner.close()


def test_receipt_rejects_conflict_with_durable_task_row(tmp_path):
    path = tmp_path / "runner.sqlite"
    runner = make_runner(path, FakeClock())
    runner.submit("job-1.t1", runner_input())
    lease = runner.claim("worker")
    runner.complete(lease, BackendResult(bundle_ref=sha("bundle")))
    assert runner.receipt("job-1.t1") is not None

    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE runner_tasks SET final_bundle_ref = ? WHERE task_id = ?",
            (sha("different-bundle"), "job-1.t1"),
        )
    with pytest.raises(RunnerDataError, match="conflicts with task state"):
        runner.receipt("job-1.t1")
    runner.close()
