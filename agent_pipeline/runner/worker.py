"""Injected worker adapter for :mod:`agent_pipeline.runner.service`."""

from __future__ import annotations

import threading
from typing import Protocol

from .models import BackendResult, WorkLease, WorkerRun
from .service import (
    BACKEND_ERROR,
    EXECUTOR_ENDED_UNSEALED,
    DurableRunner,
    LeaseLost,
)


class ExecutionNotStopped(Exception):
    """The backend could not confirm that its execution stopped.

    Raise it (or a subclass) instead of returning a result when the process,
    VM or other side effect may still be running.  The worker then neither
    completes the task nor renews its lease: the task ends when the lease
    expires, after the backend's own lease deadline.
    """


class LeaseControl:
    """The backend's narrow heartbeat and stop-request interface."""

    def __init__(self, runner: DurableRunner, lease: WorkLease) -> None:
        self._runner = runner
        self._lease = lease

    @property
    def lease(self) -> WorkLease:
        """Current lease after any renewal; engines cannot replace it."""

        return self._lease

    def stop_requested(self) -> bool:
        return self._runner.stop_requested(self.lease)

    def renew(self) -> WorkLease:
        self._lease = self._runner.renew(self._lease)
        return self._lease


class RunnerBackend(Protocol):
    def execute(
        self, lease: WorkLease, control: LeaseControl
    ) -> BackendResult | None:
        """Execute one lease.

        Return a sealed bundle reference or an explicit unsealed reason.
        Returning ``None`` means the executor ended without a bundle.  The
        backend receives no API for verdict creation.

        A production backend must carry the lease generation and token into
        its concrete process/VM ownership and fence artifact publication with
        them.  The SQLite lease prevents stale completion from being accepted;
        expiry alone cannot stop a noncooperative executor or its side effects.
        """


class RunnerWorker:
    def __init__(
        self,
        runner: DurableRunner,
        backend: RunnerBackend,
        *,
        worker_id: str,
        heartbeat_interval_s: float | None = None,
    ) -> None:
        self.runner = runner
        self.backend = backend
        self.worker_id = worker_id
        # None: a third of the lease, so two missed renewals still leave
        # the lease valid.
        self.heartbeat_interval_s = heartbeat_interval_s

    def _heartbeat(self, control: LeaseControl,
                   stop: threading.Event) -> None:
        lease = control.lease
        interval = self.heartbeat_interval_s
        if interval is None:
            interval = (lease.expires_at_ns - lease.claimed_at_ns) / 3e9
        while not stop.wait(interval):
            try:
                control.renew()
            except LeaseLost:
                return                   # cancelled, expired or reclaimed
            except Exception:
                continue                 # transient; the next beat retries

    def run_once(self) -> WorkerRun | None:
        lease = self.runner.claim(self.worker_id)
        if lease is None:
            return None
        control = LeaseControl(self.runner, lease)
        stop = threading.Event()
        beat = threading.Thread(target=self._heartbeat, args=(control, stop),
                                name=f"lease-heartbeat-{lease.generation}",
                                daemon=True)
        beat.start()
        try:
            result = self.backend.execute(lease, control)
        except ExecutionNotStopped:
            # A completion would tell the Controller the execution ended (and
            # settle a pending cancel).  Stop renewing instead; lease expiry
            # ends the task once the backend's own deadline has passed.
            result = None
            not_stopped = True
        except Exception:
            result = BackendResult(reason=BACKEND_ERROR)
            not_stopped = False
        else:
            not_stopped = False
        finally:
            stop.set()
            beat.join()
        if not_stopped:
            try:
                self.runner.stop_unconfirmed(lease)
            except LeaseLost:
                pass        # already ended; expiry recorded what it knew
            return WorkerRun(
                task_id=lease.binding.task_id,
                generation=lease.generation,
                disposition="not_stopped",
                status=self.runner.status(lease.binding.task_id),
            )
        if result is None:
            result = BackendResult(reason=EXECUTOR_ENDED_UNSEALED)
        try:
            status = self.runner.complete(control.lease, result)
        except LeaseLost:
            status = self.runner.status(lease.binding.task_id)
            return WorkerRun(
                task_id=lease.binding.task_id,
                generation=lease.generation,
                disposition="lease_lost",
                status=status,
            )
        return WorkerRun(
            task_id=lease.binding.task_id,
            generation=lease.generation,
            disposition="completed",
            status=status,
        )
