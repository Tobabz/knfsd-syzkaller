"""Frozen host-side records for the durable Runner service.

The Controller's ``task_id`` identifies one concrete stage execution.  The
current :class:`RunnerInput` contract has no separate stage-name field, so the
task id is the stage binding carried into leases and completion receipts.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..controller.tasks import RunnerInput, RunnerStatus


Identifier = Annotated[
    str,
    Field(min_length=1, max_length=256, pattern=r"^[^\s\x00-\x1f\x7f]+$"),
]
Digest = Annotated[
    str,
    Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]
Reason = Annotated[
    str,
    Field(min_length=1, max_length=256, pattern=r"^[^\x00-\x1f\x7f]+$"),
]
Timestamp = Annotated[int, Field(ge=0, le=2**63 - 1)]


class HostRecord(BaseModel):
    """Canonical data asserted by the trusted Runner host."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        revalidate_instances="always",
    )


class TaskBinding(HostRecord):
    """Identity copied from the durable submission into every work lease."""

    schema_version: Literal[1] = 1
    task_id: Identifier
    job_id: Identifier
    harness_ref: Digest
    execution_harness_id: Digest


class WorkLease(HostRecord):
    """Exclusive logical ownership of one task generation."""

    binding: TaskBinding
    task_input: RunnerInput
    generation: int = Field(ge=1, le=2**63 - 1)
    worker_id: Identifier
    token: Digest
    claimed_at_ns: Timestamp
    expires_at_ns: Timestamp

    @model_validator(mode="after")
    def _ordered(self) -> WorkLease:
        if self.expires_at_ns <= self.claimed_at_ns:
            raise ValueError("lease must expire after it is claimed")
        return self


class BackendResult(HostRecord):
    """The only result shape accepted from an injected execution backend.

    A bundle reference means the backend completed sealing.  Otherwise a
    reason is required and the service records ``ended_unsealed``.  The
    backend cannot produce a verdict or choose the task binding.
    """

    bundle_ref: Digest | None = None
    reason: Reason | None = None

    @model_validator(mode="after")
    def _shape(self) -> BackendResult:
        if (self.bundle_ref is None) == (self.reason is None):
            raise ValueError("exactly one of bundle_ref and reason is required")
        return self


class CompletionReceipt(HostRecord):
    """Canonical host-authority binding for an accepted final result."""

    schema_version: Literal[1] = 1
    binding: TaskBinding
    # Zero means cancellation won before a worker ever claimed the task.
    generation: int = Field(ge=0, le=2**63 - 1)
    final_state: Literal["sealed", "ended_unsealed"]
    bundle_ref: Digest | None = None
    reason: Reason | None = None
    completed_at_ns: Timestamp

    @model_validator(mode="after")
    def _shape(self) -> CompletionReceipt:
        sealed = self.final_state == "sealed"
        if sealed != (self.bundle_ref is not None):
            raise ValueError("sealed receipt requires a bundle reference")
        if sealed == (self.reason is not None):
            raise ValueError("only an unsealed receipt has a reason")
        return self


class RecoverableTask(HostRecord):
    """A deterministic view of work that can be claimed now."""

    task_id: Identifier
    submission_order: int = Field(ge=1)
    next_generation: int = Field(ge=1)
    reclaiming_expired_lease: bool


class AttemptFact(HostRecord):
    """Persisted facts for one claimed lease generation."""

    task_id: Identifier
    generation: int = Field(ge=1)
    worker_id: Identifier
    # Audit callers can correlate a token without obtaining the bearer value
    # needed to complete work under that lease.
    token_sha256: Digest
    claimed_at_ns: Timestamp
    expires_at_ns: Timestamp
    finished_at_ns: Timestamp | None = None
    outcome: Literal[
        "active",
        "lease_expired",
        "sealed",
        "ended_unsealed",
        "cancelled",
    ]
    bundle_ref: Digest | None = None
    reason: Reason | None = None


class TaskFacts(HostRecord):
    """Auditable task state without exposing mutable database rows."""

    task_id: Identifier
    submission_order: int = Field(ge=1)
    task_input: RunnerInput | None
    input_sha256: Digest | None
    lifecycle: Literal["queued", "leased", "sealed", "ended_unsealed"]
    lease_generation: int = Field(ge=0)
    cancel_requested_at_ns: Timestamp | None = None
    cancel_completed_at_ns: Timestamp | None = None
    cancel_disposition: Literal[
        "cancelled", "already_sealed", "already_ended_unsealed"
    ] | None = None
    final_bundle_ref: Digest | None = None
    final_reason: Reason | None = None
    receipt_sha256: Digest | None = None


class WorkerRun(HostRecord):
    """Result of one worker polling cycle; this is operational, not a verdict."""

    task_id: Identifier
    generation: int = Field(ge=1)
    disposition: Literal["completed", "lease_lost"]
    status: RunnerStatus
