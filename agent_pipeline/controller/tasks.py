"""The task contracts the Controller requires of the Runner and of the
Agent executor (09 §8)."""

from __future__ import annotations

from typing import Literal, Protocol

from ..contracts import AgentTask, Record, VulnerabilityCandidate
from .records import RepairInput


class RunnerStatus(Record):
    """status(task_id).  `bundles` are the sealed bundles, in order."""

    state: Literal["unknown", "running", "sealed", "ended_unsealed"]
    reason: str | None = None
    bundles: tuple[str, ...] = ()


class RunnerInput(Record):
    job_id: str
    harness_ref: str
    execution_harness_id: str


class SubmitRefused(Exception):
    """submit() with a different input for a known task_id, or a task_id
    that was cancelled first."""


class Runner(Protocol):
    def submit(self, task_id: str, task_input: RunnerInput) -> RunnerStatus:
        """Record task_id durably, then start.  Idempotent for task_id."""

    def status(self, task_id: str) -> RunnerStatus: ...

    def cancel(self, task_id: str) -> RunnerStatus:
        """Stop and return the final status.  An unknown task_id is recorded
        as cancelled and answered ended_unsealed(cancelled)."""


class AgentRequest(Record):
    """What an Agent Task receives (09 §7, 02 §9).  Artifacts are passed by
    digest; the Agent reads them with read-only tools."""

    job_id: str
    task_id: str
    attempt: int
    agent_task: AgentTask
    candidate: VulnerabilityCandidate
    hcap_revision: str
    analysis_ref: str | None = None
    plan_ref: str | None = None
    repair: RepairInput | None = None


class AgentExecutor(Protocol):
    def start(self, request: AgentRequest) -> None:
        """Run the task; its result comes back through the Controller's
        on_agent_result / on_agent_failure."""
