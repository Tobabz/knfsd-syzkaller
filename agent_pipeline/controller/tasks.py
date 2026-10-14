"""The task contracts the Controller requires of the Runner and of the
Agent executor (09 §8)."""

from __future__ import annotations

import hashlib
import json
from typing import Literal, Protocol

from ..contracts import (AgentModelPolicy, AgentTask, Record,
                         VulnerabilityCandidate)
from ..data import canonical_json
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


def runner_input_digest(task_input: RunnerInput) -> str:
    """Canonical identity shared by Controller, Runner, and receipts."""

    value = RunnerInput.model_validate(task_input)
    return hashlib.sha256(canonical_json(value)).hexdigest()


def legacy_runner_input_digest(task_input: RunnerInput) -> str:
    """Authenticate the pre-``job_id`` Controller digest during migration.

    This deliberately reproduces the old encoding instead of defining an
    alternate identity for new Runner tasks.  New tasks, the DurableRunner,
    and evidence receipts must use :func:`runner_input_digest`.
    """

    value = RunnerInput.model_validate(task_input)
    payload = {
        "harness_ref": value.harness_ref,
        "execution_harness_id": value.execution_harness_id,
    }
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str)
    return hashlib.sha256(text.encode()).hexdigest()


def agent_input_payload(*, agent_task: AgentTask,
                        model_policy: AgentModelPolicy,
                        candidate: VulnerabilityCandidate,
                        hcap_revision: str,
                        analysis_ref: str | None,
                        plan_ref: str | None,
                        repair: RepairInput | None,
                        include_model_policy: bool = True) -> dict:
    """Canonical logical Agent input, including the selected model policy.

    ``include_model_policy=False`` exists only to authenticate tasks written
    before model policy was part of the durable input contract.
    """

    payload = {
        "agent_task": agent_task.value,
        "candidate": candidate.model_dump(mode="json"),
        "hcap_revision": hcap_revision,
        "analysis_ref": analysis_ref,
        "plan_ref": plan_ref if agent_task is
        AgentTask.REACHABILITY_PLANNING else None,
        "repair": repair.model_dump(mode="json") if repair else None,
    }
    if include_model_policy:
        payload["model_policy"] = model_policy.model_dump(mode="json")
    return payload


def agent_input_digest(**kwargs) -> str:
    """Digest an Agent logical input using the Controller's stable encoding."""

    payload = agent_input_payload(**kwargs)
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str)
    return hashlib.sha256(text.encode()).hexdigest()


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
    model_policy: AgentModelPolicy
    candidate: VulnerabilityCandidate
    hcap_revision: str
    analysis_ref: str | None = None
    plan_ref: str | None = None
    repair: RepairInput | None = None


class AgentExecutor(Protocol):
    def start(self, request: AgentRequest) -> None:
        """Run the task; its result comes back through the Controller's
        on_agent_result / on_agent_failure."""
