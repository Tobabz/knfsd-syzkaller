"""Events the machine handles.  Each is stored with its transition, so a
job can be replayed from its first record (09 §8, oracle 4).

Facts the machine cannot compute from its inputs alone (an intake result,
a registry lookup) arrive inside the event; the deterministic components
(HCAP check, Materializer, Q1 Judge) the machine calls itself.
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import Field, TypeAdapter

from ..contracts import (AgentOutput, GapRef, HarnessBinding, JudgeVersions,
                         Record, Sha256, VulnerabilityCandidate)


class IntakeChecked(Record):
    """02 §3 intake and 01 §11.2 binding, done by the service."""

    type: Literal["intake_checked"] = "intake_checked"
    candidate: VulnerabilityCandidate | None = None
    rejection: str | None = None
    binding: HarnessBinding | None = None
    judge_versions: JudgeVersions


class AgentSucceeded(Record):
    type: Literal["agent_succeeded"] = "agent_succeeded"
    task_id: str
    attempt: int
    output: AgentOutput
    model_id: str


class AgentFailed(Record):
    type: Literal["agent_failed"] = "agent_failed"
    task_id: str
    attempt: int
    failure: str


class AgentAttemptRestarted(Record):
    """A restarted Controller sent the pending Agent task again (09 §8)."""

    type: Literal["agent_attempt_restarted"] = "agent_attempt_restarted"
    task_id: str
    attempt: int


class RunnerFinished(Record):
    """status(task_id) reached `sealed` or `ended_unsealed` (09 §8).  A
    Stage 1 run seals at most one bundle.  For a Stage 2 gate or campaign
    task `bundle_refs` is the task's whole bundle list, in order."""

    type: Literal["runner_finished"] = "runner_finished"
    task_id: str
    state: Literal["sealed", "ended_unsealed"]
    bundle_ref: str | None = None
    reason: str | None = None
    bundle_refs: tuple[str, ...] = ()


class RunnerBundleSealed(Record):
    """status(task_id) lists a bundle the job has not taken yet, of a task
    that seals bundles while it runs (a campaign task, 09 §8).  `index` is
    its position in the task's list; bundles are taken in order, each
    once, also after the job stopped taking the task's result."""

    type: Literal["runner_bundle_sealed"] = "runner_bundle_sealed"
    task_id: str
    index: int
    bundle_ref: str


class RunnerInputDigestMigrated(Record):
    """Replace one authenticated pre-``job_id`` Runner input digest."""

    type: Literal["runner_input_digest_migrated"] = \
        "runner_input_digest_migrated"
    task_id: str
    legacy_digest: Sha256
    canonical_digest: Sha256


class ApprovalGiven(Record):
    type: Literal["approval_given"] = "approval_given"
    task_id: str
    review_manifest_sha256: str
    decision_id: str


class ApprovalDenied(Record):
    type: Literal["approval_denied"] = "approval_denied"
    task_id: str
    note: str


class IssueChanged(Record):
    """A HarnessGapIssue changed status (07 §7)."""

    type: Literal["issue_changed"] = "issue_changed"
    gap: GapRef
    status: Literal["resolved", "deferred", "reopened", "wont_fix"]
    resolution: str = ""


class BindingChanged(Record):
    """The registry's binding for the job's commit and sanitizer, looked up
    again: after an issue is resolved (retry_pending), or because a harness
    build or HCAP revision changed (09 §5).  None: no validated build."""

    type: Literal["binding_changed"] = "binding_changed"
    binding: HarnessBinding | None
    judge_versions: JudgeVersions | None = None
    # Absent in historical events. New registry/recovery events set this so
    # binding, materialization and judge authority change atomically while old
    # transition logs retain their original reduction.
    rematerialize_authority: bool = False
    # Set by the service: the job's current harness has the same
    # HCAP-derived authority refs under `binding` (09 §5).  The machine then
    # re-validates the plan and keeps the harness instead of rebuilding it.
    harness_authority_current: bool = False


class JudgeVersionsChanged(Record):
    type: Literal["judge_versions_changed"] = "judge_versions_changed"
    judge_versions: JudgeVersions
    # Absent in historical events, whose reduction kept the old verdict when
    # the re-judge gave the same decision.  Current events consume the new
    # authority's verdict in that case too (09 §5).
    consume_same_verdict: bool = False


class PolicyChanged(Record):
    """`binding` is the registry's binding for the new policy's sanitizer,
    looked up by the service; the machine uses it only when the sanitizer
    changes."""

    type: Literal["policy_changed"] = "policy_changed"
    job_policy_id: str
    binding: HarnessBinding | None = None
    judge_versions: JudgeVersions | None = None
    rematerialize_authority: bool = False
    # Set by the service: the job's current harness has the same
    # HCAP-derived authority refs under `binding` (09 §5).  The machine then
    # re-validates the plan and keeps the harness instead of rebuilding it.
    harness_authority_current: bool = False


class OperatorAction(Record):
    type: Literal["operator"] = "operator"
    #: start_stage2 is the 09 §4 "Stage 2 start by operator" on s1_reached;
    #: route_gate / route_strategy are 09 §5 route(to) on
    #: blocked_operator(gate_regression); start_fixed is the 09 §3.1
    #: fixed start by operator on s1_reached.
    #: retry_generation is the 09 §3.2 operator restart of Harness
    #: Generation on blocked_harness_gap or parked.
    action: Literal["resume", "close", "cancel", "start_stage2",
                    "start_fixed", "route_gate", "route_strategy",
                    "retry_generation"]
    action_id: str


class GenerationEnded(Record):
    """The Harness Generation of the job's gap key ended, looked up by the
    service (09 §3.2).  ``passed`` carries the staged binding; the others
    leave the job on its issue.  ``unavailable``: the policy asks for
    generation but the host has no generator configured, or the job's
    policy no longer does.  ``not_filled``: the job already runs on the
    generation's staged binding and still meets the gap."""

    type: Literal["generation_ended"] = "generation_ended"
    gap: GapRef
    generation_id: str | None = None
    outcome: Literal["passed", "infeasible", "exhausted", "failed",
                     "unavailable", "not_filled"]
    binding: HarnessBinding | None = None
    reason: str | None = None


class CancelConfirmed(Record):
    """cancel(task_id) answered with a final status (09 §8)."""

    type: Literal["cancel_confirmed"] = "cancel_confirmed"
    task_id: str
    #: The final status was ``cleanup_unconfirmed``: the lease ended, but
    #: the execution was not confirmed stopped.  Absent in earlier logs.
    cleanup_unconfirmed: bool = False


class CleanupUnconfirmed(Record):
    """The Runner reported, after the task's final status, that its
    execution was not confirmed stopped (09 §8)."""

    type: Literal["cleanup_unconfirmed"] = "cleanup_unconfirmed"
    task_id: str
    generation: int


Event = Annotated[
    Union[IntakeChecked, AgentSucceeded, AgentFailed, AgentAttemptRestarted,
          RunnerFinished, RunnerBundleSealed, RunnerInputDigestMigrated,
          ApprovalGiven, ApprovalDenied, IssueChanged, BindingChanged,
          JudgeVersionsChanged,
          PolicyChanged, OperatorAction, GenerationEnded, CancelConfirmed,
          CleanupUnconfirmed],
    Field(discriminator="type"),
]

EVENT = TypeAdapter(Event)
