"""Job, Transition and AgentAttempt records (09 §1, §7, §8)."""

from __future__ import annotations

import enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..contracts import (AgentModelPolicy, AgentTask, CandidateSubmission, GapRef,
                         HarnessBinding, JudgeVersions, Materialized,
                         Q1Result, Record, VulnerabilityCandidate)


class JobState(str, enum.Enum):
    """09 §1, the Stage 1 states.  Stage 2 states come with Stage 2."""

    SUBMITTED = "submitted"
    S1_ANALYSIS = "s1_analysis"
    S1_PLANNING = "s1_planning"
    S1_APPROVAL = "s1_approval"
    S1_RUNNING = "s1_running"
    S1_REACHED = "s1_reached"
    BLOCKED_HARNESS_GAP = "blocked_harness_gap"
    RETRY_PENDING = "retry_pending"
    PARKED = "parked"
    BLOCKED_OPERATOR = "blocked_operator"
    REJECTED = "rejected"
    CLOSED_UNSUPPORTED = "closed_unsupported"
    CLOSED = "closed"


#: Waiting states end only through their own operator action or issue
#: event; re-evaluation events only move their resume_point (09 §1, §5).
WAITING = frozenset({JobState.BLOCKED_OPERATOR, JobState.BLOCKED_HARNESS_GAP,
                     JobState.PARKED})
TERMINAL = frozenset({JobState.REJECTED, JobState.CLOSED_UNSUPPORTED,
                      JobState.CLOSED})


class BlockedReason(str, enum.Enum):
    """blocked_operator reasons used in Stage 1 (09 §3, §6, §2)."""

    Q1_EVIDENCE = "q1_evidence"
    Q1_MAPPING = "q1_mapping"
    STAGE1_REPAIR_BUDGET = "stage1_repair_budget"
    AGENT_FAILURE = "agent_failure"
    RUNTIME_RETRY_EXHAUSTED = "runtime_retry_exhausted"
    GAP_ID_UNKNOWN = "gap_id_unknown"
    UNEXPECTED_EVENT = "unexpected_event"
    HOST_AUTHORITY = "host_authority"
    EXECUTION_CLEANUP = "execution_cleanup"


class RepairCause(str, enum.Enum):
    """09 §7, the Stage 1 causes."""

    HCAP_INVALID = "hcap_invalid"
    MATERIALIZER_REJECTED = "materializer_rejected"
    REVIEWER_DENIED = "reviewer_denied"
    Q1_NOT_REACHED = "q1_not_reached"
    REANALYSIS_REQUESTED = "reanalysis_requested"
    HCAP_CHANGED = "hcap_changed"


class TargetKind(str, enum.Enum):
    """Where a job can be sent.  analysis/planning start an Agent Task,
    materialize runs the HCAP check and Materializer on the stored plan,
    running enters s1_running through the approval guard, reached is
    s1_reached; the last two are waiting states with a resume point of their
    own (`inner`)."""

    ANALYSIS = "analysis"
    PLANNING = "planning"
    MATERIALIZE = "materialize"
    RUNNING = "running"
    REACHED = "reached"
    BLOCKED_OPERATOR = "blocked_operator"
    BLOCKED_HARNESS_GAP = "blocked_harness_gap"


class Target(Record):
    """A resume point, or where a transition sends a job (09 §1, §5)."""

    kind: TargetKind
    cause: RepairCause | None = None        # repair, for analysis/planning
    findings: tuple[str, ...] = ()
    charged: bool = False                   # repair already counted (§6)
    rerun: bool = False                     # running: same Runner input
    external: bool = False                  # rerun: asked by an outside
                                            # event, no budget (§6)
    reason: BlockedReason | None = None     # blocked_operator
    gap: GapRef | None = None               # blocked_harness_gap
    inner: Target | None = None             # a waiting target's own resume


Target.model_rebuild()


class TaskKind(str, enum.Enum):
    AGENT = "agent"
    RUNNER = "runner"
    HUMAN = "human"


class RepairInput(Record):
    """09 §7.  Data for the Agent, never instructions."""

    job_id: str
    attempt: int
    agent_task: AgentTask
    cause: RepairCause
    previous_outputs: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    remaining_budget: int


class PendingTask(Record):
    """The job's one unfinished task (09 §1, §8)."""

    task_id: str
    kind: TaskKind
    input_digest: str
    agent_task: AgentTask | None = None
    # Pinned when the task is minted so a policy change or Controller restart
    # cannot silently run the same task identity with another model policy.
    # None preserves replay of tasks stored before model policy was explicit.
    model_policy: AgentModelPolicy | None = None
    attempt: int = 1                        # agent only
    repair: RepairInput | None = None


class Counters(Record):
    """09 §6."""

    agent_repair_stage1: int = 0
    agent_retry: int = 0
    runtime_retry: int = 0


class ConsumedVerdict(Record):
    """The last Q1 verdict a transition consumed, with the binding it was
    consumed under, so a JudgeProfile change can re-judge it (09 §5)."""

    result: Q1Result
    bundle_ref: str
    binding: HarnessBinding
    plan_ref: str
    harness_ref: str


class Stage2Input(Record):
    """01 §5.1, fixed when the job reaches s1_reached (09 §3)."""

    q1_verdict_id: str
    bundle_ref: str
    plan_ref: str
    harness_ref: str
    execution_harness_id: str


class Job(BaseModel):
    """09 §8.  Not frozen: the machine works on a deep copy."""

    model_config = ConfigDict(extra="forbid")

    job_id: str
    submission: CandidateSubmission
    candidate: VulnerabilityCandidate | None = None
    state: JobState = JobState.SUBMITTED
    state_reason: str | None = None
    gap: GapRef | None = None
    binding: HarnessBinding | None = None
    judge_versions: JudgeVersions | None = None
    job_policy_id: str
    counters: Counters = Field(default_factory=Counters)
    pending_task: PendingTask | None = None
    cancelling_tasks: tuple[str, ...] = ()
    #: Runner tasks whose lease ended without confirmed cleanup (09 §8).
    uncleaned_tasks: tuple[str, ...] = ()
    resume_point: Target | None = None
    analysis_ref: str | None = None
    plan_ref: str | None = None
    harness: Materialized | None = None
    approved_manifests: tuple[str, ...] = ()
    last_verdict: ConsumedVerdict | None = None
    stage2_input: Stage2Input | None = None
    seq: int = 0
    task_seq: int = 0


class Transition(Record):
    """Append-only (09 §8).  `job` is the state after the transition, so
    replay can be compared with what was stored."""

    job_id: str
    seq: int
    from_state: JobState | None
    to_state: JobState
    reason: str | None = None
    event: dict
    consumed: tuple[str, ...] = ()
    job_policy_id: str
    at: str
    job: Job


class AgentAttempt(Record):
    """09 §8."""

    task_id: str
    attempt: int
    job_id: str
    agent_task: AgentTask
    input_digest: str
    repair_input_digest: str | None = None
    # sending: recorded, start() not yet returned; running: start() took it
    status: Literal["sending", "running", "succeeded", "failed",
                    "abandoned"]
    model_id: str | None = None
    output_ref: str | None = None
    failure: str | None = None
