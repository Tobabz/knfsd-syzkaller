"""Job, Transition and AgentAttempt records (09 §1, §7, §8)."""

from __future__ import annotations

import enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer

from ..contracts import (AgentModelPolicy, AgentTask, AgentUsage,
                         CandidateSubmission,
                         CompiledRuleSet, GapRef, GateRun, HarnessBinding,
                         JudgeVersions, Materialized, Q1Result, Record,
                         ReplayOutcome, VulnerabilityCandidate)


class JobState(str, enum.Enum):
    """09 §1."""

    SUBMITTED = "submitted"
    S1_ANALYSIS = "s1_analysis"
    S1_PLANNING = "s1_planning"
    S1_APPROVAL = "s1_approval"
    S1_RUNNING = "s1_running"
    S1_REACHED = "s1_reached"
    S2_STRATEGY = "s2_strategy"
    S2_GATE = "s2_gate"
    S2_CAMPAIGN = "s2_campaign"
    S2_REPLAYING = "s2_replaying"
    CRASH_REVIEW = "crash_review"
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
                     JobState.PARKED, JobState.CRASH_REVIEW})
TERMINAL = frozenset({JobState.REJECTED, JobState.CLOSED_UNSUPPORTED,
                      JobState.CLOSED})


class BlockedReason(str, enum.Enum):
    """blocked_operator reasons (09 §2-§4, §6)."""

    Q1_EVIDENCE = "q1_evidence"
    Q1_MAPPING = "q1_mapping"
    STAGE1_REPAIR_BUDGET = "stage1_repair_budget"
    STAGE2_REPAIR_BUDGET = "stage2_repair_budget"
    AGENT_FAILURE = "agent_failure"
    RUNTIME_RETRY_EXHAUSTED = "runtime_retry_exhausted"
    GAP_ID_UNKNOWN = "gap_id_unknown"
    UNEXPECTED_EVENT = "unexpected_event"
    HOST_AUTHORITY = "host_authority"
    EXECUTION_CLEANUP = "execution_cleanup"
    GATE_REGRESSION = "gate_regression"
    EVIDENCE_PATH = "evidence_path"
    CAMPAIGN_BUDGET_EXHAUSTED = "campaign_budget_exhausted"
    CAMPAIGN_EVIDENCE = "campaign_evidence"
    REPLAY_EVIDENCE = "replay_evidence"
    # Host configuration, not in the 09 tables: no Mutation Rule Compiler,
    # or no Stage 2 execution backend (Runner steps and Stage2Judge), is
    # configured.  The job waits with its rule set; resume compiles it
    # again.
    STAGE2_COMPILER_UNAVAILABLE = "stage2_compiler_unavailable"
    STAGE2_GATE_UNAVAILABLE = "stage2_gate_unavailable"


class RepairCause(str, enum.Enum):
    """09 §7."""

    HCAP_INVALID = "hcap_invalid"
    MATERIALIZER_REJECTED = "materializer_rejected"
    REVIEWER_DENIED = "reviewer_denied"
    Q1_NOT_REACHED = "q1_not_reached"
    REANALYSIS_REQUESTED = "reanalysis_requested"
    HCAP_CHANGED = "hcap_changed"
    COMPILER_REJECTED = "compiler_rejected"
    GATE_NOT_APPLIED = "gate_not_applied"
    CAMPAIGN_NOT_APPLIED = "campaign_not_applied"
    CAMPAIGN_NO_SIGNAL = "campaign_no_signal"


#: Causes of a Mutation Strategy repair; they count agent_repair[stage2].
STAGE2_CAUSES = frozenset({RepairCause.COMPILER_REJECTED,
                           RepairCause.GATE_NOT_APPLIED,
                           RepairCause.CAMPAIGN_NOT_APPLIED,
                           RepairCause.CAMPAIGN_NO_SIGNAL})


class TargetKind(str, enum.Enum):
    """Where a job can be sent.  analysis/planning start an Agent Task,
    materialize runs the HCAP check and Materializer on the stored plan,
    running enters s1_running through the approval guard, reached is
    s1_reached; strategy starts Mutation Strategy, compile runs the Mutation
    Rule Compiler on the stored rule set, gate runs the baseline-with-rules
    gate on the compiled set, campaign continues the job's campaign and
    replay replays its crash again; the last two are waiting states with a
    resume point of their own (`inner`)."""

    ANALYSIS = "analysis"
    PLANNING = "planning"
    MATERIALIZE = "materialize"
    RUNNING = "running"
    REACHED = "reached"
    STRATEGY = "strategy"
    COMPILE = "compile"
    GATE = "gate"
    CAMPAIGN = "campaign"
    REPLAY = "replay"
    BLOCKED_OPERATOR = "blocked_operator"
    BLOCKED_HARNESS_GAP = "blocked_harness_gap"


class Target(Record):
    """A resume point, or where a transition sends a job (09 §1, §5)."""

    kind: TargetKind
    cause: RepairCause | None = None        # repair, for an Agent target
    findings: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()          # repair: bundles behind it
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


#: The Stage 2 Runner steps (09 §4).  A Stage 1 run has no step.
STAGE2_STEPS = ("gate", "campaign", "replay")


class RunnerInput(Record):
    """One Runner execution.  A Stage 1 run carries the harness only; a
    Stage 2 run also names its step and the compiled rule set to install.
    Unset Stage 2 fields are left out of the encoding, so a Stage 1 input
    keeps the bytes and digest it had before Stage 2 existed."""

    job_id: str
    harness_ref: str
    execution_harness_id: str
    step: Literal["gate", "campaign", "replay"] | None = None
    compiled_ref: str | None = None
    gate_repetitions: int | None = None     # gate
    campaign_id: str | None = None          # campaign, replay
    crash_bundle_ref: str | None = None     # replay

    @model_serializer(mode="wrap")
    def _omit_unset_stage2(self, handler):
        data = handler(self)
        for key in ("step", "compiled_ref", "gate_repetitions",
                    "campaign_id", "crash_bundle_ref"):
            if data.get(key) is None:
                data.pop(key, None)
        return data


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
    #: A Stage 2 Runner task's input (09 §4).  A Stage 1 run's input is
    #: the job's harness, so it is not stored.
    runner_input: RunnerInput | None = None


class Counters(Record):
    """09 §6."""

    agent_repair_stage1: int = 0
    agent_repair_stage2: int = 0
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


class CampaignTally(Record):
    """What a campaign's segments add up to (01 §12, 09 §4).  The
    thresholds that read it are JobPolicy's."""

    segments: int = 0
    executions: int = 0
    reached_generations: int = 0
    hypothesis_applied: int = 0
    hypothesis_not_applied: int = 0
    hypothesis_inconclusive: int = 0
    #: Q2 OBSERVED segments with an APPLIED rule in their window.
    applied_crashes: int = 0


class Campaign(Record):
    """One Stage2Campaign (01 §3): one candidate, harness and compiled rule
    set.  Started when the gate passes; continued by new Runner tasks."""

    campaign_id: str
    compiled_ref: str
    rule_set_ref: str
    binding: HarnessBinding
    harness_ref: str
    execution_harness_id: str
    gate_consumed: tuple[str, ...] = ()
    tally: CampaignTally = Field(default_factory=CampaignTally)


class BundleCursor(Record):
    """A Runner task that seals bundles while it runs (a campaign task):
    how many of its bundles the job has taken, in order (09 §8)."""

    task_id: str
    campaign_id: str
    compiled: CompiledRuleSet
    delivered: int = 0


class CrashRef(Record):
    """A crash to replay: the campaign bundle and the identity it ran on
    (03-nfs-proxy/05 §25, §26)."""

    bundle_ref: str
    campaign_id: str
    compiled: CompiledRuleSet
    binding: HarnessBinding
    harness_ref: str
    execution_harness_id: str
    q2_verdict_id: str
    m1_verdict_id: str


class Replay(Record):
    """The replay in progress or under review, and where the job goes
    after crash_review (09 §4).  ``resume`` already reflects a binding
    change during the replay (09 §5)."""

    crash: CrashRef
    resume: Target
    outcome: ReplayOutcome | None = None


class TriageItem(Record):
    """09 §4: a human review item that does not change the job's state.

    ``routing`` says what happened to an APPLIED crash among them:
    ``none`` (no APPLIED rule in its window, or no signal), ``replayed``
    (it went to s2_replaying), ``queued`` (another crash of the campaign
    was under replay or review; crash_review replays it next) or
    ``unrouted`` (it arrived after the campaign stopped and the job was
    elsewhere; only a person can take it further)."""

    campaign_id: str
    task_id: str
    bundle_ref: str
    q2_verdict_id: str
    q2_status: str
    q2_reason: str | None = None
    m1_verdict_id: str
    crash_window_applied: tuple[str, ...] = ()
    late: bool = False
    routing: Literal["none", "replayed", "queued", "unrouted"] = "none"


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
    #: Late Runner cleanup reports already applied, as "task_id:generation",
    #: so a report re-sent after a lost acknowledgement applies once.
    cleanup_reports_applied: tuple[str, ...] = ()
    resume_point: Target | None = None
    analysis_ref: str | None = None
    plan_ref: str | None = None
    harness: Materialized | None = None
    approved_manifests: tuple[str, ...] = ()
    last_verdict: ConsumedVerdict | None = None
    stage2_input: Stage2Input | None = None
    #: The Stage2Input a started Stage 2 works from (01 §5.1).  Kept while
    #: the job is in Stage 2 or waits to return there; cleared when it
    #: goes back to Stage 1 work.
    stage2_basis: Stage2Input | None = None
    rule_set_ref: str | None = None
    compiled: CompiledRuleSet | None = None
    #: The last gate's judged repetitions (01 §3).
    gate_runs: tuple[GateRun, ...] = ()
    campaign: Campaign | None = None
    bundle_cursors: tuple[BundleCursor, ...] = ()
    replay: Replay | None = None
    #: APPLIED crashes of the campaign under review, replayed next.
    crash_queue: tuple[CrashRef, ...] = ()
    triage: tuple[TriageItem, ...] = ()
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
    #: What the run used, when its runtime counted it (#75).
    usage: AgentUsage | None = None
