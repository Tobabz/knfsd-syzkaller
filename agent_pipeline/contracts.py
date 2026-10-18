"""Data contracts the Stage 1 Controller reads and writes.

Each model is the Python form of a contract another document owns; the
section is named on the class.  Records are immutable (frozen) and refuse
fields their contract does not have (extra="forbid"), so a typo or a guest
value cannot ride along unnoticed.
"""

from __future__ import annotations

import enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Commit = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]


class Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------- candidate


class LocationKind(str, enum.Enum):
    FUNCTION = "function"
    SOURCE_RANGE = "source_range"


class LocationRequest(Record):
    """What a caller submits (02 §4).  Lines are resolved by intake for a
    function; a range gives them."""

    kind: LocationKind
    path: str
    symbol: str | None = None
    start_line: int | None = None
    end_line: int | None = None


class CandidateSubmission(Record):
    """Untrusted input: the commit may be anything until intake proves it."""

    kernel_commit: str
    location: LocationRequest


class CandidateLocation(Record):
    kind: LocationKind
    path: str
    symbol: str | None = None
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def _shape(self) -> CandidateLocation:
        if (self.kind is LocationKind.FUNCTION) != (self.symbol is not None):
            raise ValueError("symbol is required for a function and only then")
        if self.end_line < self.start_line:
            raise ValueError("end_line before start_line")
        return self


class VulnerabilityCandidate(Record):
    """02 §4: the accepted candidate, immutable."""

    candidate_id: str
    kernel_commit: Commit
    location: CandidateLocation


# ---------------------------------------------------------------- policy


class Sanitizer(str, enum.Enum):
    KASAN = "kasan"
    KCSAN = "kcsan"


class AgentModelPolicy(Record):
    """Trusted model selection for one Agent Task execution.

    The provider and requested model are policy, not Candidate or Agent
    output.  ``output_retries`` is the structured-output repair allowance
    inside one execution; exhausting it is one Agent failure for the
    Controller's separate ``agent_retry_limit`` accounting (09 §6).
    """

    provider: str = Field(min_length=1, max_length=64,
                          pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    model: str = Field(min_length=1, max_length=160,
                       pattern=r"^[^\s:]+$")
    output_retries: int = Field(default=2, ge=0, le=8)
    max_output_tokens: int = Field(default=8192, ge=256, le=65536)

    @property
    def requested_model_id(self) -> str:
        return f"{self.provider}:{self.model}"


class Stage1AgentPolicy(Record):
    """Task-specific model policy selected by the trusted Controller."""

    candidate_analysis: AgentModelPolicy = Field(default_factory=lambda:
        AgentModelPolicy(provider="openai", model="gpt-5"))
    reachability_planning: AgentModelPolicy = Field(default_factory=lambda:
        AgentModelPolicy(provider="openai", model="gpt-5"))


class Stage2AgentPolicy(Record):
    """Model policy of the Stage 2 Agent Task (08 §1)."""

    mutation_strategy: AgentModelPolicy = Field(default_factory=lambda:
        AgentModelPolicy(provider="openai", model="gpt-5"))


class JobPolicy(Record):
    """01 §11.1, 09 §6.  Limits count retries: how many times the counted
    thing may happen after the first try.  With a limit of 1 one repair runs
    and the next blocks.

    Defaults (owner decision, 2026-10-13): three Stage 1 repairs, three
    Agent retries, three Runner reruns, no human approval before a run.
    run_stage2 becomes true by default once Stage 2 is implemented.  The
    backend and judges are in, but no gate, campaign or replay has run on a
    real VM and the campaign thresholds below are placeholders, so it
    stays false by default: a policy may opt in, and otherwise an operator
    starts Stage 2 of a reached job.  The Stage 2 repair budget follows the
    Stage 1 default."""

    policy_id: str
    sanitizer: Sanitizer
    approval_required: bool = False
    # False: a REACHED job waits in s1_reached (09 rationale 11).  True on
    # a host without a Stage 2 backend leaves the job in
    # blocked_operator(stage2_gate_unavailable) after compiling.
    run_stage2: bool = False
    stage1_agents: Stage1AgentPolicy = Field(default_factory=Stage1AgentPolicy)
    stage2_agents: Stage2AgentPolicy = Field(default_factory=Stage2AgentPolicy)
    stage1_repair_budget: int = Field(default=3, ge=1)
    stage2_repair_budget: int = Field(default=3, ge=1)
    agent_retry_limit: int = Field(default=3, ge=1)
    runtime_retry_limit: int = Field(default=3, ge=1)
    # Stage 2 execution policy (01 §3, §11.1, §12).  The values are not
    # owner decisions; they only bound the loop until someone sets them.
    #: Repetitions of the baseline-with-rules gate in one gate task.
    gate_repetitions: int = Field(default=1, ge=1)
    #: Reached generations with no hypothesis APPLIED after which the
    #: campaign goes back to Mutation Strategy (campaign_not_applied).
    campaign_not_applied_generations: int = Field(default=1000, ge=1)
    #: Reached generations with a hypothesis APPLIED, and no APPLIED crash
    #: in the campaign, after which it is refined (campaign_no_signal).
    campaign_no_signal_generations: int = Field(default=10000, ge=1)
    #: Reached generations whose hypothesis M1 is INCONCLUSIVE after which
    #: the evidence path goes to an operator (evidence_path).
    campaign_inconclusive_generations: int = Field(default=100, ge=1)
    #: Program executions a campaign may run before an operator decides.
    fuzz_budget_executions: int = Field(default=100000, ge=1)


# ---------------------------------------------------------------- binding


class HarnessBinding(Record):
    """01 §11.2: the validated harness build for a commit and sanitizer,
    and the HCAP revision of the same repository revision."""

    kernel_commit: Commit
    sanitizer: Sanitizer
    execution_harness_id: Sha256
    hcap_revision: str


# ---------------------------------------------------------------- gaps


class GapClass(str, enum.Enum):
    """07 §4."""

    SYZLANG = "syzlang"
    PSEUDO_SYSCALL_EXECUTOR = "pseudo_syscall_executor"
    FIXTURE_OR_TOOL = "fixture_or_tool"
    MUTATION_ENGINE = "mutation_engine"
    REMOTE_KCOV_ATTRIBUTION = "remote_kcov_attribution"


class GapRef(Record):
    """The key of a HarnessGapIssue (07 §3)."""

    gap_class: GapClass
    missing_capability_id: str


def kernel_revision_gap(commit: str) -> GapRef:
    return GapRef(gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
                  missing_capability_id=f"remote_kcov.kernel_revision.{commit}")


# ---------------------------------------------------------------- Q1


class Q1Status(str, enum.Enum):
    REACHED = "reached"
    NOT_REACHED = "not_reached"
    INCONCLUSIVE = "inconclusive"


class Q1Result(Record):
    """06 §7.  `reason` stays a string: a value 06 §10 does not define must
    reach the Controller and route to unexpected_event (09 §2), not fail
    parsing."""

    verdict_id: str
    candidate_id: str
    execution_harness_id: Sha256
    judge_profile_id: str
    support_boundary_id: str
    evidence_manifest_sha256: Sha256
    status: Q1Status
    reason: str | None = None
    gap_signal: GapRef | None = None


class JudgeVersions(Record):
    """The EvaluationIdentity parts a Q1 Judge run uses (01 §11.2)."""

    judge_profile_id: str
    support_boundary_id: str


# ---------------------------------------------------------------- Agent


class AgentTask(str, enum.Enum):
    CANDIDATE_ANALYSIS = "candidate_analysis"
    REACHABILITY_PLANNING = "reachability_planning"
    MUTATION_STRATEGY = "mutation_strategy"


class AnalysisOutput(Record):
    """03 §5, stored as an artifact; the Controller routes on the variant."""

    variant: Literal["analysis"] = "analysis"
    analysis_ref: Sha256


class PlanOutput(Record):
    """05 §4."""

    variant: Literal["plan"] = "plan"
    plan_ref: Sha256


class RuleSetOutput(Record):
    """08 §5, a MutationRuleSet stored as an artifact."""

    variant: Literal["rule_set"] = "rule_set"
    rule_set_ref: Sha256


class UnsupportedOutput(Record):
    """05 §8, 07 §3.  An empty missing_capability_id is allowed here and
    routes to an operator (09 §2, Agent guidance)."""

    variant: Literal["unsupported"] = "unsupported"
    gap_class: GapClass
    missing_capability_id: str
    reason: str


class ReanalysisRequired(Record):
    """03 §14, 09 rationale 6."""

    variant: Literal["reanalysis_required"] = "reanalysis_required"
    reason: str


AgentOutput = Annotated[
    Union[AnalysisOutput, PlanOutput, RuleSetOutput, UnsupportedOutput,
          ReanalysisRequired],
    Field(discriminator="variant"),
]

#: Variants each Agent Task may return (09 §2).  Anything else is an
#: unexpected event.
TASK_VARIANTS = {
    AgentTask.CANDIDATE_ANALYSIS: {"analysis"},
    AgentTask.REACHABILITY_PLANNING: {"plan", "unsupported",
                                      "reanalysis_required"},
    AgentTask.MUTATION_STRATEGY: {"rule_set", "unsupported"},
}


# ---------------------------------------------------------------- components


class HcapCheck(Record):
    """The deterministic plan check against one HCAP revision (04 §1.1).

    ``host_authority`` marks a host-side catalog integrity failure: no plan
    change can fix it, so it is not an Agent repair finding.
    """

    violations: tuple[str, ...] = ()
    host_authority: bool = False

    @property
    def ok(self) -> bool:
        return not self.violations


class Materialized(Record):
    """05 §12: a ReachabilityHarness and its review manifest."""

    harness_ref: Sha256
    review_manifest_sha256: Sha256
    execution_harness_id: Sha256
    # None loads records written before materialization authority provenance
    # was persisted.  The Controller treats those records as stale and
    # rematerializes them before another Runner dispatch.
    hcap_revision: str | None = None
    # A later HCAP revision under which the Controller re-validated the plan
    # and found the HCAP-derived authority refs (call admission profile,
    # neutral control catalog) unchanged (09 §5).  The harness itself stays
    # the one built under `hcap_revision`.
    authority_hcap_revision: str | None = None


class MaterializationHcapAuthority(Record):
    """HCAP authority selected for one materialization.

    A new Agent plan must name the effective revision exactly.  A stored plan
    may instead be materialized under a compatible replacement revision after
    the Controller has revalidated it.  The Materializer still repeats the
    complete plan/catalog validation under that effective revision; this flag
    only makes the otherwise deliberate revision mismatch explicit.
    """

    effective_hcap_revision: str
    validation: Literal["exact_plan_revision", "compatible_replacement"]


NEUTRAL_CONTROL_UNAVAILABLE = "neutral_control_unavailable"
#: Host-side authority (build approval, HCAP or admission records, parser
#: identity) is unusable.  No plan change can fix it (09 §3).
HOST_AUTHORITY_UNAVAILABLE = "host_authority_unavailable"


class MaterializeRejected(Record):
    """05 §13: a typed refusal.  `profile` names the runtime selection when
    the reason is neutral_control_unavailable."""

    reason: str
    detail: str = ""
    profile: str | None = None



# ---------------------------------------------------------------- Stage 2

#: Mutation Rule Compiler refusals (08 §12).  The Agent can fix these.
COMPILER_AGENT_FIXABLE = frozenset({
    "unknown_path", "type_mismatch", "message_type_inconsistent",
    "selector_mismatch", "missing_required_field"})
#: Schema-valid, but the runtime cannot do it: a mutation_engine gap.
COMPILER_GAP = frozenset({"unsupported_capability", "requires_state_lineage"})


class CompiledRuleSet(Record):
    """08 §12: the CompiledMutationRule[] artifact of one rule set."""

    rule_set_ref: Sha256
    compiled_ref: Sha256
    hcap_revision: str


class CompileRejected(Record):
    """08 §12: a typed refusal.  ``reason`` stays a string so a value 08
    does not name reaches the Controller and routes to unexpected_event.
    A gap reason names the HCAP vocabulary id it lacks."""

    reason: str
    intent_id: str | None = None
    detail: str = ""
    missing_capability_id: str | None = None


# ---------------------------------------------------------------- Stage 2
# execution verdicts.  Statuses stay strings, like Q1Result.reason: a value
# the contracts do not name reaches the Controller and routes to
# unexpected_event (09 §2) instead of failing to parse.

M1_STATUSES = frozenset({"applied", "not_applied", "inconclusive"})
Q2_STATUSES = frozenset({"observed", "not_observed", "inconclusive"})
REPLAY_STATUSES = frozenset({"replay_equivalent", "replay_diverged",
                             "replay_inconclusive", "replay_invalid"})
#: The replay bundle failed manifest or correlation checks: no comparison
#: verdict is made from it (01 §11.1, 03-nfs-proxy/05 §29).
REPLAY_EVIDENCE_REJECTED = "evidence_rejected"


class RuleM1(Record):
    """01 §7.1, one rule in one gate execution."""

    rule_id: str
    intent_id: str
    status: str


class IntentM1(Record):
    """01 §7.1 intent aggregate.  ``targets_baseline_traffic`` comes from
    the MutationRuleSet the Judge read (08 §16)."""

    intent_id: str
    status: str
    targets_baseline_traffic: bool


class GateRun(Record):
    """One judged repetition of the baseline-with-rules gate (01 §3): the
    Stage 1 scenario with the rule set installed, and its neutral run.

    ``ambient`` holds the control flags (``q1_preservation_unverifiable``,
    ``ambient_applied:<rule>``, ``ambient_control_unavailable``).  They are
    recorded and never change the route."""

    bundle_ref: str
    q1: Q1Result
    m1_verdict_id: str
    rules: tuple[RuleM1, ...]
    intents: tuple[IntentM1, ...]
    ambient: tuple[str, ...] = ()


class CampaignSegment(Record):
    """One sealed campaign bundle (a fuzz VM instance's execution span),
    judged (01 §3, §8.2, §12).

    The generation counts are over generations whose Stage 2 Q1 was
    REACHED: ``hypothesis_applied`` counts those where some hypothesis was
    APPLIED, ``hypothesis_not_applied`` those where every hypothesis was
    NOT_APPLIED, and ``hypothesis_inconclusive`` the rest.
    ``crash_window_applied`` names the rules APPLIED in the
    CrashContextWindow of an observed signal (01 §8.1)."""

    bundle_ref: str
    q2_verdict_id: str
    q2_status: str
    q2_reason: str | None = None
    m1_verdict_id: str
    crash_window_applied: tuple[str, ...] = ()
    executions: int = Field(ge=0)
    reached_generations: int = Field(ge=0)
    hypothesis_applied: int = Field(ge=0)
    hypothesis_not_applied: int = Field(ge=0)
    hypothesis_inconclusive: int = Field(ge=0)


class ReplayOutcome(Record):
    """The replay comparator's verdict on a sealed replay bundle
    (03-nfs-proxy/05 §29), or ``evidence_rejected``."""

    verdict_id: str
    status: str
    reason: str | None = None
