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


class JobPolicy(Record):
    """01 §11.1, 09 §6.  Limits count retries: how many times the counted
    thing may happen after the first try.  With a limit of 1 one repair runs
    and the next blocks.

    Defaults (owner decision, 2026-10-13): three Stage 1 repairs, three
    Agent retries, three Runner reruns, no human approval before a run.
    run_stage2 becomes true by default once Stage 2 is implemented; until
    then it only accepts false."""

    policy_id: str
    sanitizer: Sanitizer
    approval_required: bool = False
    # Stage 2 is not implemented yet (decision record, decision 1); a
    # REACHED job waits in s1_reached (09 rationale 11).
    run_stage2: Literal[False] = False
    stage1_agents: Stage1AgentPolicy = Field(default_factory=Stage1AgentPolicy)
    stage1_repair_budget: int = Field(default=3, ge=1)
    agent_retry_limit: int = Field(default=3, ge=1)
    runtime_retry_limit: int = Field(default=3, ge=1)


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


class AnalysisOutput(Record):
    """03 §5, stored as an artifact; the Controller routes on the variant."""

    variant: Literal["analysis"] = "analysis"
    analysis_ref: Sha256


class PlanOutput(Record):
    """05 §4."""

    variant: Literal["plan"] = "plan"
    plan_ref: Sha256


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
    Union[AnalysisOutput, PlanOutput, UnsupportedOutput, ReanalysisRequired],
    Field(discriminator="variant"),
]

#: Variants each Agent Task may return (09 §2).  Anything else is an
#: unexpected event.
TASK_VARIANTS = {
    AgentTask.CANDIDATE_ANALYSIS: {"analysis"},
    AgentTask.REACHABILITY_PLANNING: {"plan", "unsupported",
                                      "reanalysis_required"},
}


# ---------------------------------------------------------------- components


class HcapCheck(Record):
    """The deterministic plan check against one HCAP revision (04 §1.1)."""

    violations: tuple[str, ...] = ()

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

