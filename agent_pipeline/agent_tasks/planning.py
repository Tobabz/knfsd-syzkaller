"""Structured reasoning output for Reachability Planning (05 §4-§10)."""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import ConfigDict, Field, RootModel, model_validator

from ..contracts import GapClass, Record, Sha256
from ..hcap import (CapabilityUse, ExecutionConstraint, Identifier, NfsVersion,
                    Q1Observation, ReachabilityPlan, RuntimeSelection,
                    ScenarioStep, SelectedPath)
from .analysis import LongText, ShortText, SourcePath

MAX_PROGRAM_CHARS = 256 * 1024


class InlineProgram(Record):
    kind: Literal["program"] = "program"
    text: str = Field(min_length=1, max_length=MAX_PROGRAM_CHARS)


class ExistingSeed(Record):
    kind: Literal["seed"] = "seed"
    artifact_ref: Sha256
    seed_manifest_ref: Sha256
    seed_id: Identifier


ProgramDraft = Annotated[
    Union[InlineProgram, ExistingSeed], Field(discriminator="kind")]


class ReachabilityPlanDraft(Record):
    """A plan before the host stores an inline program by digest."""

    schema_version: Literal["reachability-plan-draft.v1"] = \
        "reachability-plan-draft.v1"
    candidate_id: ShortText
    hcap_revision: Sha256
    selected_path: SelectedPath
    nfs_version: NfsVersion
    scenario_steps: tuple[ScenarioStep, ...] = Field(
        min_length=1, max_length=128)
    required_capabilities: tuple[Identifier, ...] = Field(
        min_length=1, max_length=128)
    capability_uses: tuple[CapabilityUse, ...] = Field(
        min_length=1, max_length=128)
    q1_observation: Q1Observation
    program: ProgramDraft
    runtime_selection: RuntimeSelection
    execution_constraints: tuple[ExecutionConstraint, ...] = Field(
        max_length=64)
    uncertainties: tuple[LongText, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def _shape(self) -> ReachabilityPlanDraft:
        required = set(self.required_capabilities)
        if len(required) != len(self.required_capabilities):
            raise ValueError("duplicate required capability ID")
        uses = tuple(use.capability_id for use in self.capability_uses)
        if len(set(uses)) != len(uses) or set(uses) != required:
            raise ValueError("each required capability needs exactly one use")
        if any(step.capability_id not in required
               for step in self.scenario_steps):
            raise ValueError(
                "scenario step references a non-required capability")
        if self.q1_observation.capability_id not in required:
            raise ValueError("Q1 oracle must reference a required capability")
        if self.nfs_version != self.runtime_selection.nfs_version:
            raise ValueError("plan and runtime NFS versions differ")
        return self


class Planned(Record):
    variant: Literal["plan"] = "plan"
    plan: ReachabilityPlanDraft


class ProposalSourceEvidence(Record):
    """Kernel source that shows the condition the plan cannot create."""

    source_path: SourcePath
    symbol: ShortText | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    note: LongText


class InsufficientCapability(Record):
    """Why one promoted HCAP entry cannot create the condition."""

    capability_id: Identifier
    reason: LongText


class CapabilityProposal(Record):
    """A typed proposal for a capability no promoted HCAP entry provides
    (#75 step 8).  Data for a person and a coding agent with a shell; the
    pipeline never creates or promotes HCAP entries from it.  Promotion
    still needs typed KVM evidence and owner approval."""

    schema_version: Literal["capability-proposal.v1"] = \
        "capability-proposal.v1"
    #: The missing layer: syzlang, pseudo-syscall/executor, fixture or
    #: tool, or remote-KCOV attribution context.
    layer: Literal["syzlang", "pseudo_syscall_executor", "fixture_or_tool",
                   "remote_kcov_attribution"]
    summary: ShortText
    #: The condition on the selected path that must be created.
    required_condition: LongText
    source_evidence: tuple[ProposalSourceEvidence, ...] = Field(
        min_length=1, max_length=16)
    insufficient_capabilities: tuple[InsufficientCapability, ...] = Field(
        max_length=32)
    #: The interface to add: calls, pseudo-syscall, fixture or attribution.
    proposed_interface: LongText
    #: The KVM evidence that would let an owner promote it.
    promotion_evidence: tuple[LongText, ...] = Field(
        min_length=1, max_length=16)


class Unsupported(Record):
    variant: Literal["unsupported"] = "unsupported"
    gap_class: GapClass
    missing_capability_id: str = Field(min_length=1, max_length=256)
    reason: LongText
    proposal: CapabilityProposal | None = None

    @model_validator(mode="after")
    def _layer(self) -> Unsupported:
        if self.proposal is not None and \
                self.proposal.layer != self.gap_class.value:
            raise ValueError("proposal layer must equal gap_class")
        return self


class ReanalysisRequired(Record):
    variant: Literal["reanalysis_required"] = "reanalysis_required"
    reason: LongText


PlanningDecision = Annotated[
    Union[Planned, Unsupported, ReanalysisRequired],
    Field(discriminator="variant"),
]


class ReachabilityPlanningOutput(RootModel[PlanningDecision]):
    """A top-level discriminated union accepted as structured output."""

    model_config = ConfigDict(frozen=True)


def completed_plan(draft: ReachabilityPlanDraft,
                   program_ref: str) -> ReachabilityPlan:
    """Convert a validated draft after the host stores its program bytes."""

    if isinstance(draft.program, ExistingSeed):
        proposal = {
            "kind": "seed",
            "artifact_ref": draft.program.artifact_ref,
            "seed_manifest_ref": draft.program.seed_manifest_ref,
            "seed_id": draft.program.seed_id,
        }
    else:
        proposal = {"kind": "program", "artifact_ref": program_ref}
    values = draft.model_dump(mode="python", exclude={"program"})
    values["schema_version"] = "reachability-plan.v1"
    values["program_proposal"] = proposal
    return ReachabilityPlan.model_validate(values)
