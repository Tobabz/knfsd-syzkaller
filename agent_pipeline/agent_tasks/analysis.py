"""Structured output of Candidate Analysis (03 §5-§10)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from ..contracts import Record

ShortText = Annotated[str, Field(min_length=1, max_length=512, pattern=r"\S")]
LongText = Annotated[str, Field(min_length=1, max_length=4096,
                                pattern=r"\S")]
SourcePath = Annotated[str, Field(min_length=1, max_length=512,
                                  pattern=r"^[^\x00]+$")]


class CodeRole(Record):
    summary: LongText
    subsystem: ShortText
    relevant_objects: tuple[ShortText, ...] = Field(max_length=64)


class CallPathStep(Record):
    source_path: SourcePath
    symbol: ShortText
    role: LongText


class RequiredState(Record):
    category: ShortText
    description: LongText
    setup_condition: LongText


class ControllableInput(Record):
    direction: Literal[
        "C2S", "S2C", "local_client_action", "timing/concurrency"]
    surface: ShortText
    semantic_target: LongText
    available_control: Literal[
        "existing syscall", "existing syzlang", "raw NFS/RPC send",
        "proxy", "fixture action", "concurrency/order"]


class ReachabilityPath(Record):
    entry_surface: Literal[
        "nfs_request", "rpc_callback", "client_vfs_operation",
        "background_work", "timer", "cleanup", "reclaim"]
    steps: tuple[CallPathStep, ...] = Field(min_length=1, max_length=128)
    required_state: tuple[RequiredState, ...] = Field(max_length=64)
    controllable_inputs: tuple[ControllableInput, ...] = Field(max_length=64)


class ReusableCapability(Record):
    capability_id: ShortText
    purpose: LongText


class HarnessGap(Record):
    kind: Literal[
        "syzlang", "pseudo_syscall", "seed/scenario", "fixture",
        "state_setup", "observability", "unsupported"]
    description: LongText


class HarnessAssessment(Record):
    reusable: tuple[ReusableCapability, ...] = Field(max_length=128)
    gaps: tuple[HarnessGap, ...] = Field(max_length=128)


class ObservabilityConstraint(Record):
    description: LongText


class Uncertainty(Record):
    description: LongText
    impact_on_reachability: LongText


class CandidateAnalysis(Record):
    """The Agent may identify gaps here but cannot declare unsupported."""

    schema_version: Literal["candidate-analysis.v1"] = "candidate-analysis.v1"
    candidate_id: ShortText
    code_role: CodeRole
    reachability_paths: tuple[ReachabilityPath, ...] = Field(
        min_length=1, max_length=32)
    harness_assessment: HarnessAssessment
    observability_constraints: tuple[ObservabilityConstraint, ...] = Field(
        max_length=64)
    uncertainties: tuple[Uncertainty, ...] = Field(max_length=64)
