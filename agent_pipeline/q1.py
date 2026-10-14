"""Bounded, pure Q1 decision kernel (06 §5–§10 and 01 §11.1).

The caller is the Controller's trusted adapter, NOT the guest. It must verify
the sealed manifest and its artifacts, derive ``expected_*`` from host records,
load the authoritative profile/boundary, and bind the collected PCs/counters to
that manifest before setting ``evidence_verified``. A guest's verification flag
or a self-consistent guest correlation is not sufficient.

``TargetPcMapping`` is an externally verified source-to-runtime-PC mapping. Its
whole candidate (including a function's resolved range), vmlinux, instrumentation,
execution identity and KASLR relocation must match this run. Automatic DWARF
mapping, artifact I/O, runtime collection and the components.Q1Judge adapter are
deliberately outside this module. No production support boundary is inferred.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contracts import GapClass, GapRef, Q1Result, Q1Status
from .data import canonical_json

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Commit = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
Text = Annotated[str, Field(min_length=1)]
Context = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")]
Count = Annotated[int, Field(ge=0, le=2**64 - 1)]
Positive = Annotated[int, Field(ge=1, le=2**64 - 1)]
Reason = Literal["infra", "evidence", "loss", "mapping", "unsupported_attribution"]


def _digest(value: object) -> str:
    return sha256(canonical_json(value)).hexdigest()


class _Record(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, validate_default=True,
        revalidate_instances="always", allow_inf_nan=False,
    )

    @property
    def digest(self) -> str:
        """Digest of the versioned canonical record, without a self reference."""
        return _digest(self)


class CandidateTarget(_Record):
    """An intake-accepted target; function ranges must already be resolved."""

    candidate_id: Text
    kernel_commit: Commit
    kind: Literal["function", "source_range"]
    path: Text
    symbol: Text | None = None
    start_line: Positive
    end_line: Positive

    @model_validator(mode="after")
    def _source_shape(self) -> Self:
        if "\\" in self.path or any(p in ("", ".", "..") for p in self.path.split("/")):
            raise ValueError("target path must be repository-relative and normalized")
        if (self.kind == "function") != (self.symbol is not None):
            raise ValueError("a symbol is required exactly for a function target")
        if self.end_line < self.start_line:
            raise ValueError("end_line precedes start_line")
        return self


class KernelIdentity(_Record):
    """Mapping-relevant projection of the host's full execution identity.

    The adapter verifies execution_harness_id against the full identity (which
    also binds config, command line, syzkaller, proxy, and image). kaslr_offset
    is the runtime relocation verified for this VM, not a guessed default.
    """

    execution_harness_id: Digest
    kernel_commit: Commit
    instrumentation_sha256: Digest
    vmlinux_sha256: Digest
    kaslr_enabled: bool
    kaslr_offset: Count

    @model_validator(mode="after")
    def _relocation(self) -> Self:
        if not self.kaslr_enabled and self.kaslr_offset != 0:
            raise ValueError("disabled KASLR requires a zero relocation")
        return self


class ExecutionCorrelation(_Record):
    """Host-stamped execution position, compared in full with observation."""

    job_id: Text
    task_id: Text
    execution_harness_id: Digest
    vm_instance_id: Text
    lane: Count
    generation_id: Positive


class ObservationRequirement(_Record):
    target: CandidateTarget
    expected_context: Context
    oracle: Literal["generation_attributed_remote_kcov"] = "generation_attributed_remote_kcov"


class CounterLimit(_Record):
    counter: Text
    max_delta: Count = 0


class ContextLossPolicy(_Record):
    """Required deltas in one exact profile-defined window.

    Window labels denote intervals already verified by the adapter. The profile
    author must include post-FINISH late sections where applicable; this kernel
    cannot prove time boundaries from a label. Normal counter movement outside
    the named window must not be substituted for a required in-window delta.
    """

    context: Context
    window: Text
    counters: Annotated[tuple[CounterLimit, ...], Field(min_length=1)]
    normal_counters: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def _unique_counters(self) -> Self:
        names = tuple(rule.counter for rule in self.counters)
        if len(set(names)) != len(names) or len(set(self.normal_counters)) != len(self.normal_counters):
            raise ValueError("duplicate counter policy")
        if set(names).intersection(self.normal_counters):
            raise ValueError("a required loss counter cannot also be normal")
        return self


class Q1AdmissibilityProfile(_Record):
    """Trusted, versioned evaluation policy; ``digest`` is judge_profile_id.

    Required generation integrity cannot be disabled by this policy. Counts in
    GenerationCounters describe the single correlated generation; remote starts
    can occur multiple times. A missing context policy never permits a miss.
    """

    schema_version: Literal["q1-admissibility-v1"] = "q1-admissibility-v1"
    name: Text
    revision: Text
    minimum_remote_start_ok: Positive = 1
    allowed_trace_modes: Annotated[tuple[Text, ...], Field(min_length=1)]
    contexts: tuple[ContextLossPolicy, ...]

    @model_validator(mode="after")
    def _unique_contexts(self) -> Self:
        contexts = tuple(policy.context for policy in self.contexts)
        if len(set(contexts)) != len(contexts):
            raise ValueError("duplicate context policy")
        if len(set(self.allowed_trace_modes)) != len(self.allowed_trace_modes):
            raise ValueError("duplicate trace mode")
        return self


class RemoteKcovSupportBoundary(_Record):
    """Trusted attribution-patch boundary; ``digest`` is support_boundary_id.

    Matching source commit AND instrumentation digest is mandatory. A boundary
    is independent of sanitizer/vmlinux variants of that same patch series.
    """

    schema_version: Literal["remote-kcov-boundary-v1"] = "remote-kcov-boundary-v1"
    name: Text
    revision: Text
    kernel_commit: Commit
    instrumentation_sha256: Digest
    supported_contexts: tuple[Context, ...]

    @field_validator("supported_contexts")
    @classmethod
    def _unique_contexts(cls, contexts: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(contexts)) != len(contexts):
            raise ValueError("duplicate supported context")
        return contexts


class TargetPcMapping(_Record):
    """Trusted external mapping to runtime PCs, already relocated for KASLR.

    ``verified`` must be set by the Controller's mapper/validator. A guest's
    mapping claim must never be copied into it. Missing/empty/unverified mapping
    yields INCONCLUSIVE(mapping), including when the coverage is empty.
    """

    schema_version: Literal["q1-target-pcs-v1"] = "q1-target-pcs-v1"
    mapping_method: Text
    verified: bool
    target: CandidateTarget
    identity: KernelIdentity
    target_pcs: tuple[Positive, ...]

    @field_validator("target_pcs")
    @classmethod
    def _pc_set(cls, pcs: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(sorted(set(pcs)))


class GenerationCounters(_Record):
    """Missing values are unknown, never implicit zero.

    generation_begin and aggregate_published are per-generation event deltas;
    outstanding_tokens and remote_refs are the drain snapshot. A published
    aggregate requires begin=publish=1, sufficient remote starts, and zero for
    all abort/overflow/truncation/drain fields.
    """

    generation_begin: Count | None = None
    remote_start_ok: Count | None = None
    aggregate_published: Count | None = None
    generation_aborted: Count | None = None
    scratch_overflow: Count | None = None
    merge_truncation: Count | None = None
    outstanding_tokens: Count | None = None
    remote_refs: Count | None = None


class CounterDelta(_Record):
    counter: Text
    window: Text | None = None
    value: Count | None = None


class RemoteKcovObservation(_Record):
    """Normalized sealed facts, not an execution authority or target verdict.

    Only published_pcs are an oracle. None means absent PCs; () means a collected
    empty aggregate. coverage_artifacts must identify its verified source bytes.
    The optional guest_target_observed claim is retained but never consulted.
    """

    candidate_id: Text
    identity: KernelIdentity
    correlation: ExecutionCorrelation | None
    boot_ok: bool
    fixture_ok: bool
    lane_ok: bool
    runner_completed: bool
    collection_started: bool
    collection_completed: bool
    generation_attributed: bool
    channel: Text
    lane_trace_mode: Text | None
    coverage_artifacts: tuple[Digest, ...]
    published_pcs: tuple[Positive, ...] | None
    generation: GenerationCounters
    counter_deltas: tuple[CounterDelta, ...] = ()
    internal_errors: tuple[Text, ...] = ()
    runtime_errors: tuple[Text, ...] = ()
    guest_target_observed: bool | None = None

    @field_validator("published_pcs")
    @classmethod
    def _pc_set(cls, pcs: tuple[int, ...] | None) -> tuple[int, ...] | None:
        return None if pcs is None else tuple(sorted(set(pcs)))

    @model_validator(mode="after")
    def _unique_deltas(self) -> Self:
        keys = tuple((delta.counter, delta.window) for delta in self.counter_deltas)
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate counter delta in the same window")
        return self


class Q1Input(_Record):
    schema_version: Literal["q1-input-v1"] = "q1-input-v1"
    candidate: CandidateTarget
    plan_ref: Digest
    hcap_revision: Text
    requirement: ObservationRequirement
    evidence_manifest_sha256: Digest
    evidence_verified: bool
    expected_identity: KernelIdentity
    expected_correlation: ExecutionCorrelation
    observation: RemoteKcovObservation
    profile: Q1AdmissibilityProfile
    boundary: RemoteKcovSupportBoundary
    mapping: TargetPcMapping | None


class Q1Decision(_Record):
    """Immutable deterministic verdict plus the references used to derive it."""

    schema_version: Literal["q1-decision-v1"] = "q1-decision-v1"
    verdict_id: Digest
    evaluation_input_sha256: Digest
    candidate_id: Text
    execution_harness_id: Digest
    plan_ref: Digest
    hcap_revision: Text
    judge_profile_id: Digest
    support_boundary_id: Digest
    evidence_manifest_sha256: Digest
    mapping_ref: Digest | None
    status: Q1Status
    reason: Reason | None
    gap_signal: GapRef | None
    target_observed: bool | None
    execution_valid: bool
    matched_pcs: tuple[Positive, ...]
    observations: tuple[Text, ...]

    def as_result(self) -> Q1Result:
        """Controller-compatible result; persist this decision for full lineage."""
        return Q1Result(
            verdict_id=self.verdict_id, candidate_id=self.candidate_id,
            execution_harness_id=self.execution_harness_id,
            judge_profile_id=self.judge_profile_id,
            support_boundary_id=self.support_boundary_id,
            evidence_manifest_sha256=self.evidence_manifest_sha256,
            status=self.status, reason=self.reason, gap_signal=self.gap_signal,
        )


def evaluate(inputs: Q1Input) -> Q1Decision:
    """Apply 06 §8 precedence without I/O or state.

    Schema/type violations raise pydantic.ValidationError. Well-typed missing,
    invalid or contradictory evidence returns INCONCLUSIVE. Revalidate even
    model instances so unvalidated model_copy/model_construct cannot bypass
    strict counters, frozen nested records, or unknown-field checks.
    """
    data = Q1Input.model_validate(inputs)
    obs, identity, profile = data.observation, data.expected_identity, data.profile
    generation = obs.generation

    def decide(status: Q1Status, reason: Reason | None, diagnostic: str, *,
               execution_valid: bool = False, target_observed: bool | None = None,
               matched_pcs: tuple[int, ...] = ()) -> Q1Decision:
        gap = None
        if reason == "unsupported_attribution":
            gap = GapRef(
                gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
                missing_capability_id=f"remote_kcov.context.{data.requirement.expected_context}",
            )
        fields = dict(
            schema_version="q1-decision-v1", evaluation_input_sha256=data.digest,
            candidate_id=data.candidate.candidate_id,
            execution_harness_id=identity.execution_harness_id,
            plan_ref=data.plan_ref, hcap_revision=data.hcap_revision,
            judge_profile_id=profile.digest, support_boundary_id=data.boundary.digest,
            evidence_manifest_sha256=data.evidence_manifest_sha256,
            mapping_ref=data.mapping.digest if data.mapping is not None else None,
            status=status, reason=reason, gap_signal=gap,
            target_observed=target_observed, execution_valid=execution_valid,
            matched_pcs=matched_pcs, observations=(diagnostic,),
        )
        # Convert the one nested existing contract to canonical JSON data.
        identity_fields = {**fields, "gap_signal": gap.model_dump(mode="json") if gap else None}
        return Q1Decision(verdict_id=_digest(identity_fields), **fields)

    def unknown(reason: Reason, diagnostic: str, *, valid: bool = False,
                observed: bool | None = None) -> Q1Decision:
        return decide(Q1Status.INCONCLUSIVE, reason, diagnostic,
                      execution_valid=valid, target_observed=observed)

    # 1. Host authority, evidence consistency and generation integrity.
    if not data.evidence_verified or obs.internal_errors:
        return unknown("evidence", "unverified_or_inconsistent_evidence")
    if (data.requirement.target != data.candidate
            or obs.candidate_id != data.candidate.candidate_id
            or data.candidate.kernel_commit != identity.kernel_commit):
        return unknown("evidence", "candidate_or_plan_target_mismatch")
    if obs.identity != identity:
        return unknown("evidence", "execution_identity_mismatch")
    if (data.boundary.kernel_commit != identity.kernel_commit
            or data.boundary.instrumentation_sha256 != identity.instrumentation_sha256):
        return unknown("evidence", "support_boundary_build_mismatch")
    if (obs.correlation != data.expected_correlation
            or data.expected_correlation.execution_harness_id != identity.execution_harness_id):
        return unknown("evidence", "generation_correlation_mismatch")
    counts = generation.model_dump()
    counters_complete = all(value is not None for value in counts.values())
    if ((generation.generation_begin is not None and generation.generation_begin > 1)
            or (generation.aggregate_published is not None
                and generation.aggregate_published > 1)):
        return unknown("evidence",
                       "multiple_generations_in_single_generation_evidence")
    if generation.aggregate_published:
        unsafe_known_publish = (
            (generation.generation_begin is not None
             and generation.generation_begin != 1)
            or (generation.remote_start_ok is not None
                and generation.remote_start_ok < profile.minimum_remote_start_ok)
            or (generation.generation_aborted is not None
                and generation.generation_aborted != 0)
            or (generation.scratch_overflow is not None
                and generation.scratch_overflow != 0)
            or (generation.merge_truncation is not None
                and generation.merge_truncation != 0)
            or (generation.outstanding_tokens is not None
                and generation.outstanding_tokens != 0)
            or (generation.remote_refs is not None and generation.remote_refs != 0)
        )
        if unsafe_known_publish:
            return unknown(
                "evidence", "published_aggregate_contradicts_generation_counters")

    # An early execution failure can legitimately precede attribution, trace
    # setup and generation-counter collection. Trust bindings and any
    # checkable publication contradictions above still take precedence.
    if not all((obs.boot_ok, obs.fixture_ok, obs.lane_ok, obs.runner_completed)) or obs.runtime_errors:
        return unknown("infra", "execution_incomplete_or_failed")
    if obs.channel != "remote_kcov" or not obs.generation_attributed:
        return unknown("evidence", "coverage_not_generation_attributed_remote_kcov")
    if obs.lane_trace_mode not in profile.allowed_trace_modes:
        return unknown("evidence", "trace_mode_missing_or_disallowed")
    if generation.aggregate_published is None:
        return unknown("evidence", "missing_generation_counter")
    if not generation.aggregate_published:
        loss_counters = (generation.scratch_overflow, generation.merge_truncation)
        if any(value is not None and value != 0 for value in loss_counters):
            return unknown("loss", "aggregate_unpublished_after_coverage_loss")
        if any(value is None for value in loss_counters):
            return unknown("evidence", "missing_generation_counter")
        generation_failure = (
            None if generation.generation_aborted is None
            else generation.generation_aborted != 0,
            None if generation.outstanding_tokens is None
            else generation.outstanding_tokens != 0,
            None if generation.remote_refs is None else generation.remote_refs != 0,
            None if generation.generation_begin is None else generation.generation_begin != 1,
            None if generation.remote_start_ok is None
            else generation.remote_start_ok < profile.minimum_remote_start_ok,
        )
        if any(failed is True for failed in generation_failure):
            return unknown("infra", "aggregate_unpublished_after_generation_failure")
        if any(failed is None for failed in generation_failure):
            return unknown("evidence", "missing_generation_counter")
        return unknown("evidence", "current_generation_aggregate_absent")
    if not counters_complete:
        return unknown("evidence", "missing_generation_counter")
    if not obs.collection_started or not obs.collection_completed:
        return unknown("evidence", "coverage_collection_incomplete")
    if obs.published_pcs is None or not obs.coverage_artifacts:
        return unknown("evidence", "published_coverage_artifact_absent")

    # 2. External mapping availability and binding, including resolved range.
    mapping = data.mapping
    if mapping is not None and (mapping.target != data.candidate or mapping.identity != identity):
        return unknown("evidence", "mapping_target_or_build_mismatch")
    if mapping is None or not mapping.verified or not mapping.target_pcs:
        return unknown("mapping", "target_pc_mapping_unavailable", valid=True)

    # 3. A valid hit precedes unsupported contexts and permissible-loss gates.
    matched = tuple(sorted(set(mapping.target_pcs).intersection(obs.published_pcs)))
    if matched:
        return decide(Q1Status.REACHED, None, "target_pc_in_published_remote_coverage",
                      execution_valid=True, target_observed=True, matched_pcs=matched)

    # 4. Only misses consult the plan's claimed context and loss profile.
    context = data.requirement.expected_context
    if context not in data.boundary.supported_contexts:
        return unknown("unsupported_attribution", "expected_context_outside_support_boundary",
                       valid=True, observed=False)
    policy = next((item for item in profile.contexts if item.context == context), None)
    if policy is None:
        return unknown("loss", "context_loss_policy_absent", valid=True, observed=False)
    deltas = {(item.counter, item.window): item.value for item in obs.counter_deltas}
    for limit in policy.counters:
        value = deltas.get((limit.counter, policy.window))
        if value is None:
            return unknown("loss", f"required_counter_window_absent:{limit.counter}",
                           valid=True, observed=False)
        if value > limit.max_delta:
            return unknown("loss", f"counter_delta_exceeds_profile:{limit.counter}",
                           valid=True, observed=False)
    return decide(Q1Status.NOT_REACHED, None, "target_absent_with_admissible_coverage",
                  execution_valid=True, target_observed=False)
