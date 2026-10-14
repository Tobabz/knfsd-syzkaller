"""Controller Q1 adapter over host-receipted, sealed evidence.

Receipts, mapping references and JudgeVersions are trusted control-plane
inputs. They must not be reconstructed from guest JSON. This component
does not collect KCOV, verify DWARF mappings, or authenticate a Runner;
those remain responsibilities of the real Runner/mapper integration.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .artifacts import ArtifactStore
from .contracts import JudgeVersions, Q1Result, Q1Status, Record, Sha256
from .data import canonical_json, load_record, parse_json
from .evidence import EvidenceStore, ExecutionCorrelation as BundleCorrelation
from .hcap import ReachabilityPlan
from .q1 import (CandidateTarget, ExecutionCorrelation, KernelIdentity,
                 ObservationRequirement, Q1AdmissibilityProfile, Q1Decision,
                 Q1Input, RemoteKcovObservation, RemoteKcovSupportBoundary,
                 TargetPcMapping, evaluate)

OBSERVATION_ID = "reachability"
OBSERVATION_TYPE = "application/vnd.knfsd.reachability+json"
COVERAGE_TYPE = "application/vnd.knfsd.remote-kcov+json"
Model = TypeVar("Model", bound=BaseModel)
_INVALID = (OSError, ValueError, TypeError, RecursionError)


class PublishedCoverage(Record):
    """A normalized published aggregate, not arbitrary tracepoint PCs."""

    model_config = ConfigDict(strict=True, revalidate_instances="always")
    schema_version: Literal["remote-kcov-pcs-v1"] = "remote-kcov-pcs-v1"
    correlation: ExecutionCorrelation
    pcs: tuple[Annotated[int, Field(ge=1, le=2**64 - 1)], ...]

    @field_validator("pcs")
    @classmethod
    def _set(cls, pcs: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(sorted(set(pcs)))


class TrustedQ1Execution(Record):
    """Out-of-band receipt from host execution and mapping records.

    Freezing this receipt prevents changing the meaning of a bundle between
    Controller event replay and its original evaluation. Provision a new
    adapter snapshot when the trusted receipt registry grows.
    """

    model_config = ConfigDict(strict=True, revalidate_instances="always")
    bundle_ref: Sha256
    plan_ref: Sha256
    candidate: CandidateTarget
    identity: KernelIdentity
    correlation: ExecutionCorrelation
    trace_mode: Literal["off", "on"]
    mapping_ref: Sha256 | None


class UnknownExecution(ValueError):
    """No trusted identity exists for the supplied bundle; no verdict is safe."""


def _payload(raw: bytes, model: type[Model]) -> Model:
    parse_json(raw)
    result = model.model_validate_json(raw)
    if canonical_json(result) != raw:
        raise ValueError("noncanonical typed evidence payload")
    return result


class ArtifactQ1Judge:
    """components.Q1Judge with explicit host authority and byte verification.

    ``assess`` returns the full decision for callers to persist alongside the
    Controller's Q1Result. All methods are read-only; no VM queries or changes
    to evidence occur while a Controller transition is being evaluated.
    """

    def __init__(self, artifacts: ArtifactStore, *,
                 receipts: Mapping[str, TrustedQ1Execution],
                 evidence: EvidenceStore | None = None) -> None:
        checked = {}
        for ref, receipt in receipts.items():
            receipt = TrustedQ1Execution.model_validate(receipt)
            if ref != receipt.bundle_ref:
                raise ValueError("receipt key differs from its bundle reference")
            checked[ref] = receipt
        self.artifacts = artifacts
        self.evidence = evidence if evidence is not None else EvidenceStore(artifacts)
        self.receipts = MappingProxyType(checked)

    def _receipt(self, bundle_ref: str) -> TrustedQ1Execution:
        try:
            return self.receipts[bundle_ref]
        except KeyError as exc:
            raise UnknownExecution("bundle has no trusted host receipt") from exc

    def matches_execution(self, bundle_ref: str, *, job_id: str,
                          task_id: str) -> bool:
        """Bind the Controller's pending task to independent host provenance.

        Unknown receipts raise so the transition remains uncommitted until
        the host publishes its receipt. Recording absence as a mismatch
        would make replay change after a later receipt snapshot is installed.
        """
        receipt = self._receipt(bundle_ref)
        return (receipt.correlation.job_id == job_id
                and receipt.correlation.task_id == task_id)

    def _prepare(self, bundle_ref: str, plan_ref: str, candidate_id: str,
                 versions: JudgeVersions) -> Q1Input:
        receipt = self._receipt(bundle_ref)
        if plan_ref != receipt.plan_ref or candidate_id != receipt.candidate.candidate_id:
            raise ValueError("request does not match the trusted execution receipt")
        expected = BundleCorrelation.model_validate(receipt.correlation.model_dump())
        bundle = self.evidence.verify(
            bundle_ref, expected_correlation=expected,
            expected_types={OBSERVATION_ID: OBSERVATION_TYPE})
        plan = load_record(self.artifacts, plan_ref, ReachabilityPlan)
        if plan.candidate_id != candidate_id:
            raise ValueError("plan belongs to another candidate")
        location = plan.q1_observation.target
        target = CandidateTarget(
            candidate_id=candidate_id, kernel_commit=receipt.candidate.kernel_commit,
            **location.model_dump(mode="json"))
        if target != receipt.candidate:
            raise ValueError("plan target differs from the intake-accepted candidate")
        if plan.runtime_selection.trace_mode != receipt.trace_mode:
            raise ValueError("plan trace mode differs from the executed configuration")
        observation = _payload(bundle.get(OBSERVATION_ID, expected_type=OBSERVATION_TYPE),
                               RemoteKcovObservation)
        if observation.lane_trace_mode is not None and \
                observation.lane_trace_mode != receipt.trace_mode:
            raise ValueError("observation trace mode differs from trusted execution")
        # Bind the normalized PC claim to actual separately sealed bytes.
        # A guest's boolean 'observed' flag is never an oracle.
        by_digest = {a.descriptor.sha256: a for a in bundle.artifacts
                     if a.descriptor.type == COVERAGE_TYPE}
        references = observation.coverage_artifacts
        if len(references) != len(set(references)):
            raise ValueError("duplicate published coverage reference")
        # Omitting a sealed aggregate could hide a target hit and turn it
        # into a false miss. Every coverage payload must belong to this
        # execution and participate in the normalized PC union.
        if set(references) != set(by_digest):
            raise ValueError("coverage references do not cover the sealed bundle")
        if observation.published_pcs is not None or observation.coverage_artifacts:
            if not observation.coverage_artifacts or observation.published_pcs is None:
                raise ValueError("incomplete published coverage references")
            pcs: set[int] = set()
            for ref in observation.coverage_artifacts:
                artifact = by_digest[ref]
                coverage = _payload(artifact.data, PublishedCoverage)
                if coverage.correlation != receipt.correlation:
                    raise ValueError("coverage correlation conflicts with trusted execution")
                pcs.update(coverage.pcs)
            if tuple(sorted(pcs)) != observation.published_pcs:
                raise ValueError("observation PCs differ from sealed coverage bytes")
        profile = load_record(self.artifacts, versions.judge_profile_id,
                              Q1AdmissibilityProfile)
        boundary = load_record(self.artifacts, versions.support_boundary_id,
                               RemoteKcovSupportBoundary)
        mapping = (load_record(self.artifacts, receipt.mapping_ref, TargetPcMapping)
                   if receipt.mapping_ref is not None else None)
        return Q1Input(
            candidate=receipt.candidate, plan_ref=plan_ref,
            hcap_revision=plan.hcap_revision,
            requirement=ObservationRequirement(
                target=target, expected_context=plan.q1_observation.expected_context),
            evidence_manifest_sha256=bundle.manifest_sha256, evidence_verified=True,
            expected_identity=receipt.identity, expected_correlation=receipt.correlation,
            observation=observation, profile=profile, boundary=boundary, mapping=mapping)

    def assess(self, bundle_ref: str, plan_ref: str, candidate_id: str,
               versions: JudgeVersions) -> Q1Decision:
        """Full successful parsing/evaluation; invalid artifacts raise ValueError."""
        return evaluate(self._prepare(bundle_ref, plan_ref, candidate_id, versions))

    def judge(self, bundle_ref: str, plan_ref: str, candidate_id: str,
              versions: JudgeVersions) -> Q1Result:
        receipt = self._receipt(bundle_ref)  # Never fabricate a missing host identity.
        try:
            return self.assess(bundle_ref, plan_ref, candidate_id, versions).as_result()
        except OSError:
            raise
        except _INVALID:
            fields = dict(
                candidate_id=receipt.candidate.candidate_id,
                execution_harness_id=receipt.identity.execution_harness_id,
                judge_profile_id=versions.judge_profile_id,
                support_boundary_id=versions.support_boundary_id,
                evidence_manifest_sha256=bundle_ref,
                status=Q1Status.INCONCLUSIVE, reason="evidence", gap_signal=None)
            lineage = dict(**fields, plan_ref=plan_ref,
                           requested_candidate_id=candidate_id,
                           receipt=receipt.model_dump(mode="json"))
            return Q1Result(verdict_id=hashlib.sha256(canonical_json(lineage)).hexdigest(),
                            **fields)

    def has_required_evidence(self, bundle_ref: str,
                              versions: JudgeVersions) -> bool:
        try:
            receipt = self._receipt(bundle_ref)
            inputs = self._prepare(bundle_ref, receipt.plan_ref,
                                   receipt.candidate.candidate_id, versions)
            decision = evaluate(inputs)
            if decision.reason in ("evidence", "mapping"):
                return False
            # A threshold exceedance is judgeable from existing bytes; a
            # newly required counter/window absent from them is not.
            return not any(d.startswith("required_counter_window_absent:")
                           or d == "context_loss_policy_absent"
                           for d in decision.observations)
        except OSError:
            raise
        except _INVALID:
            return False
