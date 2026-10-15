"""Controller-side Q2 adapter over host-receipted, sealed evidence.

The evidence manifest provides byte integrity, while ``TrustedQ2Execution``
provides provenance.  Receipt values must come from host execution/collection
state; constructing them from the sealed observation would let guest claims
stamp execution identity, log completeness or collection-window closure.

Storage unavailability is raised as ``Q2EvidenceUnavailable`` so a caller can
retry without recording a verdict.  A present but malformed, miscorrelated or
hash-invalid bundle is instead evaluated as INCONCLUSIVE(invalid_evidence), as
required by the Q2 precedence table.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Literal, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .artifacts import ArtifactStore
from .data import canonical_json, load_record, parse_json
from .evidence import (ArtifactType, EvidenceStore,
                       ExecutionCorrelation, Identifier, VerifiedBundle)
from .q2 import (CandidateAssociation, ConsoleLogCompleteness, Digest,
                 ManagerCrashReport, Q2CollectionWindow, Q2Decision, Q2Evidence,
                 Q2Input, Q2JudgeProfile, Q2Result, VmTermination, evaluate)


Q2_EVIDENCE_ID = "q2-evidence"
Q2_EVIDENCE_TYPE = "application/vnd.knfsd.q2-evidence+json"
CONSOLE_LOG_TYPE = "application/vnd.knfsd.console-log"
MANAGER_REPORT_TYPE = "application/vnd.knfsd.syz-manager-report"

Model = TypeVar("Model", bound=BaseModel)


class _Record(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        validate_default=True,
        revalidate_instances="always",
        allow_inf_nan=False,
    )


class SealedArtifactRef(_Record):
    identity: Identifier
    sha256: Digest


class SealedQ2Evidence(_Record):
    """Typed bundle index whose authority is checked against a host receipt."""

    schema_version: Literal["sealed-q2-evidence-v1"] = "sealed-q2-evidence-v1"
    execution_harness_id: Digest
    correlation: ExecutionCorrelation
    console_log_identity: Identifier | None
    console_log_ref: Digest | None
    console_log_completeness: ConsoleLogCompleteness
    manager_crash_reports: tuple[SealedArtifactRef, ...]
    vm_termination: VmTermination
    collection_window: Q2CollectionWindow
    internal_errors: tuple[Annotated[str, Field(min_length=1)], ...] = ()
    candidate_association: CandidateAssociation | None = None

    @model_validator(mode="after")
    def _unique_artifacts(self) -> Self:
        identities = tuple(item.identity for item in self.manager_crash_reports)
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate manager report identity")
        return self


class TrustedQ2Execution(_Record):
    """Immutable host authority for one Stage 2 execution bundle.

    The report identities are the host collector's complete inventory, in
    collection order.  The manifest supplies their hashes and bytes.  A new
    adapter snapshot is installed when the trusted receipt registry grows;
    historical snapshots remain sufficient to replay old decisions.
    """

    bundle_ref: Digest
    execution_harness_id: Digest
    correlation: ExecutionCorrelation
    console_log_identity: Identifier | None
    console_log_completeness: ConsoleLogCompleteness
    manager_crash_report_identities: tuple[Identifier, ...]
    vm_termination: VmTermination
    collection_window: Q2CollectionWindow

    @model_validator(mode="after")
    def _unique_artifacts(self) -> Self:
        reports = self.manager_crash_report_identities
        if len(set(reports)) != len(reports):
            raise ValueError("duplicate trusted manager report identity")
        reserved = {Q2_EVIDENCE_ID}
        if self.console_log_identity is not None:
            if self.console_log_identity in reserved:
                raise ValueError("console identity conflicts with Q2 evidence index")
            reserved.add(self.console_log_identity)
        if reserved.intersection(reports):
            raise ValueError("Q2 artifact identities overlap")
        return self


class UnknownQ2Execution(ValueError):
    """No trusted host receipt is available; producing a verdict is unsafe."""


class Q2EvidenceUnavailable(RuntimeError):
    """Artifact/profile I/O is unavailable and the same evaluation may be retried."""


def _payload(raw: bytes, model: type[Model]) -> Model:
    parse_json(raw)
    result = model.model_validate_json(raw)
    if canonical_json(result) != raw:
        raise ValueError("noncanonical typed Q2 evidence payload")
    return result


class ArtifactQ2Judge:
    """Read-only sealed-evidence adapter for the pure Q2 evaluator."""

    def __init__(self, artifacts: ArtifactStore, *,
                 receipts: Mapping[str, TrustedQ2Execution],
                 evidence: EvidenceStore | None = None) -> None:
        checked: dict[str, TrustedQ2Execution] = {}
        for ref, value in receipts.items():
            receipt = TrustedQ2Execution.model_validate(value)
            if ref != receipt.bundle_ref:
                raise ValueError("receipt key differs from its bundle reference")
            checked[ref] = receipt
        self.artifacts = artifacts
        self.evidence = evidence if evidence is not None else EvidenceStore(artifacts)
        self.receipts = MappingProxyType(checked)

    def _receipt(self, bundle_ref: str) -> TrustedQ2Execution:
        try:
            return self.receipts[bundle_ref]
        except KeyError as exc:
            raise UnknownQ2Execution("bundle has no trusted Q2 host receipt") from exc

    def matches_execution(self, bundle_ref: str, *, job_id: str,
                          task_id: str) -> bool:
        """Bind a future Controller task to independent host provenance."""

        receipt = self._receipt(bundle_ref)
        return (receipt.correlation.job_id == job_id
                and receipt.correlation.task_id == task_id)

    def _profile(self, judge_profile_id: str) -> Q2JudgeProfile:
        try:
            return load_record(self.artifacts, judge_profile_id, Q2JudgeProfile)
        except OSError as exc:
            raise Q2EvidenceUnavailable("Q2 judge profile artifact is unavailable") from exc

    @staticmethod
    def _trusted_fields_match(observation: SealedQ2Evidence,
                              receipt: TrustedQ2Execution) -> bool:
        return (
            observation.execution_harness_id == receipt.execution_harness_id
            and observation.correlation == receipt.correlation
            and observation.console_log_identity == receipt.console_log_identity
            and observation.console_log_completeness
            == receipt.console_log_completeness
            and tuple(item.identity for item in observation.manager_crash_reports)
            == receipt.manager_crash_report_identities
            and observation.vm_termination == receipt.vm_termination
            and observation.collection_window == receipt.collection_window
        )

    @staticmethod
    def _typed_identities(bundle: VerifiedBundle,
                          artifact_type: ArtifactType) -> set[str]:
        return {item.descriptor.identity for item in bundle.artifacts
                if item.descriptor.type == artifact_type}

    def _prepare(self, receipt: TrustedQ2Execution,
                 profile: Q2JudgeProfile) -> Q2Input:
        expected_types: dict[str, str] = {Q2_EVIDENCE_ID: Q2_EVIDENCE_TYPE}
        if receipt.console_log_identity is not None:
            expected_types[receipt.console_log_identity] = CONSOLE_LOG_TYPE
        expected_types.update({identity: MANAGER_REPORT_TYPE
                               for identity in receipt.manager_crash_report_identities})
        bundle = self.evidence.verify(
            receipt.bundle_ref,
            expected_correlation=receipt.correlation,
            expected_types=expected_types,
        )
        observation = _payload(
            bundle.get(Q2_EVIDENCE_ID, expected_type=Q2_EVIDENCE_TYPE),
            SealedQ2Evidence,
        )
        if not self._trusted_fields_match(observation, receipt):
            raise ValueError("sealed Q2 claims conflict with trusted host receipt")

        expected_console = ({receipt.console_log_identity}
                            if receipt.console_log_identity is not None else set())
        if self._typed_identities(bundle, CONSOLE_LOG_TYPE) != expected_console:
            raise ValueError("console artifacts differ from trusted host inventory")
        expected_reports = set(receipt.manager_crash_report_identities)
        if self._typed_identities(bundle, MANAGER_REPORT_TYPE) != expected_reports:
            raise ValueError("manager reports differ from trusted host inventory")
        if self._typed_identities(bundle, Q2_EVIDENCE_TYPE) != {Q2_EVIDENCE_ID}:
            raise ValueError("multiple Q2 evidence indexes in one bundle")

        by_identity = {item.descriptor.identity: item for item in bundle.artifacts}
        console_ref: str | None = None
        if receipt.console_log_identity is not None:
            console = by_identity[receipt.console_log_identity]
            console_ref = console.descriptor.sha256
            if observation.console_log_ref != console_ref:
                raise ValueError("console reference differs from sealed console bytes")
        elif observation.console_log_ref is not None:
            raise ValueError("missing console cannot carry a console reference")

        reports: list[ManagerCrashReport] = []
        indexed_reports = {item.identity: item for item in observation.manager_crash_reports}
        for identity in receipt.manager_crash_report_identities:
            artifact = by_identity[identity]
            indexed = indexed_reports[identity]
            if indexed.sha256 != artifact.descriptor.sha256:
                raise ValueError("manager report reference differs from sealed bytes")
            reports.append(ManagerCrashReport(
                artifact_identity=identity,
                report_ref=artifact.descriptor.sha256,
                text=artifact.data.decode("utf-8"),
            ))

        evidence = Q2Evidence(
            execution_harness_id=observation.execution_harness_id,
            correlation=observation.correlation,
            console_log_ref=console_ref,
            console_log_completeness=receipt.console_log_completeness,
            manager_crash_reports=tuple(reports),
            vm_termination=receipt.vm_termination,
            collection_window=receipt.collection_window,
            internal_errors=observation.internal_errors,
            candidate_association=observation.candidate_association,
        )
        return Q2Input(
            evidence_manifest_sha256=bundle.manifest_sha256,
            evidence_verified=True,
            expected_execution_harness_id=receipt.execution_harness_id,
            expected_correlation=receipt.correlation,
            evidence=evidence,
            profile=profile,
        )

    @staticmethod
    def _invalid_input(receipt: TrustedQ2Execution,
                       profile: Q2JudgeProfile) -> Q2Input:
        """Stable fail-closed input; do not persist storage error text."""

        return Q2Input(
            evidence_manifest_sha256=receipt.bundle_ref,
            evidence_verified=False,
            expected_execution_harness_id=receipt.execution_harness_id,
            expected_correlation=receipt.correlation,
            evidence=Q2Evidence(
                execution_harness_id=receipt.execution_harness_id,
                correlation=receipt.correlation,
                console_log_ref=None,
                console_log_completeness=receipt.console_log_completeness,
                manager_crash_reports=(),
                vm_termination=receipt.vm_termination,
                collection_window=receipt.collection_window,
                internal_errors=("sealed_evidence_invalid",),
            ),
            profile=profile,
        )

    def assess(self, bundle_ref: str, judge_profile_id: str) -> Q2Decision:
        """Return a deterministic decision, or raise when evaluation is retryable."""

        receipt = self._receipt(bundle_ref)
        profile = self._profile(judge_profile_id)
        try:
            inputs = self._prepare(receipt, profile)
        except OSError as exc:
            # EvidenceUnavailableError is an OSError too. Preserve that typed
            # boundary: an integrity error may have an OS cause (e.g. ELOOP)
            # without being a retryable availability failure.
            raise Q2EvidenceUnavailable("sealed Q2 artifacts are unavailable") from exc
        except (ValueError, TypeError, RecursionError):
            inputs = self._invalid_input(receipt, profile)
        return evaluate(inputs)

    def judge(self, bundle_ref: str, judge_profile_id: str) -> Q2Result:
        return self.assess(bundle_ref, judge_profile_id).as_result()
