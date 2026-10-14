"""Runner sealing and Controller verification of bounded evidence bundles.

Implements the storage boundary in 01 §11.1 and 06 §4/§6/§8. A bundle digest
is a content address, NOT proof of host authenticity. The caller must obtain
expected correlation independently from trusted execution state and ensure a
trusted Runner/storage or authenticated transfer path. No VM, collection,
host journal, signature, or Q1 verdict is implemented here.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .artifacts import ArtifactError, ArtifactStore
from .data import canonical_json, parse_json


Identifier = Annotated[str, Field(min_length=1, max_length=256,
                                  pattern=r"^[^\s\x00-\x1f\x7f]+$")]
Digest = Annotated[str, Field(min_length=64, max_length=64,
                              pattern=r"^[0-9a-f]{64}$")]
ArtifactType = Annotated[str, Field(min_length=1, max_length=128,
                                    pattern=r"^[A-Za-z0-9][A-Za-z0-9._+/-]*$")]
Timestamp = Annotated[int, Field(ge=0, le=2**63 - 1)]


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True,
                              revalidate_instances="always")


class ExecutionCorrelation(EvidenceRecord):
    """Values stamped by the trusted Runner, compared without coercion."""

    job_id: Identifier
    task_id: Identifier
    execution_harness_id: Digest
    vm_instance_id: Identifier
    lane: int = Field(ge=0, le=2**32 - 1)
    generation_id: int = Field(ge=0, le=2**64 - 1)


class CollectionMetadata(EvidenceRecord):
    """Host-provided metadata; times are integer nanoseconds since the epoch."""

    collector_id: Identifier
    started_at_ns: Timestamp
    completed_at_ns: Timestamp

    @model_validator(mode="after")
    def _ordered(self) -> CollectionMetadata:
        if self.completed_at_ns < self.started_at_ns:
            raise ValueError("collection completed before it started")
        return self


class SealingMetadata(EvidenceRecord):
    sealer_id: Identifier
    sealed_at_ns: Timestamp


class ArtifactInput(EvidenceRecord):
    """Already collected bytes, with any separately decoded guest claim.

    The caller must extract guest correlation from its typed payload format.
    This layer treats bytes as opaque and does not discover claims inside them.
    """

    identity: Identifier
    type: ArtifactType
    data: bytes
    reported_correlation: ExecutionCorrelation | None = None


class EvidenceArtifact(EvidenceRecord):
    identity: Identifier
    sha256: Digest
    size: int = Field(ge=0)
    type: ArtifactType
    reported_correlation: ExecutionCorrelation | None = None


class EvidenceManifest(EvidenceRecord):
    schema_version: Literal[1] = 1
    artifacts: tuple[EvidenceArtifact, ...] = Field(min_length=1, max_length=256)
    correlation: ExecutionCorrelation
    collection: CollectionMetadata
    sealing: SealingMetadata

    @field_validator("schema_version", mode="before")
    @classmethod
    def _strict_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> EvidenceManifest:
        identities = [artifact.identity for artifact in self.artifacts]
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate artifact identity")
        for artifact in self.artifacts:
            if (artifact.reported_correlation is not None
                    and artifact.reported_correlation != self.correlation):
                raise ValueError("reported correlation conflicts with host correlation")
        if self.sealing.sealed_at_ns < self.collection.completed_at_ns:
            raise ValueError("evidence sealed before collection completed")
        return self


class EvidenceLimits(EvidenceRecord):
    max_manifest_bytes: int = Field(default=1024 * 1024, ge=1)
    max_artifacts: int = Field(default=256, ge=1, le=256)
    max_artifact_bytes: int = Field(default=16 * 1024 * 1024, ge=1)
    max_bundle_bytes: int = Field(default=64 * 1024 * 1024, ge=1)


class EvidenceError(ValueError):
    """Evidence cannot be sealed or verified."""


class EvidenceSealingError(EvidenceError):
    """The proposed bundle is invalid or could not be stored."""


class EvidenceVerificationError(EvidenceError):
    """Fail closed: no VerifiedBundle is produced for this reference."""


class EvidenceUnavailableError(EvidenceVerificationError, OSError):
    """Artifact bytes could not be read due to a retryable I/O failure."""


@dataclass(frozen=True)
class VerifiedArtifact:
    descriptor: EvidenceArtifact
    data: bytes


@dataclass(frozen=True)
class VerifiedBundle:
    """A snapshot of checked bytes, not a signature or a Q1 judgment.

    Consumers obtain this through ``verify``; constructing this dataclass is
    not verification. Artifact types are labels, checked against a consumer's
    expectations, not inferred from opaque bytes or asserted as MIME validation.
    """

    manifest_sha256: str
    manifest: EvidenceManifest
    artifacts: tuple[VerifiedArtifact, ...]

    def get(self, identity: str, *, expected_type: str) -> bytes:
        for artifact in self.artifacts:
            if artifact.descriptor.identity == identity:
                if artifact.descriptor.type != expected_type:
                    raise EvidenceVerificationError(f"artifact type mismatch: {identity}")
                return artifact.data
        raise EvidenceVerificationError(f"missing required artifact: {identity}")


class EvidenceStore:
    """Seals supplied bytes and validates persisted bundles, without I/O to guests."""

    def __init__(self, artifacts: ArtifactStore, *,
                 limits: EvidenceLimits | None = None) -> None:
        self.artifacts = artifacts
        self.limits = EvidenceLimits.model_validate(limits or EvidenceLimits())

    def _check_limits(self, manifest: EvidenceManifest) -> None:
        if len(manifest.artifacts) > self.limits.max_artifacts:
            raise ValueError("artifact count exceeds the limit")
        if any(a.size > self.limits.max_artifact_bytes for a in manifest.artifacts):
            raise ValueError("artifact size exceeds the limit")
        if sum(a.size for a in manifest.artifacts) > self.limits.max_bundle_bytes:
            raise ValueError("bundle size exceeds the limit")

    def seal(self, artifacts: Sequence[ArtifactInput], *,
             correlation: ExecutionCorrelation, collection: CollectionMetadata,
             sealing: SealingMetadata) -> str:
        """Runner entry point. Return the canonical manifest's SHA-256.

        Metadata and correlation must come from trusted host state. Failed
        storage can leave unreferenced content-addressed objects; a manifest is
        published last. Sealing claims no collection or execution was performed.
        """
        try:
            if not 1 <= len(artifacts) <= self.limits.max_artifacts:
                raise ValueError("artifact count is outside the limit")
            inputs = tuple(ArtifactInput.model_validate(a) for a in artifacts)
            if any(len(a.data) > self.limits.max_artifact_bytes for a in inputs):
                raise ValueError("artifact size exceeds the limit")
            if sum(len(a.data) for a in inputs) > self.limits.max_bundle_bytes:
                raise ValueError("bundle size exceeds the limit")
            inputs = tuple(sorted(inputs, key=lambda a: a.identity))
            manifest = EvidenceManifest(
                artifacts=tuple(EvidenceArtifact(
                    identity=a.identity, sha256=hashlib.sha256(a.data).hexdigest(),
                    size=len(a.data), type=a.type,
                    reported_correlation=a.reported_correlation,
                ) for a in inputs),
                correlation=correlation, collection=collection, sealing=sealing,
            )
            self._check_limits(manifest)
            data = canonical_json(manifest)
            if len(data) > self.limits.max_manifest_bytes:
                raise ValueError("manifest size exceeds the limit")
            for artifact in inputs:
                self.artifacts.put(artifact.data)
            return self.artifacts.put(data)
        except (ValueError, TypeError, OSError, RecursionError) as exc:
            raise EvidenceSealingError(str(exc)) from exc

    def verify(self, bundle_ref: str, *, expected_correlation: ExecutionCorrelation,
               expected_types: Mapping[str, str] | None = None) -> VerifiedBundle:
        """Controller entry point; expected correlation is a REQUIRED trust input.

        Never derive it from the bundle being checked. ``expected_types`` maps
        required artifact identities to trusted type labels; other entries are
        allowed and still fully verified. Payload semantics belong to the Judge.
        """
        try:
            expected = ExecutionCorrelation.model_validate(expected_correlation)
            raw = self.artifacts.get(bundle_ref, max_bytes=self.limits.max_manifest_bytes)
            parse_json(raw)  # Shared rejection of duplicate/non-finite JSON values.
            manifest = EvidenceManifest.model_validate_json(raw)
            if canonical_json(manifest) != raw:
                raise ValueError("manifest is not in its canonical serialized form")
            if manifest.correlation != expected:
                raise ValueError("manifest correlation conflicts with trusted expected correlation")
            self._check_limits(manifest)
            descriptors = {a.identity: a for a in manifest.artifacts}
            for identity, expected_type in (expected_types or {}).items():
                if identity not in descriptors:
                    raise ValueError(f"missing required artifact: {identity}")
                if descriptors[identity].type != expected_type:
                    raise ValueError(f"artifact type mismatch: {identity}")
            verified = []
            for artifact in manifest.artifacts:
                # Limit by the declaration as well as the configured cap; a
                # forged small size must not trigger a large allocation.
                data = self.artifacts.get(
                    artifact.sha256, max_bytes=max(1, artifact.size))
                if len(data) != artifact.size:
                    raise ValueError(f"artifact size mismatch: {artifact.identity}")
                if hashlib.sha256(data).hexdigest() != artifact.sha256:
                    raise ValueError(f"artifact hash mismatch: {artifact.identity}")
                verified.append(VerifiedArtifact(artifact, data))
            return VerifiedBundle(bundle_ref, manifest, tuple(verified))
        except OSError as exc:
            # Keep storage availability distinct from stable malformed,
            # schema, limit and digest-integrity failures. The Judge lets this
            # escape so the Controller does not commit a replay-unstable
            # semantic verdict.
            raise EvidenceUnavailableError(str(exc)) from exc
        except (ArtifactError, ValueError, TypeError, RecursionError) as exc:
            raise EvidenceVerificationError(str(exc)) from exc
