"""Host-authoritative execution capture and evidence sealing backend.

The injected engine captures bytes and reports host execution facts.  It has
no output field for Controller identity or verdicts.  This adapter derives the
execution correlation from the active Runner lease, validates the complete
capture before publishing, and records immutable provenance for the resulting
manifest digest.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Literal, Protocol

from pydantic import Field, field_validator, model_validator

from ..artifacts import validate_digest
from ..controller.tasks import RunnerInput, runner_input_digest
from ..data import canonical_json, parse_json
from ..evidence import (
    ArtifactInput,
    CollectionMetadata,
    EvidenceArtifact,
    EvidenceManifest,
    EvidenceStore,
    ExecutionCorrelation,
    SealingMetadata,
)
from .models import BackendResult, Digest, HostRecord, Identifier, Timestamp, WorkLease
from .worker import LeaseControl


CAPTURE_FAILED = "capture_failed"
INVALID_CAPTURE = "invalid_capture"
INVALID_LEASE_BINDING = "invalid_lease_binding"
LEASE_LOST_DURING_CAPTURE = "lease_lost_during_capture"
REPORTED_CORRELATION_MISMATCH = "reported_correlation_mismatch"
DUPLICATE_ARTIFACT = "duplicate_artifact"
EVIDENCE_LIMIT_EXCEEDED = "evidence_limit_exceeded"
EVIDENCE_SEALING_FAILED = "evidence_sealing_failed"
EVIDENCE_VERIFICATION_FAILED = "evidence_verification_failed"
RECEIPT_PERSISTENCE_FAILED = "receipt_persistence_failed"


class HostExecutionFacts(HostRecord):
    """Facts stamped by the host execution engine, never by the guest."""

    vm_instance_id: Identifier
    lane: int = Field(ge=0, le=2**32 - 1)
    generation_id: int = Field(ge=0, le=2**64 - 1)
    collector_id: Identifier
    collection_started_at_ns: Timestamp
    collection_completed_at_ns: Timestamp

    @model_validator(mode="after")
    def _ordered(self) -> HostExecutionFacts:
        if self.collection_completed_at_ns < self.collection_started_at_ns:
            raise ValueError("collection completed before it started")
        return self


class ExecutionCapture(HostRecord):
    """A bounded immutable capture returned by :class:`ExecutionEngine`."""

    facts: HostExecutionFacts
    artifacts: tuple[ArtifactInput, ...] = Field(min_length=1, max_length=256)


class ExecutionEngine(Protocol):
    def capture(
        self, lease: WorkLease, control: LeaseControl
    ) -> ExecutionCapture:
        """Return captured bytes and host facts, without identity or verdicts."""


class ReceiptInventory(HostRecord):
    identity: Identifier
    type: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+/-]*$",
    )
    sha256: Digest
    size: int = Field(ge=0)
    reported_correlation: ExecutionCorrelation | None = None


class RunnerEvidenceReceipt(HostRecord):
    """Host provenance for one sealed manifest, without a Judge claim."""

    schema_version: Literal[1] = 1
    bundle_ref: Digest
    manifest_sha256: Digest
    task_input_sha256: Digest
    lease_generation: int = Field(ge=1, le=2**63 - 1)
    task_id: Identifier
    job_id: Identifier
    harness_ref: Digest
    execution_harness_id: Digest
    correlation: ExecutionCorrelation
    collection: CollectionMetadata
    sealing: SealingMetadata
    artifacts: tuple[ReceiptInventory, ...] = Field(min_length=1, max_length=256)

    @field_validator("schema_version", mode="before")
    @classmethod
    def _strict_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> RunnerEvidenceReceipt:
        if self.bundle_ref != self.manifest_sha256:
            raise ValueError("bundle and manifest digests differ")
        if (
            self.correlation.task_id != self.task_id
            or self.correlation.job_id != self.job_id
            or self.correlation.execution_harness_id != self.execution_harness_id
        ):
            raise ValueError("receipt identity conflicts with correlation")
        task_input = RunnerInput(
            job_id=self.job_id,
            harness_ref=self.harness_ref,
            execution_harness_id=self.execution_harness_id)
        if self.task_input_sha256 != runner_input_digest(task_input):
            raise ValueError("receipt task input digest conflicts with identity")
        identities = tuple(artifact.identity for artifact in self.artifacts)
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate receipt artifact identity")
        if identities != tuple(sorted(identities)):
            raise ValueError("receipt artifact inventory is not canonical")
        if any(
            artifact.reported_correlation is not None
            and artifact.reported_correlation != self.correlation
            for artifact in self.artifacts
        ):
            raise ValueError("reported correlation conflicts with host correlation")
        if self.sealing.sealed_at_ns < self.collection.completed_at_ns:
            raise ValueError("evidence sealed before collection completed")
        return self


class RunnerEvidenceReceiptError(ValueError):
    """A receipt could not be persisted or failed integrity validation."""


class EvidenceReceiptSink(Protocol):
    def put(self, receipt: RunnerEvidenceReceipt) -> None: ...


_RECEIPT_SCHEMA = """
CREATE TABLE IF NOT EXISTS runner_evidence_receipts (
    bundle_ref TEXT PRIMARY KEY,
    receipt_sha256 TEXT NOT NULL,
    body BLOB NOT NULL
);
"""


class RunnerEvidenceReceiptStore:
    """Restart-safe canonical receipt storage keyed by manifest digest."""

    def __init__(self, path: Path | str) -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False, timeout=30
        )
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA busy_timeout = 30000")
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.executescript(_RECEIPT_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    def put(self, receipt: RunnerEvidenceReceipt) -> None:
        try:
            receipt = RunnerEvidenceReceipt.model_validate(receipt)
            raw = canonical_json(receipt)
            digest = hashlib.sha256(raw).hexdigest()
            with self._transaction():
                row = self._db.execute(
                    "SELECT receipt_sha256, body FROM runner_evidence_receipts "
                    "WHERE bundle_ref = ?",
                    (receipt.bundle_ref,),
                ).fetchone()
                if row is not None:
                    if row["receipt_sha256"] != digest or bytes(row["body"]) != raw:
                        raise RunnerEvidenceReceiptError(
                            "bundle already has a different evidence receipt"
                        )
                    return
                self._db.execute(
                    "INSERT INTO runner_evidence_receipts VALUES (?, ?, ?)",
                    (receipt.bundle_ref, digest, raw),
                )
        except RunnerEvidenceReceiptError:
            raise
        except (ValueError, TypeError, OSError, sqlite3.Error, RecursionError) as exc:
            raise RunnerEvidenceReceiptError("could not persist evidence receipt") from exc

    def get(self, bundle_ref: str) -> RunnerEvidenceReceipt:
        try:
            bundle_ref = validate_digest(bundle_ref)
            with self._lock:
                row = self._db.execute(
                    "SELECT receipt_sha256, body FROM runner_evidence_receipts "
                    "WHERE bundle_ref = ?",
                    (bundle_ref,),
                ).fetchone()
            if row is None:
                raise KeyError(bundle_ref)
            raw = bytes(row["body"])
            parse_json(raw)
            receipt = RunnerEvidenceReceipt.model_validate_json(raw)
            if canonical_json(receipt) != raw:
                raise RunnerEvidenceReceiptError("receipt is not canonical")
            if hashlib.sha256(raw).hexdigest() != row["receipt_sha256"]:
                raise RunnerEvidenceReceiptError("receipt digest mismatch")
            if receipt.bundle_ref != bundle_ref:
                raise RunnerEvidenceReceiptError("receipt key mismatch")
            return receipt
        except KeyError:
            raise
        except RunnerEvidenceReceiptError:
            raise
        except (ValueError, TypeError, OSError, sqlite3.Error, RecursionError) as exc:
            raise RunnerEvidenceReceiptError("could not load evidence receipt") from exc

    def has(self, bundle_ref: str) -> bool:
        try:
            self.get(bundle_ref)
        except KeyError:
            return False
        return True


class EvidenceSealingBackend:
    """Turn one host capture into a verified sealed evidence bundle."""

    def __init__(
        self,
        engine: ExecutionEngine,
        evidence: EvidenceStore,
        receipts: EvidenceReceiptSink,
        *,
        sealer_id: str,
        clock: Callable[[], int] = time.time_ns,
    ) -> None:
        # Validate static host authority data at construction time.
        SealingMetadata(sealer_id=sealer_id, sealed_at_ns=0)
        self.engine = engine
        self.evidence = evidence
        self.receipts = receipts
        self.sealer_id = sealer_id
        self.clock = clock

    @staticmethod
    def _unsealed(reason: str) -> BackendResult:
        return BackendResult(reason=reason)

    @staticmethod
    def _same_lease(left: WorkLease, right: WorkLease) -> bool:
        return (
            left.binding == right.binding
            and left.task_input == right.task_input
            and left.generation == right.generation
            and left.worker_id == right.worker_id
            and left.token == right.token
        )

    @staticmethod
    def _binding_is_exact(lease: WorkLease) -> bool:
        return (
            lease.binding.job_id == lease.task_input.job_id
            and lease.binding.harness_ref == lease.task_input.harness_ref
            and lease.binding.execution_harness_id
            == lease.task_input.execution_harness_id
        )

    @staticmethod
    def _stopped(control: LeaseControl) -> bool:
        try:
            return control.stop_requested()
        except Exception:
            return True

    def execute(
        self, lease: WorkLease, control: LeaseControl
    ) -> BackendResult:
        try:
            lease = WorkLease.model_validate(lease)
            active_lease = WorkLease.model_validate(control.lease)
        except (TypeError, ValueError, AttributeError):
            return self._unsealed(INVALID_LEASE_BINDING)
        if not self._same_lease(lease, active_lease) or not self._binding_is_exact(lease):
            return self._unsealed(INVALID_LEASE_BINDING)
        if self._stopped(control):
            return self._unsealed(LEASE_LOST_DURING_CAPTURE)

        try:
            raw_capture = self.engine.capture(lease, control)
        except Exception:
            if self._stopped(control):
                return self._unsealed(LEASE_LOST_DURING_CAPTURE)
            return self._unsealed(CAPTURE_FAILED)
        try:
            capture = ExecutionCapture.model_validate(raw_capture)
            active_lease = WorkLease.model_validate(control.lease)
        except (TypeError, ValueError, AttributeError):
            return self._unsealed(INVALID_CAPTURE)
        if not self._same_lease(lease, active_lease):
            return self._unsealed(INVALID_LEASE_BINDING)

        correlation = ExecutionCorrelation(
            job_id=lease.binding.job_id,
            task_id=lease.binding.task_id,
            execution_harness_id=lease.binding.execution_harness_id,
            vm_instance_id=capture.facts.vm_instance_id,
            lane=capture.facts.lane,
            generation_id=capture.facts.generation_id,
        )
        collection = CollectionMetadata(
            collector_id=capture.facts.collector_id,
            started_at_ns=capture.facts.collection_started_at_ns,
            completed_at_ns=capture.facts.collection_completed_at_ns,
        )
        try:
            sealing = SealingMetadata(
                sealer_id=self.sealer_id,
                sealed_at_ns=self.clock(),
            )
        except Exception:
            return self._unsealed(INVALID_CAPTURE)
        if (
            collection.started_at_ns < lease.claimed_at_ns
            or sealing.sealed_at_ns < collection.completed_at_ns
        ):
            return self._unsealed(INVALID_CAPTURE)

        artifacts = capture.artifacts
        identities = tuple(artifact.identity for artifact in artifacts)
        if len(set(identities)) != len(identities):
            return self._unsealed(DUPLICATE_ARTIFACT)
        if any(
            artifact.reported_correlation is not None
            and artifact.reported_correlation != correlation
            for artifact in artifacts
        ):
            return self._unsealed(REPORTED_CORRELATION_MISMATCH)
        limits = self.evidence.limits
        if (
            not 1 <= len(artifacts) <= limits.max_artifacts
            or any(
                len(artifact.data) > limits.max_artifact_bytes
                for artifact in artifacts
            )
            or sum(len(artifact.data) for artifact in artifacts) > limits.max_bundle_bytes
        ):
            return self._unsealed(EVIDENCE_LIMIT_EXCEEDED)

        ordered = tuple(sorted(artifacts, key=lambda artifact: artifact.identity))
        try:
            expected_manifest = EvidenceManifest(
                artifacts=tuple(
                    EvidenceArtifact(
                        identity=artifact.identity,
                        sha256=hashlib.sha256(artifact.data).hexdigest(),
                        size=len(artifact.data),
                        type=artifact.type,
                        reported_correlation=artifact.reported_correlation,
                    )
                    for artifact in ordered
                ),
                correlation=correlation,
                collection=collection,
                sealing=sealing,
            )
            manifest_bytes = canonical_json(expected_manifest)
        except (TypeError, ValueError, RecursionError):
            return self._unsealed(INVALID_CAPTURE)
        if len(manifest_bytes) > limits.max_manifest_bytes:
            return self._unsealed(EVIDENCE_LIMIT_EXCEEDED)
        expected_ref = hashlib.sha256(manifest_bytes).hexdigest()

        # The engine may have renewed the same generation while capturing.
        # It may not replace its identity, generation, worker, or bearer token.
        if self._stopped(control):
            return self._unsealed(LEASE_LOST_DURING_CAPTURE)
        try:
            bundle_ref = self.evidence.seal(
                ordered,
                correlation=correlation,
                collection=collection,
                sealing=sealing,
            )
        except Exception:
            return self._unsealed(EVIDENCE_SEALING_FAILED)
        if bundle_ref != expected_ref:
            return self._unsealed(EVIDENCE_VERIFICATION_FAILED)
        try:
            verified = self.evidence.verify(
                bundle_ref, expected_correlation=correlation
            )
            if verified.manifest != expected_manifest:
                return self._unsealed(EVIDENCE_VERIFICATION_FAILED)
        except Exception:
            return self._unsealed(EVIDENCE_VERIFICATION_FAILED)
        if self._stopped(control):
            return self._unsealed(LEASE_LOST_DURING_CAPTURE)

        receipt = RunnerEvidenceReceipt(
            bundle_ref=bundle_ref,
            manifest_sha256=bundle_ref,
            task_input_sha256=runner_input_digest(lease.task_input),
            lease_generation=lease.generation,
            task_id=lease.binding.task_id,
            job_id=lease.binding.job_id,
            harness_ref=lease.binding.harness_ref,
            execution_harness_id=lease.binding.execution_harness_id,
            correlation=correlation,
            collection=collection,
            sealing=sealing,
            artifacts=tuple(
                ReceiptInventory(
                    identity=artifact.identity,
                    type=artifact.type,
                    sha256=artifact.sha256,
                    size=artifact.size,
                    reported_correlation=artifact.reported_correlation,
                )
                for artifact in verified.manifest.artifacts
            ),
        )
        try:
            self.receipts.put(receipt)
        except Exception:
            return self._unsealed(RECEIPT_PERSISTENCE_FAILED)
        if self._stopped(control):
            return self._unsealed(LEASE_LOST_DURING_CAPTURE)
        return BackendResult(bundle_ref=bundle_ref)
