"""Publish accepted Runner completions as immutable Q1 authority snapshots.

All context is supplied by the trusted host/control plane, never decoded from
guest evidence. A content address is byte integrity, not an authority grant.
See Q1_RECEIPTS.md for the publication and Controller retry contract.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import BaseModel, Field

from ..artifacts import ArtifactStore, validate_digest
from ..contracts import HarnessBinding, Materialized, VulnerabilityCandidate
from ..controller.tasks import RunnerInput, runner_input_digest
from ..data import canonical_json, parse_json
from ..evidence import EvidenceStore, ExecutionCorrelation as BundleCorrelation
from ..hcap import ReachabilityPlan
from ..materializer import (ExecutionHarnessDescriptor,
                            MaterializationReviewManifest, ParsedProgram,
                            ReachabilityHarness)
from ..q1 import CandidateTarget, ExecutionCorrelation, KernelIdentity, TargetPcMapping
from ..sealed_q1 import ArtifactQ1Judge, TrustedQ1Execution, UnknownExecution
from .evidence_backend import RunnerEvidenceReceiptStore
from .models import Digest, HostRecord, Identifier, TaskBinding
from .service import DurableRunner


MAX_RECORD_BYTES = 1024 * 1024
MAX_SNAPSHOT_RECEIPTS = 4096
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
Model = TypeVar("Model", bound=BaseModel)


class Q1AuthorityPending(UnknownExecution):
    """Authority is not published yet; retry without committing a verdict."""


class Q1ReceiptRejected(ValueError):
    """Host records conflict or have failed integrity validation."""


class Q1HostContext(HostRecord):
    """Independent host authority for one Stage 1 Runner lease generation.

    ``candidate`` is the intake-accepted Controller record. ``materialized``
    and ``binding`` are the records used to dispatch this task, not the job's
    potentially newer current binding. The host verifies the boot identity,
    relocation and trace configuration, and a trusted mapper supplies
    ``mapping_ref``. None of these can be copied from a guest observation.

    Descriptor artifact names are explicit because existing descriptors have
    no standardized names for vmlinux and the instrumentation/patch artifact.
    """

    schema_version: Literal["runner-q1-context.v1"] = "runner-q1-context.v1"
    candidate: VulnerabilityCandidate
    plan_ref: Digest
    binding: HarnessBinding
    materialized: Materialized
    lease_generation: int = Field(ge=1, le=2**63 - 1)
    identity: KernelIdentity
    correlation: ExecutionCorrelation
    trace_mode: Literal["off", "on"]
    mapping_ref: Digest | None
    vmlinux_artifact_name: Identifier
    instrumentation_artifact_name: Identifier


class Q1ReceiptPublication(HostRecord):
    """Append-only authority and source-receipt lineage for an execution."""

    schema_version: Literal["runner-q1-publication.v1"] = "runner-q1-publication.v1"
    context: Q1HostContext
    completion_sha256: Digest
    evidence_receipt_sha256: Digest
    execution: TrustedQ1Execution


def _sha(value: BaseModel) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _target(context: Q1HostContext) -> CandidateTarget:
    candidate = context.candidate
    return CandidateTarget(candidate_id=candidate.candidate_id,
                           kernel_commit=candidate.kernel_commit,
                           **candidate.location.model_dump(mode="json"))


def _execution(context: Q1HostContext, bundle_ref: str) -> TrustedQ1Execution:
    return TrustedQ1Execution(
        bundle_ref=bundle_ref, plan_ref=context.plan_ref, candidate=_target(context),
        identity=context.identity, correlation=context.correlation,
        trace_mode=context.trace_mode, mapping_ref=context.mapping_ref)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Q1ReceiptRejected(message)


class RunnerQ1ReceiptBridge:
    """Validate, persist and snapshot Q1 authority; never produce a verdict.

    ``publish`` requires a sealed completion accepted by ``DurableRunner``.
    Sealing-backend receipts alone, including orphaned lease results, are not
    accepted. Publication is atomic and idempotent; an existing bundle or task
    cannot acquire different authority. ``snapshot`` returns a new ordinary
    ArtifactQ1Judge, whose immutable registry is independent of later writes.

    The history DB and CAS root must be trusted host storage. No signatures,
    runtime boot measurement, source intake or mapping generation occur here.
    """

    def __init__(self, path: Path | str, *, runner: DurableRunner,
                 receipts: RunnerEvidenceReceiptStore, artifacts: ArtifactStore,
                 evidence: EvidenceStore | None = None) -> None:
        self.runner = runner
        self.receipts = receipts
        self.artifacts = artifacts
        self.evidence = evidence if evidence is not None else EvidenceStore(artifacts)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), isolation_level=None,
                                   check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS runner_q1_publications (
                bundle_ref TEXT PRIMARY KEY,
                task_id TEXT NOT NULL UNIQUE,
                body_sha256 TEXT NOT NULL,
                body BLOB NOT NULL
            )
        """)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _record(self, ref: str, model: type[Model]) -> Model:
        try:
            raw = self.artifacts.get(ref, max_bytes=MAX_RECORD_BYTES)
        except FileNotFoundError as exc:
            raise Q1AuthorityPending("referenced host artifact is not available") from exc
        parse_json(raw)
        value = model.model_validate_json(raw)
        _require(canonical_json(value) == raw, "noncanonical host artifact")
        return value

    def _check_materialization(self, context: Q1HostContext) -> None:
        materialized = context.materialized
        binding = context.binding
        harness_id = binding.execution_harness_id
        _require(materialized.execution_harness_id == harness_id
                 == context.identity.execution_harness_id
                 == context.correlation.execution_harness_id,
                 "execution harness identity mismatch")
        _require(materialized.hcap_revision == binding.hcap_revision,
                 "materialization HCAP binding mismatch")
        descriptor = self._record(harness_id, ExecutionHarnessDescriptor)
        _require(descriptor.kernel_commit == binding.kernel_commit
                 == context.candidate.kernel_commit == context.identity.kernel_commit
                 and descriptor.sanitizer == binding.sanitizer,
                 "kernel/build identity mismatch")
        _require(context.vmlinux_artifact_name != context.instrumentation_artifact_name,
                 "build identity roles must be distinct")
        builds = {item.name: item.artifact_ref for item in descriptor.build_artifacts}
        _require(builds.get(context.vmlinux_artifact_name) == context.identity.vmlinux_sha256
                 and builds.get(context.instrumentation_artifact_name)
                 == context.identity.instrumentation_sha256,
                 "mapping identity does not match descriptor build artifacts")
        plan = self._record(context.plan_ref, ReachabilityPlan)
        harness = self._record(materialized.harness_ref, ReachabilityHarness)
        review = self._record(materialized.review_manifest_sha256,
                              MaterializationReviewManifest)
        _require(harness.execution_harness_id == harness_id
                 and harness.hcap_revision == binding.hcap_revision
                 and harness.review_manifest_sha256 == materialized.review_manifest_sha256
                 and harness.plan_ref == context.plan_ref,
                 "materialized harness binding mismatch")
        # The review is the canonical projection produced by the Materializer.
        for name in MaterializationReviewManifest.model_fields:
            if name != "schema_version":
                _require(getattr(review, name) == getattr(harness, name),
                         f"materialization review mismatch: {name}")
        _require(harness.candidate_id == plan.candidate_id == context.candidate.candidate_id
                 and plan.q1_observation.target == context.candidate.location,
                 "plan does not target the intake-accepted candidate")
        _require(harness.q1_observation == plan.q1_observation
                 and harness.runtime_selection == plan.runtime_selection
                 and harness.required_capability_ids == tuple(sorted(plan.required_capabilities)),
                 "harness differs from execution plan")
        for name in ("kind", "artifact_ref", "seed_manifest_ref", "seed_id"):
            harness_name = {"kind": "program_kind", "artifact_ref": "program_ref"}.get(name, name)
            _require(getattr(plan.program_proposal, name) == getattr(harness, harness_name),
                     "materialized program differs from plan")
        # Materializer normalizes interface order when comparing runtime choices.
        def runtime_key(selection):
            data = selection.model_dump(mode="json")
            data["enabled_interfaces"] = sorted(data["enabled_interfaces"])
            return canonical_json(data)
        _require(runtime_key(harness.runtime_selection) in {
            runtime_key(selection) for selection in descriptor.allowed_runtime_selections
        } and harness.runtime_selection.trace_mode == context.trace_mode,
            "executed runtime/trace configuration differs from descriptor or plan")
        for parsed_ref, program_ref in (
            (harness.scenario_parser_result_ref, harness.program_ref),
            (harness.neutral_parser_result_ref, harness.neutral_program_ref),
        ):
            parsed = self._record(parsed_ref, ParsedProgram)
            _require(parsed.identity == descriptor.syzkaller_identity
                     and parsed.program_sha256 == program_ref,
                     "parsed program identity mismatch")
        if context.mapping_ref is None:
            raise Q1AuthorityPending("trusted target mapping is not available")
        mapping = self._record(context.mapping_ref, TargetPcMapping)
        _require(mapping.target == _target(context) and mapping.identity.same_kernel(context.identity),
                 "target mapping identity mismatch")
        if not mapping.verified:
            raise Q1AuthorityPending("target mapping is not verified")

    def check_materialization(self, context: Q1HostContext) -> None:
        """The descriptor, plan, harness and mapping checks of ``publish``
        alone.  A Stage 2 gate repetition runs the Stage 1 harness under a
        streamed lease, so it has no Stage 1 completion to publish, but its
        Q1 authority must hold the same way."""
        raw = canonical_json(context)
        _require(len(raw) <= MAX_RECORD_BYTES, "host context exceeds size limit")
        self._check_materialization(Q1HostContext.model_validate_json(raw))

    def _prepare(self, context: Q1HostContext) -> Q1ReceiptPublication:
        # JSON round-trip revalidates even nested model_copy/model_construct values.
        raw = canonical_json(context)
        _require(len(raw) <= MAX_RECORD_BYTES, "host context exceeds size limit")
        context = Q1HostContext.model_validate_json(raw)
        _require(raw == canonical_json(context), "noncanonical host context")
        completion = self.runner.receipt(context.correlation.task_id)
        if completion is None:
            raise Q1AuthorityPending("Runner has not accepted a final completion")
        _require(completion.final_state == "sealed" and completion.generation > 0,
                 "Runner completion is unsealed")
        expected = TaskBinding(
            task_id=context.correlation.task_id, job_id=context.correlation.job_id,
            harness_ref=context.materialized.harness_ref,
            execution_harness_id=context.binding.execution_harness_id)
        _require(completion.binding == expected
                 and completion.generation == context.lease_generation,
                 "accepted completion task or generation mismatch")
        try:
            receipt = self.receipts.get(completion.bundle_ref)
        except KeyError as exc:
            raise Q1AuthorityPending("sealing receipt is not available") from exc
        _require(receipt.bundle_ref == completion.bundle_ref
                 and receipt.lease_generation == completion.generation
                 and receipt.task_id == expected.task_id
                 and receipt.job_id == expected.job_id
                 and receipt.harness_ref == expected.harness_ref
                 and receipt.execution_harness_id == expected.execution_harness_id,
                 "sealing receipt does not bind the accepted completion")
        task_input = RunnerInput(job_id=expected.job_id, harness_ref=expected.harness_ref,
                                 execution_harness_id=expected.execution_harness_id)
        _require(receipt.task_input_sha256 == runner_input_digest(task_input),
                 "sealing receipt input digest mismatch")
        correlation = BundleCorrelation.model_validate(context.correlation.model_dump())
        _require(receipt.correlation == correlation, "host execution position mismatch")
        self._check_materialization(context)
        bundle = self.evidence.verify(receipt.bundle_ref, expected_correlation=correlation)
        manifest = bundle.manifest
        _require(bundle.manifest_sha256 == receipt.manifest_sha256
                 and manifest.collection == receipt.collection
                 and manifest.sealing == receipt.sealing
                 and tuple(item.model_dump() for item in manifest.artifacts)
                 == tuple(item.model_dump() for item in receipt.artifacts),
                 "sealed evidence differs from receipt inventory or metadata")
        return Q1ReceiptPublication(
            context=context, completion_sha256=_sha(completion),
            evidence_receipt_sha256=_sha(receipt),
            execution=_execution(context, receipt.bundle_ref))

    @staticmethod
    def _decode(row: sqlite3.Row) -> Q1ReceiptPublication:
        raw = bytes(row["body"])
        _require(len(raw) <= MAX_RECORD_BYTES, "publication exceeds size limit")
        parse_json(raw)
        entry = Q1ReceiptPublication.model_validate_json(raw)
        _require(canonical_json(entry) == raw
                 and hashlib.sha256(raw).hexdigest() == row["body_sha256"],
                 "publication integrity failure")
        _require(entry.execution.bundle_ref == row["bundle_ref"]
                 and entry.context.correlation.task_id == row["task_id"]
                 and entry.context.mapping_ref is not None
                 and entry.execution == _execution(entry.context, row["bundle_ref"]),
                 "publication identity failure")
        return entry

    def publish(self, context: Q1HostContext) -> TrustedQ1Execution:
        """Publish only after all authorities arrive; reject conflicting history.

        Pending authority and I/O errors propagate. Callers retain the old
        snapshot and retry; they must not translate these into a Q1 verdict.
        """
        entry = self._prepare(context)
        raw = canonical_json(entry)
        _require(len(raw) <= MAX_RECORD_BYTES, "publication exceeds size limit")
        bundle_ref = entry.execution.bundle_ref
        task_id = entry.context.correlation.task_id
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM runner_q1_publications WHERE bundle_ref = ? OR task_id = ?",
                    (bundle_ref, task_id)).fetchone()
                if row is not None:
                    _require(self._decode(row) == entry,
                             "published execution authority is immutable")
                else:
                    count, size = self._db.execute(
                        "SELECT COUNT(*), COALESCE(SUM(LENGTH(body)), 0) "
                        "FROM runner_q1_publications").fetchone()
                    _require(count < MAX_SNAPSHOT_RECEIPTS, "Q1 snapshot capacity exceeded")
                    _require(size + len(raw) <= MAX_SNAPSHOT_BYTES,
                             "Q1 snapshot byte limit exceeded")
                    self._db.execute("INSERT INTO runner_q1_publications VALUES (?, ?, ?, ?)",
                                     (bundle_ref, task_id, _sha(entry), raw))
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")
        return entry.execution

    def publication(self, bundle_ref: str) -> Q1ReceiptPublication:
        """Read persisted authority/lineage without consulting mutable job state."""
        validate_digest(bundle_ref)
        with self._lock:
            row = self._db.execute("SELECT * FROM runner_q1_publications WHERE bundle_ref = ?",
                                   (bundle_ref,)).fetchone()
        if row is None:
            raise KeyError(bundle_ref)
        return self._decode(row)

    def snapshot(self) -> ArtifactQ1Judge:
        """Freeze all published authority for a Controller instance or replay."""
        entries = []
        size = 0
        with self._lock:
            # Bound allocations even when a damaged DB contains oversized rows.
            rows = self._db.execute(
                "SELECT bundle_ref, task_id, body_sha256, SUBSTR(body, 1, ?) AS body "
                "FROM runner_q1_publications ORDER BY bundle_ref LIMIT ?",
                (MAX_RECORD_BYTES + 1, MAX_SNAPSHOT_RECEIPTS + 1))
            try:
                for row in rows:
                    size += len(row["body"])
                    _require(len(entries) < MAX_SNAPSHOT_RECEIPTS,
                             "Q1 snapshot capacity exceeded")
                    _require(size <= MAX_SNAPSHOT_BYTES, "Q1 snapshot byte limit exceeded")
                    entries.append(self._decode(row))
            finally:
                rows.close()
        return ArtifactQ1Judge(self.artifacts, evidence=self.evidence,
                               receipts={entry.execution.bundle_ref: entry.execution
                                         for entry in entries})
