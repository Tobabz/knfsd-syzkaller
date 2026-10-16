"""Publish accepted Runner captures as immutable, host-supplied Q2 authority.

Guest Q2 payload semantics belong to ArtifactQ2Judge, not this bridge. See
Q2_RECEIPTS.md for the independent host inputs and storage trust boundary.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator

from ..artifacts import ArtifactStore, validate_digest
from ..controller.tasks import RunnerInput, runner_input_digest
from ..data import canonical_json, parse_json
from ..evidence import CollectionMetadata, EvidenceStore, ExecutionCorrelation
from ..q2 import ConsoleLogCompleteness, Q2CollectionWindow, VmTermination
from ..sealed_q2 import (
    CONSOLE_LOG_TYPE,
    MANAGER_REPORT_TYPE,
    ArtifactQ2Judge,
    Q2EvidenceUnavailable,
    TrustedQ2Execution,
    UnknownQ2Execution,
)
from .evidence_backend import (
    ReceiptInventory,
    RunnerEvidenceReceiptError,
    RunnerEvidenceReceiptStore,
)
from .models import Digest, HostRecord, Identifier, TaskBinding
from .service import DurableRunner


MAX_RECORD_BYTES = 1024 * 1024
MAX_SNAPSHOT_RECEIPTS = 4096
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
_UNAVAILABLE_SQLITE_CODES = frozenset({
    sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_IOERR,
    sqlite3.SQLITE_FULL, sqlite3.SQLITE_NOMEM, sqlite3.SQLITE_CANTOPEN,
})


class Q2AuthorityPending(UnknownQ2Execution):
    """An accepted completion or sealing receipt has not arrived; retry."""


class Q2ReceiptRejected(ValueError):
    """Host authority, capture integrity or publication history conflicts."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Q2ReceiptRejected(message)


class Q2HostContext(HostRecord):
    """Independent host facts for one task's accepted lease generation.

    ``binding`` is the dispatch record, not a job's current harness binding.
    ``artifacts`` names every captured artifact, including ancillary artifacts,
    sorted by identity. Report identities retain host collection order instead.
    Window markers are opaque host facts, not timestamps inferred from sealing.
    No field may be populated by trusting a sealed guest Q2 index.
    """

    schema_version: Literal["runner-q2-context.v1"] = "runner-q2-context.v1"
    binding: TaskBinding
    lease_generation: int = Field(ge=1, le=2**63 - 1)
    correlation: ExecutionCorrelation
    collection: CollectionMetadata
    artifacts: tuple[ReceiptInventory, ...] = Field(min_length=1, max_length=256)
    console_log_identity: Identifier | None
    console_log_completeness: ConsoleLogCompleteness
    manager_crash_report_identities: tuple[Identifier, ...] = Field(max_length=256)
    vm_termination: VmTermination
    collection_window: Q2CollectionWindow

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        _require(self.binding.task_id == self.correlation.task_id
                 and self.binding.job_id == self.correlation.job_id
                 and self.binding.execution_harness_id == self.correlation.execution_harness_id,
                 "host task binding conflicts with correlation")
        identities = tuple(item.identity for item in self.artifacts)
        _require(identities == tuple(sorted(set(identities))),
                 "host inventory must be unique and sorted by identity")
        _require(all(item.reported_correlation is None
                     or item.reported_correlation == self.correlation
                     for item in self.artifacts), "host inventory correlation mismatch")
        reports = self.manager_crash_report_identities
        _require(len(reports) == len(set(reports)), "duplicate host report identity")
        expected = {
            CONSOLE_LOG_TYPE: ({self.console_log_identity}
                               if self.console_log_identity is not None else set()),
            MANAGER_REPORT_TYPE: set(reports),
        }
        # Compare roles with the independently supplied *complete* inventory.
        # Ancillary artifact types are permitted and must also match the seal.
        # The guest index may be absent or malformed. Window/completeness
        # semantics, including internally inconsistent facts, belong to Q2.
        for artifact_type, required in expected.items():
            _require({item.identity for item in self.artifacts
                      if item.type == artifact_type} == required,
                     "Q2 artifact roles differ from host inventory")
        return self


class Q2ReceiptPublication(HostRecord):
    """Immutable authority with digests of both validated source receipts."""

    schema_version: Literal["runner-q2-publication.v1"] = "runner-q2-publication.v1"
    context: Q2HostContext
    completion_sha256: Digest
    evidence_receipt_sha256: Digest
    execution: TrustedQ2Execution


def _sha(value: BaseModel) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _execution(context: Q2HostContext, bundle_ref: str) -> TrustedQ2Execution:
    return TrustedQ2Execution(
        bundle_ref=bundle_ref,
        execution_harness_id=context.binding.execution_harness_id,
        correlation=context.correlation,
        console_log_identity=context.console_log_identity,
        console_log_completeness=context.console_log_completeness,
        manager_crash_report_identities=context.manager_crash_report_identities,
        vm_termination=context.vm_termination,
        collection_window=context.collection_window,
    )


# Cast before SUBSTR so a damaged TEXT row cannot turn the byte limit into a
# character limit. Every read path, including idempotent publish, uses this.
_COLUMNS = ("SUBSTR(bundle_ref, 1, 65) AS bundle_ref, "
            "SUBSTR(task_id, 1, 257) AS task_id, "
            "SUBSTR(body_sha256, 1, 65) AS body_sha256, "
            "SUBSTR(CAST(body AS BLOB), 1, ?) AS body")


class RunnerQ2ReceiptBridge:
    """Validate and persist Q2 authority; return detached Judge snapshots.

    History, Runner/receipt databases, CAS and supplied context are trusted
    host resources. Hashes detect corruption; they do not authenticate writers.
    Snapshot/history reads never consult Runner or collection state.
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
            CREATE TABLE IF NOT EXISTS runner_q2_publications (
                bundle_ref TEXT PRIMARY KEY,
                task_id TEXT NOT NULL UNIQUE,
                body_sha256 TEXT NOT NULL,
                body BLOB NOT NULL
            )
        """)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _prepare(self, context: Q2HostContext) -> Q2ReceiptPublication:
        # Revalidate nested model_copy/model_construct values and detach caller
        # state. JSON validation alone does not reject duplicate keys on disk.
        raw = canonical_json(context)
        _require(len(raw) <= MAX_RECORD_BYTES, "host context exceeds size limit")
        context = Q2HostContext.model_validate_json(raw)
        _require(canonical_json(context) == raw, "noncanonical host context")
        expected = context.binding
        completion = self.runner.receipt(expected.task_id)
        if completion is None:
            raise Q2AuthorityPending("Runner has not accepted a final completion")
        _require(completion.final_state == "sealed" and completion.generation > 0,
                 "Runner completion is unsealed")
        _require(completion.binding == expected
                 and completion.generation == context.lease_generation,
                 "accepted completion task or generation mismatch")
        try:
            receipt = self.receipts.get(completion.bundle_ref)
        except KeyError as exc:
            raise Q2AuthorityPending("sealing receipt is not available") from exc
        except RunnerEvidenceReceiptError as exc:
            # The real receipt API wraps direct storage errors. Do not walk
            # arbitrary cause chains: integrity errors can have OS causes too.
            cause = exc.__cause__
            code = getattr(cause, "sqlite_errorcode", None)
            sqlite_unavailable = (isinstance(cause, sqlite3.Error)
                                  and not isinstance(cause, sqlite3.ProgrammingError)
                                  and type(code) is int
                                  and (code & 0xff) in _UNAVAILABLE_SQLITE_CODES)
            if isinstance(cause, OSError) or sqlite_unavailable:
                raise Q2EvidenceUnavailable("sealing receipt storage is unavailable") from exc
            raise
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
        _require(receipt.correlation == context.correlation,
                 "host execution position mismatch")
        _require(receipt.collection == context.collection
                 and receipt.artifacts == context.artifacts,
                 "sealing receipt differs from host collection or inventory")
        _require(completion.completed_at_ns >= receipt.sealing.sealed_at_ns,
                 "completion predates evidence sealing")
        # Verify every byte and manifest claim, but never decode the guest Q2
        # index here. An authorized malformed index must reach the real Judge.
        try:
            bundle = self.evidence.verify(receipt.bundle_ref,
                                          expected_correlation=context.correlation)
        except OSError as exc:
            raise Q2EvidenceUnavailable("sealed Q2 artifacts are unavailable") from exc
        manifest = bundle.manifest
        _require(bundle.manifest_sha256 == receipt.manifest_sha256
                 and manifest.collection == receipt.collection
                 and manifest.sealing == receipt.sealing
                 and tuple(item.model_dump() for item in manifest.artifacts)
                 == tuple(item.model_dump() for item in context.artifacts),
                 "sealed evidence differs from receipt inventory or metadata")
        return Q2ReceiptPublication(
            context=context, completion_sha256=_sha(completion),
            evidence_receipt_sha256=_sha(receipt),
            execution=_execution(context, receipt.bundle_ref))

    @staticmethod
    def _decode(row: sqlite3.Row) -> Q2ReceiptPublication:
        raw = bytes(row["body"])
        _require(len(raw) <= MAX_RECORD_BYTES, "publication exceeds size limit")
        parse_json(raw)
        entry = Q2ReceiptPublication.model_validate_json(raw)
        _require(canonical_json(entry) == raw
                 and hashlib.sha256(raw).hexdigest() == row["body_sha256"],
                 "publication integrity failure")
        _require(entry.execution.bundle_ref == row["bundle_ref"]
                 and entry.context.binding.task_id == row["task_id"]
                 and entry.execution == _execution(entry.context, row["bundle_ref"]),
                 "publication identity failure")
        return entry

    def publish(self, context: Q2HostContext) -> TrustedQ2Execution:
        """Publish once, or return identical authority after full revalidation.

        Missing authority and storage failures raise without writing history.
        Invalid present evidence and conflicting history also raise; none of
        these errors creates a verdict or replaces an existing publication.
        """
        entry = self._prepare(context)
        raw = canonical_json(entry)
        _require(len(raw) <= MAX_RECORD_BYTES, "publication exceeds size limit")
        bundle_ref = entry.execution.bundle_ref
        task_id = entry.context.binding.task_id
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                rows = self._db.execute(
                    f"SELECT {_COLUMNS} FROM runner_q2_publications "
                    "WHERE bundle_ref = ? OR task_id = ? LIMIT 2",
                    (MAX_RECORD_BYTES + 1, bundle_ref, task_id)).fetchall()
                if rows:
                    _require(len(rows) == 1 and self._decode(rows[0]) == entry,
                             "published execution authority is immutable")
                else:
                    count, size = self._db.execute(
                        "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(body AS BLOB))), 0) "
                        "FROM runner_q2_publications").fetchone()
                    _require(count < MAX_SNAPSHOT_RECEIPTS, "Q2 snapshot capacity exceeded")
                    _require(size + len(raw) <= MAX_SNAPSHOT_BYTES,
                             "Q2 snapshot byte limit exceeded")
                    self._db.execute("INSERT INTO runner_q2_publications VALUES (?, ?, ?, ?)",
                                     (bundle_ref, task_id, _sha(entry), raw))
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")
        return entry.execution

    def publication(self, bundle_ref: str) -> Q2ReceiptPublication:
        """Read bounded persisted authority without live Runner/collector I/O."""
        validate_digest(bundle_ref)
        with self._lock:
            row = self._db.execute(
                f"SELECT {_COLUMNS} FROM runner_q2_publications WHERE bundle_ref = ?",
                (MAX_RECORD_BYTES + 1, bundle_ref)).fetchone()
        if row is None:
            raise KeyError(bundle_ref)
        return self._decode(row)

    def snapshot(self) -> ArtifactQ2Judge:
        """Freeze all retained publications in one SQLite read snapshot."""
        entries = []
        size = 0
        with self._lock:
            rows = self._db.execute(
                f"SELECT {_COLUMNS} FROM runner_q2_publications "
                "ORDER BY bundle_ref LIMIT ?",
                (MAX_RECORD_BYTES + 1, MAX_SNAPSHOT_RECEIPTS + 1))
            try:
                for row in rows:
                    size += len(row["body"])
                    _require(len(entries) < MAX_SNAPSHOT_RECEIPTS,
                             "Q2 snapshot capacity exceeded")
                    _require(size <= MAX_SNAPSHOT_BYTES, "Q2 snapshot byte limit exceeded")
                    entries.append(self._decode(row))
            finally:
                rows.close()
        return ArtifactQ2Judge(self.artifacts, evidence=self.evidence,
                               receipts={entry.execution.bundle_ref: entry.execution
                                         for entry in entries})
