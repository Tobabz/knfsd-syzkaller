"""Stage 2 host authority for the wired service.

Each bundle a Stage 2 Runner task adds (``DurableRunner.bundles``) gets one
``Stage2Execution``, published append-only and keyed by its bundle.  Every
field comes from host records: the Controller transition that dispatched
the task (candidate, plan, harness, compiled rule set, crash to replay),
the Runner's bundle record and lease generation, the sealing receipt with
its full task input, the execution harness descriptor, an operator
registered verified target mapping, the sealed ``stage2-host`` facts the
engine wrote, and the profiles the host configured.  Guest evidence is not
read for any of it.

After a publication the service installs a new ``ArtifactStage2Judge``
snapshot before the Controller polls, as it does for Q1.  A bundle whose
authority is not published yet makes the judge raise, which leaves the
Controller transition uncommitted until it is.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..artifacts import ArtifactStore, validate_digest
from ..contracts import (CampaignSegment, CompiledRuleSet, GateRun,
                         JudgeVersions, ReplayOutcome, Sha256)
from ..controller.records import Job, RunnerInput, TaskKind
from ..controller.store import Store
from ..data import canonical_json, load_record, parse_json
from ..evidence import EvidenceStore
from ..materializer import ExecutionHarnessDescriptor, ReachabilityHarness
from ..q1 import ExecutionCorrelation as Q1Correlation
from ..runner.evidence_backend import RunnerEvidenceReceiptStore
from ..runner.models import SealedBundleFact
from ..runner.q1_receipts import (Q1AuthorityPending, Q1HostContext,
                                  Q1ReceiptRejected, RunnerQ1ReceiptBridge)
from ..runner.service import DurableRunner
from ..sealed_q1 import TrustedQ1Execution
from ..sealed_q2 import TrustedQ2Execution
from ..stage1.authority import (DescriptorKernelIdentity, MappingCatalog,
                                Publication, candidate_target)
from .evidence import HOST_FACTS_ID, HOST_FACTS_TYPE, Stage2HostFacts
from .judge import MAX_WINDOW, ArtifactStage2Judge, Stage2Execution

MAX_RECORD_BYTES = 1024 * 1024
MAX_SNAPSHOT_RECORDS = 65536
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024


class Stage2Profiles(BaseModel):
    """The judge profiles and window bound the host publishes with every
    Stage 2 bundle: CAS references of an ``M1JudgeProfile``, a
    ``Q2JudgeProfile`` and a ``ReplayJudgeProfile``."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    m1_profile_ref: Sha256
    q2_profile_ref: Sha256
    replay_profile_ref: Sha256
    crash_window_bound: int = Field(default=4, ge=1, le=MAX_WINDOW)


class Stage2Publication(BaseModel):
    """Append-only authority and its source-record lineage for one bundle."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    schema_version: Literal["runner-stage2-publication.v1"] = \
        "runner-stage2-publication.v1"
    task_id: str
    task_input: RunnerInput
    bundle_fact_sha256: Sha256
    evidence_receipt_sha256: Sha256
    execution: Stage2Execution


def _sha(value: BaseModel) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Q1ReceiptRejected(message)


class Stage2AuthorityStore:
    """Persist publications; an existing bundle cannot change authority."""

    def __init__(self, path: Path | str, *, artifacts: ArtifactStore,
                 evidence: EvidenceStore) -> None:
        self.artifacts = artifacts
        self.evidence = evidence
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), isolation_level=None,
                                   check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS runner_stage2_publications (
                bundle_ref TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                idx INTEGER NOT NULL,
                body_sha256 TEXT NOT NULL,
                body BLOB NOT NULL,
                UNIQUE (task_id, idx)
            )
        """)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @staticmethod
    def _decode(row: sqlite3.Row) -> Stage2Publication:
        raw = bytes(row["body"])
        _require(len(raw) <= MAX_RECORD_BYTES, "publication exceeds size limit")
        parse_json(raw)
        entry = Stage2Publication.model_validate_json(raw)
        _require(canonical_json(entry) == raw
                 and hashlib.sha256(raw).hexdigest() == row["body_sha256"],
                 "publication integrity failure")
        _require(entry.execution.bundle_ref == row["bundle_ref"]
                 and entry.task_id == row["task_id"]
                 and entry.execution.index == row["idx"],
                 "publication identity failure")
        return entry

    def publish(self, entry: Stage2Publication) -> None:
        raw = canonical_json(entry)
        _require(len(raw) <= MAX_RECORD_BYTES, "publication exceeds size limit")
        x = entry.execution
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    """SELECT * FROM runner_stage2_publications
                       WHERE bundle_ref = ? OR (task_id = ? AND idx = ?)""",
                    (x.bundle_ref, entry.task_id, x.index)).fetchone()
                if row is not None:
                    _require(self._decode(row) == entry,
                             "published Stage 2 authority is immutable")
                else:
                    # A row snapshot() cannot load would stop every later
                    # install and a restart: refuse it before it is stored.
                    count, size = self._db.execute(
                        "SELECT COUNT(*), COALESCE(SUM(LENGTH(body)), 0) "
                        "FROM runner_stage2_publications").fetchone()
                    _require(count < MAX_SNAPSHOT_RECORDS,
                             "Stage 2 snapshot capacity exceeded")
                    _require(size + len(raw) <= MAX_SNAPSHOT_BYTES,
                             "Stage 2 snapshot byte limit exceeded")
                    self._db.execute(
                        "INSERT INTO runner_stage2_publications "
                        "VALUES (?, ?, ?, ?, ?)",
                        (x.bundle_ref, entry.task_id, x.index, _sha(entry), raw))
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    def publication(self, bundle_ref: str) -> Stage2Publication:
        validate_digest(bundle_ref)
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM runner_stage2_publications WHERE bundle_ref = ?",
                (bundle_ref,)).fetchone()
        if row is None:
            raise KeyError(bundle_ref)
        return self._decode(row)

    def snapshot(self) -> ArtifactStage2Judge:
        entries = []
        size = 0
        with self._lock:
            rows = self._db.execute(
                "SELECT bundle_ref, task_id, idx, body_sha256, "
                "SUBSTR(body, 1, ?) AS body FROM runner_stage2_publications "
                "ORDER BY bundle_ref LIMIT ?",
                (MAX_RECORD_BYTES + 1, MAX_SNAPSHOT_RECORDS + 1))
            try:
                for row in rows:
                    size += len(row["body"])
                    _require(len(entries) < MAX_SNAPSHOT_RECORDS,
                             "Stage 2 snapshot capacity exceeded")
                    _require(size <= MAX_SNAPSHOT_BYTES,
                             "Stage 2 snapshot byte limit exceeded")
                    entries.append(self._decode(row))
            finally:
                rows.close()
        return ArtifactStage2Judge(
            self.artifacts, evidence=self.evidence,
            executions={e.execution.bundle_ref: e.execution for e in entries})


class PublishedStage2Judge:
    """``components.Stage2Judge`` over the latest installed snapshot.
    Publications are append-only, so a newer snapshot never changes the
    answer for a bundle an older one knew."""

    def __init__(self, snapshot: ArtifactStage2Judge) -> None:
        self.snapshot = snapshot

    def install(self, snapshot: ArtifactStage2Judge) -> None:
        self.snapshot = snapshot

    def matches_execution(self, bundle_ref: str, *, job_id: str,
                          task_id: str) -> bool:
        return self.snapshot.matches_execution(bundle_ref, job_id=job_id,
                                               task_id=task_id)

    def judge_gate(self, bundle_ref: str, *, plan_ref: str,
                   candidate_id: str, compiled: CompiledRuleSet,
                   versions: JudgeVersions) -> GateRun:
        return self.snapshot.judge_gate(
            bundle_ref, plan_ref=plan_ref, candidate_id=candidate_id,
            compiled=compiled, versions=versions)

    def judge_campaign(self, bundle_ref: str, *, candidate_id: str,
                       compiled: CompiledRuleSet) -> CampaignSegment:
        return self.snapshot.judge_campaign(
            bundle_ref, candidate_id=candidate_id, compiled=compiled)

    def judge_replay(self, bundle_ref: str, *, crash_bundle_ref: str,
                     compiled: CompiledRuleSet) -> ReplayOutcome:
        return self.snapshot.judge_replay(
            bundle_ref, crash_bundle_ref=crash_bundle_ref, compiled=compiled)

    def replay_sides(self, bundle_ref: str, *, crash_bundle_ref: str,
                     compiled: CompiledRuleSet):
        """``ArtifactStage2Judge.replay_sides`` (M7 stage 2)."""
        return self.snapshot.replay_sides(
            bundle_ref, crash_bundle_ref=crash_bundle_ref, compiled=compiled)


@dataclass(frozen=True)
class _Dispatch:
    job: Job
    task_input: RunnerInput
    compiled: CompiledRuleSet


class Stage2AuthorityPublisher:
    """Publish authority for every bundle of a job's Stage 2 Runner tasks:
    its pending one and every campaign task it still takes bundles from."""

    def __init__(self, store: Store, runner: DurableRunner,
                 receipts: RunnerEvidenceReceiptStore,
                 publications: Stage2AuthorityStore,
                 q1_bridge: RunnerQ1ReceiptBridge, artifacts: ArtifactStore,
                 identities: DescriptorKernelIdentity,
                 mappings: MappingCatalog, profiles: Stage2Profiles,
                 judge: PublishedStage2Judge) -> None:
        self.store = store
        self.runner = runner
        self.receipts = receipts
        self.publications = publications
        self.q1_bridge = q1_bridge
        self.artifacts = artifacts
        self.evidence = publications.evidence
        self.identities = identities
        self.mappings = mappings
        self.profiles = Stage2Profiles.model_validate(profiles)
        self.judge = judge

    @staticmethod
    def _tasks(job: Job) -> list[str]:
        tasks = []
        p = job.pending_task
        if p is not None and p.kind is TaskKind.RUNNER and \
                p.runner_input is not None and p.runner_input.step is not None:
            tasks.append(p.task_id)
        for cursor in job.bundle_cursors:
            if cursor.task_id not in tasks:
                tasks.append(cursor.task_id)
        return tasks

    def publish_ready(self) -> list[Publication]:
        results = []
        published = False
        for job in list(self.store.jobs()):
            for task_id in self._tasks(job):
                for fact in self.runner.bundles(task_id):
                    try:
                        self.publications.publication(fact.bundle_ref)
                        continue            # already published
                    except KeyError:
                        pass
                    try:
                        self.publications.publish(self.publication(job, fact))
                    except Q1AuthorityPending as exc:
                        results.append(Publication(job.job_id, task_id,
                                                   "pending", str(exc)))
                        break               # later bundles wait in order
                    except (Q1ReceiptRejected, ValueError, OSError) as exc:
                        results.append(Publication(
                            job.job_id, task_id, "rejected",
                            f"{type(exc).__name__}: {exc}"))
                        break
                    else:
                        published = True
                        results.append(Publication(job.job_id, task_id,
                                                   "published"))
        if published:
            self.judge.install(self.publications.snapshot())
        return results

    # ------------------------------------------------------------ records

    def _dispatch(self, job_id: str, task_id: str) -> _Dispatch:
        """The job as stored by the transition that minted this task, and
        the compiled rule set it was dispatched with."""
        for t in self.store.transitions(job_id):
            p = t.job.pending_task
            if p is None or p.kind is not TaskKind.RUNNER or \
                    p.task_id != task_id:
                continue
            snapshot = t.job
            task_input = p.runner_input
            _require(task_input is not None and task_input.step is not None,
                     f"{task_id} is not a Stage 2 Runner task")
            if task_input.step == "gate":
                compiled = snapshot.compiled
            elif task_input.step == "campaign":
                compiled = next((c.compiled for c in snapshot.bundle_cursors
                                 if c.task_id == task_id), None)
            else:
                compiled = snapshot.replay.crash.compiled \
                    if snapshot.replay is not None else None
            _require(compiled is not None
                     and compiled.compiled_ref == task_input.compiled_ref,
                     f"dispatch record of {task_id} names another rule set")
            return _Dispatch(snapshot, task_input, compiled)
        raise Q1ReceiptRejected(f"no dispatch transition for {task_id}")

    def publication(self, job: Job, fact: SealedBundleFact
                    ) -> Stage2Publication:
        fact = SealedBundleFact.model_validate(fact)
        d = self._dispatch(job.job_id, fact.task_id)
        snapshot, task_input = d.job, d.task_input
        _require(snapshot.candidate is not None and
                 snapshot.binding is not None,
                 f"incomplete dispatch record for {fact.task_id}")
        try:
            receipt = self.receipts.get(fact.bundle_ref)
        except KeyError as exc:
            raise Q1AuthorityPending("sealing receipt is not available") from exc
        _require(receipt.bundle_ref == fact.bundle_ref
                 and receipt.stage2_input == task_input
                 and receipt.task_id == fact.task_id
                 and receipt.job_id == job.job_id
                 and receipt.lease_generation == fact.generation
                 and receipt.harness_ref == task_input.harness_ref
                 and receipt.execution_harness_id
                 == task_input.execution_harness_id,
                 "sealing receipt does not bind the Runner's bundle record")
        bundle = self.evidence.verify(fact.bundle_ref,
                                      expected_correlation=receipt.correlation)
        _require(bundle.manifest_sha256 == receipt.manifest_sha256,
                 "sealed evidence differs from its receipt")
        facts = Stage2HostFacts.model_validate_json(
            bundle.get(HOST_FACTS_ID, expected_type=HOST_FACTS_TYPE))
        _require(facts.step == task_input.step,
                 "sealed host facts name another step")

        harness_id = task_input.execution_harness_id
        harness = load_record(self.artifacts, task_input.harness_ref,
                              ReachabilityHarness)
        _require(harness.execution_harness_id == harness_id
                 and harness.candidate_id == snapshot.candidate.candidate_id,
                 "dispatched harness does not match the execution")
        descriptor = load_record(self.artifacts, harness_id,
                                 ExecutionHarnessDescriptor)
        identity = self.identities.identity(descriptor, harness_id)
        if identity is None:
            raise Q1AuthorityPending(
                "no host kernel identity: the descriptor must boot with "
                "nokaslr and name the vmlinux and instrumentation artifacts")
        target = candidate_target(snapshot.candidate)
        mapping_ref = self.mappings.lookup(target, identity)
        if mapping_ref is None:
            raise Q1AuthorityPending("no verified target mapping is registered")

        q1 = q2 = None
        if task_input.step == "gate":
            q1 = self._gate_q1(snapshot, task_input, receipt, identity,
                               mapping_ref, fact)
        elif task_input.step == "campaign":
            c = facts.campaign
            q2 = TrustedQ2Execution(
                bundle_ref=fact.bundle_ref, execution_harness_id=harness_id,
                correlation=receipt.correlation,
                console_log_identity=c.console_log_identity,
                console_log_completeness=c.console_log_completeness,
                manager_crash_report_identities=(
                    c.manager_crash_report_identities),
                vm_termination=c.vm_termination,
                collection_window=c.collection_window)
        else:
            crash = snapshot.replay.crash
            _require(task_input.crash_bundle_ref == crash.bundle_ref,
                     "replay input names another crash than its dispatch")
        p = self.profiles
        execution = Stage2Execution(
            bundle_ref=fact.bundle_ref, step=task_input.step, index=fact.index,
            lease_generation=fact.generation, correlation=receipt.correlation,
            candidate=target, compiled=d.compiled, identity=identity,
            mapping_ref=mapping_ref, program_ref=harness.program_ref,
            plan_ref=snapshot.plan_ref if task_input.step == "gate" else None,
            q1=q1, q2=q2, crash_bundle_ref=task_input.crash_bundle_ref,
            crash_window_bound=p.crash_window_bound,
            m1_profile_ref=p.m1_profile_ref, q2_profile_ref=p.q2_profile_ref,
            replay_profile_ref=p.replay_profile_ref)
        return Stage2Publication(
            task_id=fact.task_id, task_input=task_input,
            bundle_fact_sha256=_sha(fact), evidence_receipt_sha256=_sha(receipt),
            execution=execution)

    def _gate_q1(self, snapshot: Job, task_input: RunnerInput, receipt,
                 identity, mapping_ref: str,
                 fact: SealedBundleFact) -> TrustedQ1Execution:
        """The Stage 1 harness under the rule set: its Q1 authority holds
        exactly as a Stage 1 run's does (``check_materialization``)."""
        harness = snapshot.harness
        _require(harness is not None and snapshot.plan_ref is not None
                 and harness.harness_ref == task_input.harness_ref
                 and harness.execution_harness_id
                 == task_input.execution_harness_id,
                 "gate input differs from the dispatched harness")
        record = load_record(self.artifacts, harness.harness_ref,
                             ReachabilityHarness)
        correlation = Q1Correlation.model_validate(
            receipt.correlation.model_dump())
        context = Q1HostContext(
            candidate=snapshot.candidate, plan_ref=snapshot.plan_ref,
            binding=snapshot.binding, materialized=harness,
            lease_generation=fact.generation, identity=identity,
            correlation=correlation,
            trace_mode=record.runtime_selection.trace_mode,
            mapping_ref=mapping_ref,
            vmlinux_artifact_name=self.identities.vmlinux_artifact_name,
            instrumentation_artifact_name=(
                self.identities.instrumentation_artifact_name))
        self.q1_bridge.check_materialization(context)
        return TrustedQ1Execution(
            bundle_ref=fact.bundle_ref, plan_ref=snapshot.plan_ref,
            candidate=candidate_target(snapshot.candidate), identity=identity,
            correlation=correlation, trace_mode=context.trace_mode,
            mapping_ref=mapping_ref)


__all__ = ["PublishedStage2Judge", "Stage2AuthorityPublisher",
           "Stage2AuthorityStore", "Stage2Profiles", "Stage2Publication"]
