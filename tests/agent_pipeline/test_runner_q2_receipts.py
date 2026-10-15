"""Standalone Q2 publication tests using real Runner/sealer/Judge APIs."""

from __future__ import annotations

import errno
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.controller.tasks import RunnerInput, runner_input_digest
from agent_pipeline.data import canonical_json, put_record
from agent_pipeline.evidence import (
    ArtifactInput, CollectionMetadata, EvidenceLimits, EvidenceStore,
    ExecutionCorrelation,
)
from agent_pipeline.q2 import Q2CollectionWindow, Q2Status, default_q2_profile
from agent_pipeline.runner import q2_receipts
from agent_pipeline.runner.evidence_backend import (
    EvidenceSealingBackend, ExecutionCapture, HostExecutionFacts, ReceiptInventory,
    RunnerEvidenceReceipt, RunnerEvidenceReceiptError, RunnerEvidenceReceiptStore,
)
from agent_pipeline.runner.models import BackendResult, TaskBinding
from agent_pipeline.runner.q2_receipts import (
    Q2AuthorityPending, Q2HostContext, Q2ReceiptRejected, RunnerQ2ReceiptBridge,
)
from agent_pipeline.runner.service import DurableRunner, LeaseLost, RunnerDataError
from agent_pipeline.runner.worker import LeaseControl
from agent_pipeline.sealed_q2 import (
    CONSOLE_LOG_TYPE, MANAGER_REPORT_TYPE, Q2_EVIDENCE_ID, Q2_EVIDENCE_TYPE,
    Q2EvidenceUnavailable, SealedArtifactRef, SealedQ2Evidence, UnknownQ2Execution,
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Pipeline:
    """Synthetic host capture, with no materializer, Controller, VM or model."""

    def __init__(self, root):
        self.runner_path = root / "runner.sqlite"
        self.receipt_path = root / "receipts.sqlite"
        self.history_path = root / "q2.sqlite"
        self.now = 100
        self.artifacts = ArtifactStore(root / "artifacts")
        self.evidence = EvidenceStore(self.artifacts, limits=EvidenceLimits(
            max_artifact_bytes=4096, max_bundle_bytes=16384, max_artifacts=16))
        self.runner = self.new_runner()
        self.receipts = RunnerEvidenceReceiptStore(self.receipt_path)
        self.bridge = self.new_bridge()
        self.profile_ref = put_record(self.artifacts, default_q2_profile())
        self.prepare()

    def new_runner(self):
        return DurableRunner(self.runner_path, clock=lambda: self.now,
                             lease_duration_ns=1000)

    def new_bridge(self):
        return RunnerQ2ReceiptBridge(self.history_path, runner=self.runner,
                                    receipts=self.receipts, artifacts=self.artifacts,
                                    evidence=self.evidence)

    def prepare(self, *, task="task-1", reports=(), completeness="complete",
                termination="runner_stopped", window=None, guest_update=None,
                index_bytes=None, omit_index=False, extras=()):
        self.now = 100
        binding = TaskBinding(task_id=task, job_id="job-1", harness_ref=sha(b"harness"),
                              execution_harness_id=sha(b"execution-harness"))
        correlation = ExecutionCorrelation(
            task_id=task, job_id=binding.job_id,
            execution_harness_id=binding.execution_harness_id,
            vm_instance_id="vm-1", lane=3, generation_id=7)
        collection = CollectionMetadata(collector_id="host", started_at_ns=110,
                                        completed_at_ns=120)
        window = window if window is not None else Q2CollectionWindow(
            start_marker="host-start", end_marker="host-end")
        console_id = None if completeness == "missing" else "console"
        console = b"bounded synthetic console\n"
        # Reverse lexical order deliberately: report order is host collection
        # order, while the complete inventory has canonical identity order.
        report_inputs = tuple(ArtifactInput(identity=f"report-{255 - i}",
            type=MANAGER_REPORT_TYPE, data=data) for i, data in enumerate(reports))
        observation = SealedQ2Evidence(
            execution_harness_id=binding.execution_harness_id, correlation=correlation,
            console_log_identity=console_id,
            console_log_ref=sha(console) if console_id else None,
            console_log_completeness=completeness,
            manager_crash_reports=tuple(SealedArtifactRef(identity=a.identity,
                sha256=sha(a.data)) for a in report_inputs),
            vm_termination=termination, collection_window=window)
        if guest_update:
            observation = observation.model_copy(update=guest_update)
        inputs = list(extras) + list(report_inputs)
        if not omit_index:
            inputs.append(ArtifactInput(identity=Q2_EVIDENCE_ID, type=Q2_EVIDENCE_TYPE,
                data=canonical_json(observation) if index_bytes is None else index_bytes))
        if console_id:
            inputs.append(ArtifactInput(identity=console_id, type=CONSOLE_LOG_TYPE,
                                         data=console))
        self.capture = ExecutionCapture(facts=HostExecutionFacts(
            vm_instance_id=correlation.vm_instance_id, lane=correlation.lane,
            generation_id=correlation.generation_id, collector_id=collection.collector_id,
            collection_started_at_ns=collection.started_at_ns,
            collection_completed_at_ns=collection.completed_at_ns), artifacts=tuple(inputs))
        # Authority comes from the synthetic host's inputs, never observation.
        self.context = Q2HostContext(binding=binding, lease_generation=1,
            correlation=correlation, collection=collection,
            artifacts=tuple(ReceiptInventory(identity=a.identity, type=a.type,
                sha256=sha(a.data), size=len(a.data)) for a in sorted(inputs, key=lambda a: a.identity)),
            console_log_identity=console_id, console_log_completeness=completeness,
            manager_crash_report_identities=tuple(a.identity for a in report_inputs),
            vm_termination=termination, collection_window=window)

    def start(self):
        b = self.context.binding
        self.runner.submit(b.task_id, RunnerInput(job_id=b.job_id, harness_ref=b.harness_ref,
                                                  execution_harness_id=b.execution_harness_id))
        self.lease = self.runner.claim("worker")
        self.control = LeaseControl(self.runner, self.lease)

    def seal(self):
        engine = SimpleNamespace(capture=lambda lease, control: self.capture)
        backend = EvidenceSealingBackend(engine, self.evidence, self.receipts,
                                        sealer_id="host-sealer", clock=lambda: 130)
        self.result = backend.execute(self.lease, self.control)
        assert self.result.bundle_ref is not None, self.result
        return self.result.bundle_ref

    def complete(self):
        self.start()
        ref = self.seal()
        self.now = 140
        self.runner.complete(self.control.lease, self.result)
        return ref

    def judge(self, snapshot=None):
        return (snapshot or self.bridge.snapshot()).judge(self.result.bundle_ref,
                                                         self.profile_ref)

    def restart(self):
        self.close()
        self.runner = self.new_runner()
        self.receipts = RunnerEvidenceReceiptStore(self.receipt_path)
        self.bridge = self.new_bridge()

    def close(self):
        self.bridge.close()
        self.receipts.close()
        self.runner.close()


@pytest.fixture
def pipeline(tmp_path):
    p = Pipeline(tmp_path)
    yield p
    p.close()


def replace_receipt(p, data):
    receipt = RunnerEvidenceReceipt.model_validate_json(canonical_json(data))
    raw = canonical_json(receipt)
    with sqlite3.connect(p.receipt_path) as db:
        db.execute("UPDATE runner_evidence_receipts SET body = ?, receipt_sha256 = ?",
                   (raw, sha(raw)))


@pytest.mark.parametrize("reports,status", [
    ((), Q2Status.NOT_OBSERVED),
    ((b"BUG: KASAN: synthetic error\n",), Q2Status.OBSERVED),
    ((b"unclassified report\n",), Q2Status.INCONCLUSIVE),
])
def test_real_runner_sealer_and_q2_judge(pipeline, reports, status):
    p = pipeline
    p.prepare(reports=reports, extras=(ArtifactInput(identity="ancillary",
                                                   type="application/octet-stream", data=b"extra"),))
    ref = p.complete()
    execution = p.bridge.publish(p.context)
    lineage = p.bridge.publication(ref)
    assert lineage.execution == execution
    assert lineage.context == p.context
    assert lineage.completion_sha256 == sha(canonical_json(p.runner.receipt("task-1")))
    assert lineage.evidence_receipt_sha256 == sha(canonical_json(p.receipts.get(ref)))
    assert p.judge().status is status
    assert p.judge() == p.judge()
    assert p.bridge.snapshot().matches_execution(ref, job_id="job-1", task_id="task-1")
    assert not p.bridge.snapshot().matches_execution(ref, job_id="job-1", task_id="other")


@pytest.mark.parametrize("window,reason", [
    (Q2CollectionWindow(start_marker="start"), "collection_window_open"),
    (Q2CollectionWindow(), "collection_window_not_started"),
    (Q2CollectionWindow(end_marker="end"), "invalid_evidence"),
])
@pytest.mark.parametrize("fatal", [False, True])
def test_marker_precedence_belongs_to_existing_judge(pipeline, window, reason, fatal):
    p = pipeline
    p.prepare(window=window, reports=(b"BUG: KASAN: test\n",) if fatal else ())
    p.complete()
    p.bridge.publish(p.context)
    result = p.judge()
    observed = fatal and reason != "invalid_evidence"
    assert result.status is (Q2Status.OBSERVED if observed else Q2Status.INCONCLUSIVE)
    assert result.reason == (None if observed else reason)


@pytest.mark.parametrize("completeness,termination,reason", [
    ("truncated", "runner_stopped", "console_log_truncated"),
    ("missing", "runner_stopped", "console_log_missing"),
    ("complete", "lost", "runner_lost"),
    ("complete", "unknown", "termination_unknown"),
    ("complete", "guest_crashed", "guest_crashed_without_report"),
])
def test_host_incomplete_capture_is_publishable(pipeline, completeness, termination, reason):
    p = pipeline
    p.prepare(completeness=completeness, termination=termination)
    p.complete()
    p.bridge.publish(p.context)
    assert p.judge().status is Q2Status.INCONCLUSIVE
    assert p.judge().reason == reason


@pytest.mark.parametrize("kind", ["malformed", "duplicate", "missing", "task", "harness",
                                  "window", "completeness", "termination", "inventory", "hash"])
def test_guest_index_cannot_supply_or_block_authority(pipeline, kind):
    p = pipeline
    changes = {
        "task": {"correlation": p.context.correlation.model_copy(update={"task_id": "forged"})},
        "harness": {"execution_harness_id": "f" * 64},
        "window": {"collection_window": Q2CollectionWindow(start_marker="guest")},
        "completeness": {"console_log_completeness": "truncated"},
        "termination": {"vm_termination": "lost"},
        "inventory": {"manager_crash_reports": ()},
        "hash": {"console_log_ref": "f" * 64},
    }
    raw = {"malformed": b"{", "duplicate": b'{"x":1,"x":2}'}.get(kind)
    p.prepare(reports=(b"BUG: KASAN: real report\n",), guest_update=changes.get(kind),
              index_bytes=raw, omit_index=kind == "missing")
    ref = p.complete()
    assert p.bridge.publish(p.context).correlation == p.context.correlation
    assert p.bridge.publication(ref).context == p.context
    assert p.judge().status is Q2Status.INCONCLUSIVE
    assert p.judge().reason == "invalid_evidence"


def test_unknown_and_orphan_completion_remain_pending_across_restart(pipeline):
    p = pipeline
    with pytest.raises(Q2AuthorityPending):
        p.bridge.publish(p.context)
    p.start()
    ref = p.seal()
    with pytest.raises(Q2AuthorityPending):
        p.bridge.publish(p.context)
    old = p.bridge.snapshot()
    p.restart()
    with pytest.raises(UnknownQ2Execution):
        old.judge(ref, p.profile_ref)
    p.now = 140
    p.runner.complete(p.lease, p.result)
    p.bridge.publish(p.context)
    assert p.judge().status is Q2Status.NOT_OBSERVED


def test_late_receipt_is_pending_then_retryable(pipeline):
    p = pipeline
    ref = p.complete()
    receipt = p.receipts.get(ref)
    with sqlite3.connect(p.receipt_path) as db:
        db.execute("DELETE FROM runner_evidence_receipts")
    with pytest.raises(Q2AuthorityPending, match="sealing receipt"):
        p.bridge.publish(p.context)
    assert not p.bridge.snapshot().receipts
    p.restart()
    p.receipts.put(receipt)
    p.bridge.publish(p.context)
    assert p.judge().status is Q2Status.NOT_OBSERVED


def test_reclaimed_lease_cannot_adopt_stale_seal(pipeline):
    p = pipeline
    p.start()
    p.seal()
    p.now = p.lease.expires_at_ns + 1
    replacement = p.runner.claim("replacement")
    with pytest.raises(LeaseLost):
        p.runner.complete(p.lease, p.result)
    p.runner.complete(replacement, p.result)
    with pytest.raises(Q2ReceiptRejected, match="generation"):
        p.bridge.publish(p.context)
    with pytest.raises(Q2ReceiptRejected, match="accepted completion"):
        p.bridge.publish(p.context.model_copy(update={"lease_generation": 2}))
    assert not p.bridge.snapshot().receipts


def test_wrong_task_cannot_adopt_accepted_bundle(pipeline):
    p = pipeline
    p.complete()
    old_result = p.result
    p.prepare(task="task-2")
    p.start()
    p.now = 140
    p.runner.complete(p.lease, old_result)
    with pytest.raises(Q2ReceiptRejected, match="accepted completion"):
        p.bridge.publish(p.context)


def test_unsealed_completion_never_publishes(pipeline):
    p = pipeline
    p.start()
    p.runner.complete(p.lease, BackendResult(reason="capture_failed"))
    with pytest.raises(Q2ReceiptRejected, match="unsealed"):
        p.bridge.publish(p.context)


@pytest.mark.parametrize("field,value", [("job_id", "other"), ("harness_ref", "f" * 64),
    ("execution_harness_id", "e" * 64), ("vm_instance_id", "vm-2"),
    ("lane", 4), ("generation_id", 8), ("lease_generation", 2)])
def test_independent_host_binding_must_match(pipeline, field, value):
    p = pipeline
    p.complete()
    data = p.context.model_dump(mode="json")
    if field in data["binding"]:
        data["binding"][field] = value
    if field in data["correlation"]:
        data["correlation"][field] = value
    if field == "lease_generation":
        data[field] = value
    context = Q2HostContext.model_validate_json(canonical_json(data))
    with pytest.raises(Q2ReceiptRejected):
        p.bridge.publish(context)


@pytest.mark.parametrize("kind", ["collector", "interval", "omitted", "extra", "hash", "size", "type"])
def test_complete_host_inventory_and_collection_must_match(pipeline, kind):
    p = pipeline
    p.prepare(extras=(ArtifactInput(identity="extra", type="application/octet-stream", data=b"x"),))
    p.complete()
    data = p.context.model_dump(mode="json")
    if kind == "collector":
        data["collection"]["collector_id"] = "other"
    elif kind == "interval":
        data["collection"]["completed_at_ns"] += 1
    elif kind == "omitted":
        data["artifacts"] = [a for a in data["artifacts"] if a["identity"] != "extra"]
    elif kind == "extra":
        data["artifacts"].append({**data["artifacts"][-1], "identity": "z-extra",
                                  "type": "application/octet-stream"})
    else:
        extra = next(a for a in data["artifacts"] if a["identity"] == "extra")
        extra[{"hash": "sha256", "size": "size", "type": "type"}[kind]] = {
            "hash": "f" * 64, "size": 100, "type": "text/plain"}[kind]
    context = Q2HostContext.model_validate_json(canonical_json(data))
    with pytest.raises(Q2ReceiptRejected, match="collection or inventory"):
        p.bridge.publish(context)


@pytest.mark.parametrize("kind", ["inventory", "collection", "sealing", "task", "job", "harness"])
def test_schema_valid_forged_receipt_is_rejected(pipeline, kind):
    p = pipeline
    ref = p.complete()
    data = p.receipts.get(ref).model_dump(mode="json")
    if kind == "inventory":
        data["artifacts"][0]["size"] += 1
    elif kind == "collection":
        data["collection"]["collector_id"] = "other"
    elif kind == "sealing":
        data["sealing"]["sealer_id"] = "other"
    elif kind in ("task", "job"):
        data[f"{kind}_id"] = data["correlation"][f"{kind}_id"] = "other"
    else:
        data["harness_ref"] = "f" * 64
    data["task_input_sha256"] = runner_input_digest(RunnerInput(
        job_id=data["job_id"], harness_ref=data["harness_ref"],
        execution_harness_id=data["execution_harness_id"]))
    replace_receipt(p, data)
    with pytest.raises(Q2ReceiptRejected):
        p.bridge.publish(p.context)


@pytest.mark.parametrize("kind", ["inventory", "collection"])
def test_receipt_and_context_must_also_match_manifest(pipeline, kind):
    p = pipeline
    ref = p.complete()
    data = p.receipts.get(ref).model_dump(mode="json")
    context = p.context.model_dump(mode="json")
    if kind == "inventory":
        data["artifacts"][0]["size"] += 1
        context["artifacts"] = data["artifacts"]
    else:
        data["collection"]["collector_id"] = "other"
        context["collection"] = data["collection"]
    replace_receipt(p, data)
    with pytest.raises(Q2ReceiptRejected, match="sealed evidence"):
        p.bridge.publish(Q2HostContext.model_validate_json(canonical_json(context)))


def test_completion_must_follow_sealing(pipeline):
    p = pipeline
    p.start()
    p.seal()
    p.now = 125
    p.runner.complete(p.lease, p.result)
    with pytest.raises(Q2ReceiptRejected, match="predates"):
        p.bridge.publish(p.context)


@pytest.mark.parametrize("source", ["completion", "receipt"])
def test_source_receipt_integrity_is_not_hidden(pipeline, source):
    p = pipeline
    p.complete()
    path = p.runner_path if source == "completion" else p.receipt_path
    table = "runner_tasks" if source == "completion" else "runner_evidence_receipts"
    with sqlite3.connect(path) as db:
        db.execute(f"UPDATE {table} SET receipt_sha256 = ?", ("0" * 64,))
    with pytest.raises(RunnerDataError if source == "completion" else RunnerEvidenceReceiptError):
        p.bridge.publish(p.context)


@pytest.mark.parametrize("target", ["manifest", "console", "q2-evidence", "report-255"])
@pytest.mark.parametrize("kind", ["missing", "corrupt", "symlink"])
def test_storage_availability_is_distinct_from_invalid_bytes(pipeline, target, kind):
    p = pipeline
    p.prepare(reports=(b"BUG: KASAN: report\n",))
    ref = p.complete()
    p.bridge.publish(p.context)
    snapshot = p.bridge.snapshot()
    artifact_ref = ref if target == "manifest" else next(
        a.sha256 for a in p.context.artifacts if a.identity == target)
    path = p.artifacts._path(artifact_ref)
    original = path.read_bytes()
    if kind == "corrupt":
        path.write_bytes(b"invalid")
    else:
        path.unlink()
        if kind == "symlink":
            path.symlink_to("absent-object")
    if kind == "missing":
        with pytest.raises(Q2EvidenceUnavailable):
            p.bridge.publish(p.context)
        with pytest.raises(Q2EvidenceUnavailable):
            p.judge(snapshot)
        path.write_bytes(original)
        p.bridge.publish(p.context)
        assert p.judge(snapshot).status is Q2Status.OBSERVED
    else:
        with pytest.raises(ValueError) as error:
            p.bridge.publish(p.context)
        assert not isinstance(error.value, Q2AuthorityPending)
        assert p.judge(snapshot).reason == "invalid_evidence"


def test_actual_busy_receipt_database_remains_retryable(pipeline):
    p = pipeline
    p.complete()
    # WAL readers normally survive a writer. DELETE mode + exclusive writer
    # forces the real receipt store's SELECT to encounter SQLITE_BUSY.
    p.receipts._db.execute("PRAGMA journal_mode = DELETE")
    p.receipts._db.execute("PRAGMA busy_timeout = 0")
    blocker = sqlite3.connect(p.receipt_path, isolation_level=None)
    try:
        blocker.execute("BEGIN EXCLUSIVE")
        with pytest.raises(Q2EvidenceUnavailable) as error:
            p.bridge.publish(p.context)
        assert error.value.__cause__.__cause__.sqlite_errorcode == sqlite3.SQLITE_BUSY
        assert not p.bridge.snapshot().receipts
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    p.bridge.publish(p.context)


@pytest.mark.parametrize("code,retry", [
    (sqlite3.SQLITE_LOCKED, True), (sqlite3.SQLITE_IOERR_READ, True),
    (sqlite3.SQLITE_BUSY_SNAPSHOT, True), (sqlite3.SQLITE_FULL, True),
    (sqlite3.SQLITE_NOMEM, True), (sqlite3.SQLITE_CANTOPEN, True),
    (sqlite3.SQLITE_CORRUPT, False), (sqlite3.SQLITE_NOTADB, False),
    (sqlite3.SQLITE_MISUSE, False), (None, False),
])
def test_wrapped_sqlite_error_codes_are_classified_narrowly(pipeline, monkeypatch, code, retry):
    p = pipeline
    p.complete()
    cause = sqlite3.ProgrammingError("closed") if code is None else sqlite3.DatabaseError("storage")
    if code is not None:
        cause.sqlite_errorcode = code

    def broken(_):
        raise RunnerEvidenceReceiptError("could not load evidence receipt") from cause

    monkeypatch.setattr(p.receipts, "get", broken)
    with pytest.raises(Q2EvidenceUnavailable if retry else RunnerEvidenceReceiptError):
        p.bridge.publish(p.context)


def test_wrapped_os_error_is_retryable_but_nested_integrity_cause_is_not(pipeline, monkeypatch):
    p = pipeline
    p.complete()

    def unavailable(_):
        raise RunnerEvidenceReceiptError("read") from OSError(errno.EIO, "temporary")

    monkeypatch.setattr(p.receipts, "get", unavailable)
    with pytest.raises(Q2EvidenceUnavailable):
        p.bridge.publish(p.context)

    def invalid(_):
        try:
            raise ValueError("integrity") from OSError(errno.ELOOP, "symlink")
        except ValueError as exc:
            raise RunnerEvidenceReceiptError("read") from exc

    monkeypatch.setattr(p.receipts, "get", invalid)
    with pytest.raises(RunnerEvidenceReceiptError):
        p.bridge.publish(p.context)


def test_unavailable_bytes_before_publication_create_no_history(pipeline, monkeypatch):
    p = pipeline
    ref = p.complete()
    original = p.artifacts.get

    def unavailable(*args, **kwargs):
        raise OSError(errno.EIO, "temporary storage failure")

    monkeypatch.setattr(p.artifacts, "get", unavailable)
    with pytest.raises(Q2EvidenceUnavailable):
        p.bridge.publish(p.context)
    assert not p.bridge.snapshot().receipts
    with pytest.raises(KeyError):
        p.bridge.publication(ref)
    monkeypatch.setattr(p.artifacts, "get", original)
    p.bridge.publish(p.context)


def test_idempotence_restart_and_detached_snapshots(pipeline):
    p = pipeline
    first_ref = p.complete()
    trusted = p.bridge.publish(p.context)
    old = p.bridge.snapshot()
    lineage = p.bridge.publication(first_ref)
    assert p.bridge.publish(p.context) == trusted
    p.restart()
    assert p.bridge.publish(p.context) == trusted
    assert p.bridge.publication(first_ref) == lineage
    assert p.judge() == p.judge(old)
    p.prepare(task="task-2", reports=(b"WARNING: second task\n",))
    second_ref = p.complete()
    p.bridge.publish(p.context)
    assert set(p.bridge.snapshot().receipts) == {first_ref, second_ref}
    assert tuple(old.receipts) == (first_ref,)
    with pytest.raises(UnknownQ2Execution):
        p.judge(old)
    with pytest.raises(TypeError):
        old.receipts[second_ref] = trusted


def test_reopened_history_needs_no_live_runner_or_collector(pipeline, monkeypatch):
    p = pipeline
    ref = p.complete()
    p.bridge.publish(p.context)
    entry = p.bridge.publication(ref)
    p.restart()
    p.runner.close()
    p.receipts.close()
    assert p.bridge.publication(ref) == entry
    assert p.judge().status is Q2Status.NOT_OBSERVED
    # Even CAS unavailability cannot prevent reading authority itself.
    def unavailable(*args, **kwargs):
        raise OSError(errno.EIO, "unavailable")
    monkeypatch.setattr(p.artifacts, "get", unavailable)
    assert p.bridge.publication(ref) == entry
    assert ref in p.bridge.snapshot().receipts


@pytest.mark.parametrize("field,value", [
    ("console_log_completeness", "truncated"), ("vm_termination", "lost"),
    ("collection_window", Q2CollectionWindow(start_marker="different")),
    ("manager_crash_report_identities", ("report-254", "report-255")),
])
def test_changed_host_history_is_rejected(pipeline, field, value):
    p = pipeline
    p.prepare(reports=(b"WARNING: first\n", b"BUG: KASAN: second\n"))
    ref = p.complete()
    p.bridge.publish(p.context)
    old = p.bridge.publication(ref)
    p.restart()
    with pytest.raises(Q2ReceiptRejected, match="immutable"):
        p.bridge.publish(p.context.model_copy(update={field: value}))
    assert p.bridge.publication(ref) == old
    assert [signal.signal_class for signal in p.judge().signals] == ["WARNING", "KASAN"]


def test_changed_source_completion_cannot_rewrite_history(pipeline):
    p = pipeline
    ref = p.complete()
    p.bridge.publish(p.context)
    data = p.runner.receipt("task-1").model_dump(mode="json")
    data["completed_at_ns"] += 1
    raw = canonical_json(data)
    with sqlite3.connect(p.runner_path) as db:
        db.execute("UPDATE runner_tasks SET receipt_json = ?, receipt_sha256 = ?", (raw, sha(raw)))
    with pytest.raises(Q2ReceiptRejected, match="immutable"):
        p.bridge.publish(p.context)
    assert p.bridge.publication(ref).completion_sha256 != sha(raw)


@pytest.mark.parametrize("kind", ["hash", "task_key", "bundle_key", "execution", "noncanonical", "duplicate"])
def test_damaged_publication_is_rejected_on_all_read_paths(pipeline, kind):
    p = pipeline
    ref = p.complete()
    p.bridge.publish(p.context)
    entry = p.bridge.publication(ref)
    raw = canonical_json(entry)
    key = ref
    with sqlite3.connect(p.history_path) as db:
        if kind == "hash":
            db.execute("UPDATE runner_q2_publications SET body_sha256 = ?", ("0" * 64,))
        elif kind == "task_key":
            db.execute("UPDATE runner_q2_publications SET task_id = 'other'")
        elif kind == "bundle_key":
            key = "f" * 64
            db.execute("UPDATE runner_q2_publications SET bundle_ref = ?", (key,))
        else:
            data = entry.model_dump(mode="json")
            if kind == "execution":
                data["execution"]["collection_window"]["end_marker"] = "changed"
                raw = canonical_json(data)
            elif kind == "noncanonical":
                raw = json.dumps(data, indent=2).encode()
            else:
                raw = b'{"schema_version":"runner-q2-publication.v1",' + raw[1:]
            db.execute("UPDATE runner_q2_publications SET body = ?, body_sha256 = ?", (raw, sha(raw)))
    p.restart()
    for read in (lambda: p.bridge.publication(key), p.bridge.snapshot,
                 lambda: p.bridge.publish(p.context)):
        with pytest.raises(ValueError):
            read()


@pytest.mark.parametrize("as_text", [False, True])
def test_all_history_reads_bound_oversized_persisted_rows(pipeline, monkeypatch, as_text):
    p = pipeline
    ref = p.complete()
    p.bridge.publish(p.context)
    limit = len(canonical_json(p.bridge.publication(ref)))
    monkeypatch.setattr(q2_receipts, "MAX_RECORD_BYTES", limit)
    oversized = "가" * limit if as_text else b"x" * (limit * 2)
    with sqlite3.connect(p.history_path) as db:
        db.execute("UPDATE runner_q2_publications SET body = ?", (oversized,))
    lengths = []
    original = p.bridge._decode
    def checked(row):
        lengths.append(len(row["body"]))
        return original(row)
    monkeypatch.setattr(p.bridge, "_decode", checked)
    for read in (lambda: p.bridge.publication(ref), p.bridge.snapshot,
                 lambda: p.bridge.publish(p.context)):
        with pytest.raises(Q2ReceiptRejected, match="size limit"):
            read()
    assert lengths == [limit + 1] * 3


@pytest.mark.parametrize("limit", ["MAX_SNAPSHOT_BYTES", "MAX_SNAPSHOT_RECEIPTS"])
def test_limits_preserve_retained_history_and_idempotence(pipeline, monkeypatch, limit):
    p = pipeline
    ref = p.complete()
    p.bridge.publish(p.context)
    entry = p.bridge.publication(ref)
    cap = len(canonical_json(entry)) if limit == "MAX_SNAPSHOT_BYTES" else 1
    monkeypatch.setattr(q2_receipts, limit, cap)
    assert p.bridge.publish(p.context) == entry.execution
    assert tuple(p.bridge.snapshot().receipts) == (ref,)
    p.prepare(task="task-2")
    p.complete()
    with pytest.raises(Q2ReceiptRejected, match="capacity|limit"):
        p.bridge.publish(p.context)
    assert p.bridge.publication(ref) == entry
    monkeypatch.setattr(q2_receipts, limit, cap - 1)
    with pytest.raises(Q2ReceiptRejected, match="capacity|limit"):
        p.bridge.snapshot()


def test_host_context_size_and_nested_validation(pipeline, monkeypatch):
    p = pipeline
    p.complete()
    with pytest.raises(ValueError):
        p.bridge.publish(p.context.model_copy(update={"correlation":
            p.context.correlation.model_copy(update={"lane": True})}))
    monkeypatch.setattr(q2_receipts, "MAX_RECORD_BYTES", len(canonical_json(p.context)) - 1)
    with pytest.raises(Q2ReceiptRejected, match="host context exceeds"):
        p.bridge.publish(p.context)
    assert not p.bridge.snapshot().receipts


def test_caller_mutation_cannot_change_published_snapshot(pipeline):
    p = pipeline
    p.complete()
    p.bridge.publish(p.context)
    snapshot = p.bridge.snapshot()
    object.__setattr__(p.context.collection_window, "end_marker", "mutated")
    assert p.judge(snapshot).status is Q2Status.NOT_OBSERVED
    assert snapshot.receipts[p.result.bundle_ref].collection_window.end_marker == "host-end"


def test_two_connections_serialize_identical_publication(pipeline):
    p = pipeline
    ref = p.complete()
    other = p.new_bridge()
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda bridge: bridge.publish(p.context), [p.bridge, other]))
        assert results[0] == results[1]
        assert tuple(p.bridge.snapshot().receipts) == (ref,)
    finally:
        other.close()


def test_snapshot_single_select_isolated_from_concurrent_publication(pipeline, monkeypatch):
    p = pipeline
    ref = p.complete()
    p.bridge.publish(p.context)
    p.prepare(task="task-2")
    second_ref = p.complete()
    p.bridge.publish(p.context)
    p.prepare(task="task-3")
    third_ref = p.complete()
    other = p.new_bridge()
    original = p.bridge._decode
    def publish_during_read(row):
        other.publish(p.context)
        return original(row)
    monkeypatch.setattr(p.bridge, "_decode", publish_during_read)
    try:
        snapshot = p.bridge.snapshot()
        assert set(snapshot.receipts) == {ref, second_ref}
        assert set(other.snapshot().receipts) == {ref, second_ref, third_ref}
    finally:
        other.close()
