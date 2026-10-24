"""Stage 2 Runner backend: bundles a lease seals while it runs (09 §4, §8),
the streaming sealing backend and the Stage 1 / Stage 2 routing."""

from __future__ import annotations

import hashlib
import time

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.controller.tasks import RunnerInput, runner_input_digest
from agent_pipeline.data import canonical_json
from agent_pipeline.evidence import ArtifactInput, EvidenceStore
from agent_pipeline.runner import DurableRunner, LeaseLost, RunnerWorker
from agent_pipeline.runner.evidence_backend import (
    CAPTURE_FAILED, DUPLICATE_ARTIFACT, LEASE_LOST_DURING_CAPTURE,
    STAGE2_BACKEND_UNAVAILABLE,
    EvidenceSealingBackend, ExecutionCapture, HostExecutionFacts,
    RunnerEvidenceReceiptStore, StepRoutingBackend, StreamingSealingBackend)
from agent_pipeline.runner.models import BackendResult


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


STAGE1 = RunnerInput(job_id="job-1", harness_ref=sha("harness"),
                     execution_harness_id=sha("execution-harness"))
CAMPAIGN = RunnerInput(job_id="job-1", harness_ref=sha("harness"),
                       execution_harness_id=sha("execution-harness"),
                       step="campaign", compiled_ref=sha("compiled"),
                       campaign_id="job-1.c1")


def capture(n: int, *, duplicate: bool = False) -> ExecutionCapture:
    artifacts = (ArtifactInput(identity="segment", type="text/plain",
                               data=f"segment {n}".encode()),)
    if duplicate:
        artifacts += artifacts
    return ExecutionCapture(
        facts=HostExecutionFacts(
            vm_instance_id=f"vm-{n}", lane=0, generation_id=n + 1,
            collector_id="stage2-test",
            collection_started_at_ns=time.time_ns(),
            collection_completed_at_ns=time.time_ns()),
        artifacts=artifacts)


class World:
    def __init__(self, tmp_path, task_input=CAMPAIGN):
        self.runner = DurableRunner(tmp_path / "runner.sqlite",
                                    lease_duration_ns=60_000_000_000)
        self.artifacts = ArtifactStore(tmp_path / "artifacts")
        self.evidence = EvidenceStore(self.artifacts)
        self.receipts = RunnerEvidenceReceiptStore(tmp_path / "receipts.sqlite")
        self.runner.submit("job-1.t1", task_input)

    def streaming(self, engine) -> StreamingSealingBackend:
        return StreamingSealingBackend(engine, self.evidence, self.receipts,
                                       self.runner, sealer_id="stage2-test")

    def close(self):
        self.receipts.close()
        self.runner.close()


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    yield w
    w.close()


class Segments:
    """Emits ``captures`` in order and records what the Runner reports
    after each one, as the Controller would see it mid-run."""

    def __init__(self, runner, captures, *, fail_after: int | None = None):
        self.runner = runner
        self.captures = captures
        self.fail_after = fail_after
        self.seen: list[tuple[str, int]] = []

    def run(self, lease, control, emit):
        for i, c in enumerate(self.captures):
            if self.fail_after is not None and i == self.fail_after:
                raise RuntimeError("the VM went away")
            emit(c() if callable(c) else c)
            st = self.runner.status(lease.binding.task_id)
            self.seen.append((st.state, len(st.bundles)))


def test_campaign_bundles_reach_the_controller_while_the_task_runs(world):
    engine = Segments(world.runner, [lambda: capture(0), lambda: capture(1), lambda: capture(2)])
    run = RunnerWorker(world.runner, world.streaming(engine),
                       worker_id="w").run_once()
    assert engine.seen == [("running", 1), ("running", 2), ("running", 3)]
    st = run.status
    assert st.state == "sealed" and len(st.bundles) == 3
    facts = world.runner.bundles("job-1.t1")
    assert [f.bundle_ref for f in facts] == list(st.bundles)
    assert [f.index for f in facts] == [0, 1, 2]
    assert {f.generation for f in facts} == {run.generation}
    for ref in st.bundles:
        receipt = world.receipts.get(ref)
        # A Stage 2 receipt carries its full task input.
        assert receipt.stage2_input == CAMPAIGN
        assert receipt.task_input_sha256 == runner_input_digest(CAMPAIGN)
        assert b'"stage2_input"' in canonical_json(receipt)


def test_failure_after_some_segments_keeps_them(world):
    engine = Segments(world.runner, [lambda: capture(0), lambda: capture(1), lambda: capture(2)],
                      fail_after=2)
    run = RunnerWorker(world.runner, world.streaming(engine),
                       worker_id="w").run_once()
    assert run.status.state == "ended_unsealed"
    assert run.status.reason == CAPTURE_FAILED
    assert len(run.status.bundles) == 2


def test_a_refused_segment_ends_the_lease_with_its_reason(world):
    engine = Segments(world.runner, [lambda: capture(0),
                                     lambda: capture(1, duplicate=True),
                                     lambda: capture(2)])
    run = RunnerWorker(world.runner, world.streaming(engine),
                       worker_id="w").run_once()
    assert run.status.state == "ended_unsealed"
    assert run.status.reason == DUPLICATE_ARTIFACT
    assert len(run.status.bundles) == 1
    assert engine.seen == [("running", 1)]


def test_no_segment_is_a_capture_failure(world):
    run = RunnerWorker(world.runner, world.streaming(Segments(world.runner, [])),
                       worker_id="w").run_once()
    assert run.status.state == "ended_unsealed"
    assert run.status.reason == CAPTURE_FAILED and run.status.bundles == ()


def test_append_is_fenced_idempotent_and_completion_names_the_last(world):
    lease = world.runner.claim("w")
    a, b = sha("a"), sha("b")
    world.runner.append_bundle(lease, a)
    world.runner.append_bundle(lease, a)
    world.runner.append_bundle(lease, b)
    assert world.runner.status("job-1.t1").bundles == (a, b)
    with pytest.raises(ValueError):
        world.runner.complete(lease, BackendResult(bundle_ref=a))
    stale = lease.model_copy(update={"token": "0" * 64})
    with pytest.raises(LeaseLost):
        world.runner.append_bundle(stale, sha("c"))
    st = world.runner.complete(lease, BackendResult(bundle_ref=b))
    assert st.state == "sealed" and st.bundles == (a, b)


def test_cancel_meanwhile_keeps_the_sealed_bundles(world):
    lease = world.runner.claim("w")
    world.runner.append_bundle(lease, sha("a"))
    world.runner.cancel("job-1.t1")
    world.runner.append_bundle(lease, sha("b"))
    st = world.runner.complete(lease, BackendResult(bundle_ref=sha("b")))
    assert st.state == "ended_unsealed"
    assert st.bundles == (sha("a"), sha("b"))


def test_segments_finished_after_a_cancel_are_still_sealed(world):
    class CancelMidway:
        def run(self, lease, control, emit):
            emit(capture(0))
            world.runner.cancel(lease.binding.task_id)
            assert control.stop_requested()
            emit(capture(1))         # finished before the command stopped

    run = RunnerWorker(world.runner, world.streaming(CancelMidway()),
                       worker_id="w").run_once()
    assert run.status.state == "ended_unsealed"
    assert len(run.status.bundles) == 2


def test_a_segment_of_a_lost_lease_is_refused(world):
    class Lost:
        def append_bundle(self, lease, bundle_ref):
            raise LeaseLost(lease.binding.task_id)

    backend = StreamingSealingBackend(
        Segments(world.runner, [lambda: capture(0), lambda: capture(1)]),
        world.evidence, world.receipts, Lost(), sealer_id="stage2-test")
    lease = world.runner.claim("w")
    from agent_pipeline.runner.worker import LeaseControl
    result = backend.execute(lease, LeaseControl(world.runner, lease))
    assert result.bundle_ref is None
    assert result.reason == LEASE_LOST_DURING_CAPTURE


def test_stage1_receipt_bytes_have_no_stage2_input(tmp_path):
    w = World(tmp_path, STAGE1)
    try:
        class One:
            def capture(self, lease, control):
                return capture(0)

        backend = StepRoutingBackend(
            EvidenceSealingBackend(One(), w.evidence, w.receipts,
                                   sealer_id="s"), None)
        run = RunnerWorker(w.runner, backend, worker_id="w").run_once()
        assert run.status.state == "sealed"
        receipt = w.receipts.get(run.status.bundles[-1])
        assert receipt.stage2_input is None
        assert b"stage2_input" not in canonical_json(receipt)
        # A Stage 1 task seals through complete() alone.
        assert w.runner.bundles("job-1.t1") == ()
    finally:
        w.close()


def test_routing_without_a_stage2_backend_ends_unsealed(world):
    class Never:
        def capture(self, lease, control):
            raise AssertionError("a Stage 2 lease reached the Stage 1 engine")

    backend = StepRoutingBackend(
        EvidenceSealingBackend(Never(), world.evidence, world.receipts,
                               sealer_id="s"), None)
    run = RunnerWorker(world.runner, backend, worker_id="w").run_once()
    assert run.status.state == "ended_unsealed"
    assert run.status.reason == STAGE2_BACKEND_UNAVAILABLE
