"""Local process → capture → accepted Runner receipt, without VM claims."""

from __future__ import annotations

import hashlib
import sys

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.controller.tasks import RunnerInput
from agent_pipeline.evidence import ArtifactInput, EvidenceStore
from agent_pipeline.runner import DurableRunner, RunnerWorker
from agent_pipeline.runner.evidence_backend import (
    CAPTURE_FAILED, EvidenceSealingBackend, ExecutionCapture,
    HostExecutionFacts, RunnerEvidenceReceiptStore,
)
from agent_pipeline.runner.process_supervisor import (
    HostCommand, ProcessLimits, ProcessSupervisor,
)


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux process supervision")


@pytest.mark.parametrize("timed_out", [False, True])
def test_supervised_process_to_accepted_evidence(tmp_path, timed_out):
    store = ArtifactStore(tmp_path / "cas")
    evidence = EvidenceStore(store)
    runner = DurableRunner(tmp_path / "runner.sqlite", lease_duration_ns=30_000_000_000)
    receipts = RunnerEvidenceReceiptStore(tmp_path / "receipts.sqlite")
    supervisor = ProcessSupervisor(tmp_path / "processes")
    results = []

    class LocalCaptureFixture:
        # A test adapter shows the composition point. A real VM engine must
        # supply measured identity, collection boundaries and resource scope.
        def capture(self, lease, control):
            code = ('import time; print("capture bytes", flush=True); '
                    + ("time.sleep(60)" if timed_out else "pass"))
            result = supervisor.run(
                HostCommand((sys.executable, "-c", code), tmp_path), lease, control,
                resource_key="test-host-resource",
                limits=ProcessLimits(timeout_s=0.3 if timed_out else 10,
                                     term_grace_s=0.1, kill_grace_s=2),
            )
            results.append(result)
            if result.reason != "completed" or result.returncode != 0:
                raise RuntimeError("test capture did not complete")
            return ExecutionCapture(
                facts=HostExecutionFacts(
                    vm_instance_id="synthetic-host-position", lane=0, generation_id=7,
                    collector_id="local-test", collection_started_at_ns=result.started_at_ns,
                    collection_completed_at_ns=result.completed_at_ns,
                ),
                artifacts=(ArtifactInput(identity="stdout", type="text/plain",
                                         data=result.stdout),),
            )

    try:
        digest = hashlib.sha256(b"synthetic harness").hexdigest()
        runner.submit("task", RunnerInput(job_id="job", harness_ref=digest,
                                          execution_harness_id=digest))
        worker = RunnerWorker(
            runner, EvidenceSealingBackend(LocalCaptureFixture(), evidence, receipts,
                                           sealer_id="test-host"), worker_id="worker",
        )
        run = worker.run_once()
        assert run.disposition == "completed"
        completion = runner.receipt("task")
        assert results
        if timed_out:
            assert results[0].reason == "timed_out"
            assert completion.final_state == "ended_unsealed"
            assert completion.reason == CAPTURE_FAILED
            assert completion.bundle_ref is None
        else:
            assert completion.final_state == "sealed"
            receipt = receipts.get(completion.bundle_ref)
            assert receipt.lease_generation == completion.generation
            assert receipt.task_id == "task" and receipt.job_id == "job"
            assert receipt.collection.started_at_ns == results[0].started_at_ns
            assert receipt.collection.completed_at_ns == results[0].completed_at_ns
            bundle = evidence.verify(completion.bundle_ref,
                                     expected_correlation=receipt.correlation)
            assert store.get(bundle.manifest.artifacts[0].sha256) == b"capture bytes\n"
    finally:
        receipts.close()
        runner.close()
