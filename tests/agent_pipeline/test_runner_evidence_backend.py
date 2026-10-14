"""Host tests for execution capture -> EvidenceStore sealing."""

from __future__ import annotations

import hashlib
import sqlite3

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.controller.tasks import (RunnerInput,
                                             runner_input_digest)
from agent_pipeline.data import canonical_json
from agent_pipeline.evidence import (
    ArtifactInput,
    EvidenceLimits,
    EvidenceManifest,
    EvidenceStore,
    ExecutionCorrelation,
)
from agent_pipeline.runner import DurableRunner, LeaseControl
from agent_pipeline.runner.evidence_backend import (
    CAPTURE_FAILED,
    DUPLICATE_ARTIFACT,
    EVIDENCE_LIMIT_EXCEEDED,
    EVIDENCE_SEALING_FAILED,
    INVALID_CAPTURE,
    INVALID_LEASE_BINDING,
    LEASE_LOST_DURING_CAPTURE,
    REPORTED_CORRELATION_MISMATCH,
    EvidenceSealingBackend,
    ExecutionCapture,
    HostExecutionFacts,
    ReceiptInventory,
    RunnerEvidenceReceipt,
    RunnerEvidenceReceiptError,
    RunnerEvidenceReceiptStore,
)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class FakeClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class FakeEngine:
    def __init__(self, result, *, hook=None, error: Exception | None = None):
        self.result = result
        self.hook = hook
        self.error = error
        self.calls = 0

    def capture(self, lease, control):
        self.calls += 1
        if self.hook is not None:
            self.hook(lease, control)
        if self.error is not None:
            raise self.error
        return self.result


def valid_capture(*artifacts: ArtifactInput) -> ExecutionCapture:
    if not artifacts:
        artifacts = (
            ArtifactInput(
                identity="status", type="application/json", data=b'{"ok":true}'
            ),
            ArtifactInput(
                identity="coverage", type="remote_kcov", data=b"\x00\xffcoverage"
            ),
        )
    return ExecutionCapture(
        facts=HostExecutionFacts(
            vm_instance_id="vm-1",
            lane=3,
            generation_id=7,
            collector_id="runner-host-1",
            collection_started_at_ns=110,
            collection_completed_at_ns=120,
        ),
        artifacts=artifacts,
    )


class World:
    def __init__(self, tmp_path, *, limits: EvidenceLimits | None = None):
        self.runner_clock = FakeClock(100)
        self.sealing_clock = FakeClock(130)
        self.runner_path = tmp_path / "runner.sqlite"
        self.receipt_path = tmp_path / "receipts.sqlite"
        self.runner = DurableRunner(
            self.runner_path,
            clock=self.runner_clock,
            lease_duration_ns=1_000,
        )
        self.task_input = RunnerInput(
            job_id="job-1",
            harness_ref=sha("harness"),
            execution_harness_id=sha("execution-harness"),
        )
        self.runner.submit("job-1.t1", self.task_input)
        self.lease = self.runner.claim("worker-1")
        self.control = LeaseControl(self.runner, self.lease)
        self.artifacts = ArtifactStore(tmp_path / "artifacts")
        self.evidence = EvidenceStore(self.artifacts, limits=limits)
        self.receipts = RunnerEvidenceReceiptStore(self.receipt_path)

    def backend(self, engine, *, evidence=None, receipts=None):
        return EvidenceSealingBackend(
            engine,
            evidence or self.evidence,
            receipts or self.receipts,
            sealer_id="runner-sealer-1",
            clock=self.sealing_clock,
        )

    def files(self):
        return tuple(path for path in self.artifacts.root.rglob("*") if path.is_file())

    def close(self):
        self.receipts.close()
        self.runner.close()


@pytest.fixture
def world(tmp_path):
    value = World(tmp_path)
    yield value
    value.close()


def expected_correlation(world) -> ExecutionCorrelation:
    return ExecutionCorrelation(
        job_id="job-1",
        task_id="job-1.t1",
        execution_harness_id=world.task_input.execution_harness_id,
        vm_instance_id="vm-1",
        lane=3,
        generation_id=7,
    )


def test_success_seals_verifies_bytes_and_persists_provenance(world):
    capture = valid_capture()
    result = world.backend(FakeEngine(capture)).execute(world.lease, world.control)
    assert result.reason is None
    assert result.bundle_ref is not None
    status = world.runner.complete(world.control.lease, result)
    assert status.state == "sealed"
    assert status.bundles == (result.bundle_ref,)

    correlation = expected_correlation(world)
    verified = world.evidence.verify(
        result.bundle_ref, expected_correlation=correlation
    )
    assert verified.manifest.correlation == correlation
    assert verified.get("coverage", expected_type="remote_kcov") == b"\x00\xffcoverage"
    assert verified.get("status", expected_type="application/json") == b'{"ok":true}'
    assert canonical_json(verified.manifest) == world.artifacts.get(result.bundle_ref)

    receipt = world.receipts.get(result.bundle_ref)
    assert receipt.bundle_ref == receipt.manifest_sha256 == result.bundle_ref
    assert receipt.task_input_sha256 == runner_input_digest(world.task_input)
    assert receipt.lease_generation == world.lease.generation
    assert receipt.task_id == world.lease.binding.task_id
    assert receipt.job_id == world.lease.binding.job_id
    assert receipt.harness_ref == world.lease.binding.harness_ref
    assert receipt.execution_harness_id == world.lease.binding.execution_harness_id
    assert receipt.correlation == correlation
    assert receipt.collection == verified.manifest.collection
    assert receipt.sealing == verified.manifest.sealing
    assert [item.identity for item in receipt.artifacts] == ["coverage", "status"]
    assert [(item.sha256, item.size) for item in receipt.artifacts] == [
        (item.sha256, item.size) for item in verified.manifest.artifacts
    ]

    with pytest.raises(ValueError, match="task input digest conflicts"):
        RunnerEvidenceReceipt.model_validate_json(canonical_json({
            **receipt.model_dump(mode="json"),
            "task_input_sha256": sha("different-runner-input"),
        }))


def test_receipt_is_deterministic_idempotent_and_restart_safe(world):
    backend = world.backend(FakeEngine(valid_capture()))
    first = backend.execute(world.lease, world.control)
    second = backend.execute(world.lease, world.control)
    assert first == second
    receipt = world.receipts.get(first.bundle_ref)
    raw = canonical_json(receipt)
    world.receipts.put(receipt)

    world.receipts.close()
    world.receipts = RunnerEvidenceReceiptStore(world.receipt_path)
    assert canonical_json(world.receipts.get(first.bundle_ref)) == raw
    assert world.receipts.has(first.bundle_ref)
    with pytest.raises(KeyError):
        world.receipts.get(sha("unknown-bundle"))


@pytest.mark.parametrize(
    "extra",
    [
        {"task_id": "other-task"},
        {"job_id": "other-job"},
        {"execution_harness_id": sha("other-harness")},
        {"q1_verdict": "reached"},
    ],
)
def test_engine_cannot_choose_runner_identity_or_verdict(world, extra):
    raw = valid_capture().model_dump(mode="python")
    raw.update(extra)
    result = world.backend(FakeEngine(raw)).execute(world.lease, world.control)
    assert (result.bundle_ref, result.reason) == (None, INVALID_CAPTURE)
    assert world.files() == ()


def test_models_have_no_verdict_fields():
    for model in (
        HostExecutionFacts,
        ExecutionCapture,
        ReceiptInventory,
        RunnerEvidenceReceipt,
    ):
        assert all("verdict" not in name.lower() for name in model.model_fields)


@pytest.mark.parametrize("field", ["job_id", "harness_ref", "execution_harness_id"])
def test_forged_lease_binding_is_rejected_before_engine(world, field):
    value = "other-job" if field == "job_id" else sha(f"other-{field}")
    forged = world.lease.model_copy(
        update={
            "binding": world.lease.binding.model_copy(update={field: value})
        }
    )
    engine = FakeEngine(valid_capture())
    result = world.backend(engine).execute(forged, world.control)
    assert (result.bundle_ref, result.reason) == (None, INVALID_LEASE_BINDING)
    assert engine.calls == 0
    assert world.files() == ()


def test_guest_reported_correlation_is_cross_checked_not_authoritative(world):
    reported = expected_correlation(world).model_copy(update={"job_id": "other-job"})
    artifact = ArtifactInput(
        identity="coverage",
        type="remote_kcov",
        data=b"coverage",
        reported_correlation=reported,
    )
    result = world.backend(FakeEngine(valid_capture(artifact))).execute(
        world.lease, world.control
    )
    assert (result.bundle_ref, result.reason) == (
        None,
        REPORTED_CORRELATION_MISMATCH,
    )
    assert world.files() == ()


def test_matching_guest_correlation_is_retained_but_host_constructed(world):
    correlation = expected_correlation(world)
    artifact = ArtifactInput(
        identity="coverage",
        type="remote_kcov",
        data=b"coverage",
        reported_correlation=correlation,
    )
    result = world.backend(FakeEngine(valid_capture(artifact))).execute(
        world.lease, world.control
    )
    verified = world.evidence.verify(
        result.bundle_ref, expected_correlation=correlation
    )
    assert verified.manifest.correlation == correlation
    assert verified.manifest.artifacts[0].reported_correlation == correlation


def test_duplicate_artifacts_fail_before_publication(world):
    artifact = ArtifactInput(identity="same", type="log", data=b"one")
    other = ArtifactInput(identity="same", type="log", data=b"two")
    result = world.backend(FakeEngine(valid_capture(artifact, other))).execute(
        world.lease, world.control
    )
    assert (result.bundle_ref, result.reason) == (None, DUPLICATE_ARTIFACT)
    assert world.files() == ()


@pytest.mark.parametrize(
    "limits,artifacts",
    [
        (
            EvidenceLimits(max_artifact_bytes=3),
            (ArtifactInput(identity="large", type="log", data=b"four"),),
        ),
        (
            EvidenceLimits(max_bundle_bytes=3),
            (
                ArtifactInput(identity="a", type="log", data=b"aa"),
                ArtifactInput(identity="b", type="log", data=b"bb"),
            ),
        ),
        (
            EvidenceLimits(max_artifacts=1),
            (
                ArtifactInput(identity="a", type="log", data=b"a"),
                ArtifactInput(identity="b", type="log", data=b"b"),
            ),
        ),
    ],
)
def test_artifact_limits_fail_before_publication(world, limits, artifacts):
    limited = EvidenceStore(world.artifacts, limits=limits)
    result = world.backend(
        FakeEngine(valid_capture(*artifacts)), evidence=limited
    ).execute(world.lease, world.control)
    assert (result.bundle_ref, result.reason) == (None, EVIDENCE_LIMIT_EXCEEDED)
    assert world.files() == ()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["facts"].update(lane=-1),
        lambda value: value["facts"].update(collection_started_at_ns=121),
        lambda value: value["facts"].update(
            collection_started_at_ns=99, collection_completed_at_ns=120
        ),
        lambda value: value["artifacts"][0].pop("data"),
    ],
)
def test_invalid_host_facts_or_missing_bytes_fail_closed(world, mutation):
    raw = valid_capture().model_dump(mode="python")
    # Keep the strict tuple container while mutating its nested dictionaries.
    raw["artifacts"] = tuple(raw["artifacts"])
    mutation(raw)
    result = world.backend(FakeEngine(raw)).execute(world.lease, world.control)
    assert (result.bundle_ref, result.reason) == (None, INVALID_CAPTURE)
    assert world.files() == ()


def test_sealing_timestamp_must_follow_collection(world):
    world.sealing_clock.value = 119
    result = world.backend(FakeEngine(valid_capture())).execute(
        world.lease, world.control
    )
    assert (result.bundle_ref, result.reason) == (None, INVALID_CAPTURE)
    assert world.files() == ()


def test_cancel_before_capture_does_not_call_engine_or_publish(world):
    world.runner.cancel(world.lease.binding.task_id)
    engine = FakeEngine(valid_capture())
    result = world.backend(engine).execute(world.lease, world.control)
    assert (result.bundle_ref, result.reason) == (
        None,
        LEASE_LOST_DURING_CAPTURE,
    )
    assert engine.calls == 0
    assert world.files() == ()


def test_cancel_during_capture_prevents_publication(world):
    def cancel(lease, control):
        world.runner.cancel(lease.binding.task_id)

    engine = FakeEngine(valid_capture(), hook=cancel)
    result = world.backend(engine).execute(world.lease, world.control)
    assert (result.bundle_ref, result.reason) == (
        None,
        LEASE_LOST_DURING_CAPTURE,
    )
    assert engine.calls == 1
    assert world.files() == ()


def test_expired_lease_reclaimed_during_capture_prevents_publication(world):
    def reclaim(lease, control):
        world.runner_clock.value = lease.expires_at_ns
        replacement = world.runner.claim("worker-2")
        assert replacement.generation == lease.generation + 1

    engine = FakeEngine(valid_capture(), hook=reclaim)
    result = world.backend(engine).execute(world.lease, world.control)
    assert (result.bundle_ref, result.reason) == (
        None,
        LEASE_LOST_DURING_CAPTURE,
    )
    assert world.files() == ()


def test_engine_exception_has_stable_reason_without_detail(world):
    engine = FakeEngine(None, error=RuntimeError("secret backend detail"))
    result = world.backend(engine).execute(world.lease, world.control)
    assert (result.bundle_ref, result.reason) == (None, CAPTURE_FAILED)
    assert "secret" not in result.reason
    assert world.files() == ()


class ManifestFailingArtifactStore(ArtifactStore):
    def __init__(self, root):
        super().__init__(root)
        self.rejected_manifest: bytes | None = None

    def put(self, data: bytes) -> str:
        if data.startswith(b'{"artifacts":'):
            self.rejected_manifest = data
            raise OSError("simulated manifest write failure")
        return super().put(data)


def test_sealing_io_failure_never_publishes_manifest_or_receipt(world, tmp_path):
    failing_artifacts = ManifestFailingArtifactStore(tmp_path / "failing-artifacts")
    evidence = EvidenceStore(failing_artifacts)
    result = world.backend(
        FakeEngine(valid_capture()), evidence=evidence
    ).execute(world.lease, world.control)
    assert (result.bundle_ref, result.reason) == (None, EVIDENCE_SEALING_FAILED)
    assert failing_artifacts.rejected_manifest is not None
    manifest_ref = hashlib.sha256(failing_artifacts.rejected_manifest).hexdigest()
    assert not failing_artifacts.has(manifest_ref)
    with pytest.raises(KeyError):
        world.receipts.get(manifest_ref)


def test_receipt_store_detects_key_body_and_digest_corruption(world):
    result = world.backend(FakeEngine(valid_capture())).execute(
        world.lease, world.control
    )
    receipt = world.receipts.get(result.bundle_ref)
    assert isinstance(receipt, RunnerEvidenceReceipt)

    with sqlite3.connect(world.receipt_path) as db:
        db.execute(
            "UPDATE runner_evidence_receipts SET receipt_sha256 = ? "
            "WHERE bundle_ref = ?",
            (sha("wrong"), result.bundle_ref),
        )
    with pytest.raises(RunnerEvidenceReceiptError, match="digest mismatch"):
        world.receipts.get(result.bundle_ref)


def test_receipt_inventory_matches_manifest_contract(world):
    result = world.backend(FakeEngine(valid_capture())).execute(
        world.lease, world.control
    )
    manifest = EvidenceManifest.model_validate_json(
        world.artifacts.get(result.bundle_ref)
    )
    receipt = world.receipts.get(result.bundle_ref)
    assert tuple(
        (item.identity, item.type, item.sha256, item.size)
        for item in receipt.artifacts
    ) == tuple(
        (item.identity, item.type, item.sha256, item.size)
        for item in manifest.artifacts
    )
