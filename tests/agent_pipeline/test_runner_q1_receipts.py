"""Real intake/materialization/Runner/sealing/Q1 handoff, synthetic captures.

No VM, mapper or LLM is invoked; verdicts come from the real Q1 evaluator.
"""

from __future__ import annotations

import hashlib
import sqlite3
from types import SimpleNamespace

import pytest

from agent_pipeline.contracts import (CandidateSubmission, JudgeVersions,
                                      LocationKind, LocationRequest, Materialized,
                                      PlanOutput, Q1Status, Sanitizer)
from agent_pipeline.controller.tasks import RunnerInput, runner_input_digest
from agent_pipeline.data import canonical_json, put_record
from agent_pipeline.evidence import ArtifactInput, EvidenceStore
from agent_pipeline.hcap import ArtifactHcapChecker
from agent_pipeline.intake import validate
from agent_pipeline.materializer import (ArtifactHarnessMaterializer,
    ExecutionHarnessApproval, HarnessBuildArtifact, MaterializationReviewManifest,
    ParsedProgram, ReachabilityHarness, StaticExecutionHarnessAuthority, descriptor_id)
from agent_pipeline.q1 import (CandidateTarget, ContextLossPolicy, CounterDelta,
    CounterLimit, ExecutionCorrelation, GenerationCounters, KernelIdentity,
    Q1AdmissibilityProfile, RemoteKcovObservation, RemoteKcovSupportBoundary,
    TargetPcMapping)
from agent_pipeline.runner import (BackendResult, DurableRunner, LeaseControl,
                                  LeaseLost, RunnerDataError)
from agent_pipeline.runner.evidence_backend import (EvidenceSealingBackend,
    ExecutionCapture, HostExecutionFacts, RunnerEvidenceReceipt,
    RunnerEvidenceReceiptError, RunnerEvidenceReceiptStore)
from agent_pipeline.runner.q1_receipts import (Q1AuthorityPending, Q1HostContext,
    Q1ReceiptRejected, RunnerQ1ReceiptBridge)
from agent_pipeline.sealed_q1 import (COVERAGE_TYPE, OBSERVATION_ID, OBSERVATION_TYPE,
    PublishedCoverage, UnknownExecution)

from .fakes import FakeTree
from .test_materializer import world as materializer_world  # noqa: F401


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Clock:
    value = 100

    def __call__(self):
        return self.value


@pytest.fixture
def build(materializer_world):
    w = materializer_world
    instrumentation = w.store.put(b"synthetic remote KCOV instrumentation")
    descriptor = w.descriptor.model_copy(update={"build_artifacts": (
        HarnessBuildArtifact(name="instrumentation", artifact_ref=instrumentation),
        *w.descriptor.build_artifacts,
    )})
    w.binding = w.binding.model_copy(update={"execution_harness_id": descriptor_id(descriptor)})
    w.descriptor = descriptor
    w.builds = StaticExecutionHarnessAuthority((ExecutionHarnessApproval(
        descriptor=descriptor, approved_hcap_revisions=(w.hcap_ref,)),))
    w.materializer = ArtifactHarnessMaterializer(w.store, w.builds, w.parser)
    w.instrumentation = instrumentation
    return w


def authority(build, *, job_id="job", task_id="task", candidate=None, plan_ref=None,
              materialized=None):
    w = build
    if candidate is None:
        candidate = validate(CandidateSubmission(kernel_commit=w.binding.kernel_commit,
            location=LocationRequest(kind=LocationKind.FUNCTION,
                path="fs/nfsd/synthetic.c", symbol="target")),
            FakeTree({w.binding.kernel_commit: {"fs/nfsd/synthetic.c": "void target(void) {\n}\n"}}),
            "candidate-1")
    plan_ref = plan_ref or w.plan_ref
    materialized = materialized or w.materializer.materialize(plan_ref, w.binding)
    assert isinstance(materialized, Materialized)
    identity = KernelIdentity(execution_harness_id=w.binding.execution_harness_id,
        kernel_commit=candidate.kernel_commit, instrumentation_sha256=w.instrumentation,
        vmlinux_sha256=next(a.artifact_ref for a in w.descriptor.build_artifacts if a.name == "kernel"),
        kaslr_enabled=False, kaslr_offset=0)
    target = CandidateTarget(candidate_id=candidate.candidate_id,
        kernel_commit=candidate.kernel_commit, **candidate.location.model_dump(mode="json"))
    mapping = TargetPcMapping(mapping_method="synthetic mapping fixture", verified=True,
        target=target, identity=identity, target_pcs=(4096,))
    return Q1HostContext(candidate=candidate, plan_ref=plan_ref, binding=w.binding,
        materialized=materialized, lease_generation=1, identity=identity,
        correlation=ExecutionCorrelation(job_id=job_id, task_id=task_id,
            execution_harness_id=w.binding.execution_harness_id, vm_instance_id="vm",
            lane=0, generation_id=1), trace_mode="off", mapping_ref=put_record(w.store, mapping),
        vmlinux_artifact_name="kernel", instrumentation_artifact_name="instrumentation")


def capture(context, *, pcs=(4096,), observation_update=None):
    coverage = canonical_json(PublishedCoverage(correlation=context.correlation, pcs=pcs))
    observation = RemoteKcovObservation(candidate_id=context.candidate.candidate_id,
        identity=context.identity, correlation=context.correlation,
        boot_ok=True, fixture_ok=True, lane_ok=True, runner_completed=True,
        collection_started=True, collection_completed=True, generation_attributed=True,
        channel="remote_kcov", lane_trace_mode=context.trace_mode,
        coverage_artifacts=(sha(coverage),), published_pcs=pcs,
        generation=GenerationCounters(generation_begin=1, remote_start_ok=1,
            aggregate_published=1, generation_aborted=0, scratch_overflow=0,
            merge_truncation=0, outstanding_tokens=0, remote_refs=0),
        counter_deltas=(CounterDelta(counter="lane_owner_failed",
                                    window="generation-plus-drain", value=0),))
    if observation_update:
        observation = observation.model_copy(update=observation_update)
    c = context.correlation
    return ExecutionCapture(facts=HostExecutionFacts(vm_instance_id=c.vm_instance_id,
        lane=c.lane, generation_id=c.generation_id, collector_id="collector",
        collection_started_at_ns=110, collection_completed_at_ns=120),
        artifacts=(ArtifactInput(identity=OBSERVATION_ID, type=OBSERVATION_TYPE,
                                 data=canonical_json(observation)),
                   ArtifactInput(identity="coverage", type=COVERAGE_TYPE, data=coverage)))


def versions(build):
    profile = Q1AdmissibilityProfile(name="synthetic", revision="1", allowed_trace_modes=("off",),
        contexts=(ContextLossPolicy(context="synthetic_worker", window="generation-plus-drain",
            counters=(CounterLimit(counter="lane_owner_failed", max_delta=0),)),))
    boundary = RemoteKcovSupportBoundary(name="synthetic", revision="1",
        kernel_commit=build.binding.kernel_commit, instrumentation_sha256=build.instrumentation,
        supported_contexts=("synthetic_worker",))
    return JudgeVersions(judge_profile_id=put_record(build.store, profile),
                         support_boundary_id=put_record(build.store, boundary))


class Pipeline:
    def __init__(self, tmp_path, build):
        self.build = build
        self.context = authority(build)
        self.clock = Clock()
        self.runner_path = tmp_path / "runner.sqlite"
        self.receipt_path = tmp_path / "receipts.sqlite"
        self.history_path = tmp_path / "q1.sqlite"
        self.runner = DurableRunner(self.runner_path, clock=self.clock, lease_duration_ns=1000)
        self.receipts = RunnerEvidenceReceiptStore(self.receipt_path)
        self.evidence = EvidenceStore(build.store)
        self.bridge = self.new_bridge()
        self.versions = versions(build)

    def new_bridge(self):
        return RunnerQ1ReceiptBridge(self.history_path, runner=self.runner,
            receipts=self.receipts, artifacts=self.build.store, evidence=self.evidence)

    def start(self):
        c = self.context
        self.runner.submit(c.correlation.task_id, RunnerInput(job_id=c.correlation.job_id,
            harness_ref=c.materialized.harness_ref, execution_harness_id=c.identity.execution_harness_id))
        self.lease = self.runner.claim("worker")
        self.control = LeaseControl(self.runner, self.lease)

    def seal(self, **kw):
        data = capture(self.context, **kw)
        engine = SimpleNamespace(capture=lambda lease, control: data)
        backend = EvidenceSealingBackend(engine, self.evidence, self.receipts,
                                        sealer_id="sealer", clock=lambda: 130)
        self.result = backend.execute(self.lease, self.control)
        assert self.result.bundle_ref is not None, self.result
        return self.result.bundle_ref

    def complete(self, **kw):
        self.start()
        ref = self.seal(**kw)
        self.clock.value = 140
        self.runner.complete(self.control.lease, self.result)
        return ref

    def judge(self, snapshot=None):
        c = self.context
        return (snapshot or self.bridge.snapshot()).judge(self.result.bundle_ref,
            c.plan_ref, c.candidate.candidate_id, self.versions)

    def restart(self):
        self.bridge.close()
        self.runner.close()
        self.receipts.close()
        self.runner = DurableRunner(self.runner_path, clock=self.clock, lease_duration_ns=1000)
        self.receipts = RunnerEvidenceReceiptStore(self.receipt_path)
        self.bridge = self.new_bridge()

    def close(self):
        self.bridge.close()
        self.receipts.close()
        self.runner.close()


@pytest.fixture
def pipeline(tmp_path, build):
    p = Pipeline(tmp_path, build)
    yield p
    p.close()


@pytest.mark.parametrize("pcs,expected", [((4096,), Q1Status.REACHED),
    ((), Q1Status.NOT_REACHED), ((8192,), Q1Status.NOT_REACHED)])
def test_real_materializer_runner_sealer_and_judge(pipeline, pcs, expected):
    p = pipeline
    ref = p.complete(pcs=pcs)
    trusted = p.bridge.publish(p.context)
    assert trusted.bundle_ref == ref
    assert trusted.identity == p.context.identity
    assert p.judge().status is expected
    assert p.judge() == p.judge()
    publication = p.bridge.publication(ref)
    assert publication.completion_sha256 == sha(canonical_json(p.runner.receipt("task")))
    assert publication.evidence_receipt_sha256 == sha(canonical_json(p.receipts.get(ref)))


def test_guest_boolean_cannot_inject_success(pipeline):
    p = pipeline
    p.complete(pcs=(), observation_update={"guest_target_observed": True})
    p.bridge.publish(p.context)
    assert p.judge().status is Q1Status.NOT_REACHED


def test_guest_identity_cannot_become_host_authority(pipeline):
    p = pipeline
    wrong = p.context.identity.model_copy(update={"vmlinux_sha256": "f" * 64})
    p.complete(observation_update={"identity": wrong})
    trusted = p.bridge.publish(p.context)
    assert trusted.identity == p.context.identity
    assert p.judge().status is Q1Status.INCONCLUSIVE
    assert p.judge().reason == "evidence"


def test_orphan_backend_receipt_is_pending_until_runner_accepts(pipeline):
    p = pipeline
    p.start()
    ref = p.seal()
    assert p.receipts.has(ref)
    with pytest.raises(Q1AuthorityPending, match="accepted"):
        p.bridge.publish(p.context)
    with pytest.raises(UnknownExecution):
        p.judge()
    p.clock.value = 140
    p.runner.complete(p.lease, p.result)
    p.bridge.publish(p.context)
    assert p.judge().status is Q1Status.REACHED


def test_stale_sealed_generation_cannot_be_adopted_by_new_lease(pipeline):
    p = pipeline
    p.start()
    p.seal()
    p.clock.value = p.lease.expires_at_ns + 1
    new_lease = p.runner.claim("replacement-worker")
    assert new_lease.generation == 2
    with pytest.raises(LeaseLost):
        p.runner.complete(p.lease, p.result)
    p.runner.complete(new_lease, p.result)  # Runner is bundle-opaque; bridge must reject.
    with pytest.raises(Q1ReceiptRejected, match="generation"):
        p.bridge.publish(p.context)
    with pytest.raises(Q1ReceiptRejected, match="accepted completion"):
        p.bridge.publish(p.context.model_copy(update={"lease_generation": 2}))
    assert dict(p.bridge.snapshot().receipts) == {}


def test_unsealed_completion_never_publishes(pipeline):
    p = pipeline
    p.start()
    p.runner.complete(p.lease, BackendResult(reason="capture_failed"))
    with pytest.raises(Q1ReceiptRejected, match="unsealed"):
        p.bridge.publish(p.context)
    assert dict(p.bridge.snapshot().receipts) == {}


@pytest.mark.parametrize("field,value", [
    ("job_id", "other-job"), ("vm_instance_id", "other-vm"),
    ("lane", 1), ("generation_id", 2), ("execution_harness_id", "f" * 64),
])
def test_independent_execution_position_must_match(pipeline, field, value):
    p = pipeline
    p.complete()
    context = p.context.model_copy(update={"correlation":
        p.context.correlation.model_copy(update={field: value})})
    with pytest.raises(Q1ReceiptRejected):
        p.bridge.publish(context)


@pytest.mark.parametrize("field,value", [("kernel_commit", "b" * 40),
    ("execution_harness_id", "f" * 64), ("instrumentation_sha256", "f" * 64),
    ("vmlinux_sha256", "f" * 64), ("kaslr_enabled", True)])
def test_mapping_identity_must_match_descriptor_and_trusted_mapping(pipeline, field, value):
    p = pipeline
    p.complete()
    context = p.context.model_copy(update={"identity":
        p.context.identity.model_copy(update={field: value})})
    with pytest.raises(Q1ReceiptRejected):
        p.bridge.publish(context)


@pytest.mark.parametrize("field,value", [("candidate_id", "other"),
                                       ("kernel_commit", "b" * 40)])
def test_intake_identity_must_match_plan(pipeline, field, value):
    p = pipeline
    p.complete()
    with pytest.raises(Q1ReceiptRejected):
        p.bridge.publish(p.context.model_copy(update={"candidate":
            p.context.candidate.model_copy(update={field: value})}))


def test_intake_target_location_cannot_be_replaced(pipeline):
    p = pipeline
    p.complete()
    candidate = p.context.candidate.model_copy(update={"location":
        p.context.candidate.location.model_copy(update={"end_line": 3})})
    with pytest.raises(Q1ReceiptRejected, match="intake"):
        p.bridge.publish(p.context.model_copy(update={"candidate": candidate}))


@pytest.mark.parametrize("updates", [
    {"trace_mode": "on"}, {"vmlinux_artifact_name": "vm-image"},
    {"instrumentation_artifact_name": "kernel"},
    {"vmlinux_artifact_name": "absent"}, {"lease_generation": 2},
])
def test_host_context_cannot_override_execution(pipeline, updates):
    p = pipeline
    p.complete()
    with pytest.raises(Q1ReceiptRejected):
        p.bridge.publish(p.context.model_copy(update=updates))


@pytest.mark.parametrize("updates", [
    {"hcap_revision": "f" * 64}, {"sanitizer": Sanitizer.KCSAN},
    {"kernel_commit": "b" * 40}, {"execution_harness_id": "f" * 64},
])
def test_dispatch_binding_must_match_materialization(pipeline, updates):
    p = pipeline
    p.complete()
    with pytest.raises(Q1ReceiptRejected):
        p.bridge.publish(p.context.model_copy(update={"binding":
            p.context.binding.model_copy(update=updates)}))


def replace_receipt(p, receipt):
    raw = canonical_json(receipt)
    with sqlite3.connect(p.receipt_path) as db:
        db.execute("UPDATE runner_evidence_receipts SET body = ?, receipt_sha256 = ?",
                   (raw, sha(raw)))


@pytest.mark.parametrize("which", ["inventory", "collection", "sealing", "task", "job", "harness"])
def test_schema_valid_receipt_conflicts_are_rejected(pipeline, which):
    p = pipeline
    ref = p.complete()
    data = p.receipts.get(ref).model_dump(mode="json")
    if which == "inventory":
        data["artifacts"][0]["size"] += 1
    elif which == "collection":
        data["collection"]["collector_id"] = "other"
    elif which == "sealing":
        data["sealing"]["sealer_id"] = "other"
    elif which in ("task", "job"):
        field = f"{which}_id"
        data[field] = data["correlation"][field] = "other"
    else:
        data["harness_ref"] = "f" * 64
    data["task_input_sha256"] = runner_input_digest(RunnerInput(job_id=data["job_id"],
        harness_ref=data["harness_ref"], execution_harness_id=data["execution_harness_id"]))
    receipt = RunnerEvidenceReceipt.model_validate_json(canonical_json(data))
    replace_receipt(p, receipt)
    with pytest.raises(Q1ReceiptRejected):
        p.bridge.publish(p.context)


def test_receipt_integrity_failure_is_not_hidden(pipeline):
    p = pipeline
    p.complete()
    with sqlite3.connect(p.receipt_path) as db:
        db.execute("UPDATE runner_evidence_receipts SET body = ?", (b"{}",))
    with pytest.raises(RunnerEvidenceReceiptError):
        p.bridge.publish(p.context)


def test_accepted_completion_integrity_is_verified(pipeline):
    p = pipeline
    p.complete()
    with sqlite3.connect(p.runner_path) as db:
        db.execute("UPDATE runner_tasks SET receipt_sha256 = ?", ("0" * 64,))
    with pytest.raises(RunnerDataError, match="digest mismatch"):
        p.bridge.publish(p.context)


def test_unknown_task_is_pending_without_consulting_unaccepted_bundle(pipeline):
    p = pipeline
    p.complete()
    context = p.context.model_copy(update={"correlation":
        p.context.correlation.model_copy(update={"task_id": "unknown"})})
    with pytest.raises(Q1AuthorityPending):
        p.bridge.publish(context)


@pytest.mark.parametrize("which", ["candidate", "runtime", "program", "parsed-identity", "review"])
def test_canonical_but_inconsistent_materialization_is_rejected(pipeline, which):
    p = pipeline
    store = p.build.store
    materialized = p.context.materialized
    harness = ReachabilityHarness.model_validate_json(store.get(materialized.harness_ref))
    review = MaterializationReviewManifest.model_validate_json(
        store.get(materialized.review_manifest_sha256))
    changes = {}
    if which == "candidate":
        changes["candidate_id"] = "another-candidate"
    elif which == "runtime":
        changes["runtime_selection"] = harness.runtime_selection.model_copy(update={"trace_mode": "on"})
    elif which == "program":
        changes["program_ref"] = store.put(b"a different program")
    elif which == "parsed-identity":
        parsed = ParsedProgram.model_validate_json(store.get(harness.scenario_parser_result_ref))
        parsed = parsed.model_copy(update={"identity":
            parsed.identity.model_copy(update={"syzkaller_commit": "e" * 40})})
        changes["scenario_parser_result_ref"] = put_record(store, parsed)
    if which == "review":
        review = review.model_copy(update={"candidate_id": "different-review-candidate"})
    else:
        review = review.model_copy(update=changes)
    review_ref = put_record(store, review)
    harness = harness.model_copy(update={**changes, "review_manifest_sha256": review_ref})
    p.context = p.context.model_copy(update={"materialized": materialized.model_copy(update={
        "harness_ref": put_record(store, harness), "review_manifest_sha256": review_ref})})
    p.complete()
    with pytest.raises(Q1ReceiptRejected):
        p.bridge.publish(p.context)


def test_receipt_for_different_bundle_is_not_authority(pipeline):
    p = pipeline
    p.complete()
    p.clock.value = 100
    p.context = p.context.model_copy(update={"correlation":
        p.context.correlation.model_copy(update={"job_id": "job-2", "task_id": "task-2"})})
    p.start()
    p.clock.value = 140
    p.runner.complete(p.lease, p.result)  # Wrong task's bundle deliberately accepted by Runner.
    with pytest.raises(Q1ReceiptRejected, match="accepted completion"):
        p.bridge.publish(p.context)


@pytest.mark.parametrize("which", ["mapping", "descriptor", "plan", "harness", "review", "coverage"])
def test_tampered_artifacts_never_publish(pipeline, which):
    p = pipeline
    ref = p.complete()
    refs = {"mapping": p.context.mapping_ref, "descriptor": p.context.binding.execution_harness_id,
        "plan": p.context.plan_ref, "harness": p.context.materialized.harness_ref,
        "review": p.context.materialized.review_manifest_sha256,
        "coverage": p.receipts.get(ref).artifacts[0].sha256}
    digest = refs[which]
    (p.build.store.root / digest[:2] / digest).write_bytes(b"corrupt")
    with pytest.raises(ValueError):
        p.bridge.publish(p.context)
    assert dict(p.bridge.snapshot().receipts) == {}


@pytest.mark.parametrize("which", ["missing", "unverified", "absent-bytes"])
def test_missing_mapping_authority_remains_retriable(pipeline, which):
    p = pipeline
    p.complete()
    old_snapshot = p.bridge.snapshot()
    original = p.build.store.get(p.context.mapping_ref)
    context = p.context
    if which == "missing":
        context = context.model_copy(update={"mapping_ref": None})
    elif which == "unverified":
        mapping = TargetPcMapping.model_validate_json(original).model_copy(update={"verified": False})
        context = context.model_copy(update={"mapping_ref": put_record(p.build.store, mapping)})
    else:
        (p.build.store.root / context.mapping_ref[:2] / context.mapping_ref).unlink()
    with pytest.raises(Q1AuthorityPending):
        p.bridge.publish(context)
    p.build.store.put(original)
    p.bridge.publish(p.context)
    with pytest.raises(UnknownExecution):
        p.judge(old_snapshot)
    assert p.judge().status is Q1Status.REACHED


def test_late_sealing_receipt_is_retryable_across_restart(pipeline):
    p = pipeline
    ref = p.complete()
    receipt = p.receipts.get(ref)
    with sqlite3.connect(p.receipt_path) as db:
        db.execute("DELETE FROM runner_evidence_receipts")
    with pytest.raises(Q1AuthorityPending, match="sealing receipt"):
        p.bridge.publish(p.context)
    p.restart()
    p.receipts.put(receipt)
    p.bridge.publish(p.context)
    assert p.judge().status is Q1Status.REACHED


def test_publication_is_idempotent_restart_safe_and_immutable(pipeline):
    p = pipeline
    ref = p.complete()
    trusted = p.bridge.publish(p.context)
    first = p.bridge.snapshot()
    publication = p.bridge.publication(ref)
    assert p.bridge.publish(p.context) == trusted
    p.restart()
    assert p.bridge.publication(ref) == publication
    assert p.bridge.publish(p.context) == trusted
    assert p.judge() == p.judge(first)
    mapping = TargetPcMapping.model_validate_json(p.build.store.get(p.context.mapping_ref))
    new_ref = put_record(p.build.store, mapping.model_copy(update={"target_pcs": (8192,)}))
    with pytest.raises(Q1ReceiptRejected, match="immutable"):
        p.bridge.publish(p.context.model_copy(update={"mapping_ref": new_ref}))
    assert p.bridge.publication(ref) == publication
    assert p.judge().status is Q1Status.REACHED
    with pytest.raises(TypeError):
        first.receipts[ref] = trusted


def test_growing_snapshot_does_not_mutate_prior_snapshot(pipeline):
    p = pipeline
    first_ref = p.complete()
    p.bridge.publish(p.context)
    old_snapshot = p.bridge.snapshot()
    p.clock.value = 100
    p.context = p.context.model_copy(update={"correlation":
        p.context.correlation.model_copy(update={"job_id": "job-2", "task_id": "task-2"})})
    second_ref = p.complete()
    p.bridge.publish(p.context)
    assert tuple(old_snapshot.receipts) == (first_ref,)
    assert set(p.bridge.snapshot().receipts) == {first_ref, second_ref}
    with pytest.raises(UnknownExecution):
        p.judge(old_snapshot)
    assert p.judge().status is Q1Status.REACHED


def test_corrupt_publication_history_is_rejected_after_restart(pipeline):
    p = pipeline
    p.complete()
    p.bridge.publish(p.context)
    with sqlite3.connect(p.history_path) as db:
        db.execute("UPDATE runner_q1_publications SET body_sha256 = ?", ("0" * 64,))
    p.restart()
    with pytest.raises(Q1ReceiptRejected, match="integrity"):
        p.bridge.snapshot()


@pytest.mark.parametrize("limit", ["MAX_SNAPSHOT_BYTES", "MAX_SNAPSHOT_RECEIPTS"])
def test_snapshot_limits_do_not_discard_published_history(pipeline, monkeypatch, limit):
    from agent_pipeline.runner import q1_receipts

    p = pipeline
    first_ref = p.complete()
    p.bridge.publish(p.context)
    first = p.bridge.publication(first_ref)
    cap = len(canonical_json(first)) if limit == "MAX_SNAPSHOT_BYTES" else 1
    monkeypatch.setattr(q1_receipts, limit, cap)
    assert tuple(p.bridge.snapshot().receipts) == (first_ref,)
    p.clock.value = 100
    p.context = p.context.model_copy(update={"correlation":
        p.context.correlation.model_copy(update={"job_id": "job-2", "task_id": "task-2"})})
    p.complete()
    with pytest.raises(Q1ReceiptRejected, match="limit|capacity"):
        p.bridge.publish(p.context)
    assert p.bridge.publication(first_ref) == first
    assert tuple(p.bridge.snapshot().receipts) == (first_ref,)
    monkeypatch.setattr(q1_receipts, limit, cap - 1)
    with pytest.raises(Q1ReceiptRejected, match="limit|capacity"):
        p.bridge.snapshot()


def test_controller_late_authority_and_restart_replay(world, pipeline):
    p = pipeline
    b = p.build
    world.artifacts = b.store
    world.materializer = b.materializer
    world.hcap = ArtifactHcapChecker(b.store)
    world.runner = p.runner
    world.registry.put(b.binding)
    world.judge = p.bridge.snapshot()
    world.controller = world._controller()
    job_id = world.submit()
    world.analysis(job_id)
    candidate = world.job(job_id).candidate
    observation = b.plan.q1_observation.model_copy(update={"target": candidate.location})
    plan = b.plan.model_copy(update={"candidate_id": candidate.candidate_id,
                                     "q1_observation": observation})
    plan_ref = put_record(b.store, plan)
    world.agent_ok(job_id, PlanOutput(plan_ref=plan_ref))
    job = world.job(job_id)
    assert job.state.value == "s1_running"
    p.context = authority(b, job_id=job_id, task_id=job.pending_task.task_id,
                          candidate=candidate, plan_ref=plan_ref, materialized=job.harness)
    world.c.on_judge_versions(p.versions)
    p.complete()
    before = world.job(job_id)
    world.expected_failures += 1
    assert len(world.c.poll()) == 1
    assert world.job(job_id) == before
    assert world.job(job_id).last_verdict is None
    p.bridge.publish(p.context)
    world.judge = p.bridge.snapshot()
    world.controller = world._controller()
    world.controller.judge_versions = p.versions
    assert world.c.poll() == []
    assert world.job(job_id).state.value == "s1_reached"
    assert world.c.replay(job_id) == world.job(job_id)
    p.restart()
    world.runner = p.runner
    world.judge = p.bridge.snapshot()
    world.restart()
    assert world.c.replay(job_id) == world.job(job_id)
    assert world.job(job_id).last_verdict.result == p.judge()
