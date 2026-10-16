"""Real artifact/checker/judge plumbing; synthetic facts, no VM or mapper."""

import errno
import os
from types import SimpleNamespace

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import JudgeVersions, PlanOutput, Q1Status
from agent_pipeline.data import canonical_json, put_record
from agent_pipeline.evidence import (ArtifactInput, CollectionMetadata,
                                     EvidenceStore, ExecutionCorrelation as EC,
                                     SealingMetadata)
from agent_pipeline.hcap import (ArtifactHcapChecker, Capability,
                                 CapabilityInterface, CapabilityUse, HcapCatalog,
                                 ProgramProposal, Q1Observation, ReachabilityPlan,
                                 RuntimeSelection, ScenarioStep, SelectedPath)
from agent_pipeline.contracts import CandidateLocation, LocationKind
from agent_pipeline.q1 import (CandidateTarget, ContextLossPolicy, CounterDelta,
                              CounterLimit, ExecutionCorrelation, GenerationCounters,
                              KernelIdentity, Q1AdmissibilityProfile,
                              RemoteKcovObservation, RemoteKcovSupportBoundary,
                              TargetPcMapping)
from agent_pipeline.sealed_q1 import (COVERAGE_TYPE, OBSERVATION_ID, OBSERVATION_TYPE,
                                     ArtifactQ1Judge, PublishedCoverage,
                                     TrustedQ1Execution, UnknownExecution)


def catalog(store):
    cap = Capability(
        id="HCAP-03", name="Synthetic remote coverage",
        purpose="Controller component test only", usable_stage=("stage1",),
        usable_by=("agent_stage1",), status="validated", scope=("request",),
        interface=CapabilityInterface(runtime_features=("remote_kcov",)),
        evidence_refs=(store.put(b"synthetic fixture, no real validation"),))
    return put_record(store, HcapCatalog(capabilities=(cap,),
        missing_capability_ids=("remote_kcov.context.client_side",)))


def target(candidate=None):
    if candidate is not None:
        return CandidateTarget(candidate_id=candidate.candidate_id,
            kernel_commit=candidate.kernel_commit,
            **candidate.location.model_dump(mode="json"))
    return CandidateTarget(candidate_id="candidate", kernel_commit="a" * 40,
        kind="function", path="fs/nfsd/test.c", symbol="target",
        start_line=10, end_line=20)


def make_plan(store, candidate, hcap_ref, *, context="request"):
    return ReachabilityPlan(
        candidate_id=candidate.candidate_id, hcap_revision=hcap_ref,
        selected_path=SelectedPath(entry_surface="fixture",
                                  path_summary="synthetic fixture"),
        nfs_version="4.1", scenario_steps=(ScenarioStep(
            capability_id="HCAP-03", action="observe", expected_state_change="none"),),
        required_capabilities=("HCAP-03",), capability_uses=(CapabilityUse(
            capability_id="HCAP-03", status="validated", scope=("request",)),),
        q1_observation=Q1Observation(
            target=CandidateLocation(kind=LocationKind(candidate.kind), path=candidate.path,
                symbol=candidate.symbol, start_line=candidate.start_line,
                end_line=candidate.end_line),
            expected_context=context, capability_id="HCAP-03"),
        program_proposal=ProgramProposal(kind="program", artifact_ref=store.put(
            b"# synthetic program: Materializer is not tested here\n")),
        runtime_selection=RuntimeSelection(profile="knfsd-v41", nfs_version="4.1",
            fixture_mode="single", route="client0-knfsd", topology="both",
            enabled_interfaces=("remote_kcov",), trace_mode="off"))


def setup(tmp_path, *, store=None, pcs=(4096,), candidate=None, plan=None,
          plan_ref=None, harness_id="b" * 64, job_id="job", task_id="task",
          observation_update=None, coverage_update=None, include_coverage=True,
          coverage_type=COVERAGE_TYPE, mapping_present=True):
    store = store or ArtifactStore(tmp_path / "artifacts")
    candidate = candidate or target()
    plan = plan or make_plan(store, candidate, catalog(store))
    plan_ref = plan_ref or put_record(store, plan)
    identity = KernelIdentity(execution_harness_id=harness_id,
        kernel_commit=candidate.kernel_commit, instrumentation_sha256="c" * 64,
        vmlinux_sha256="d" * 64, kaslr_enabled=False, kaslr_offset=0)
    correlation = ExecutionCorrelation(job_id=job_id, task_id=task_id,
        execution_harness_id=harness_id, vm_instance_id="vm", lane=0, generation_id=1)
    coverage = PublishedCoverage(correlation=correlation, pcs=pcs)
    if coverage_update:
        coverage = coverage.model_copy(update=coverage_update)
    coverage_raw = canonical_json(coverage)
    coverage_ref = store.put(coverage_raw)
    observation = RemoteKcovObservation(
        candidate_id=candidate.candidate_id, identity=identity, correlation=correlation,
        boot_ok=True, fixture_ok=True, lane_ok=True, runner_completed=True,
        collection_started=True, collection_completed=True, generation_attributed=True,
        channel="remote_kcov", lane_trace_mode="off",
        coverage_artifacts=(coverage_ref,), published_pcs=pcs,
        generation=GenerationCounters(generation_begin=1, remote_start_ok=1,
            aggregate_published=1, generation_aborted=0, scratch_overflow=0,
            merge_truncation=0, outstanding_tokens=0, remote_refs=0),
        counter_deltas=(CounterDelta(counter="lane_owner_failed",
                                    window="generation-plus-drain", value=0),))
    if observation_update:
        observation = observation.model_copy(update=observation_update)
    artifacts = [ArtifactInput(identity=OBSERVATION_ID, type=OBSERVATION_TYPE,
                               data=canonical_json(observation))]
    if include_coverage:
        artifacts.append(ArtifactInput(identity="coverage", type=coverage_type,
                                       data=coverage_raw))
    evidence = EvidenceStore(store)
    bundle_ref = evidence.seal(artifacts, correlation=EC(**correlation.model_dump()),
        collection=CollectionMetadata(collector_id="test", started_at_ns=1,
                                      completed_at_ns=2),
        sealing=SealingMetadata(sealer_id="test", sealed_at_ns=3))
    profile = Q1AdmissibilityProfile(name="synthetic", revision="1",
        allowed_trace_modes=("off",), contexts=(ContextLossPolicy(context="request",
            window="generation-plus-drain", counters=(CounterLimit(
                counter="lane_owner_failed", max_delta=0),)),))
    boundary = RemoteKcovSupportBoundary(name="synthetic", revision="1",
        kernel_commit=candidate.kernel_commit, instrumentation_sha256="c" * 64,
        supported_contexts=("request",))
    versions = JudgeVersions(judge_profile_id=put_record(store, profile),
                             support_boundary_id=put_record(store, boundary))
    mapping = TargetPcMapping(mapping_method="synthetic test mapping", verified=True,
                             target=candidate, identity=identity, target_pcs=(4096,))
    mapping_ref = put_record(store, mapping) if mapping_present else None
    receipt = TrustedQ1Execution(bundle_ref=bundle_ref, plan_ref=plan_ref,
        candidate=candidate, identity=identity, correlation=correlation,
        trace_mode="off", mapping_ref=mapping_ref)
    judge = ArtifactQ1Judge(store, receipts={bundle_ref: receipt})
    return SimpleNamespace(**locals())


def result(f):
    return f.judge.judge(f.bundle_ref, f.plan_ref, f.candidate.candidate_id, f.versions)


def reseal(f, artifacts):
    f.bundle_ref = f.evidence.seal(artifacts,
        correlation=EC(**f.correlation.model_dump()),
        collection=CollectionMetadata(collector_id="test", started_at_ns=1,
                                      completed_at_ns=2),
        sealing=SealingMetadata(sealer_id="test", sealed_at_ns=3))
    f.receipt = f.receipt.model_copy(update={"bundle_ref": f.bundle_ref})
    f.judge = ArtifactQ1Judge(f.store, receipts={f.bundle_ref: f.receipt})


def test_real_sealed_bytes_yield_deterministic_hit(tmp_path):
    f = setup(tmp_path)
    verdict = result(f)
    assert verdict.status is Q1Status.REACHED
    assert verdict == result(f)
    assert f.judge.has_required_evidence(f.bundle_ref, f.versions)
    decision = f.judge.assess(f.bundle_ref, f.plan_ref, f.candidate.candidate_id, f.versions)
    assert decision.matched_pcs == (4096,)
    assert decision.mapping_ref == f.mapping_ref


def test_empty_published_aggregate_is_a_judgeable_miss(tmp_path):
    f = setup(tmp_path, pcs=())
    assert result(f).status is Q1Status.NOT_REACHED


@pytest.mark.parametrize("where", ["object", "shard"])
@pytest.mark.parametrize("code", [errno.EIO, errno.EMFILE])
@pytest.mark.parametrize("which", [
    "bundle_ref", "coverage_ref", "plan_ref", "mapping_ref", "profile", "boundary",
])
def test_open_failure_never_becomes_a_q1_verdict(tmp_path, monkeypatch, where, code, which):
    f = setup(tmp_path)
    baseline = result(f)
    assert baseline.status is Q1Status.REACHED
    refs = {"profile": f.versions.judge_profile_id,
            "boundary": f.versions.support_boundary_id}
    ref = refs[which] if which in refs else getattr(f, which)
    target = ref if where == "object" else ref[:2]
    real_open = os.open

    def unavailable(path, flags, mode=0o777, *, dir_fd=None):
        if path == target and dir_fd is not None:
            raise OSError(code, os.strerror(code), path)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", unavailable)
        with pytest.raises(OSError):
            result(f)
        with pytest.raises(OSError):
            f.judge.has_required_evidence(f.bundle_ref, f.versions)

    assert result(f) == baseline
    assert f.judge.has_required_evidence(f.bundle_ref, f.versions)


@pytest.mark.parametrize("where", ["object", "shard"])
def test_symlink_is_invalid_q1_evidence(tmp_path, where):
    f = setup(tmp_path)
    assert result(f).status is Q1Status.REACHED
    path = f.store._path(f.coverage_ref)
    if where == "shard":
        path = path.parent
    saved = tmp_path / "original"
    path.rename(saved)
    path.symlink_to(saved, target_is_directory=where == "shard")

    verdict = result(f)
    assert verdict.status is Q1Status.INCONCLUSIVE
    assert verdict.reason == "evidence"
    assert not f.judge.has_required_evidence(f.bundle_ref, f.versions)


@pytest.mark.parametrize("include_hit", [False, True])
def test_all_sealed_coverage_must_participate_in_pc_union(tmp_path, include_hit):
    f = setup(tmp_path, pcs=())
    hit = canonical_json(PublishedCoverage(correlation=f.correlation, pcs=(4096,)))
    hit_ref = f.store.put(hit)
    observation = f.observation
    if include_hit:
        observation = observation.model_copy(update={
            "coverage_artifacts": (f.coverage_ref, hit_ref), "published_pcs": (4096,)})
    reseal(f, [ArtifactInput(identity=OBSERVATION_ID, type=OBSERVATION_TYPE,
                            data=canonical_json(observation)),
               ArtifactInput(identity="empty", type=COVERAGE_TYPE, data=f.coverage_raw),
               ArtifactInput(identity="hit", type=COVERAGE_TYPE, data=hit)])
    if include_hit:
        assert result(f).status is Q1Status.REACHED
    else:
        assert result(f).status is Q1Status.INCONCLUSIVE
        assert result(f).reason == "evidence"
        assert not f.judge.has_required_evidence(f.bundle_ref, f.versions)


def test_duplicate_coverage_references_are_rejected(tmp_path):
    f = setup(tmp_path)
    observation = f.observation.model_copy(update={
        "coverage_artifacts": (f.coverage_ref, f.coverage_ref)})
    reseal(f, [ArtifactInput(identity=OBSERVATION_ID, type=OBSERVATION_TYPE,
                            data=canonical_json(observation)),
               ArtifactInput(identity="coverage", type=COVERAGE_TYPE,
                             data=f.coverage_raw)])
    assert result(f).reason == "evidence"


def test_unpublished_claim_cannot_hide_sealed_coverage(tmp_path):
    f = setup(tmp_path, observation_update={"coverage_artifacts": (),
                                          "published_pcs": None})
    assert result(f).reason == "evidence"
    assert not f.judge.has_required_evidence(f.bundle_ref, f.versions)


def test_payload_alias_with_another_type_cannot_shadow_coverage(tmp_path):
    f = setup(tmp_path)
    reseal(f, f.artifacts + [ArtifactInput(identity="z-log", type="text/plain",
                                         data=f.coverage_raw)])
    assert result(f).status is Q1Status.REACHED


@pytest.mark.parametrize("update", [
    {"published_pcs": (8192,)},
    {"coverage_artifacts": ("0" * 64,)},
    {"guest_target_observed": True, "published_pcs": (8192,)},
    {"lane_trace_mode": "on"},
    {"channel": "tracepoint"},
])
def test_observation_cannot_override_verified_bytes_or_oracle(tmp_path, update):
    f = setup(tmp_path, observation_update=update)
    assert result(f).status is Q1Status.INCONCLUSIVE
    assert result(f).reason == "evidence"


def test_guest_boolean_is_not_an_oracle(tmp_path):
    f = setup(tmp_path, pcs=(), observation_update={"guest_target_observed": True})
    assert result(f).status is Q1Status.NOT_REACHED


@pytest.mark.parametrize("kw", [
    {"include_coverage": False}, {"coverage_type": "text/plain"},
])
def test_digest_exists_outside_bundle_is_not_enough(tmp_path, kw):
    f = setup(tmp_path, **kw)
    assert f.store.has(f.coverage_ref)
    assert result(f).reason == "evidence"
    assert not f.judge.has_required_evidence(f.bundle_ref, f.versions)


def test_coverage_for_another_generation_cannot_be_relabelled(tmp_path):
    other = ExecutionCorrelation(job_id="job", task_id="task",
        execution_harness_id="b" * 64, vm_instance_id="vm", lane=0, generation_id=2)
    f = setup(tmp_path, coverage_update={"correlation": other})
    assert result(f).reason == "evidence"


@pytest.mark.parametrize("which", ["bundle_ref", "coverage_ref", "plan_ref", "mapping_ref"])
def test_corrupt_referenced_bytes_never_yield_a_hit(tmp_path, which):
    f = setup(tmp_path)
    ref = getattr(f, which)
    (f.store.root / ref[:2] / ref).write_bytes(b"corrupt")
    assert result(f).status is Q1Status.INCONCLUSIVE
    assert result(f).reason == "evidence"
    assert not f.judge.has_required_evidence(f.bundle_ref, f.versions)


def test_mapping_is_required_even_with_collected_pcs(tmp_path):
    f = setup(tmp_path, mapping_present=False)
    assert result(f).reason == "mapping"


def test_no_host_receipt_means_no_fabricated_identity(tmp_path):
    f = setup(tmp_path)
    judge = ArtifactQ1Judge(f.store, receipts={})
    with pytest.raises(UnknownExecution):
        judge.judge(f.bundle_ref, f.plan_ref, f.candidate.candidate_id, f.versions)
    with pytest.raises(UnknownExecution):
        judge.matches_execution(f.bundle_ref, job_id="job", task_id="task")
    assert not judge.has_required_evidence(f.bundle_ref, f.versions)


def test_receipt_is_snapshot_not_callers_mutable_mapping(tmp_path):
    f = setup(tmp_path)
    receipts = {f.bundle_ref: f.receipt}
    judge = ArtifactQ1Judge(f.store, receipts=receipts)
    receipts.clear()
    assert judge.judge(f.bundle_ref, f.plan_ref, f.candidate.candidate_id,
                       f.versions).status is Q1Status.REACHED


def test_receipt_conflict_does_not_replace_host_correlation(tmp_path):
    f = setup(tmp_path)
    receipt = f.receipt.model_copy(update={"correlation": f.correlation.model_copy(
        update={"task_id": "different-task"})})
    judge = ArtifactQ1Judge(f.store, receipts={f.bundle_ref: receipt})
    assert judge.judge(f.bundle_ref, f.plan_ref, f.candidate.candidate_id,
                       f.versions).reason == "evidence"


def test_new_profile_without_new_counter_requires_more_evidence(tmp_path):
    f = setup(tmp_path, pcs=())
    profile = f.profile.model_copy(update={"revision": "2", "contexts": (
        ContextLossPolicy(context="request", window="generation-plus-drain",
                          counters=(CounterLimit(counter="new_counter"),)),)})
    versions = f.versions.model_copy(update={"judge_profile_id": put_record(f.store, profile)})
    assert not f.judge.has_required_evidence(f.bundle_ref, versions)
    verdict = f.judge.judge(f.bundle_ref, f.plan_ref, f.candidate.candidate_id, versions)
    assert verdict.status is Q1Status.INCONCLUSIVE and verdict.reason == "loss"


def test_known_plan_and_candidate_binding_required(tmp_path):
    f = setup(tmp_path)
    assert f.judge.judge(f.bundle_ref, "0" * 64, f.candidate.candidate_id,
                         f.versions).reason == "evidence"
    assert f.judge.judge(f.bundle_ref, f.plan_ref, "another-candidate",
                         f.versions).reason == "evidence"


def start_real_judge_run(world, wrong_owner=None):
    from .fakes import binding

    hcap_ref = catalog(world.artifacts)
    world.registry.put(binding(hcap=hcap_ref))
    world.hcap = ArtifactHcapChecker(world.artifacts)
    world.controller = world._controller()
    job_id = world.submit()
    world.analysis(job_id)
    candidate = target(world.job(job_id).candidate)
    plan = make_plan(world.artifacts, candidate, hcap_ref)
    plan_ref = put_record(world.artifacts, plan)
    world.agent_ok(job_id, PlanOutput(plan_ref=plan_ref))
    job = world.job(job_id)
    assert job.state.value == "s1_running"
    f = setup(world.tmp, store=world.artifacts, candidate=candidate,
        plan=plan, plan_ref=plan_ref, harness_id=job.binding.execution_harness_id,
        job_id="other-job" if wrong_owner == "job" else job_id,
        task_id="old-task" if wrong_owner == "task" else job.pending_task.task_id)
    world.judge = f.judge
    world.controller = world._controller()
    world.c.on_judge_versions(f.versions)
    return job_id, job, f


@pytest.mark.parametrize("corrupt, wrong_owner, expected", [
    (False, None, "s1_reached"), (True, None, "blocked_operator"),
    (False, "job", "blocked_operator"), (False, "task", "blocked_operator"),
])
def test_controller_uses_real_hcap_and_sealed_judge(world, corrupt, wrong_owner, expected):
    job_id, job, f = start_real_judge_run(world, wrong_owner)
    if corrupt:
        (f.store.root / f.coverage_ref[:2] / f.coverage_ref).write_bytes(b"corrupt")
    world.runner.finish(job.pending_task.task_id, bundle=f.bundle_ref)
    world.c.poll()
    assert world.job(job_id).state.value == expected
    assert world.c.replay(job_id) == world.job(job_id)
    if corrupt or wrong_owner:
        assert world.job(job_id).state_reason == "q1_evidence"
        assert world.job(job_id).stage2_input is None
    else:
        assert world.job(job_id).stage2_input is not None
    # Adding an unrelated receipt must not change a consumed result's
    # ownership check or the replay of a known cross-task rejection.
    extra = f.receipt.model_copy(update={"bundle_ref": "0" * 64})
    world.judge = ArtifactQ1Judge(f.store, receipts={f.bundle_ref: f.receipt,
                                                  extra.bundle_ref: extra})
    world.controller = world._controller()
    assert world.c.replay(job_id) == world.job(job_id)


def test_late_host_receipt_retries_without_committing_a_replayable_mismatch(world):
    job_id, job, f = start_real_judge_run(world)
    world.judge = ArtifactQ1Judge(f.store, receipts={})
    world.controller = world._controller()
    before = world.job(job_id)
    world.runner.finish(job.pending_task.task_id, bundle=f.bundle_ref)
    world.expected_failures += 1  # Host receipt publication is deliberately delayed.
    failures = world.c.poll()
    assert len(failures) == 1
    assert world.job(job_id) == before
    assert world.job(job_id).last_verdict is None
    assert world.store.effect_failures(job_id)
    world.judge = f.judge
    world.controller = world._controller()
    assert world.c.poll() == []
    assert world.job(job_id).state.value == "s1_reached"
    assert world.c.replay(job_id) == world.job(job_id)
