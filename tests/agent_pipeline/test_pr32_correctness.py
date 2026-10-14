"""Focused regressions for the independently reproduced PR #32 findings."""

import errno
import json
from unittest.mock import patch

import pytest

from agent_pipeline.contracts import PlanOutput, Q1Status, Sanitizer
from agent_pipeline.controller.events import EVENT
from agent_pipeline.data import load_record, put_record
from agent_pipeline.hcap import ArtifactHcapChecker, AuthorityRef, HcapCatalog
from agent_pipeline.q1 import GenerationCounters
from agent_pipeline.registry import (
    ArtifactHarnessRegistry,
    HarnessCatalog,
    HarnessRegistration,
)

from .fakes import COMMIT, OTHER_COMMIT, binding, function_submission, policy
from .test_sealed_q1 import make_plan, setup, start_real_judge_run, target


def install_judge(world, judge):
    world.judge = judge
    world.c.machine.env.judge = judge


def test_compatible_hcap_update_rematerializes_stored_plan(world):
    job_id, old_job, facts = start_real_judge_run(world)
    old_catalog = load_record(
        world.artifacts, old_job.binding.hcap_revision, HcapCatalog)
    new_ref = put_record(world.artifacts, old_catalog.model_copy(update={
        "missing_capability_ids": (*old_catalog.missing_capability_ids,
                                   "fixture.unrelated_future_capability"),
    }))
    checker = ArtifactHcapChecker(world.artifacts)

    assert checker.check_plan(facts.plan_ref, new_ref).violations == (
        "hcap_revision_mismatch",)
    assert checker.revalidate_plan(facts.plan_ref, new_ref).ok

    world.registry.put(old_job.binding.model_copy(
        update={"hcap_revision": new_ref}))
    world.c.on_registry_changed()

    current = world.job(job_id)
    assert current.state.value == "s1_running"
    assert current.plan_ref == old_job.plan_ref
    assert current.harness.harness_ref != old_job.harness.harness_ref
    assert current.pending_task.task_id != old_job.pending_task.task_id
    assert world.runner.cancel_calls[old_job.pending_task.task_id] == 1
    assert current.counters.agent_repair_stage1 == 0
    assert world.c.replay(job_id) == current


def test_jobs_use_q1_authorities_from_their_own_bindings(world):
    seeds = [
        setup(world.tmp, store=world.artifacts,
              candidate=target().model_copy(update={"kernel_commit": commit}))
        for commit in (COMMIT, OTHER_COMMIT)
    ]
    registrations = []
    for index, seed in enumerate(seeds):
        hcap = load_record(world.artifacts, seed.plan.hcap_revision, HcapCatalog)
        hcap_ref = put_record(world.artifacts, hcap.model_copy(update={
            "authority_refs": (
                AuthorityRef(kind="RemoteKcovSupportBoundary",
                             artifact_ref=seed.versions.support_boundary_id),
                AuthorityRef(kind="Q1AdmissibilityProfile",
                             artifact_ref=seed.versions.judge_profile_id),
            ),
        }))
        registrations.append(HarnessRegistration(
            binding=binding(execution=f"validated-build-{index}",
                            hcap=hcap_ref,
                            commit=seed.candidate.kernel_commit),
            evidence_refs=(world.artifacts.put(b"synthetic host approval"),),
        ))

    catalog_ref = put_record(
        world.artifacts, HarnessCatalog(registrations=tuple(registrations)))
    world.registry = ArtifactHarnessRegistry(world.artifacts, catalog_ref)
    world.hcap = ArtifactHcapChecker(world.artifacts)
    world.controller = world._controller()
    world.c.judge_versions = seeds[0].versions

    cases = []
    for registration, seed in zip(registrations, seeds, strict=True):
        selected = registration.binding
        job_id = world.submit(function_submission(
            commit=selected.kernel_commit))
        world.analysis(job_id)
        candidate = target(world.job(job_id).candidate)
        plan = make_plan(world.artifacts, candidate,
                         selected.hcap_revision)
        plan_ref = put_record(world.artifacts, plan)
        world.agent_ok(job_id, PlanOutput(plan_ref=plan_ref))
        job = world.job(job_id)
        facts = setup(
            world.tmp, store=world.artifacts, candidate=candidate,
            plan=plan, plan_ref=plan_ref,
            harness_id=selected.execution_harness_id, job_id=job_id,
            task_id=job.pending_task.task_id)
        assert job.judge_versions == seed.versions == facts.versions
        cases.append((job_id, job, facts))

    judge = facts.judge.__class__(
        world.artifacts,
        receipts={facts.bundle_ref: facts.receipt
                  for _, _, facts in cases})
    install_judge(world, judge)

    for _, job, facts in cases:
        world.runner.finish(job.pending_task.task_id,
                            bundle=facts.bundle_ref)
    assert world.c.poll() == []
    assert tuple(world.job(job_id).state.value
                 for job_id, _, _ in cases) == ("s1_reached", "s1_reached")

    # Changing the fallback does not perturb jobs whose binding pins Q1.
    world.c.on_judge_versions(seeds[1].versions)
    for job_id, _, facts in cases:
        current = world.job(job_id)
        assert current.state.value == "s1_reached"
        assert current.judge_versions == facts.versions
        assert world.c.replay(job_id) == current


@pytest.mark.parametrize("event_type", ("binding_changed", "policy_changed"))
def test_legacy_revalidation_event_without_judge_versions_replays(
        world, event_type):
    job_id = world.to_running()
    if event_type == "binding_changed":
        world.registry.put(binding(hcap="hcap-2"))
        world.c.on_registry_changed()
    else:
        world.store.save_policy(policy("p2", sanitizer=Sanitizer.KCSAN))
        kcsan = binding(execution="build-kcsan").model_copy(
            update={"sanitizer": Sanitizer.KCSAN})
        world.registry.put(kcsan)
        world.c.set_policy(job_id, "p2")

    transition = next(
        item for item in world.store.transitions(job_id)
        if item.event["type"] == event_type)
    legacy_event = dict(transition.event)
    assert legacy_event.pop("judge_versions") is not None
    parsed = EVENT.validate_json(json.dumps(legacy_event))
    assert parsed.judge_versions is None

    legacy_transition = transition.model_copy(
        update={"event": legacy_event})
    world.store.db.execute(
        "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = ?",
        (legacy_transition.model_dump_json(), job_id, transition.seq))
    assert world.c.replay(job_id) == world.job(job_id)


EARLY_FAILURES = ("boot_ok", "fixture_ok", "lane_ok", "runner_completed")


@pytest.mark.parametrize("failure", EARLY_FAILURES)
@pytest.mark.parametrize("missing", ("counters", "attribution", "trace"))
def test_early_execution_failure_retries_before_missing_observations(
        world, failure, missing):
    job_id, old_job, successful = start_real_judge_run(world)
    changes = {
        failure: False,
        "collection_started": False,
        "collection_completed": False,
        "coverage_artifacts": (),
        "published_pcs": None,
        "generation": GenerationCounters(
            generation_begin=0, remote_start_ok=0, aggregate_published=0,
            generation_aborted=0, scratch_overflow=0, merge_truncation=0,
            outstanding_tokens=0, remote_refs=0),
    }
    if missing == "counters":
        changes["generation"] = GenerationCounters()
    elif missing == "attribution":
        changes["generation_attributed"] = False
    else:
        changes["lane_trace_mode"] = None

    facts = setup(
        world.tmp, store=world.artifacts, candidate=successful.candidate,
        plan=successful.plan, plan_ref=successful.plan_ref,
        harness_id=old_job.binding.execution_harness_id, job_id=job_id,
        task_id=old_job.pending_task.task_id,
        observation_update=changes, include_coverage=False)
    install_judge(world, facts.judge)

    decision = facts.judge.assess(
        facts.bundle_ref, facts.plan_ref,
        facts.candidate.candidate_id, facts.versions)
    assert decision.status is Q1Status.INCONCLUSIVE
    assert decision.reason == "infra"

    world.runner.finish(old_job.pending_task.task_id,
                        bundle=facts.bundle_ref)
    assert world.c.poll() == []
    current = world.job(job_id)
    assert current.last_verdict.result.reason == "infra"
    assert current.state.value == "s1_running"
    assert current.counters.runtime_retry == 1
    assert world.c.replay(job_id) == current


def test_contradictory_publish_precedes_known_execution_failure(tmp_path):
    facts = setup(tmp_path, observation_update={
        "boot_ok": False,
        "generation": GenerationCounters(
            generation_begin=1, remote_start_ok=1, aggregate_published=1,
            generation_aborted=1, scratch_overflow=0, merge_truncation=0,
            outstanding_tokens=0, remote_refs=0),
    })
    decision = facts.judge.assess(
        facts.bundle_ref, facts.plan_ref,
        facts.candidate.candidate_id, facts.versions)
    assert decision.reason == "evidence"
    assert decision.observations == (
        "published_aggregate_contradicts_generation_counters",)


@pytest.mark.parametrize("unavailable_name",
                         ("mapping_ref", "bundle_ref", "coverage_ref"))
def test_transient_q1_artifact_io_keeps_runner_task_pending(
        world, unavailable_name):
    job_id, job, facts = start_real_judge_run(world)
    unavailable = getattr(facts, unavailable_name)
    original_get = facts.store.get
    calls = []

    def transient(ref, **kwargs):
        if ref == unavailable:
            calls.append(ref)
            raise OSError(errno.EIO,
                          "synthetic temporary artifact read failure")
        return original_get(ref, **kwargs)

    before = world.job(job_id)
    world.runner.finish(job.pending_task.task_id, bundle=facts.bundle_ref)
    world.expected_failures += 1
    with patch.object(facts.store, "get", transient):
        failures = world.c.poll()

    assert calls
    assert len(failures) == 1
    assert world.job(job_id) == before
    assert world.store.verdicts(job_id) == []
    assert world.c.replay(job_id) == before

    assert world.c.poll() == []
    current = world.job(job_id)
    assert current.state.value == "s1_reached"
    assert current.last_verdict.result.status is Q1Status.REACHED
    assert world.c.replay(job_id) == current
