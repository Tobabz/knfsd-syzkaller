"""#81 D10, R5: a KCSAN job is a new job under a KCSAN policy; it can be
seeded from another job's plan, which is re-validated and materialized on
the KCSAN harness, and Q1 must reach again there."""

from __future__ import annotations

import pytest

from agent_pipeline.contracts import Q1Status, Sanitizer
from agent_pipeline.controller.records import JobState, TaskKind, TargetKind

from .fakes import binding, policy, sha


@pytest.fixture
def world(world):
    world.store.save_policy(policy("kcsan", sanitizer=Sanitizer.KCSAN))
    world.registry.put(binding("build-kcsan", "hcap-kcsan",
                               sanitizer=Sanitizer.KCSAN))
    return world


def reached(world) -> str:
    j = world.to_running()
    world.run(j, Q1Status.REACHED)
    return j


def test_a_seeded_job_starts_from_the_plan_on_the_kcsan_harness(world):
    src = reached(world)
    agent_requests = len(world.agents.requests)
    k = world.c.seed(src, "kcsan")
    job = world.job(k)
    assert job.state is JobState.S1_RUNNING
    assert job.pending_task.kind is TaskKind.RUNNER
    assert job.seed.from_job == src
    old = world.job(src)
    assert (job.analysis_ref, job.plan_ref) == (old.analysis_ref,
                                                old.plan_ref)
    assert job.candidate == old.candidate
    # The KCSAN binding, its HCAP (compatible replacement) and harness.
    assert job.binding.sanitizer is Sanitizer.KCSAN
    assert job.binding.execution_harness_id == sha("build-kcsan")
    assert (job.plan_ref, "hcap-kcsan") in world.hcap.revalidated
    assert job.harness.execution_harness_id == sha("build-kcsan")
    assert job.harness.harness_ref != old.harness.harness_ref
    assert len(world.agents.requests) == agent_requests     # no Agent
    # Q1 must reach again here.
    world.run(k, Q1Status.REACHED)
    assert world.job(k).state is JobState.S1_REACHED
    assert world.c.replay(k) == world.job(k)
    assert world.job(src) == old


def test_a_seeded_plan_the_kcsan_hcap_refuses_is_repaired(world):
    src = reached(world)
    plan = world.job(src).plan_ref
    world.hcap.violations[(plan, "hcap-kcsan")] = ("capability_unknown",)
    k = world.c.seed(src, "kcsan")
    job = world.job(k)
    assert job.state is JobState.S1_PLANNING
    assert job.pending_task.kind is TaskKind.AGENT


def test_a_seeded_job_without_a_kcsan_harness_waits_for_one(world):
    src = reached(world)
    world.registry.remove(world.job(src).binding.kernel_commit,
                          Sanitizer.KCSAN)
    k = world.c.seed(src, "kcsan")
    job = world.job(k)
    assert job.state is JobState.BLOCKED_HARNESS_GAP
    assert job.resume_point.kind is TargetKind.MATERIALIZE
    assert job.plan_ref == world.job(src).plan_ref
    assert world.c.replay(k) == job


def test_only_a_job_with_a_plan_can_seed(world):
    j = world.submit()
    with pytest.raises(ValueError, match="no plan"):
        world.c.seed(j, "kcsan")


def test_a_kcsan_job_binds_the_kcsan_harness(world):
    j = world.c.submit(world.job(world.submit()).submission, "kcsan")
    job = world.job(j)
    assert job.binding.sanitizer is Sanitizer.KCSAN
    assert job.state is JobState.S1_ANALYSIS
