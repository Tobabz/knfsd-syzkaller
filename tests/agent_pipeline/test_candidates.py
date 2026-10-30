"""A candidate is immutable and can have many jobs (02 §7, owner decision
2026-10-13), and the JobPolicy defaults."""

import pytest

from agent_pipeline.contracts import (AgentModelPolicy, HarnessBinding,
                                      JobPolicy, LocationKind, Q1Status,
                                      Sanitizer)
from agent_pipeline.controller.records import JobState
from agent_pipeline.intake import IntakeRejected

from .fakes import COMMIT, binding, function_submission, sha


def kcsan(w):
    w.store.save_policy(JobPolicy(policy_id="kcsan", sanitizer=Sanitizer.KCSAN,
                                  agent_retry_limit=2, runtime_retry_limit=2))
    w.registry.put(HarnessBinding(
        kernel_commit=COMMIT, sanitizer=Sanitizer.KCSAN,
        execution_harness_id=sha("build-kcsan"), hcap_revision="hcap-1"))


def test_same_target_is_one_candidate(world):
    a = world.c.register(function_submission())
    b = world.c.register(function_submission())
    assert a.candidate_id == b.candidate_id
    c = world.c.register(function_submission(symbol="helper"))
    assert c.candidate_id != a.candidate_id


def test_refused_target_is_not_registered(world):
    r = world.c.register(function_submission(symbol="missing"))
    assert isinstance(r, IntakeRejected)


def test_one_candidate_two_jobs_two_sanitizers(world):
    kcsan(world)
    cand = world.c.register(function_submission())
    a = world.c.start_job(cand.candidate_id, "p1")
    b = world.c.start_job(cand.candidate_id, "kcsan")
    ja, jb = world.job(a), world.job(b)
    assert ja.candidate == jb.candidate == cand
    assert ja.binding == binding()
    assert jb.binding.sanitizer is Sanitizer.KCSAN
    assert {j.job_id for j in world.store.jobs_for(cand.candidate_id)} == \
        {a, b}
    # The jobs move independently.
    world.to_running(a)
    world.run(a, Q1Status.REACHED)
    assert world.job(a).state is JobState.S1_REACHED
    assert world.job(b).state is JobState.S1_ANALYSIS


def test_submit_registers_and_reuses_the_candidate(world):
    a = world.submit()
    b = world.submit()
    assert world.job(a).candidate.candidate_id == \
        world.job(b).candidate.candidate_id
    assert world.job(a).candidate.location.kind is LocationKind.FUNCTION


def test_policy_defaults():
    p = JobPolicy(policy_id="d", sanitizer=Sanitizer.KASAN)
    assert p.stage1_repair_budget == 3
    assert p.agent_retry_limit == 3
    assert p.runtime_retry_limit == 3
    assert p.approval_required is False
    assert p.run_stage2 is False
    assert p.stage1_agents.candidate_analysis.requested_model_id == \
        "openai:gpt-5.6-sol"
    assert p.stage1_agents.reachability_planning.requested_model_id == \
        "openai:gpt-5.6-sol"
    assert p.stage2_agents.mutation_strategy.requested_model_id == \
        "openai:gpt-5.6-sol"
    assert p.harness_generation_agent.requested_model_id == \
        "openai:gpt-5.6-sol"


def test_a_model_default_change_needs_a_new_policy_id(world):
    job_id = world.submit()
    stored = world.store.policy("p1")
    pending = world.job(job_id).pending_task
    changed = stored.model_copy(update={
        "stage1_agents": stored.stage1_agents.model_copy(update={
            "candidate_analysis": AgentModelPolicy(
                provider="openai", model="another-model")})})
    with pytest.raises(ValueError, match="already exists with other values"):
        world.store.save_policy(changed)
    assert world.store.policy("p1") == stored
    assert world.job(job_id).pending_task == pending
