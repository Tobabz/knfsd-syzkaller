"""Oracle 3 (09 검증 오라클): every repair or rerun loop ends in
blocked_operator, and a judged INCONCLUSIVE never resets runtime_retry."""

import pytest

from agent_pipeline.contracts import Q1Status, ReanalysisRequired
from agent_pipeline.controller.records import BlockedReason, JobState

from .fakes import sha

ONE = dict(stage1_repair_budget=1, agent_retry_limit=1, runtime_retry_limit=1)


def assert_blocked(w, j, reason):
    job = w.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR, job.state
    assert job.state_reason == reason.value


def test_repeated_not_reached_ends(make_world):
    w = make_world(**ONE)
    j = w.to_running()
    for n in range(10):
        if w.job(j).state is not JobState.S1_RUNNING:
            break
        w.run(j, Q1Status.NOT_REACHED)
        if w.job(j).state is JobState.S1_PLANNING:
            w.plan(j, f"plan-{n + 2}")
    assert_blocked(w, j, BlockedReason.STAGE1_REPAIR_BUDGET)
    assert len(w.store.transitions(j)) < 20


def test_repeated_reanalysis_ends(make_world):
    w = make_world(**ONE)
    j = w.submit()
    w.analysis(j)
    for _ in range(5):
        if w.job(j).state is not JobState.S1_PLANNING:
            break
        w.agent_ok(j, ReanalysisRequired(reason="again"))
        if w.job(j).state is JobState.S1_ANALYSIS:
            w.analysis(j)
    assert_blocked(w, j, BlockedReason.STAGE1_REPAIR_BUDGET)


def test_repeated_agent_failure_ends(make_world):
    w = make_world(**ONE)
    j = w.submit()
    for _ in range(5):
        p = w.job(j).pending_task
        if p is None:
            break
        w.c.on_agent_failure(p.task_id, p.attempt, "provider timeout")
    assert_blocked(w, j, BlockedReason.AGENT_FAILURE)
    w.c.operator(j, "resume")
    job = w.job(j)
    assert job.state is JobState.S1_ANALYSIS and job.counters.agent_retry == 0


def test_agent_success_resets_agent_retry(make_world):
    w = make_world(agent_retry_limit=1)
    j = w.submit()
    p = w.job(j).pending_task
    w.c.on_agent_failure(p.task_id, p.attempt, "timeout")
    assert w.job(j).counters.agent_retry == 1
    w.analysis(j)
    assert w.job(j).counters.agent_retry == 0
    p = w.job(j).pending_task
    w.c.on_agent_failure(p.task_id, p.attempt, "timeout")
    assert w.job(j).state is JobState.S1_PLANNING


def test_repeated_unsealed_end_ends(make_world):
    w = make_world(**ONE)
    j = w.to_running()
    for _ in range(5):
        if w.job(j).state is not JobState.S1_RUNNING:
            break
        w.crash_run(j)
    assert_blocked(w, j, BlockedReason.RUNTIME_RETRY_EXHAUSTED)


@pytest.mark.parametrize("limit", [2, 3])
def test_judged_inconclusive_does_not_reset_runtime_retry(make_world, limit):
    w = make_world(runtime_retry_limit=limit)
    j = w.to_running()
    reasons = ["infra", "loss"] * 4
    seen = []
    for reason in reasons[:limit]:
        w.run(j, Q1Status.INCONCLUSIVE, reason)
        seen.append(w.job(j).counters.runtime_retry)
        assert w.job(j).state is JobState.S1_RUNNING
    assert seen == list(range(1, limit + 1))       # never back to 0
    w.run(j, Q1Status.INCONCLUSIVE, reasons[limit])
    assert_blocked(w, j, BlockedReason.RUNTIME_RETRY_EXHAUSTED)
    assert len(w.runner.started) == limit + 1


def test_a_row_that_is_not_a_rerun_resets_runtime_retry(make_world):
    w = make_world(runtime_retry_limit=2)
    j = w.to_running()
    w.run(j, Q1Status.INCONCLUSIVE, "infra")
    assert w.job(j).counters.runtime_retry == 1
    w.run(j, Q1Status.NOT_REACHED)
    assert w.job(j).counters.runtime_retry == 0
    w.plan(j, "plan-2")
    w.run(j, Q1Status.INCONCLUSIVE, "loss")
    w.run(j, Q1Status.INCONCLUSIVE, "infra")
    assert w.job(j).state is JobState.S1_RUNNING     # two more allowed
    assert w.job(j).plan_ref == sha("plan-2")
