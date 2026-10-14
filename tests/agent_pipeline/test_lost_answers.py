"""09 §8: a side effect sent after commit whose answer was lost, or that
failed, is recorded for its job and sent again by poll() or recover()
until it is done.  One job's failing call never stops the others."""

import sqlite3

from agent_pipeline.contracts import (AnalysisOutput, GapClass, GapRef,
                                      PlanOutput, Q1Status)
from agent_pipeline.controller.records import JobState

from .fakes import OTHER_COMMIT, binding, function_submission, sha


class Down(ConnectionError):
    pass


def fail(obj, name, times=1):
    real = getattr(obj, name)
    calls = []

    def flaky(*a, **kw):
        calls.append(a)
        if len(calls) <= times:
            raise Down(name)
        return real(*a, **kw)
    setattr(obj, name, flaky)
    return calls


def effects(world, job_id):
    return [e for _, e, _, _ in world.store.effect_failures(job_id)]


def test_gap_issue_is_linked_after_a_failed_open(world):
    fail(world.issues, "open_or_link")
    j = world.submit(function_submission(commit=OTHER_COMMIT))
    job = world.job(j)
    assert job.state is JobState.BLOCKED_HARNESS_GAP
    assert world.store.issue_ref(job.gap) is None      # committed, unlinked
    assert effects(world, j) == ["link_issue"]
    assert world.c.poll() == []
    assert world.store.issue_ref(job.gap) == world.issues.issues[job.gap]
    assert world.issues.links[job.gap] == [j]
    world.c.poll()                                     # linked once
    assert world.issues.links[job.gap] == [j]
    world.expected_failures = 1


def test_gap_issue_is_linked_on_recover(world):
    fail(world.issues, "open_or_link")
    j = world.submit(function_submission(commit=OTHER_COMMIT))
    world.restart()
    assert world.issues.links[world.job(j).gap] == [j]
    world.expected_failures = 1


def test_a_second_job_on_a_linked_gap_is_linked_too(world):
    a = world.submit(function_submission(commit=OTHER_COMMIT))
    fail(world.issues, "open_or_link")
    world.submit(function_submission(commit=OTHER_COMMIT))
    gap = world.job(a).gap
    assert world.store.issue_ref(gap) is not None      # a's link
    world.c.poll()
    assert len(world.issues.links[gap]) == 2
    world.expected_failures = 1


def test_a_recurring_gap_is_linked_again(world):
    """07 §2: the same gap after its issue was resolved is a new wait,
    linked to the gap's open issue, not to the resolved one."""
    gap = GapRef(gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
                 missing_capability_id="remote_kcov.context.softirq")
    calls = []
    real = world.issues.open_or_link

    def counting(g, job_id):
        calls.append(job_id)
        return real(g, job_id)
    world.issues.open_or_link = counting
    j = world.to_running()
    world.run(j, Q1Status.INCONCLUSIVE, "unsupported_attribution", gap)
    first = world.store.issue_ref(gap)
    world.issues.resolve(gap)
    world.c.on_issue(gap, "resolved")
    assert world.job(j).state is JobState.S1_RUNNING
    world.run(j, Q1Status.INCONCLUSIVE, "unsupported_attribution", gap)
    assert world.job(j).state is JobState.BLOCKED_HARNESS_GAP
    assert calls == [j, j]
    assert world.store.issue_ref(gap) == world.issues.issues[gap] != first
    assert world.issues.links[gap] == [j]
    world.c.poll()
    world.restart()
    assert calls == [j, j]                             # once per wait


def test_one_jobs_tracker_failure_does_not_stop_the_others(world):
    fail(world.issues, "open_or_link", times=99)
    blocked = world.submit(function_submission(commit=OTHER_COMMIT))
    j = world.to_running()
    p = world.job(j).pending_task
    world.judge.add("b", binding().execution_harness_id,
                    world.job(j).candidate.candidate_id, Q1Status.REACHED)
    world.runner.finish(p.task_id, bundle="b")
    failures = world.c.poll()
    assert [(f.job_id, f.effect) for f in failures] == \
        [(blocked, "link_issue")]
    assert world.job(j).state is JobState.S1_REACHED
    assert world.job(blocked).state is JobState.BLOCKED_HARNESS_GAP
    world.issues.open_or_link = type(world.issues).open_or_link.__get__(
        world.issues)
    assert world.c.poll() == []
    assert world.issues.links[world.job(blocked).gap] == [blocked]
    world.expected_failures = 2


def test_failed_first_submit_is_sent_again_with_its_task_id(world):
    j = world.submit()
    world.analysis(j)
    fail(world.runner, "submit")
    world.plan(j)
    job = world.job(j)
    task = job.pending_task.task_id
    assert job.state is JobState.S1_RUNNING
    assert world.runner.starts[task] == 0
    assert effects(world, j) == ["dispatch"]
    world.c.poll()
    assert world.runner.starts[task] == 1
    assert world.runner.tasks[task]["input"].execution_harness_id == \
        binding().execution_harness_id
    world.c.poll()                                     # running: no resend
    assert world.runner.submits[task] == 1
    world.run(j, Q1Status.REACHED)
    assert world.job(j).state is JobState.S1_REACHED
    world.c.replay(j)
    world.expected_failures = 1


def test_lost_cancel_answer_is_settled_by_poll(world):
    j = world.to_running()
    old = world.job(j).pending_task.task_id
    real = world.runner.cancel

    def cancel_then_drop(task_id):
        real(task_id)                       # the Runner did cancel it
        raise Down("cancel")
    world.runner.cancel = cancel_then_drop
    world.registry.put(binding("build-2"))
    world.c.on_registry_changed()
    world.runner.cancel = real
    job = world.job(j)
    new = job.pending_task.task_id
    assert job.cancelling_tasks == (old,)
    assert world.runner.starts[new] == 0
    world.c.poll()
    job = world.job(j)
    assert job.cancelling_tasks == ()
    assert world.runner.started == [old, new]
    world.c.replay(j)
    world.expected_failures = 1


def test_failed_agent_start_is_sent_again_as_a_new_attempt(world):
    fail(world.agents, "start")
    j = world.submit()
    p = world.job(j).pending_task
    assert world.agents.requests == []
    assert world.store.attempt(p.task_id, 1).status == "sending"
    assert effects(world, j) == ["dispatch"]
    assert world.c.poll() == []
    job = world.job(j)
    assert job.state is JobState.S1_ANALYSIS
    assert job.pending_task.attempt == 2
    assert [r.attempt for r in world.agents.requests] == [2]
    assert world.store.attempt(p.task_id, 1).status == "abandoned"
    assert world.store.attempt(p.task_id, 2).status == "running"
    world.c.poll()                                     # started: no resend
    assert len(world.agents.requests) == 1
    # A late answer to the unsent attempt makes no transition.
    world.c.on_agent_result(p.task_id, 1,
                            AnalysisOutput(analysis_ref=sha("late")), "m")
    assert world.job(j).analysis_ref is None
    world.analysis(j)
    assert world.job(j).state is JobState.S1_PLANNING
    world.c.replay(j)
    world.expected_failures = 1


def test_failed_agent_restart_on_an_hcap_change_is_sent_again(world):
    j = world.submit()
    world.analysis(j)
    fail(world.agents, "start")
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    n = len(world.agents.requests)
    world.c.poll()
    assert len(world.agents.requests) == n + 1
    assert world.agents.requests[-1].hcap_revision == "hcap-2"
    world.plan(j)
    assert world.job(j).state is JobState.S1_RUNNING
    world.expected_failures = 1


def test_failed_agent_start_on_recover_is_sent_again(world):
    j = world.submit()
    fail(world.agents, "start")
    world.restart()                    # new attempt 2, its start fails
    assert world.job(j).pending_task.attempt == 2
    world.c.poll()
    p = world.job(j).pending_task
    assert p.attempt == 3
    assert world.agents.requests[-1].attempt == 3
    world.analysis(j)
    assert world.job(j).state is JobState.S1_PLANNING
    world.expected_failures = 1


def lock_next_commit(world):
    """The next transition commit fails as if another writer held the
    database; the attempt row written before it stays."""
    real = world.store.commit
    hit = []

    def commit(*a, **kw):
        if not hit:
            hit.append(1)
            raise sqlite3.OperationalError("database is locked")
        return real(*a, **kw)
    world.store.commit = commit


def test_stored_agent_result_is_applied_by_poll(world):
    j = world.submit()
    p = world.job(j).pending_task
    lock_next_commit(world)
    world.analysis(j)
    assert world.store.attempt(p.task_id, 1).status == "succeeded"
    job = world.job(j)
    assert job.state is JobState.S1_ANALYSIS and job.pending_task == p
    assert effects(world, j) == ["agent_result"]
    assert world.c.poll() == []
    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.analysis_ref == sha("analysis-1")
    world.c.replay(j)
    world.expected_failures = 1


def test_stored_agent_failure_is_applied_by_poll(world):
    j = world.submit()
    p = world.job(j).pending_task
    lock_next_commit(world)
    world.c.on_agent_failure(p.task_id, 1, "model_timeout")
    assert world.store.attempt(p.task_id, 1).status == "failed"
    assert world.job(j).counters.agent_retry == 0
    world.c.poll()
    job = world.job(j)
    assert job.counters.agent_retry == 1               # retried once
    assert job.state is JobState.S1_ANALYSIS
    assert job.pending_task.task_id != p.task_id
    assert world.agents.requests[-1].task_id == job.pending_task.task_id
    world.c.poll()                                     # applied once
    assert world.job(j).counters.agent_retry == 1
    world.expected_failures = 1


def test_result_inside_start_with_a_failed_commit(world):
    """The executor answers from inside start(); the transition of that
    answer fails to commit."""
    j = world.submit()
    world.analysis(j)                      # planning is pending now
    world.agents.start = lambda req: (
        lock_next_commit(world),
        world.c.on_agent_result(req.task_id, req.attempt,
                                PlanOutput(plan_ref=sha("plan-1")), "m"))
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()          # restarts planning
    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    assert world.store.attempt(job.pending_task.task_id,
                               job.pending_task.attempt).status == \
        "succeeded"
    world.c.poll()
    assert world.job(j).state is JobState.S1_RUNNING
    world.c.replay(j)
    world.expected_failures = 1
