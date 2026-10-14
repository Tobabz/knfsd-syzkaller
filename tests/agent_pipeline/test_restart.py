"""Oracles 4 and 5 (09 검증 오라클): restart and duplicate execution.

A restart is a new Controller on the same store and the same Runner, as
after the Controller process died; recover() then runs.
"""

import hashlib

from agent_pipeline.contracts import AnalysisOutput, PlanOutput, Q1Status
from agent_pipeline.controller import events as ev
from agent_pipeline.controller.records import JobState, TaskKind, Transition
from agent_pipeline.controller.tasks import RunnerInput, SubmitRefused

from .fakes import binding, sha


def same_after_restart(w, j):
    before = w.job(j)
    w.restart()
    after = w.job(j)
    assert after.state is before.state
    if before.pending_task is not None and \
            before.pending_task.kind is not TaskKind.AGENT:
        assert after.pending_task == before.pending_task
    w.c.replay(j)
    return after


def test_restart_at_each_state_keeps_state_and_replays(world):
    j = world.submit()
    same_after_restart(world, j)                     # s1_analysis
    world.analysis(j)
    same_after_restart(world, j)                     # s1_planning
    world.plan(j)
    same_after_restart(world, j)                     # s1_running
    world.run(j, Q1Status.NOT_REACHED)
    same_after_restart(world, j)                     # planning (repair)
    world.plan(j, "plan-2")
    world.run(j, Q1Status.INCONCLUSIVE, "evidence")
    same_after_restart(world, j)                     # blocked_operator
    world.c.operator(j, "resume")
    world.run(j, Q1Status.REACHED)
    job = same_after_restart(world, j)               # s1_reached
    assert job.state is JobState.S1_REACHED


def test_replay_of_every_job_equals_the_store(make_world):
    w = make_world(approval_required=True)
    a = w.submit()
    w.analysis(a)
    w.plan(a)
    p = w.job(a).pending_task
    w.c.deny(a, p.task_id, "no")
    w.plan(a, "plan-2")
    job = w.job(a)
    w.c.approve(a, job.pending_task.task_id,
                job.harness.review_manifest_sha256, "d1")
    w.registry.put(binding("build-2"))
    w.c.on_registry_changed()
    for j in (job.job_id for job in w.store.jobs()):
        assert w.c.replay(j) == w.job(j)


def test_restart_during_a_run_starts_it_once(world):
    j = world.to_running()
    task = world.job(j).pending_task.task_id
    world.restart()
    world.restart()
    assert world.runner.starts[task] == 1
    assert world.runner.submits[task] == 3
    world.run(j, Q1Status.REACHED)
    assert world.job(j).state is JobState.S1_REACHED
    assert world.runner.started == [task]


def test_crash_after_commit_before_send_starts_once(world):
    j = world.submit()
    world.analysis(j)
    # Commit the plan transition without sending the Runner task.
    job = world.job(j)
    event = ev.AgentSucceeded(task_id=job.pending_task.task_id, attempt=1,
                              output=PlanOutput(plan_ref=sha("plan-1")),
                              model_id="m")
    out = world.c.machine.handle(job, event)
    world.store.commit(job.seq, out.job, Transition(
        job_id=j, seq=out.job.seq, from_state=job.state,
        to_state=out.job.state, event=event.model_dump(mode="json"),
        job_policy_id="p1", at="t", job=out.job))
    task = out.job.pending_task.task_id
    assert world.runner.starts[task] == 0
    world.restart()
    assert world.runner.starts[task] == 1
    world.c.replay(j)


def test_next_runner_task_waits_for_the_cancelled_one(world):
    j = world.to_running()
    old = world.job(j).pending_task.task_id
    world.runner.slow_cancel.add(old)
    world.registry.put(binding("build-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    new = job.pending_task.task_id
    assert job.cancelling_tasks == (old,)
    assert world.runner.starts[new] == 0             # not sent yet
    world.restart()                                  # cancel sent again
    job = world.job(j)
    assert job.cancelling_tasks == ()
    assert world.runner.starts[new] == 1
    assert world.runner.started == [old, new]


def test_poll_sends_the_cancel_again(world):
    j = world.to_running()
    old = world.job(j).pending_task.task_id
    world.runner.slow_cancel.add(old)
    world.registry.put(binding("build-2"))
    world.c.on_registry_changed()
    new = world.job(j).pending_task.task_id
    assert world.runner.starts[new] == 0
    world.c.poll()                                   # cancel sent again
    assert world.job(j).cancelling_tasks == ()
    assert world.runner.cancel_calls[old] == 2
    assert world.runner.started == [old, new]
    world.c.replay(j)


def test_double_abandonment_waits_for_both(world):
    j = world.to_running()
    first = world.job(j).pending_task.task_id
    world.runner.slow_cancel.add(first)
    world.registry.put(binding("build-2"))
    world.c.on_registry_changed()
    second = world.job(j).pending_task.task_id        # never sent
    world.registry.put(binding("build-3"))
    world.c.on_registry_changed()
    job = world.job(j)
    third = job.pending_task.task_id
    # The unsent second task is cancelled before any submit: the Runner
    # records it and a late submit could not start it.
    assert second in world.runner.cancelled
    assert job.cancelling_tasks == (first,)
    assert world.runner.starts[third] == 0
    world.restart()
    assert world.runner.started == [first, third]
    assert world.runner.starts[second] == 0


def test_cancel_before_submit_refuses_the_late_submit(world):
    st = world.runner.cancel("job-x.t9")
    assert (st.state, st.reason) == ("ended_unsealed", "cancelled")
    try:
        world.runner.submit("job-x.t9", RunnerInput(
            job_id="job-x", harness_ref=sha("h"),
            execution_harness_id=sha("e")))
    except SubmitRefused:
        pass
    else:
        raise AssertionError("submit after cancel was accepted")
    assert world.runner.starts["job-x.t9"] == 0


def test_resume_and_rerun_run_again_under_new_task_ids(world):
    j = world.to_running()
    world.run(j, Q1Status.INCONCLUSIVE, "evidence")
    world.c.operator(j, "resume")
    second = world.job(j).pending_task.task_id
    world.run(j, Q1Status.INCONCLUSIVE, "infra")
    third = world.job(j).pending_task.task_id
    assert len(set(world.runner.started)) == 3
    assert world.runner.started[1:] == [second, third]
    assert all(world.runner.starts[t] == 1 for t in world.runner.started)


def test_agent_task_restarts_as_a_new_attempt(world):
    j = world.submit()
    p = world.job(j).pending_task
    world.restart()
    job = world.job(j)
    assert job.pending_task.task_id == p.task_id
    assert job.pending_task.attempt == 2
    assert world.store.attempt(p.task_id, 1).status == "abandoned"
    req = world.agents.requests[-1]
    assert (req.task_id, req.attempt) == (p.task_id, 2)
    assert world.agents.requests[0].model_dump(exclude={"attempt"}) == \
        req.model_dump(exclude={"attempt"})
    # The old attempt finishing late changes nothing.
    world.c.on_agent_result(p.task_id, 1,
                            AnalysisOutput(analysis_ref=sha("late")), "m")
    assert world.job(j).state is JobState.S1_ANALYSIS
    world.c.on_agent_result(p.task_id, 2,
                            AnalysisOutput(analysis_ref=sha("ok")), "m")
    assert world.job(j).state is JobState.S1_PLANNING
    world.c.replay(j)


def test_late_outputs_are_kept_as_artifacts(world):
    j = world.submit()
    p = world.job(j).pending_task
    late = AnalysisOutput(analysis_ref=sha("late"))
    world.c.on_agent_result(p.task_id, 7, late, "m")
    ref = hashlib.sha256(late.model_dump_json().encode()).hexdigest()
    assert world.artifacts.has(ref)
    assert world.job(j).pending_task == p
