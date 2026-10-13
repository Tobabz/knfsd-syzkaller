"""09 §8: a side effect sent after commit whose answer was lost, or that
failed, is sent again by poll() or recover() until it is recorded."""

import pytest

from agent_pipeline.contracts import Q1Status
from agent_pipeline.controller.records import JobState

from .fakes import OTHER_COMMIT, binding, function_submission


class Down(ConnectionError):
    pass


def fail_once(obj, name):
    real = getattr(obj, name)
    calls = []

    def flaky(*a, **kw):
        calls.append(a)
        if len(calls) == 1:
            raise Down(name)
        return real(*a, **kw)
    setattr(obj, name, flaky)
    return calls


def test_gap_issue_is_linked_after_a_failed_open(world):
    fail_once(world.issues, "open_or_link")
    with pytest.raises(Down):
        world.submit(function_submission(commit=OTHER_COMMIT))
    (job,) = world.store.jobs()
    assert job.state is JobState.BLOCKED_HARNESS_GAP
    assert world.store.issue_ref(job.gap) is None      # committed, unlinked
    world.c.poll()
    assert world.store.issue_ref(job.gap) == world.issues.issues[job.gap]
    assert world.issues.links[job.gap] == [job.job_id]
    world.c.poll()                                     # linked once
    assert world.issues.links[job.gap] == [job.job_id]


def test_gap_issue_is_linked_on_recover(world):
    fail_once(world.issues, "open_or_link")
    with pytest.raises(Down):
        world.submit(function_submission(commit=OTHER_COMMIT))
    (job,) = world.store.jobs()
    world.restart()
    assert world.issues.links[job.gap] == [job.job_id]


def test_a_second_job_on_a_linked_gap_is_linked_too(world):
    a = world.submit(function_submission(commit=OTHER_COMMIT))
    fail_once(world.issues, "open_or_link")
    with pytest.raises(Down):
        world.submit(function_submission(commit=OTHER_COMMIT))
    gap = world.job(a).gap
    assert world.store.issue_ref(gap) is not None      # a's link
    world.c.poll()
    assert len(world.issues.links[gap]) == 2


def test_failed_first_submit_is_sent_again_with_its_task_id(world):
    j = world.submit()
    world.analysis(j)
    fail_once(world.runner, "submit")
    with pytest.raises(Down):
        world.plan(j)
    job = world.job(j)
    task = job.pending_task.task_id
    assert job.state is JobState.S1_RUNNING
    assert world.runner.starts[task] == 0
    world.c.poll()
    assert world.runner.starts[task] == 1
    assert world.runner.tasks[task]["input"].execution_harness_id == \
        binding().execution_harness_id
    world.c.poll()                                     # running: no resend
    assert world.runner.submits[task] == 1
    world.run(j, Q1Status.REACHED)
    assert world.job(j).state is JobState.S1_REACHED
    world.c.replay(j)


def test_lost_cancel_answer_is_settled_by_poll(world):
    j = world.to_running()
    old = world.job(j).pending_task.task_id
    real = world.runner.cancel

    def cancel_then_drop(task_id):
        real(task_id)                       # the Runner did cancel it
        raise Down("cancel")
    world.runner.cancel = cancel_then_drop
    world.registry.put(binding("build-2"))
    with pytest.raises(Down):
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
