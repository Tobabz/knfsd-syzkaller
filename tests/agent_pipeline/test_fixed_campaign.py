"""09 §3.1, #81 D11-D15: the fixed campaign runs the Q1 harness again,
attempt by attempt, up to fixed_parallelism at a time; its crashes are
replayed and reviewed."""

from __future__ import annotations

import pytest

from agent_pipeline.contracts import Q1Status
from agent_pipeline.controller.records import JobState, TaskKind

from .fakes import World, binding
from .test_crash_findings import KASAN, KASAN_AGAIN, WARNING, finish, \
    replays, report


def fixed_world(tmp_path, **kw):
    kw = {"campaign_mode": "fixed", "fixed_attempts": 6,
          "fixed_parallelism": 2, "fixed_replays": 2,
          "fixed_not_reached_limit": 3, **kw}
    return World(tmp_path, **kw)


@pytest.fixture
def w(tmp_path):
    return fixed_world(tmp_path)


def reach(w) -> str:
    j = w.to_running()
    w.run(j, Q1Status.REACHED, name="q1")
    return j


def in_flight(w, j) -> list[str]:
    return [a.task_id for a in w.job(j).fixed.in_flight]


def attempt(w, j, status=Q1Status.REACHED, reason=None, crash=None,
            index=0) -> str:
    """Seal the `index`th attempt in flight."""
    return finish(w, j, in_flight(w, j)[index], status, reason, crash)


def check_replay(w, j):
    assert w.c.replay(j) == w.job(j)


# ------------------------------------------------------------ attempts

def test_reaching_starts_the_campaign_with_p_attempts(w):
    j = reach(w)
    job = w.job(j)
    assert job.state is JobState.S1_FIXED and job.pending_task is None
    k = job.fixed
    assert k.harness_ref == job.harness.harness_ref
    assert [a.attempt for a in k.in_flight] == [1, 2] and k.sent == 2
    # Each attempt is a Runner task of its own, on the Q1 harness.
    for a in k.in_flight:
        assert w.runner.starts[a.task_id] == 1
        assert w.runner.tasks[a.task_id]["input"].harness_ref == \
            job.harness.harness_ref
    check_replay(w, j)


def test_n_attempts_without_a_crash_end_in_s1_reached(w):
    j = reach(w)
    for _ in range(6):
        attempt(w, j)
    job = w.job(j)
    assert (job.state, job.state_reason) == (JobState.S1_REACHED,
                                             "fixed_no_signal")
    k = job.fixed
    assert (k.sent, k.reached, k.not_reached, k.crashes) == (6, 6, 0, 0)
    assert k.in_flight == ()
    # The Q1 package of the run that reached is kept.
    assert job.stage2_input.bundle_ref == "q1"
    check_replay(w, j)
    # Mutation can still start from here (#81 D13).
    w.c.start_stage2(j)
    assert w.job(j).state is JobState.S2_STRATEGY


def test_one_attempt(tmp_path):
    w = fixed_world(tmp_path, fixed_attempts=1, fixed_parallelism=4)
    j = reach(w)
    assert len(in_flight(w, j)) == 1
    attempt(w, j, Q1Status.NOT_REACHED)
    job = w.job(j)
    assert (job.state, job.state_reason) == (JobState.S1_REACHED,
                                             "fixed_no_signal")
    assert job.fixed.not_reached == 1


def test_attempts_finish_in_any_order(w):
    j = reach(w)
    first, second = in_flight(w, j)
    attempt(w, j, index=1)
    assert in_flight(w, j)[0] == first
    assert [a.attempt for a in w.job(j).fixed.in_flight] == [1, 3]
    check_replay(w, j)


def test_a_final_status_is_counted_once(w):
    """A lease that ended and ran the task again gives one final status;
    polling it again, or after a restart, counts nothing more."""
    j = reach(w)
    task = in_flight(w, j)[0]
    attempt(w, j)
    w.c.poll()
    w.restart()
    w.c.poll()
    job = w.job(j)
    assert job.fixed.reached == 1
    assert task not in in_flight(w, j)
    assert all(w.runner.starts[t] == 1 for t in w.runner.starts)
    check_replay(w, j)


def test_a_restart_sends_the_attempts_in_flight_again(w):
    j = reach(w)
    tasks = in_flight(w, j)
    w.restart()
    for t in tasks:
        assert w.runner.submits[t] >= 2 and w.runner.starts[t] == 1
    attempt(w, j)
    assert w.job(j).fixed.reached == 1


def test_an_infra_attempt_is_sent_again_under_its_number(w):
    j = reach(w)
    attempt(w, j, Q1Status.INCONCLUSIVE, "infra")
    job = w.job(j)
    assert [a.attempt for a in job.fixed.in_flight] == [2, 1]
    assert job.counters.runtime_retry == 1
    assert job.fixed.counted == 0
    w.runner.finish(in_flight(w, j)[0])         # ended unsealed
    w.c.poll()
    job = w.job(j)
    assert job.counters.runtime_retry == 2
    assert sorted(a.attempt for a in job.fixed.in_flight) == [1, 2]
    attempt(w, j)
    assert w.job(j).counters.runtime_retry == 0
    check_replay(w, j)


def test_infra_attempts_stop_at_runtime_retry(w):
    j = reach(w)
    limit = w.store.policy("p1").runtime_retry_limit
    for _ in range(limit):
        attempt(w, j, Q1Status.INCONCLUSIVE, "infra")
    last = in_flight(w, j)
    attempt(w, j, Q1Status.INCONCLUSIVE, "infra")
    job = w.job(j)
    assert (job.state, job.state_reason) == (JobState.BLOCKED_OPERATOR,
                                             "runtime_retry_exhausted")
    assert job.fixed.in_flight == ()
    assert all(w.runner.cancel_calls[t] for t in last[1:])
    w.c.operator(j, "resume")
    job = w.job(j)
    assert job.state is JobState.S1_FIXED
    assert sorted(a.attempt for a in job.fixed.in_flight) == [1, 2]
    check_replay(w, j)


def test_consecutive_not_reached_attempts_stop_the_campaign(tmp_path):
    w = fixed_world(tmp_path, fixed_attempts=10)
    j = reach(w)
    attempt(w, j, Q1Status.NOT_REACHED)
    attempt(w, j, Q1Status.NOT_REACHED)
    attempt(w, j, Q1Status.REACHED)                 # resets the run
    for _ in range(3):
        attempt(w, j, Q1Status.NOT_REACHED)
    job = w.job(j)
    assert (job.state, job.state_reason) == (JobState.BLOCKED_OPERATOR,
                                             "fixed_not_reaching")
    assert job.fixed.consecutive_not_reached == 3
    assert job.fixed.in_flight == ()
    w.c.operator(j, "resume")
    job = w.job(j)
    assert job.state is JobState.S1_FIXED
    assert job.fixed.consecutive_not_reached == 0
    assert job.fixed.not_reached == 5
    check_replay(w, j)


def test_an_evidence_verdict_blocks_and_resumes_the_campaign(w):
    j = reach(w)
    attempt(w, j)
    attempt(w, j, Q1Status.INCONCLUSIVE, "evidence")
    job = w.job(j)
    assert (job.state, job.state_reason) == (JobState.BLOCKED_OPERATOR,
                                             "q1_evidence")
    w.c.operator(j, "resume")
    job = w.job(j)
    assert job.state is JobState.S1_FIXED and job.fixed.reached == 1
    check_replay(w, j)


# ------------------------------------------------------------ crashes

def test_the_first_crash_stops_new_attempts_then_is_replayed(w):
    j = reach(w)
    attempt(w, j, crash=report(KASAN))
    job = w.job(j)
    assert job.state is JobState.S1_FIXED
    assert len(job.fixed.in_flight) == 1        # no new attempt
    (f,) = job.crash_findings
    assert (f.source, f.campaign_id, f.attempt) == (
        "fixed", job.fixed.campaign_id, 1)
    # D11: the attempt in flight finishes and counts; its crash joins.
    attempt(w, j, crash=report(WARNING))
    job = w.job(j)
    assert job.state is JobState.S1_REPLAYING
    assert job.fixed.crashes == 2
    replays(w, j, report(KASAN_AGAIN), None, None, report(WARNING))
    job = w.job(j)
    assert (job.state, job.state_reason) == (JobState.CRASH_REVIEW,
                                             "fixed_crash")
    assert [(f.reproduced, f.replays) for f in job.crash_findings] == [
        (1, 2), (1, 2)]
    check_replay(w, j)
    # resume goes on with the same campaign.
    w.c.operator(j, "resume")
    job = w.job(j)
    assert job.state is JobState.S1_FIXED
    assert [a.attempt for a in job.fixed.in_flight] == [3, 4]
    for _ in range(4):
        attempt(w, j)
    job = w.job(j)
    assert (job.state, job.state_reason) == (JobState.S1_REACHED,
                                             "fixed_complete")
    assert job.fixed.counted == 6
    check_replay(w, j)


def test_a_crash_that_never_reproduces_goes_to_review(w):
    j = reach(w)
    attempt(w, j, crash=report(KASAN))
    attempt(w, j)
    replays(w, j, None, None)
    job = w.job(j)
    assert job.state is JobState.CRASH_REVIEW
    f = job.crash_findings[0]
    assert (f.reproduced, f.replays, f.review) == (0, 2, "queued")
    w.c.operator(j, "close")
    assert w.job(j).state_reason == "crash_reported"


def test_a_crash_replayed_already_does_not_stop_the_campaign(w):
    j = reach(w)
    attempt(w, j, crash=report(WARNING))
    attempt(w, j)
    replays(w, j, None, None)
    w.c.operator(j, "resume")
    attempt(w, j, crash=report(WARNING))
    job = w.job(j)
    assert job.state is JobState.S1_FIXED
    assert len(job.fixed.in_flight) == 2
    assert job.crash_findings[-1].replay == "duplicate"
    check_replay(w, j)


def test_a_crash_with_any_verdict_is_a_crash(w):
    j = reach(w)
    attempt(w, j, Q1Status.INCONCLUSIVE, "infra", crash=report(KASAN))
    job = w.job(j)
    assert job.fixed.crashes == 1 and job.fixed.retry == ()
    assert job.counters.runtime_retry == 0


# ------------------------------------------------------------ starting

def test_an_operator_starts_a_fixed_campaign_of_an_evidence_only_job(
        tmp_path):
    w = fixed_world(tmp_path, campaign_mode="none")
    j = reach(w)
    job = w.job(j)
    assert (job.state, job.state_reason) == (JobState.S1_REACHED,
                                             "evidence_only")
    w.c.operator(j, "start_fixed")
    job = w.job(j)
    assert job.state is JobState.S1_FIXED and len(job.fixed.in_flight) == 2
    check_replay(w, j)


def test_start_fixed_is_refused_outside_s1_reached(w):
    j = w.to_running()
    assert w.c.operator(j, "start_fixed") is None


def test_closing_cancels_every_attempt(w):
    j = reach(w)
    tasks = in_flight(w, j)
    w.c.operator(j, "close")
    job = w.job(j)
    assert job.state is JobState.CLOSED and job.fixed.in_flight == ()
    assert all(w.runner.cancel_calls[t] for t in tasks)
    check_replay(w, j)


def test_a_binding_change_to_another_harness_ends_the_campaign(w):
    j = reach(w)
    tasks = in_flight(w, j)
    w.registry.put(binding(execution="build-2"))
    w.c.on_registry_changed()
    job = w.job(j)
    assert all(w.runner.cancel_calls[t] for t in tasks)
    assert job.state is not JobState.S1_FIXED
    if job.state is JobState.S1_RUNNING:
        assert job.fixed is None
        assert job.pending_task.kind is TaskKind.RUNNER
    check_replay(w, j)
