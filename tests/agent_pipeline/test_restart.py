"""Oracles 4 and 5 (09 검증 오라클): restart and duplicate execution.

A restart is a new Controller on the same store and the same Runner, as
after the Controller process died; recover() then runs.
"""

import hashlib
import json

import pytest

from agent_pipeline.contracts import (AnalysisOutput, GapClass, GapRef,
                                      PlanOutput, Q1Status)
from agent_pipeline.controller import events as ev
from agent_pipeline.controller.records import (JobState, TargetKind, TaskKind,
                                               Transition)
from agent_pipeline.controller.service import ReplayMismatch
from agent_pipeline.controller.tasks import (RunnerInput, SubmitRefused,
                                             legacy_runner_input_digest,
                                             runner_input_digest)

from .fakes import VERSIONS, binding, sha


def remove_materialized_hcap_provenance(w, job_id):
    """Rewrite one database as records emitted before the field existed."""

    row = w.store.db.execute(
        "SELECT body FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    body = json.loads(row[0])
    body["harness"].pop("hcap_revision")
    w.store.db.execute(
        "UPDATE jobs SET body = ? WHERE job_id = ?",
        (json.dumps(body, sort_keys=True), job_id))

    rows = w.store.db.execute(
        "SELECT seq, body FROM transitions WHERE job_id = ? ORDER BY seq",
        (job_id,)).fetchall()
    for seq, raw in rows:
        transition = json.loads(raw)
        harness = transition["job"].get("harness")
        if harness is None:
            continue
        harness.pop("hcap_revision", None)
        w.store.db.execute(
            "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = ?",
            (json.dumps(transition, sort_keys=True), job_id, seq))


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


def rewrite_runner_digest(world, job_id, digest=None):
    """Rewrite one pending Runner task as a persisted historical snapshot."""

    job = world.job(job_id)
    pending = job.pending_task
    assert pending is not None and pending.kind is TaskKind.RUNNER
    task_input = RunnerInput(
        job_id=job_id, harness_ref=job.harness.harness_ref,
        execution_harness_id=job.harness.execution_harness_id)
    digest = digest or legacy_runner_input_digest(task_input)

    def historical(snapshot):
        task = snapshot.pending_task
        if task is None or task.task_id != pending.task_id:
            return snapshot
        return snapshot.model_copy(update={
            "pending_task": task.model_copy(update={"input_digest": digest}),
        })

    current = historical(job)
    world.store.db.execute(
        "UPDATE jobs SET body = ? WHERE job_id = ?",
        (current.model_dump_json(), job_id))
    for transition in world.store.transitions(job_id):
        changed = historical(transition.job)
        if changed == transition.job:
            continue
        replacement = transition.model_copy(update={"job": changed})
        world.store.db.execute(
            "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = ?",
            (replacement.model_dump_json(), job_id, transition.seq))
    return pending, task_input, digest


def migration_events(world, job_id):
    return [transition for transition in world.store.transitions(job_id)
            if transition.event["type"] ==
            "runner_input_digest_migrated"]


def test_replay_authenticates_historical_runner_digest(world):
    job_id = world.to_running()
    pending, _, legacy = rewrite_runner_digest(world, job_id)

    replayed = world.c.replay(job_id)

    assert replayed.pending_task.task_id == pending.task_id
    assert replayed.pending_task.input_digest == legacy
    assert migration_events(world, job_id) == []


@pytest.mark.parametrize("operation", ["poll", "recover"])
def test_pending_legacy_runner_digest_is_migrated_before_dispatch(
        world, operation):
    job_id = world.to_running()
    pending, task_input, legacy = rewrite_runner_digest(world, job_id)
    before_submits = world.runner.submits[pending.task_id]

    assert getattr(world.c, operation)() == []

    job = world.job(job_id)
    assert job.pending_task.input_digest == runner_input_digest(task_input)
    assert job.pending_task.input_digest != legacy
    assert world.runner.submits[pending.task_id] == before_submits + 1
    events = migration_events(world, job_id)
    assert len(events) == 1
    assert events[0].event == {
        "type": "runner_input_digest_migrated",
        "task_id": pending.task_id,
        "legacy_digest": legacy,
        "canonical_digest": runner_input_digest(task_input),
    }
    assert world.c.replay(job_id) == job


def test_runner_digest_migration_is_idempotent(world):
    job_id = world.to_running()
    pending, _, _ = rewrite_runner_digest(world, job_id)

    assert world.c.poll() == []
    migrated = world.job(job_id)
    transition_count = len(world.store.transitions(job_id))
    submit_count = world.runner.submits[pending.task_id]
    assert world.c.poll() == []

    assert world.job(job_id) == migrated
    assert len(world.store.transitions(job_id)) == transition_count
    assert len(migration_events(world, job_id)) == 1
    # A running task is polled by status and is not submitted again.
    assert world.runner.submits[pending.task_id] == submit_count


def test_forged_runner_digest_is_refused_before_runner_call(world):
    job_id = world.to_running()
    pending, _, forged = rewrite_runner_digest(
        world, job_id, digest="0" * 64)
    before_submits = world.runner.submits[pending.task_id]
    before_seq = world.job(job_id).seq

    failures = world.c.poll()

    assert len(failures) == 1
    assert failures[0].effect == "pending_task"
    assert "unauthenticated input digest" in failures[0].error
    assert world.runner.submits[pending.task_id] == before_submits
    assert world.job(job_id).seq == before_seq
    assert world.job(job_id).pending_task.input_digest == forged
    assert migration_events(world, job_id) == []
    with pytest.raises(ReplayMismatch):
        world.c.replay(job_id)
    world.expected_failures += 1


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


def test_recover_migrates_legacy_materialized_without_hcap_provenance(world):
    job_id = world.to_running()
    before = world.job(job_id)
    old_task = before.pending_task.task_id
    remove_materialized_hcap_provenance(world, job_id)
    legacy = world.job(job_id)
    assert legacy.harness.hcap_revision is None
    assert "hcap_revision" not in legacy.harness.model_fields_set

    world.restart()

    current = world.job(job_id)
    assert current.state is JobState.S1_RUNNING
    assert current.harness.hcap_revision == current.binding.hcap_revision
    assert current.pending_task.task_id != old_task
    assert world.runner.cancel_calls[old_task] == 1
    assert world.c.replay(job_id) == current


def test_recover_finishes_same_binding_hcap_mismatch_migration(world):
    job_id = world.to_running()
    before = world.job(job_id)
    old_task = before.pending_task.task_id
    replacement = binding(hcap="hcap-2")
    world.registry.put(replacement)
    world.materializer.authority_changed.add(replacement.hcap_revision)

    # Reproduce a crash after the historical HCAP-only transition committed
    # but before a flagged authority-rematerialization event was available.
    world.c._apply(job_id, ev.BindingChanged(
        binding=replacement, judge_versions=before.judge_versions))
    stale = world.job(job_id)
    assert stale.binding == replacement
    assert stale.harness.hcap_revision == before.binding.hcap_revision
    assert stale.pending_task.task_id == old_task

    # Stored events from the affected implementation predate the flag.
    transition = world.store.transitions(job_id)[-1]
    raw = json.loads(transition.model_dump_json())
    assert raw["event"].pop("rematerialize_authority") is False
    world.store.db.execute(
        "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = ?",
        (json.dumps(raw, sort_keys=True), job_id, transition.seq))

    world.restart()

    current = world.job(job_id)
    assert current.state is JobState.S1_RUNNING
    assert current.harness.hcap_revision == replacement.hcap_revision
    assert current.harness.harness_ref != before.harness.harness_ref
    assert current.pending_task.task_id != old_task
    assert world.runner.cancel_calls[old_task] == 1
    assert world.c.replay(job_id) == current


def test_recover_keeps_harness_whose_authority_is_unchanged(world):
    job_id = world.to_running()
    before = world.job(job_id)
    old_task = before.pending_task.task_id
    replacement = binding(hcap="hcap-2")
    world.registry.put(replacement)
    world.c._apply(job_id, ev.BindingChanged(
        binding=replacement, judge_versions=before.judge_versions))
    transition = world.store.transitions(job_id)[-1]
    raw = json.loads(transition.model_dump_json())
    for key in ("rematerialize_authority", "harness_authority_current"):
        raw["event"].pop(key)
    world.store.db.execute(
        "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = ?",
        (json.dumps(raw, sort_keys=True), job_id, transition.seq))

    world.restart()

    current = world.job(job_id)
    assert current.state is JobState.S1_RUNNING
    assert current.harness.harness_ref == before.harness.harness_ref
    assert current.harness.authority_hcap_revision == \
        replacement.hcap_revision
    assert current.pending_task.task_id == old_task
    assert old_task not in world.runner.cancel_calls
    world.restart()
    assert world.job(job_id).seq == current.seq
    assert world.c.replay(job_id) == current


def test_flagless_replay_combines_legacy_hcap_and_runner_digest(world):
    job_id = world.to_running()
    gap = GapRef(
        gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
        missing_capability_id="remote_kcov.context.softirq")
    bundle = world.run(
        job_id, Q1Status.INCONCLUSIVE, "unsupported_attribution", gap)
    blocked = world.job(job_id)
    world.c._apply(job_id, ev.IssueChanged(
        gap=gap, status="resolved", resolution="historical"))
    versions = VERSIONS.model_copy(update={"judge_profile_id": "jp-2"})
    world.judge.add(
        bundle, blocked.binding.execution_harness_id,
        blocked.candidate.candidate_id, Q1Status.REACHED, profile="jp-2")
    historical = ev.BindingChanged(
        binding=blocked.binding, judge_versions=versions)
    world.c._apply(job_id, historical)
    old_task = world.job(job_id).pending_task.task_id

    transition = world.store.transitions(job_id)[-1]
    raw = json.loads(transition.model_dump_json())
    assert raw["event"].pop("rematerialize_authority") is False
    world.store.db.execute(
        "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = ?",
        (json.dumps(raw, sort_keys=True), job_id, transition.seq))
    remove_materialized_hcap_provenance(world, job_id)
    rewrite_runner_digest(world, job_id)
    legacy = world.job(job_id)

    assert world.c.replay(job_id) == legacy

    world.restart()
    current = world.job(job_id)
    assert current.harness.hcap_revision == current.binding.hcap_revision
    assert current.pending_task.task_id != old_task
    assert world.runner.cancel_calls[old_task] == 1
    assert world.c.replay(job_id) == current


def test_flagless_failed_revalidation_preserves_waiting_snapshot(world):
    """A pre-migration HCAP event keeps its inert harness on replay."""

    job_id = world.to_running()
    world.run(job_id, Q1Status.INCONCLUSIVE, "evidence")
    before = world.job(job_id)
    assert before.state is JobState.BLOCKED_OPERATOR

    replacement = binding(hcap="hcap-2")
    world.hcap.violations[(sha("plan-1"), "hcap-2")] = \
        ("HCAP-02 removed",)
    historical = ev.BindingChanged(
        binding=replacement, judge_versions=before.judge_versions)
    assert "rematerialize_authority" not in historical.model_fields_set
    world.c._apply(job_id, historical)

    stored = world.job(job_id)
    assert stored.state is before.state
    assert stored.harness == before.harness
    assert stored.resume_point.kind is TargetKind.PLANNING

    transition = world.store.transitions(job_id)[-1]
    raw = json.loads(transition.model_dump_json())
    assert raw["event"].pop("rematerialize_authority") is False
    world.store.db.execute(
        "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = ?",
        (json.dumps(raw, sort_keys=True), job_id, transition.seq))

    assert world.c.replay(job_id) == stored


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


def test_adopted_judge_versions_survive_restart(world):
    """09 §5: on_judge_versions() is stored, so a restart with the
    configured default does not re-judge an adopted REACHED back."""
    j = world.to_running()
    gap = GapRef(gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
                 missing_capability_id="remote_kcov.context.softirq")
    bundle = world.run(j, Q1Status.INCONCLUSIVE, "unsupported_attribution",
                       gap)
    job = world.job(j)
    adopted = VERSIONS.model_copy(update={"judge_profile_id": "jp-2"})
    world.judge.add(bundle, job.binding.execution_harness_id,
                    job.candidate.candidate_id, Q1Status.REACHED,
                    profile="jp-2")
    world.c.on_judge_versions(adopted)
    world.c._apply(j, ev.IssueChanged(gap=gap, status="resolved"))
    assert world.job(j).state is JobState.RETRY_PENDING

    world.restart()

    assert world.c.judge_versions == adopted
    job = world.job(j)
    assert job.state is JobState.S1_REACHED
    assert job.judge_versions == adopted


def test_historical_same_verdict_rejudge_replays(world):
    """A JudgeVersionsChanged stored before `consume_same_verdict` existed
    changed only the versions when the decision was the same."""
    j = world.to_running()
    bundle = world.run(j, Q1Status.REACHED)
    job = world.job(j)
    adopted = VERSIONS.model_copy(update={"judge_profile_id": "jp-2"})
    world.judge.add(bundle, job.binding.execution_harness_id,
                    job.candidate.candidate_id, Q1Status.REACHED,
                    profile="jp-2")
    event = ev.JudgeVersionsChanged(judge_versions=adopted)
    raw = event.model_dump(mode="json")
    raw.pop("consume_same_verdict")
    historical = job.model_copy(update={"judge_versions": adopted,
                                        "seq": job.seq + 1})
    world.store.commit(job.seq, historical, Transition(
        job_id=j, seq=historical.seq, from_state=job.state,
        to_state=historical.state, reason="judge_versions_changed",
        event=raw, job_policy_id=job.job_policy_id,
        at="2026-10-01T00:00:00+00:00", job=historical))
    assert world.c.replay(j) == historical

    current = world.c.machine.handle(job, ev.JudgeVersionsChanged(
        judge_versions=adopted, consume_same_verdict=True)).job
    assert current.last_verdict.result.judge_profile_id == "jp-2"
    assert current.stage2_input.q1_verdict_id != \
        job.stage2_input.q1_verdict_id


def test_cancel_without_confirmed_cleanup_is_tracked_for_the_operator(world):
    """09 §8: a cancel whose execution was not confirmed stopped is not a
    settled cancel. The task stays on the job and the operator decides."""
    j = world.to_running()
    old = world.job(j).pending_task.task_id
    world.runner.unconfirmed.add(old)
    world.registry.put(binding("build-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.cancelling_tasks == ()
    assert job.uncleaned_tasks == (old,)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == "execution_cleanup"
    assert world.c.replay(j) == job
    world.restart()
    assert world.job(j).uncleaned_tasks == (old,)
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.uncleaned_tasks == ()
    assert job.state is JobState.S1_RUNNING
    assert world.runner.starts[job.pending_task.task_id] == 1
    assert world.c.replay(j) == job


def test_operator_cancel_without_confirmed_cleanup_keeps_the_task(world):
    j = world.to_running()
    running = world.job(j).pending_task.task_id
    world.runner.unconfirmed.add(running)
    world.c.operator(j, "cancel")
    job = world.job(j)
    assert job.state is JobState.CLOSED and job.state_reason == "cancelled"
    assert job.cancelling_tasks == ()
    assert job.uncleaned_tasks == (running,)
    assert world.c.replay(j) == job


def test_runner_end_without_confirmed_cleanup_is_not_a_retry(world):
    j = world.to_running()
    p = world.job(j).pending_task
    before = world.job(j).counters
    world.runner.finish(p.task_id, reason="cleanup_unconfirmed")
    world.c.poll()
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == "execution_cleanup"
    assert job.uncleaned_tasks == (p.task_id,)
    assert job.counters.runtime_retry == before.runtime_retry
    assert world.c.replay(j) == job


def test_waiting_job_still_needs_cleanup_confirmed_before_running(world):
    """09 §8: a job already waiting for another reason when its cancel
    settles without confirmed cleanup must not dispatch Runner work when
    that wait ends; the operator confirms the cleanup first."""
    j = world.to_running()
    old = world.job(j).pending_task.task_id
    world.runner.slow_cancel.add(old)
    world.runner.unconfirmed.add(old)
    world.hcap.corrupt.add("hcap-2")
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.state_reason == "host_authority"
    assert job.cancelling_tasks == (old,)

    world.c.poll()                      # the cancel settles, unconfirmed
    job = world.job(j)
    assert job.cancelling_tasks == ()
    assert job.uncleaned_tasks == (old,)
    assert job.state_reason == "host_authority"
    assert world.c.replay(j) == job

    # Replay re-checks the catalog, so it is not compared after the fix.
    world.hcap.corrupt.discard("hcap-2")
    world.restart()
    started = list(world.runner.started)
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == "execution_cleanup"
    assert world.runner.started == started

    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.uncleaned_tasks == ()
    assert job.state is JobState.S1_RUNNING
    assert world.runner.started == started + [job.pending_task.task_id]


def test_late_cleanup_report_is_tracked_after_the_task_settled(world):
    """A not-confirmed-stopped report that arrives after the task's final
    status still reaches the job, and is acknowledged only once recorded."""
    j = world.to_running()
    old = world.job(j).pending_task.task_id
    world.registry.put(binding("build-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.cancelling_tasks == ()
    assert job.uncleaned_tasks == ()
    assert job.state is JobState.S1_RUNNING
    replacement = job.pending_task.task_id

    world.runner.late_reports.add((old, 1))
    world.restart()
    job = world.job(j)
    assert job.uncleaned_tasks == (old,)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == "execution_cleanup"
    assert job.pending_task is None
    assert world.runner.cancel_calls[replacement] >= 1
    assert world.runner.late_reports == set()
    assert world.c.replay(j) == job
    world.c.poll()                      # acknowledged: not applied again
    assert world.job(j) == job


def test_late_cleanup_report_resent_after_failed_ack_applies_once(world):
    """A report recorded on the job but not acknowledged is sent again; it
    must not undo the operator's later cleanup confirmation."""
    j = world.to_running()
    old = world.job(j).pending_task.task_id
    world.registry.put(binding("build-2"))
    world.c.on_registry_changed()
    world.runner.late_reports.add((old, 1))
    world.runner.fail_ack = True
    assert [f.effect for f in world.c.poll()] == [f"cleanup:{old}:1"]
    world.expected_failures = 1
    job = world.job(j)
    assert job.state_reason == "execution_cleanup"
    assert world.runner.late_reports == {(old, 1)}

    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.uncleaned_tasks == ()
    assert job.state is JobState.S1_RUNNING
    resumed = job.pending_task.task_id

    world.runner.fail_ack = False
    world.restart()
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.pending_task.task_id == resumed
    assert world.runner.cancel_calls[resumed] == 0
    assert world.runner.late_reports == set()
    assert world.c.replay(j) == job
