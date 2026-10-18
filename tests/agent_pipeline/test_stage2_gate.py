"""Stage 2 after the Compiler: the baseline-with-rules gate, the campaign,
replay and crash review (01 §3, §12; 09 §4-§6, §8), including campaign
evidence that arrives after the campaign stopped.  Fake judges and Runner;
no LLM, no VM."""

from __future__ import annotations

import pytest

from agent_pipeline.contracts import (GapClass, GapRef, Q1Status,
                                      RuleSetOutput)
from agent_pipeline.controller.records import (BlockedReason, JobState,
                                               RepairCause, RunnerInput,
                                               Target, TargetKind)
from agent_pipeline.controller.tasks import runner_input_digest

from .fakes import FakeCompiler, FakeStage2, binding, sha
from .test_stage2_strategy import reached

BASE = ("forge-stateid", "applied", True)


def stage2(w) -> FakeStage2:
    w.compiler = FakeCompiler()
    w.c.machine.env.compiler = w.compiler
    w.stage2 = FakeStage2()
    w.c.machine.env.stage2 = w.stage2
    return w.stage2


def in_gate(w) -> str:
    stage2(w)
    job_id = reached(w)
    w.c.start_stage2(job_id)
    w.agent_ok(job_id, RuleSetOutput(rule_set_ref=sha("rules-1")))
    assert w.job(job_id).state is JobState.S2_GATE
    return job_id


def pending(w, job_id):
    p = w.job(job_id).pending_task
    assert p is not None, w.job(job_id)
    return p


def gate(w, job_id, *reps, n=None) -> list[str]:
    """Finish the gate task with one sealed bundle per repetition.  Each
    repetition is (q1 status, q1 reason, intents[, gap])."""
    j = w.job(job_id)
    p = pending(w, job_id)
    names = []
    for i, rep in enumerate(reps):
        status, reason, intents, *gap = rep
        name = f"gate-{p.task_id}-{i}"
        w.stage2.gates[name] = {
            "candidate_id": j.candidate.candidate_id,
            "harness_id": j.binding.execution_harness_id,
            "status": status, "reason": reason, "intents": intents,
            "gap": gap[0] if gap else None, "ambient": ()}
        names.append(name)
    for name in names[:-1]:
        w.runner.seal(p.task_id, name)
    w.runner.finish(p.task_id, bundle=names[-1])
    w.c.poll()
    return names


def passed(w, job_id):
    gate(w, job_id, (Q1Status.REACHED, None, [BASE]))
    assert w.job(job_id).state is JobState.S2_CAMPAIGN


def in_campaign(w) -> str:
    job_id = in_gate(w)
    passed(w, job_id)
    return job_id


def segment(w, job_id, q2="not_observed", applied=(), executions=10,
            reached_gens=10, h_applied=0, h_not=0, h_inc=0, task_id=None,
            name=None, poll=True) -> str:
    """Seal one campaign bundle on the running (or given) task."""
    task_id = task_id or pending(w, job_id).task_id
    name = name or f"seg-{task_id}-{len(w.runner.tasks[task_id]['bundles'])}"
    w.stage2.segments[name] = dict(
        q2_status=q2, crash_window_applied=tuple(applied),
        executions=executions, reached_generations=reached_gens,
        hypothesis_applied=h_applied, hypothesis_not_applied=h_not,
        hypothesis_inconclusive=h_inc)
    w.runner.seal(task_id, name)
    if poll:
        w.c.poll()
    return name


def replay(w, job_id, status="replay_equivalent") -> str:
    p = pending(w, job_id)
    name = f"replay-{p.task_id}"
    w.stage2.replays[name] = (status, None)
    w.runner.finish(p.task_id, bundle=name)
    w.c.poll()
    return name


def same(w, job_id):
    assert w.c.replay(job_id) == w.job(job_id)


# ---------------------------------------------------------------- inputs


def test_stage1_runner_input_encoding_is_unchanged():
    r = RunnerInput(job_id="j", harness_ref="h", execution_harness_id="e")
    assert r.model_dump(mode="json") == {
        "job_id": "j", "harness_ref": "h", "execution_harness_id": "e"}
    assert r.model_dump_json() == \
        '{"job_id":"j","harness_ref":"h","execution_harness_id":"e"}'
    g = RunnerInput(job_id="j", harness_ref="h", execution_harness_id="e",
                    step="gate", compiled_ref="c", gate_repetitions=2)
    assert RunnerInput.model_validate_json(g.model_dump_json()) == g
    assert runner_input_digest(g) != runner_input_digest(r)


def test_without_a_stage2_backend_the_compiled_set_waits(world):
    world.compiler = FakeCompiler()
    world.c.machine.env.compiler = world.compiler
    job_id = reached(world)
    world.c.start_stage2(job_id)
    world.agent_ok(job_id, RuleSetOutput(rule_set_ref=sha("rules-1")))
    j = world.job(job_id)
    assert j.state_reason == BlockedReason.STAGE2_GATE_UNAVAILABLE.value
    # The backend is configured: resume compiles again and runs the gate.
    world.stage2 = FakeStage2()
    world.c.machine.env.stage2 = world.stage2
    world.c.operator(job_id, "resume")
    assert world.job(job_id).state is JobState.S2_GATE
    # Like a newly configured Compiler, a newly configured backend changes
    # what the earlier compile transition computes: replay needs the
    # configuration the transitions were made with.


# ---------------------------------------------------------------- gate


def test_compiled_set_enters_the_gate_with_its_rules(make_world):
    w = make_world(gate_repetitions=2)
    job_id = in_gate(w)
    j = w.job(job_id)
    p = j.pending_task
    assert p.runner_input == RunnerInput(
        job_id=job_id, harness_ref=j.harness.harness_ref,
        execution_harness_id=j.harness.execution_harness_id, step="gate",
        compiled_ref=j.compiled.compiled_ref, gate_repetitions=2)
    assert w.runner.tasks[p.task_id]["input"] == p.runner_input
    assert p.input_digest == runner_input_digest(p.runner_input)
    same(w, job_id)


def test_gate_pass_starts_a_campaign(world):
    job_id = in_gate(world)
    names = gate(world, job_id, (Q1Status.REACHED, None, [
        BASE, ("background", "not_applied", False)]))
    j = world.job(job_id)
    assert j.state is JobState.S2_CAMPAIGN
    k = j.campaign
    assert k.compiled_ref == j.compiled.compiled_ref
    assert k.binding == j.binding
    assert f"q1-{names[0]}-jp-1" in k.gate_consumed
    p = j.pending_task
    assert p.runner_input.step == "campaign"
    assert p.runner_input.campaign_id == k.campaign_id
    assert [x.task_id for x in j.bundle_cursors] == [p.task_id]
    t = world.store.transitions(job_id)[-1]
    assert f"m1-{names[0]}" in t.consumed
    assert world.store.verdicts(job_id)[-1].verdict_id == \
        f"q1-{names[0]}-jp-1"
    same(world, job_id)


def test_gate_not_reached_is_a_regression_an_operator_routes(world):
    job_id = in_gate(world)
    gate(world, job_id, (Q1Status.NOT_REACHED, None, [BASE]))
    j = world.job(job_id)
    assert (j.state, j.state_reason) == (
        JobState.BLOCKED_OPERATOR, BlockedReason.GATE_REGRESSION.value)
    assert j.resume_point == Target(kind=TargetKind.GATE)
    n = len(world.agents.requests)
    world.c.route(job_id, "strategy")
    j = world.job(job_id)
    assert j.state is JobState.S2_STRATEGY
    assert j.counters.agent_repair_stage2 == 0
    assert len(world.agents.requests) == n + 1
    same(world, job_id)


def test_route_gate_runs_the_gate_again(world):
    job_id = in_gate(world)
    first = pending(world, job_id).task_id
    gate(world, job_id, (Q1Status.NOT_REACHED, None, [BASE]))
    world.c.route(job_id, "gate")
    j = world.job(job_id)
    assert j.state is JobState.S2_GATE and j.pending_task.task_id != first


def test_route_is_refused_after_a_reevaluation_moved_the_gate(world):
    job_id = in_gate(world)
    gate(world, job_id, (Q1Status.NOT_REACHED, None, [BASE]))
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    j = world.job(job_id)
    assert j.state_reason == BlockedReason.GATE_REGRESSION.value
    assert j.resume_point.kind is TargetKind.COMPILE
    out = world.c.route(job_id, "gate")
    assert out.reason == "route_refused"
    assert world.job(job_id).state is JobState.BLOCKED_OPERATOR
    world.c.operator(job_id, "resume")
    j = world.job(job_id)
    assert j.state is JobState.S2_GATE
    assert j.compiled.hcap_revision == "hcap-2"
    same(world, job_id)


@pytest.mark.parametrize("reason, state, state_reason", [
    ("infra", JobState.S2_GATE, "rerun"),
    ("loss", JobState.S2_GATE, "rerun"),
    ("evidence", JobState.BLOCKED_OPERATOR, "q1_evidence"),
    ("mapping", JobState.BLOCKED_OPERATOR, "q1_mapping"),
    ("something_new", JobState.BLOCKED_OPERATOR, "unexpected_event"),
])
def test_gate_q1_inconclusive_rows(world, reason, state, state_reason):
    job_id = in_gate(world)
    gate(world, job_id, (Q1Status.INCONCLUSIVE, reason, [BASE]))
    j = world.job(job_id)
    assert (j.state, j.state_reason) == (state, state_reason)
    if state is JobState.BLOCKED_OPERATOR:
        assert j.resume_point.kind is TargetKind.GATE
    same(world, job_id)


def test_gate_unsupported_attribution_is_a_gap(world):
    job_id = in_gate(world)
    g = GapRef(gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
               missing_capability_id="remote_kcov.context.softirq")
    gate(world, job_id, (Q1Status.INCONCLUSIVE, "unsupported_attribution",
                         [BASE], g))
    j = world.job(job_id)
    assert j.state is JobState.BLOCKED_HARNESS_GAP and j.gap == g
    assert j.resume_point.kind is TargetKind.GATE


def test_gate_rule_m1_inconclusive_reruns_and_never_resets(make_world):
    """09 oracle 3: alternating gate M1 INCONCLUSIVE and Q1 loss keep
    counting until runtime_retry is exhausted."""
    w = make_world(runtime_retry_limit=2)
    job_id = in_gate(w)
    inconclusive = (Q1Status.REACHED, None,
                    [("forge-stateid", "inconclusive", True)])
    loss = (Q1Status.INCONCLUSIVE, "loss", [BASE])
    gate(w, job_id, inconclusive)
    assert w.job(job_id).counters.runtime_retry == 1
    gate(w, job_id, loss)
    assert w.job(job_id).counters.runtime_retry == 2
    gate(w, job_id, inconclusive)
    j = w.job(job_id)
    assert (j.state, j.state_reason) == (
        JobState.BLOCKED_OPERATOR, BlockedReason.RUNTIME_RETRY_EXHAUSTED.value)
    w.c.operator(job_id, "resume")
    j = w.job(job_id)
    assert j.state is JobState.S2_GATE and j.counters.runtime_retry == 1
    same(w, job_id)


def test_baseline_intent_not_applied_repairs_the_strategy(world):
    job_id = in_gate(world)
    names = gate(world, job_id, (Q1Status.REACHED, None, [
        ("forge-stateid", "not_applied", True)]))
    j = world.job(job_id)
    assert (j.state, j.state_reason) == (
        JobState.S2_STRATEGY, RepairCause.GATE_NOT_APPLIED.value)
    r = j.pending_task.repair
    assert j.counters.agent_repair_stage2 == 1
    assert r.evidence_refs == (j.stage2_basis.bundle_ref, names[0])
    assert names[0] in r.findings[0]
    same(world, job_id)


def test_gate_ended_unsealed_reruns(world):
    job_id = in_gate(world)
    first = pending(world, job_id).task_id
    world.crash_run(job_id)
    j = world.job(job_id)
    assert j.state is JobState.S2_GATE and j.state_reason == "rerun"
    assert j.pending_task.task_id != first
    assert j.counters.runtime_retry == 1


@pytest.mark.parametrize("reps, state, state_reason", [
    # The topmost row of any repetition decides (09 open question, fixed).
    ([(Q1Status.REACHED, None, [BASE]),
      (Q1Status.NOT_REACHED, None, [BASE])],
     JobState.BLOCKED_OPERATOR, "gate_regression"),
    ([(Q1Status.REACHED, None, [("forge-stateid", "not_applied", True)]),
      (Q1Status.REACHED, None, [("forge-stateid", "inconclusive", True)])],
     JobState.S2_GATE, "rerun"),
    ([(Q1Status.REACHED, None, [("forge-stateid", "not_applied", True)]),
      (Q1Status.REACHED, None, [BASE])],
     JobState.S2_STRATEGY, "gate_not_applied"),
    ([(Q1Status.REACHED, None, [BASE]),
      (Q1Status.REACHED, None, [("forge-stateid", "partial", True)])],
     JobState.BLOCKED_OPERATOR, "unexpected_event"),
])
def test_repetitions_take_the_topmost_row(make_world, reps, state,
                                          state_reason):
    w = make_world(gate_repetitions=2)
    job_id = in_gate(w)
    gate(w, job_id, *reps)
    j = w.job(job_id)
    assert (j.state, j.state_reason) == (state, state_reason)
    assert len(j.gate_runs) == 2
    same(w, job_id)


def test_too_few_gate_bundles_is_unexpected(make_world):
    w = make_world(gate_repetitions=2)
    job_id = in_gate(w)
    gate(w, job_id, (Q1Status.REACHED, None, [BASE]))
    assert w.job(job_id).state_reason == "unexpected_event"


def test_gate_bundle_of_another_task_is_q1_evidence(world):
    job_id = in_gate(world)
    p = pending(world, job_id)
    world.runner.finish(p.task_id, bundle="unknown-bundle")
    world.c.poll()
    j = world.job(job_id)
    assert j.state_reason == BlockedReason.Q1_EVIDENCE.value
    assert j.resume_point.kind is TargetKind.GATE


# ---------------------------------------------------------------- campaign


def test_quiet_segments_keep_the_campaign_running(world):
    job_id = in_campaign(world)
    task = pending(world, job_id).task_id
    segment(world, job_id, h_applied=5)
    segment(world, job_id, h_applied=5)
    j = world.job(job_id)
    assert j.state is JobState.S2_CAMPAIGN
    assert j.pending_task.task_id == task
    assert j.campaign.tally.segments == 2
    assert j.campaign.tally.executions == 20
    assert j.bundle_cursors[0].delivered == 2
    assert not j.triage
    # The task ends sealed: the campaign goes on in a new task.
    segment(world, job_id, poll=False)
    world.runner.tasks[task]["state"] = "sealed"
    world.c.poll()
    j = world.job(job_id)
    assert j.state is JobState.S2_CAMPAIGN
    assert j.pending_task.task_id != task
    assert j.campaign.tally.segments == 3
    assert [x.task_id for x in j.bundle_cursors] == [j.pending_task.task_id]
    assert world.runner.starts[task] == 1
    same(world, job_id)


@pytest.mark.parametrize("q2, applied", [
    ("observed", ()), ("inconclusive", ())])
def test_crash_without_applied_rule_is_triage(world, q2, applied):
    job_id = in_campaign(world)
    name = segment(world, job_id, q2=q2, applied=applied)
    j = world.job(job_id)
    assert j.state is JobState.S2_CAMPAIGN
    item, = j.triage
    assert (item.bundle_ref, item.q2_status, item.late, item.routing) == (
        name, q2, False, "none")
    same(world, job_id)


def test_unknown_q2_status_is_unexpected(world):
    job_id = in_campaign(world)
    segment(world, job_id, q2="maybe")
    j = world.job(job_id)
    assert j.state_reason == "unexpected_event"
    assert j.resume_point.kind is TargetKind.CAMPAIGN


def test_applied_crash_replays_and_waits_for_review(world):
    job_id = in_campaign(world)
    task = pending(world, job_id).task_id
    crash = segment(world, job_id, q2="observed", applied=("r000",))
    j = world.job(job_id)
    assert j.state is JobState.S2_REPLAYING
    assert task in world.runner.cancel_calls
    p = j.pending_task
    assert p.runner_input.step == "replay"
    assert p.runner_input.crash_bundle_ref == crash
    assert p.runner_input.compiled_ref == j.campaign.compiled_ref
    assert j.triage[-1].routing == "replayed"
    replay(world, job_id, "replay_diverged")
    j = world.job(job_id)
    assert (j.state, j.state_reason) == (JobState.CRASH_REVIEW,
                                         "replay_diverged")
    assert j.resume_point == Target(kind=TargetKind.CAMPAIGN)
    assert j.replay.outcome.status == "replay_diverged"
    world.c.operator(job_id, "resume")
    j = world.job(job_id)
    assert j.state is JobState.S2_CAMPAIGN
    assert j.campaign.tally.applied_crashes == 1
    same(world, job_id)


def test_review_close_reports_the_crash(world):
    job_id = in_campaign(world)
    segment(world, job_id, q2="observed", applied=("r000",))
    replay(world, job_id)
    world.c.operator(job_id, "close")
    j = world.job(job_id)
    assert (j.state, j.state_reason) == (JobState.CLOSED, "crash_reported")
    same(world, job_id)


@pytest.mark.parametrize("kw, policy, state, reason", [
    (dict(h_not=5), dict(campaign_not_applied_generations=10),
     JobState.S2_STRATEGY, "campaign_not_applied"),
    (dict(h_applied=5), dict(campaign_no_signal_generations=10),
     JobState.S2_STRATEGY, "campaign_no_signal"),
    (dict(h_inc=5), dict(campaign_inconclusive_generations=10),
     JobState.BLOCKED_OPERATOR, "evidence_path"),
    (dict(executions=50), dict(fuzz_budget_executions=100),
     JobState.BLOCKED_OPERATOR, "campaign_budget_exhausted"),
])
def test_campaign_thresholds(make_world, kw, policy, state, reason):
    w = make_world(**policy)
    job_id = in_campaign(w)
    task = pending(w, job_id).task_id
    segment(w, job_id, **kw)
    assert w.job(job_id).state is JobState.S2_CAMPAIGN
    segment(w, job_id, **kw)
    j = w.job(job_id)
    assert (j.state, j.state_reason) == (state, reason)
    assert task in w.runner.cancel_calls
    if state is JobState.S2_STRATEGY:
        r = j.pending_task.repair
        assert r.cause.value == reason
        assert j.counters.agent_repair_stage2 == 1
    else:
        assert j.resume_point == Target(kind=TargetKind.CAMPAIGN)
        # resume continues the campaign with the count that stopped it at 0.
        w.c.operator(job_id, "resume")
        j = w.job(job_id)
        assert j.state is JobState.S2_CAMPAIGN
        segment(w, job_id, **kw)
        assert w.job(job_id).state is JobState.S2_CAMPAIGN
    same(w, job_id)


def test_ended_unsealed_campaign_continues_and_a_seal_resets(make_world):
    w = make_world(runtime_retry_limit=2)
    job_id = in_campaign(w)
    w.crash_run(job_id)
    j = w.job(job_id)
    assert j.state is JobState.S2_CAMPAIGN and j.counters.runtime_retry == 1
    w.crash_run(job_id)
    assert w.job(job_id).counters.runtime_retry == 2
    segment(w, job_id)
    assert w.job(job_id).counters.runtime_retry == 0
    same(w, job_id)


def test_restart_takes_every_campaign_bundle_once_in_order(world):
    job_id = in_campaign(world)
    task = pending(world, job_id).task_id
    a = segment(world, job_id, poll=False)
    b = segment(world, job_id, poll=False)
    world.restart()
    j = world.job(job_id)
    assert j.bundle_cursors[0].delivered == 2
    assert world.runner.starts[task] == 1
    ts = [t for t in world.store.transitions(job_id)
          if t.event["type"] == "runner_bundle_sealed"]
    assert [t.event["bundle_ref"] for t in ts] == [a, b]
    world.c.poll()
    assert world.job(job_id).bundle_cursors[0].delivered == 2
    same(world, job_id)


def test_hcap_change_in_campaign_compiles_again_and_gates(world):
    job_id = in_campaign(world)
    task = pending(world, job_id).task_id
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    j = world.job(job_id)
    assert j.state is JobState.S2_GATE
    assert j.compiled.hcap_revision == "hcap-2"
    assert j.campaign is None
    assert task in world.runner.cancel_calls
    same(world, job_id)


def test_identity_change_in_campaign_reestablishes_q1(world):
    job_id = in_campaign(world)
    world.registry.put(binding(execution="build-2"))
    world.c.on_registry_changed()
    j = world.job(job_id)
    assert j.state is JobState.S1_RUNNING
    assert j.campaign is None and j.stage2_basis is None


# ---------------------------------------------------------------- replay


def test_replay_evidence_rejected_waits_and_keeps_the_replay(world):
    job_id = in_campaign(world)
    segment(world, job_id, q2="observed", applied=("r000",))
    crash = world.job(job_id).replay.crash
    replay(world, job_id, "evidence_rejected")
    j = world.job(job_id)
    assert j.state_reason == BlockedReason.REPLAY_EVIDENCE.value
    assert j.resume_point == Target(kind=TargetKind.REPLAY)
    # A new identity does not move the replay (09 oracle 2).
    world.registry.put(binding(execution="build-2"))
    world.c.on_registry_changed()
    j = world.job(job_id)
    assert j.resume_point == Target(kind=TargetKind.REPLAY)
    assert j.replay.resume.kind is TargetKind.RUNNING
    world.c.operator(job_id, "resume")
    j = world.job(job_id)
    assert j.state is JobState.S2_REPLAYING
    assert j.pending_task.runner_input.execution_harness_id == \
        crash.execution_harness_id
    replay(world, job_id)
    j = world.job(job_id)
    assert j.state is JobState.CRASH_REVIEW
    assert j.resume_point.kind is TargetKind.RUNNING
    same(world, job_id)


def test_replay_ended_unsealed_reruns(world):
    job_id = in_campaign(world)
    segment(world, job_id, q2="observed", applied=("r000",))
    world.crash_run(job_id)
    j = world.job(job_id)
    assert j.state is JobState.S2_REPLAYING and j.state_reason == "rerun"


def test_binding_change_during_replay_moves_only_the_review_resume(world):
    """09 oracle 2: replay ends in crash_review; resume goes to the
    identity re-establishment point, or after an HCAP-only change to a
    re-compiled gate."""
    job_id = in_campaign(world)
    segment(world, job_id, q2="observed", applied=("r000",))
    task = pending(world, job_id).task_id
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    j = world.job(job_id)
    assert j.state is JobState.S2_REPLAYING
    assert j.pending_task.task_id == task
    assert j.binding.hcap_revision == "hcap-2"
    assert j.replay.resume.kind is TargetKind.COMPILE
    replay(world, job_id)
    j = world.job(job_id)
    assert j.state is JobState.CRASH_REVIEW
    assert j.resume_point.kind is TargetKind.COMPILE
    world.c.operator(job_id, "resume")
    j = world.job(job_id)
    assert j.state is JobState.S2_GATE
    assert j.compiled.hcap_revision == "hcap-2"
    same(world, job_id)


def test_binding_change_in_review_moves_its_resume_point(world):
    job_id = in_campaign(world)
    segment(world, job_id, q2="observed", applied=("r000",))
    replay(world, job_id)
    world.registry.put(binding(execution="build-2"))
    world.c.on_registry_changed()
    j = world.job(job_id)
    assert j.state is JobState.CRASH_REVIEW
    assert j.resume_point.kind is TargetKind.RUNNING
    world.c.operator(job_id, "resume")
    assert world.job(job_id).state is JobState.S1_RUNNING
    same(world, job_id)


# ---------------------------------------------------------------- late


def stop_slowly(w, job_id) -> str:
    """The running campaign task will not end on its first cancel."""
    task = pending(w, job_id).task_id
    w.runner.slow_cancel.add(task)
    return task


def test_late_applied_crash_is_queued_behind_the_review(world):
    job_id = in_campaign(world)
    task = stop_slowly(world, job_id)
    first = segment(world, job_id, q2="observed", applied=("r000",))
    assert world.job(job_id).state is JobState.S2_REPLAYING
    assert task in world.job(job_id).cancelling_tasks
    # The stopped task seals one more crash before its cancel settles.
    late = segment(world, job_id, q2="observed", applied=("r001",),
                   task_id=task)
    j = world.job(job_id)
    assert task not in j.cancelling_tasks and not j.bundle_cursors
    assert [x.bundle_ref for x in j.crash_queue] == [late]
    item = j.triage[-1]
    assert (item.bundle_ref, item.late, item.routing) == (late, True,
                                                          "queued")
    assert j.campaign.tally.applied_crashes == 1    # late moves no count
    replay(world, job_id)
    world.c.operator(job_id, "resume")
    j = world.job(job_id)
    assert j.state is JobState.S2_REPLAYING
    assert j.replay.crash.bundle_ref == late and not j.crash_queue
    assert j.pending_task.runner_input.crash_bundle_ref == late
    replay(world, job_id)
    world.c.operator(job_id, "resume")
    j = world.job(job_id)
    assert j.state is JobState.S2_CAMPAIGN
    assert first != late
    same(world, job_id)


def test_late_applied_crash_stops_the_campaign_repair(make_world):
    w = make_world(campaign_not_applied_generations=5)
    job_id = in_campaign(w)
    task = stop_slowly(w, job_id)
    segment(w, job_id, h_not=5)
    j = w.job(job_id)
    assert j.state is JobState.S2_STRATEGY
    repair = j.pending_task
    late = segment(w, job_id, q2="observed", applied=("r000",), task_id=task)
    j = w.job(job_id)
    assert j.state is JobState.S2_REPLAYING
    assert j.replay.crash.bundle_ref == late
    assert j.triage[-1].routing == "replayed"
    assert w.store.attempt(repair.task_id, repair.attempt).status == \
        "abandoned"
    replay(w, job_id)
    w.c.operator(job_id, "resume")
    j = w.job(job_id)
    # The same repair again, already charged.
    assert j.state is JobState.S2_STRATEGY
    assert j.pending_task.repair == repair.repair
    assert j.counters.agent_repair_stage2 == 1
    same(w, job_id)


def test_late_crash_while_waiting_on_an_operator_is_unrouted(make_world):
    w = make_world(fuzz_budget_executions=10)
    job_id = in_campaign(w)
    task = stop_slowly(w, job_id)
    segment(w, job_id)
    j = w.job(job_id)
    assert j.state_reason == BlockedReason.CAMPAIGN_BUDGET_EXHAUSTED.value
    late = segment(w, job_id, q2="observed", applied=("r000",), task_id=task)
    j = w.job(job_id)
    assert j.state_reason == BlockedReason.CAMPAIGN_BUDGET_EXHAUSTED.value
    item = j.triage[-1]
    assert (item.bundle_ref, item.routing) == (late, "unrouted")
    same(w, job_id)


def test_late_quiet_bundle_is_triage_only(make_world):
    w = make_world(fuzz_budget_executions=10)
    job_id = in_campaign(w)
    task = stop_slowly(w, job_id)
    segment(w, job_id)
    segment(w, job_id, task_id=task)
    j = w.job(job_id)
    assert j.triage[-1].late and j.triage[-1].routing == "none"
    assert j.campaign.tally.segments == 1


def test_late_bundle_after_close_is_still_kept(world):
    job_id = in_campaign(world)
    task = stop_slowly(world, job_id)
    world.c.operator(job_id, "close")
    late = segment(world, job_id, q2="observed", applied=("r000",),
                   task_id=task)
    j = world.job(job_id)
    assert j.state is JobState.CLOSED
    assert j.triage[-1].bundle_ref == late
    assert j.triage[-1].routing == "unrouted"
    same(world, job_id)
