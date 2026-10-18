"""Oracle 2 (09 검증 오라클): negative controls, the Stage 1 ones."""

import json

import pytest
from pydantic import ValidationError

from agent_pipeline.contracts import (HOST_AUTHORITY_UNAVAILABLE,
                                      AnalysisOutput, GapClass, GapRef,
                                      MaterializeRejected,
                                      HarnessBinding, PlanOutput, Q1Status,
                                      Sanitizer)
from agent_pipeline.controller import events as ev
from agent_pipeline.controller.records import (BlockedReason, JobState,
                                               TargetKind, TaskKind)

from .fakes import COMMIT, VERSIONS, binding, policy, sha


def test_stage2_is_opt_in():
    assert policy().run_stage2 is False
    assert policy(run_stage2=True).run_stage2 is True
    with pytest.raises(ValidationError):
        policy(run_stage2="maybe")


@pytest.mark.parametrize("status,reason", [
    (Q1Status.NOT_REACHED, None),
    (Q1Status.INCONCLUSIVE, "infra"),
    (Q1Status.INCONCLUSIVE, "loss"),
    (Q1Status.INCONCLUSIVE, "evidence"),
    (Q1Status.INCONCLUSIVE, "mapping"),
    (Q1Status.INCONCLUSIVE, "made_up_reason"),
])
def test_only_reached_reaches_s1_reached(make_world, status, reason):
    w = make_world()
    j = w.to_running()
    w.run(j, status, reason)
    job = w.job(j)
    assert job.state is not JobState.S1_REACHED
    assert job.stage2_input is None


@pytest.mark.parametrize("reason", ["infra", "loss", "evidence", "mapping"])
def test_inconclusive_never_calls_an_agent(make_world, reason):
    w = make_world()
    j = w.to_running()
    before = len(w.agents.requests)
    w.run(j, Q1Status.INCONCLUSIVE, reason)
    assert len(w.agents.requests) == before
    assert w.job(j).counters.agent_repair_stage1 == 0


def test_reached_from_another_identity_is_not_reached(world):
    j = world.to_running()
    p = world.job(j).pending_task
    world.judge.add("foreign", binding("build-2").execution_harness_id,
                    world.job(j).candidate.candidate_id,
                    Q1Status.REACHED)
    world.runner.finish(p.task_id, bundle="foreign")
    world.c.poll()
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == BlockedReason.Q1_EVIDENCE.value


def test_results_of_other_tasks_make_no_transition(world):
    j = world.submit()
    p = world.job(j).pending_task
    n = len(world.store.transitions(j))
    world.c.on_agent_result(p.task_id + "x", 1,
                            AnalysisOutput(analysis_ref=sha("a")), "m")
    world.c.on_agent_result(p.task_id, p.attempt + 1,
                            AnalysisOutput(analysis_ref=sha("a")), "m")
    assert len(world.store.transitions(j)) == n
    assert world.job(j).pending_task == p


def test_a_variant_its_task_cannot_return_is_unexpected(world):
    j = world.submit()
    world.agent_ok(j, PlanOutput(plan_ref=sha("p")))    # analysis expected
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == BlockedReason.UNEXPECTED_EVENT.value


def test_unknown_reason_is_unexpected(world):
    j = world.to_running()
    world.run(j, Q1Status.INCONCLUSIVE, "cosmic_rays")
    job = world.job(j)
    assert job.state_reason == BlockedReason.UNEXPECTED_EVENT.value
    assert job.resume_point.kind is TargetKind.RUNNING


def test_unsupported_attribution_without_a_context_gap_is_unexpected(world):
    j = world.to_running()
    world.run(j, Q1Status.INCONCLUSIVE, "unsupported_attribution",
              GapRef(gap_class=GapClass.SYZLANG,
                     missing_capability_id="syzlang.nfs4.op_lock"))
    assert world.job(j).state_reason == \
        BlockedReason.UNEXPECTED_EVENT.value


# ---------------------------------------------------- waiting states (§5)


def blocked_on_evidence(w):
    j = w.to_running()
    w.run(j, Q1Status.INCONCLUSIVE, "evidence")
    assert w.job(j).state is JobState.BLOCKED_OPERATOR
    return j


def test_identity_change_moves_only_the_resume_point(world):
    j = blocked_on_evidence(world)
    before = world.job(j)
    old_harness = before.harness.harness_ref
    world.registry.put(binding("build-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert (job.state, job.state_reason) == (before.state, before.state_reason)
    assert job.binding == binding("build-2")
    assert job.resume_point.kind is TargetKind.RUNNING
    assert job.harness.harness_ref != old_harness     # materialized now
    started = list(world.runner.started)
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    new_task = job.pending_task.task_id
    assert world.runner.started == started + [new_task]
    assert world.runner.tasks[new_task]["input"].execution_harness_id == \
        binding("build-2").execution_harness_id


def test_hcap_change_failing_the_plan_moves_the_resume_point(world):
    j = blocked_on_evidence(world)
    world.hcap.violations[(sha("plan-1"), "hcap-2")] = ("HCAP-02 removed",)
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    rp = job.resume_point
    assert rp.kind is TargetKind.PLANNING and rp.cause.value == "hcap_changed"
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.counters.agent_repair_stage1 == 0     # hcap_changed is free


def test_withdrawn_harness_nests_a_gap_and_comes_back(world):
    j = blocked_on_evidence(world)
    world.registry.bindings.clear()
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    rp = job.resume_point
    assert rp.kind is TargetKind.BLOCKED_HARNESS_GAP
    assert rp.inner.kind is TargetKind.RUNNING
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.BLOCKED_HARNESS_GAP
    assert job.resume_point.kind is TargetKind.RUNNING
    gap = job.gap
    world.registry.put(binding("build-3"))
    world.c.on_issue(gap, "resolved")
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.binding == binding("build-3")


def test_reevaluation_back_to_the_base_restores_it(world):
    j = blocked_on_evidence(world)
    world.registry.bindings.clear()
    world.c.on_registry_changed()
    assert world.job(j).resume_point.kind is TargetKind.BLOCKED_HARNESS_GAP
    world.registry.put(binding())         # the same build is back
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.resume_point.kind is TargetKind.RUNNING
    assert job.resume_point.inner is None


def test_rejudge_under_an_older_identity_is_recorded_not_routed(world):
    """09 오라클 2: gate INCONCLUSIVE(evidence) -> identity change ->
    boundary re-judge -> resume, in Stage 1 terms."""
    j = blocked_on_evidence(world)
    bundle = world.job(j).last_verdict.bundle_ref
    world.registry.put(binding("build-2"))
    world.c.on_registry_changed()
    world.judge.add(bundle, binding().execution_harness_id,
                    world.job(j).candidate.candidate_id,
                    Q1Status.REACHED, profile="jp-2")
    world.c.on_judge_versions(VERSIONS.model_copy(
        update={"judge_profile_id": "jp-2"}))
    assert any(v.judge_profile_id == "jp-2" and v.status is Q1Status.REACHED
               for v in world.store.verdicts(j))
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.resume_point.kind is TargetKind.RUNNING
    # Recorded, not consumed: the job's verdict is still the old one.
    assert job.last_verdict.result.status is Q1Status.INCONCLUSIVE
    assert world.store.transitions(j)[-1].consumed == ()
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING           # not s1_reached
    assert job.binding == binding("build-2")


def test_rejudge_under_the_same_binding_routes_from_the_origin(world):
    j = blocked_on_evidence(world)
    bundle = world.job(j).last_verdict.bundle_ref
    world.judge.add(bundle, binding().execution_harness_id,
                    world.job(j).candidate.candidate_id,
                    Q1Status.REACHED, profile="jp-2")
    world.c.on_judge_versions(VERSIONS.model_copy(
        update={"judge_profile_id": "jp-2"}))
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR     # still waiting
    assert job.resume_point.kind is TargetKind.REACHED
    world.c.operator(j, "resume")
    assert world.job(j).state is JobState.S1_REACHED


def test_binding_event_atomically_rebuilds_reached_stage2_for_new_judge(
        world):
    j = world.to_running()
    bundle = world.run(j, Q1Status.REACHED)
    before = world.job(j)
    versions = VERSIONS.model_copy(update={"judge_profile_id": "jp-2"})
    world.judge.add(
        bundle, before.binding.execution_harness_id,
        before.candidate.candidate_id, Q1Status.REACHED, profile="jp-2")

    out = world.c._apply(j, ev.BindingChanged(
        binding=before.binding, judge_versions=versions,
        rematerialize_authority=True))

    assert out is not None
    job = world.job(j)
    assert job.state is JobState.S1_REACHED
    assert job.judge_versions == versions
    assert job.last_verdict.result.judge_profile_id == "jp-2"
    assert job.stage2_input.q1_verdict_id == \
        job.last_verdict.result.verdict_id
    assert job.stage2_input.q1_verdict_id != \
        before.stage2_input.q1_verdict_id


def test_binding_and_judge_change_clear_stale_stage2_before_new_run(world):
    j = world.to_running()
    world.run(j, Q1Status.REACHED)
    before = world.job(j)
    versions = VERSIONS.model_copy(update={"judge_profile_id": "jp-2"})
    replacement = binding(hcap="hcap-2")

    world.c._apply(j, ev.BindingChanged(
        binding=replacement, judge_versions=versions,
        rematerialize_authority=True))

    job = world.job(j)
    assert job.binding == replacement
    assert job.judge_versions == versions
    assert job.state is JobState.S1_RUNNING
    assert job.stage2_input is None
    assert job.harness.harness_ref != before.harness.harness_ref


def test_registry_change_rebinds_reached_job_in_one_atomic_transition(world):
    j = world.to_running()
    world.run(j, Q1Status.REACHED)
    before = world.job(j)
    versions = VERSIONS.model_copy(update={"judge_profile_id": "jp-2"})
    replacement = binding(hcap="hcap-2")
    world.hcap.judge_versions = lambda revision: \
        versions if revision == replacement.hcap_revision else None
    world.materializer.authority_changed.add(replacement.hcap_revision)
    world.registry.put(replacement)

    world.c.on_registry_changed()

    transitions = [
        item for item in world.store.transitions(j)
        if item.seq > before.seq
    ]
    assert len(transitions) == 1
    transition = transitions[0]
    assert transition.event["type"] == "binding_changed"
    assert transition.event["rematerialize_authority"] is True
    job = world.job(j)
    assert transition.job == job
    assert job.binding == replacement
    assert job.judge_versions == versions
    assert job.harness.hcap_revision == replacement.hcap_revision
    assert job.state is JobState.S1_RUNNING
    assert job.stage2_input is None
    assert world.c.replay(j) == job


def test_flagless_binding_event_replays_historical_judge_assignment(world):
    j = world.to_running()
    gap = GapRef(
        gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
        missing_capability_id="remote_kcov.context.softirq")
    bundle = world.run(
        j, Q1Status.INCONCLUSIVE, "unsupported_attribution", gap)
    blocked = world.job(j)
    world.c._apply(j, ev.IssueChanged(
        gap=gap, status="resolved", resolution="historical"))
    assert world.job(j).state is JobState.RETRY_PENDING

    versions = VERSIONS.model_copy(update={"judge_profile_id": "jp-2"})
    world.judge.add(
        bundle, blocked.binding.execution_harness_id,
        blocked.candidate.candidate_id, Q1Status.REACHED, profile="jp-2")
    historical = ev.BindingChanged(
        binding=blocked.binding, judge_versions=versions)
    assert "rematerialize_authority" not in historical.model_fields_set
    world.c._apply(j, historical)
    stored = world.job(j)
    assert stored.state is JobState.S1_RUNNING
    assert stored.judge_versions == versions
    assert stored.last_verdict.result.judge_profile_id == \
        VERSIONS.judge_profile_id

    transition = world.store.transitions(j)[-1]
    raw = json.loads(transition.model_dump_json())
    assert raw["event"].pop("rematerialize_authority") is False
    world.store.db.execute(
        "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = ?",
        (json.dumps(raw, sort_keys=True), j, transition.seq))

    assert world.c.replay(j) == stored


def test_same_route_rejudge_rejects_conflicting_execution_identity(world):
    j = world.to_running()
    bundle = world.run(j, Q1Status.REACHED)
    job = world.job(j)
    world.judge.add(
        bundle, job.binding.execution_harness_id,
        job.candidate.candidate_id, Q1Status.REACHED, profile="jp-2")
    world.judge.bundles[bundle]["harness_id"] = sha("foreign-build")

    world.c.on_judge_versions(VERSIONS.model_copy(
        update={"judge_profile_id": "jp-2"}))

    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == BlockedReason.Q1_EVIDENCE.value
    assert job.stage2_input is None


def test_same_reason_rejudge_routes_changed_gap_signal(world):
    first = GapRef(
        gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
        missing_capability_id="remote_kcov.context.softirq")
    second = GapRef(
        gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
        missing_capability_id="remote_kcov.context.workqueue")
    j = world.to_running()
    bundle = world.run(
        j, Q1Status.INCONCLUSIVE, "unsupported_attribution", first)
    job = world.job(j)
    world.judge.add(
        bundle, job.binding.execution_harness_id,
        job.candidate.candidate_id, Q1Status.INCONCLUSIVE,
        "unsupported_attribution", second, profile="jp-2")

    world.c.on_judge_versions(VERSIONS.model_copy(
        update={"judge_profile_id": "jp-2"}))

    job = world.job(j)
    assert job.state is JobState.BLOCKED_HARNESS_GAP
    assert job.gap == first
    assert job.resume_point.kind is TargetKind.BLOCKED_HARNESS_GAP
    assert job.resume_point.gap == second


def test_same_not_reached_rejudge_reissues_repair_with_new_verdict(world):
    j = world.to_running()
    bundle = world.run(j, Q1Status.NOT_REACHED)
    before = world.job(j)
    old_task = before.pending_task
    repairs = before.counters.agent_repair_stage1
    world.judge.add(
        bundle, before.binding.execution_harness_id,
        before.candidate.candidate_id, Q1Status.NOT_REACHED,
        profile="jp-2")

    world.c.on_judge_versions(VERSIONS.model_copy(
        update={"judge_profile_id": "jp-2"}))

    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.last_verdict.result.judge_profile_id == "jp-2"
    assert job.pending_task.task_id != old_task.task_id
    assert job.pending_task.input_digest != old_task.input_digest
    assert job.pending_task.repair.findings == (
        job.last_verdict.result.model_dump_json(),)
    assert job.counters.agent_repair_stage1 == repairs
    assert world.store.attempt(old_task.task_id, old_task.attempt).status == \
        "abandoned"
    assert world.c.replay(j) == job


def test_rejudge_needing_evidence_reruns_without_budget(world):
    j = world.to_running()
    world.run(j, Q1Status.NOT_REACHED)
    bundle = world.job(j).last_verdict.bundle_ref
    world.judge.missing.add((bundle, "jp-2"))
    world.c.on_judge_versions(VERSIONS.model_copy(
        update={"judge_profile_id": "jp-2"}))
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.counters.runtime_retry == 0


def test_approval_policy_applies_on_resume(world):
    world.store.save_policy(policy("p2", approval_required=True))
    j = blocked_on_evidence(world)
    world.c.set_policy(j, "p2")
    assert world.job(j).resume_point.kind is TargetKind.RUNNING
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.S1_APPROVAL
    assert job.pending_task.kind is TaskKind.HUMAN


def test_hcap_change_in_planning_restarts_the_task(world):
    j = world.submit()
    world.analysis(j)
    old = world.job(j).pending_task
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.pending_task.task_id != old.task_id
    assert world.agents.requests[-1].hcap_revision == "hcap-2"
    # The old attempt's late output makes no transition.
    world.c.on_agent_result(old.task_id, old.attempt,
                            PlanOutput(plan_ref=sha("late")), "m")
    assert world.job(j).pending_task == job.pending_task
    assert world.store.attempt(old.task_id, old.attempt).status == \
        "abandoned"


def test_hcap_change_while_running_rematerializes_and_restarts(world):
    """The new HCAP revision changes the call admission or neutral
    control authority refs: the harness is rebuilt and the run restarted."""
    j = world.to_running()
    before = world.job(j)
    task = before.pending_task.task_id
    world.materializer.authority_changed.add("hcap-2")
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.harness.harness_ref != before.harness.harness_ref
    assert job.pending_task.task_id != task
    assert world.runner.cancel_calls[task] == 1


def test_hcap_change_while_running_keeps_harness_with_same_authority(world):
    """09 §5 `hcap_revision`-only row: the plan re-validates and the
    authority refs are unchanged, so the run goes on."""
    j = world.to_running()
    before = world.job(j)
    task = before.pending_task.task_id
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.binding.hcap_revision == "hcap-2"
    assert job.harness.harness_ref == before.harness.harness_ref
    assert job.harness.hcap_revision == "hcap-1"
    assert job.harness.authority_hcap_revision == "hcap-2"
    assert job.pending_task.task_id == task
    assert task not in world.runner.cancel_calls
    assert job.counters == before.counters
    seq = job.seq
    world.c.on_registry_changed()               # no repeated migration
    assert world.job(j).seq == seq
    assert world.c.replay(j) == world.job(j)


def test_hcap_change_keeps_reached_job_with_same_authority(world):
    j = world.to_running()
    world.run(j, Q1Status.REACHED)
    before = world.job(j)
    assert before.state is JobState.S1_REACHED
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.state is JobState.S1_REACHED
    assert job.stage2_input == before.stage2_input
    assert job.last_verdict == before.last_verdict
    assert job.harness.harness_ref == before.harness.harness_ref
    assert world.c.replay(j) == job


def test_host_authority_refusal_blocks_without_llm_repair(world):
    """09 §3: a host-side Materializer refusal (unapproved HCAP, corrupt
    build artifact) is not an Agent mistake: no repair task, no charge."""
    j = world.to_running()
    world.run(j, Q1Status.REACHED)
    before = world.job(j)
    refusal = MaterializeRejected(
        reason=HOST_AUTHORITY_UNAVAILABLE,
        detail="hcap_not_approved_for_execution_harness")
    world.materializer.refusals[(before.plan_ref,
                                 before.binding.execution_harness_id)] = \
        refusal
    world.materializer.authority_changed.add("hcap-2")
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == "host_authority"
    assert job.pending_task is None
    assert job.counters.agent_repair_stage1 == \
        before.counters.agent_repair_stage1

    del world.materializer.refusals[(before.plan_ref,
                                     before.binding.execution_harness_id)]
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.harness.hcap_revision == "hcap-2"
    assert job.counters.agent_repair_stage1 == \
        before.counters.agent_repair_stage1


def test_hcap_change_with_failing_plan_replans_despite_same_authority(world):
    j = world.to_running()
    before = world.job(j)
    world.hcap.violations[(before.plan_ref, "hcap-2")] = ("cap_withdrawn",)
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.harness is None
    assert world.c.replay(j) == job


def test_sanitizer_policy_change_rebinds(world):
    """01 §11.2: the job runs the build of the sanitizer its policy
    selects, also after the policy changes."""
    kcsan = HarnessBinding(kernel_commit=COMMIT, sanitizer=Sanitizer.KCSAN,
                           execution_harness_id=sha("build-kcsan"),
                           hcap_revision="hcap-1")
    world.registry.put(kcsan)
    world.store.save_policy(policy("kcsan", sanitizer=Sanitizer.KCSAN))
    j = world.submit()
    world.analysis(j)
    world.c.set_policy(j, "kcsan")
    job = world.job(j)
    assert job.binding == kcsan
    assert job.state is JobState.S1_PLANNING       # the same Agent Task
    world.plan(j)
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert world.runner.tasks[job.pending_task.task_id]["input"] \
        .execution_harness_id == kcsan.execution_harness_id
    world.c.replay(j)


def test_sanitizer_policy_change_while_running_stops_the_run(world):
    world.store.save_policy(policy("kcsan", sanitizer=Sanitizer.KCSAN))
    j = world.to_running()
    old = world.job(j).pending_task.task_id
    world.c.set_policy(j, "kcsan")                 # no KCSAN build
    job = world.job(j)
    assert job.state is JobState.BLOCKED_HARNESS_GAP
    assert job.binding is None
    assert world.runner.cancel_calls[old] == 1
    world.registry.put(HarnessBinding(
        kernel_commit=COMMIT, sanitizer=Sanitizer.KCSAN,
        execution_harness_id=sha("build-kcsan"), hcap_revision="hcap-1"))
    world.c.on_issue(job.gap, "resolved")
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.harness.execution_harness_id == sha("build-kcsan")


def test_rejudge_rerun_spends_no_runtime_budget(make_world):
    w = make_world(runtime_retry_limit=1)
    j = w.to_running()
    bundle = w.run(j, Q1Status.INCONCLUSIVE, "infra")    # rerun 1 of 1
    assert w.job(j).counters.runtime_retry == 1
    running = w.job(j).pending_task.task_id
    w.judge.add(bundle, binding().execution_harness_id,
                w.job(j).candidate.candidate_id, Q1Status.INCONCLUSIVE,
                "loss", profile="jp-2")
    w.c.on_judge_versions(VERSIONS.model_copy(
        update={"judge_profile_id": "jp-2"}))
    job = w.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.counters.runtime_retry == 1
    assert job.pending_task.task_id != running


def test_rejudge_rerun_through_a_waiting_state_spends_no_budget(world):
    j = blocked_on_evidence(world)
    bundle = world.job(j).last_verdict.bundle_ref
    world.judge.missing.add((bundle, "jp-2"))
    world.c.on_judge_versions(VERSIONS.model_copy(
        update={"judge_profile_id": "jp-2"}))
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.resume_point.kind is TargetKind.RUNNING
    assert job.resume_point.rerun and job.resume_point.external
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.counters.runtime_retry == 0


def test_issue_resolved_before_the_hcap_notice_checks_the_plan(world):
    """09 오라클 2: a promotion under the same identity closes the gap and
    its issue event comes before the HCAP change notice."""
    j = world.to_running()
    gap = GapRef(gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
                 missing_capability_id="remote_kcov.context.softirq")
    world.run(j, Q1Status.INCONCLUSIVE, "unsupported_attribution", gap)
    assert world.job(j).resume_point.kind is TargetKind.RUNNING
    world.hcap.violations[(sha("plan-1"), "hcap-2")] = ("HCAP-02 removed",)
    world.registry.put(binding(hcap="hcap-2"))      # no notice yet
    started = list(world.runner.started)
    world.c.on_issue(gap, "resolved")
    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.state_reason == "hcap_changed"
    assert job.binding == binding(hcap="hcap-2")
    assert world.runner.started == started
    n = len(world.store.transitions(j))
    world.c.on_registry_changed()                   # the late notice
    assert len(world.store.transitions(j)) == n
    world.c.replay(j)


def rejudge(w, j, bundle, profile, status, reason=None):
    w.judge.add(bundle, binding().execution_harness_id,
                w.job(j).candidate.candidate_id, status, reason,
                profile=profile)
    w.c.on_judge_versions(VERSIONS.model_copy(
        update={"judge_profile_id": profile}))


def test_rejudge_back_to_the_waiting_state_does_not_keep_reached(world):
    """09 rationale 16: evidence -> re-judged REACHED -> re-judged
    INCONCLUSIVE(evidence) again: resume runs again, it does not enter
    s1_reached on a verdict that is not REACHED."""
    j = blocked_on_evidence(world)
    bundle = world.job(j).last_verdict.bundle_ref
    rejudge(world, j, bundle, "jp-2", Q1Status.REACHED)
    assert world.job(j).resume_point.kind is TargetKind.REACHED
    rejudge(world, j, bundle, "jp-3", Q1Status.INCONCLUSIVE, "evidence")
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.resume_point.kind is TargetKind.RUNNING
    assert job.last_verdict.result.judge_profile_id == "jp-3"
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.stage2_input is None
    world.c.replay(j)


def test_rejudge_to_another_waiting_state_keeps_its_own_resume(world):
    j = blocked_on_evidence(world)
    bundle = world.job(j).last_verdict.bundle_ref
    rejudge(world, j, bundle, "jp-2", Q1Status.REACHED)
    rejudge(world, j, bundle, "jp-3", Q1Status.INCONCLUSIVE, "mapping")
    rp = world.job(j).resume_point
    assert rp.kind is TargetKind.BLOCKED_OPERATOR
    assert rp.reason is BlockedReason.Q1_MAPPING
    assert rp.inner.kind is TargetKind.RUNNING
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == BlockedReason.Q1_MAPPING.value
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.stage2_input is None
    world.c.replay(j)


def test_reached_is_entered_only_on_a_reached_verdict(world):
    j = blocked_on_evidence(world)
    bundle = world.job(j).last_verdict.bundle_ref
    rejudge(world, j, bundle, "jp-2", Q1Status.REACHED)
    world.c.operator(j, "resume")
    job = world.job(j)
    assert job.state is JobState.S1_REACHED
    assert job.last_verdict.result.status is Q1Status.REACHED
    assert job.stage2_input.q1_verdict_id == \
        job.last_verdict.result.verdict_id


def test_corrupt_host_catalog_blocks_without_llm_repair(world):
    """A corrupt host HCAP catalog fails the plan check before the
    Materializer runs; it is still a host failure, not a plan finding."""
    j = world.to_running()
    world.run(j, Q1Status.REACHED)
    before = world.job(j)
    world.hcap.corrupt.add("hcap-2")
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == "host_authority"
    assert job.pending_task is None
    assert job.counters.agent_repair_stage1 == \
        before.counters.agent_repair_stage1
    assert world.c.replay(j) == job


def test_unreadable_host_catalog_keeps_the_job_and_retries(world, monkeypatch):
    """A missing or unreadable catalog is a host availability failure: no
    transition and no charge; a later poll applies the change."""
    j = world.to_running()
    world.run(j, Q1Status.REACHED)
    before = world.job(j)
    real = world.hcap.check_plan

    def unreadable(plan_ref, hcap_revision):
        if hcap_revision == "hcap-2":
            raise FileNotFoundError("catalog")
        return real(plan_ref, hcap_revision)

    monkeypatch.setattr(world.hcap, "check_plan", unreadable)
    world.materializer.authority_changed.add("hcap-2")
    world.registry.put(binding(hcap="hcap-2"))
    with pytest.raises(FileNotFoundError):     # as a Materializer OSError
        world.c.on_registry_changed()
    job = world.job(j)
    assert job.state is before.state
    assert job.binding == before.binding
    assert job.counters == before.counters
    monkeypatch.setattr(world.hcap, "check_plan", real)
    world.c.on_registry_changed()
    assert world.job(j).binding.hcap_revision == "hcap-2"
