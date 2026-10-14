"""Oracle 1 (09 검증 오라클): every row of the §3 table, and the §5 rows a
Stage 1 job uses, from its state and event to its next state and counter."""

from agent_pipeline.contracts import (GapClass, GapRef, MaterializeRejected,
                                      Q1Status, ReanalysisRequired,
                                      UnsupportedOutput)
from agent_pipeline.controller.records import (BlockedReason, JobState,
                                               RepairCause, TaskKind)

from .fakes import (OTHER_COMMIT, binding, function_submission, policy,
                    sha)


def test_intake_failure_is_rejected(world):
    j = world.submit(function_submission(symbol="no_such_function"))
    job = world.job(j)
    assert job.state is JobState.REJECTED
    assert job.state_reason.startswith("symbol_not_found")
    assert world.agents.requests == []


def test_no_validated_harness_blocks_on_a_kernel_revision_gap(world):
    j = world.submit(function_submission(commit=OTHER_COMMIT))
    job = world.job(j)
    gap = GapRef(gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
                 missing_capability_id=f"remote_kcov.kernel_revision."
                                       f"{OTHER_COMMIT}")
    assert job.state is JobState.BLOCKED_HARNESS_GAP and job.gap == gap
    assert world.store.issue_ref(gap) == world.issues.issues[gap]
    assert world.issues.links[gap] == [j]
    assert world.agents.requests == []


def test_binding_starts_candidate_analysis(world):
    j = world.submit()
    job = world.job(j)
    assert job.state is JobState.S1_ANALYSIS
    assert job.binding == binding()
    assert job.candidate.location.start_line == 6
    assert job.candidate.location.end_line == 12
    (req,) = world.agents.requests
    assert req.task_id == job.pending_task.task_id
    assert req.hcap_revision == "hcap-1" and req.repair is None


def test_analysis_goes_to_planning(world):
    j = world.submit()
    world.analysis(j)
    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.pending_task.repair is None
    assert job.analysis_ref == sha("analysis-1")


def test_hcap_check_failure_repairs_planning(world):
    j = world.submit()
    world.analysis(j)
    world.hcap.violations[(sha("plan-1"), "hcap-1")] = ("HCAP-99 unknown",)
    world.plan(j)
    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.state_reason == RepairCause.HCAP_INVALID.value
    assert job.counters.agent_repair_stage1 == 1
    r = job.pending_task.repair
    assert r.cause is RepairCause.HCAP_INVALID
    assert r.findings == ("HCAP-99 unknown",)
    assert r.previous_outputs == (sha("analysis-1"), sha("plan-1"))
    assert r.remaining_budget == 2
    assert world.runner.started == []


def test_materializer_refusal_repairs_planning(world):
    j = world.submit()
    world.analysis(j)
    world.materializer.refusals[(sha("plan-1"), binding()
                                 .execution_harness_id)] = \
        MaterializeRejected(reason="call_not_admitted", detail="mount$nfs")
    world.plan(j)
    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.pending_task.repair.cause is RepairCause.MATERIALIZER_REJECTED
    assert job.pending_task.repair.findings == ("call_not_admitted",
                                                "mount$nfs")
    assert job.counters.agent_repair_stage1 == 1


def test_neutral_control_unavailable_is_a_fixture_gap(world):
    j = world.submit()
    world.analysis(j)
    world.materializer.refusals[(sha("plan-1"), binding()
                                 .execution_harness_id)] = \
        MaterializeRejected(reason="neutral_control_unavailable",
                            profile="v4.1-tcp")
    world.plan(j)
    job = world.job(j)
    assert job.state is JobState.BLOCKED_HARNESS_GAP
    assert job.gap == GapRef(gap_class=GapClass.FIXTURE_OR_TOOL,
                             missing_capability_id="neutral_control.v4.1-tcp")
    assert job.counters.agent_repair_stage1 == 0


def test_approval_policy_requires_approval(make_world):
    w = make_world(approval_required=True)
    j = w.submit()
    w.analysis(j)
    w.plan(j)
    job = w.job(j)
    assert job.state is JobState.S1_APPROVAL
    assert job.pending_task.kind is TaskKind.HUMAN
    assert job.pending_task.input_digest == \
        job.harness.review_manifest_sha256
    assert w.runner.started == []


def test_approval_of_the_current_manifest_runs(make_world):
    w = make_world(approval_required=True)
    j = w.submit()
    w.analysis(j)
    w.plan(j)
    job = w.job(j)
    w.c.approve(j, job.pending_task.task_id,
                job.harness.review_manifest_sha256, "decision-1")
    job = w.job(j)
    assert job.state is JobState.S1_RUNNING
    assert w.runner.started == [job.pending_task.task_id]


def test_approval_of_another_manifest_is_not_an_approval(make_world):
    w = make_world(approval_required=True)
    j = w.submit()
    w.analysis(j)
    w.plan(j)
    before = w.job(j)
    w.c.approve(j, before.pending_task.task_id, sha("other"), "decision-1")
    job = w.job(j)
    assert job.state is JobState.S1_APPROVAL
    assert job.pending_task == before.pending_task
    assert w.store.transitions(j)[-1].reason == "approval_hash_mismatch"


def test_denial_repairs_planning(make_world):
    w = make_world(approval_required=True)
    j = w.submit()
    w.analysis(j)
    w.plan(j)
    w.c.deny(j, w.job(j).pending_task.task_id, "uses the wrong export")
    job = w.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.pending_task.repair.cause is RepairCause.REVIEWER_DENIED
    assert job.pending_task.repair.findings == ("uses the wrong export",)


def test_no_approval_needed_runs_at_once(world):
    j = world.to_running()
    job = world.job(j)
    assert job.pending_task.kind is TaskKind.RUNNER
    assert world.runner.started == [job.pending_task.task_id]


def test_unsupported_opens_the_gap(world):
    j = world.submit()
    world.analysis(j)
    world.agent_ok(j, UnsupportedOutput(
        gap_class=GapClass.SYZLANG,
        missing_capability_id="syzlang.nfs4.op_lock", reason="no LOCK op"))
    job = world.job(j)
    gap = GapRef(gap_class=GapClass.SYZLANG,
                 missing_capability_id="syzlang.nfs4.op_lock")
    assert job.state is JobState.BLOCKED_HARNESS_GAP and job.gap == gap
    assert world.issues.links[gap] == [j]


def test_unsupported_outside_the_vocabulary_goes_to_an_operator(world):
    for cap in ("syzlang.made_up", ""):
        j = world.submit()
        world.analysis(j)
        world.agent_ok(j, UnsupportedOutput(gap_class=GapClass.SYZLANG,
                                            missing_capability_id=cap,
                                            reason="needs a new call"))
        job = world.job(j)
        assert job.state is JobState.BLOCKED_OPERATOR
        assert job.state_reason == BlockedReason.GAP_ID_UNKNOWN.value
    assert world.issues.issues == {}


def test_reanalysis_required_repairs_analysis(world):
    j = world.submit()
    world.analysis(j)
    world.agent_ok(j, ReanalysisRequired(reason="wrong state assumption"))
    job = world.job(j)
    assert job.state is JobState.S1_ANALYSIS
    assert job.pending_task.repair.cause is \
        RepairCause.REANALYSIS_REQUESTED
    assert job.counters.agent_repair_stage1 == 1


def test_reached_keeps_the_stage2_input(world):
    j = world.to_running()
    bundle = world.run(j, Q1Status.REACHED)
    job = world.job(j)
    assert job.state is JobState.S1_REACHED
    assert job.pending_task is None
    s2 = job.stage2_input
    assert s2.bundle_ref == bundle and s2.plan_ref == sha("plan-1")
    assert s2.execution_harness_id == binding().execution_harness_id
    assert s2.q1_verdict_id == world.store.verdicts(j)[-1].verdict_id


def test_not_reached_repairs_planning(world):
    j = world.to_running()
    bundle = world.run(j, Q1Status.NOT_REACHED)
    job = world.job(j)
    assert job.state is JobState.S1_PLANNING
    r = job.pending_task.repair
    assert r.cause is RepairCause.Q1_NOT_REACHED
    assert r.evidence_refs == (bundle,)
    assert job.counters.agent_repair_stage1 == 1


def test_infra_loss_and_unsealed_end_rerun_the_same_harness(world):
    j = world.to_running()
    first = world.job(j).pending_task.task_id
    world.run(j, Q1Status.INCONCLUSIVE, "infra")
    second = world.job(j).pending_task.task_id
    world.crash_run(j)
    third = world.job(j).pending_task.task_id
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert len({first, second, third}) == 3
    assert world.runner.started == [first, second, third]
    assert job.counters.runtime_retry == 2
    harnesses = {world.runner.tasks[t]["input"].harness_ref
                 for t in (first, second, third)}
    assert len(harnesses) == 1


def test_loss_reruns(world):
    j = world.to_running()
    world.run(j, Q1Status.INCONCLUSIVE, "loss")
    assert world.job(j).state is JobState.S1_RUNNING
    assert world.job(j).counters.runtime_retry == 1


def test_evidence_and_mapping_go_to_an_operator(make_world):
    for reason, blocked in (("evidence", BlockedReason.Q1_EVIDENCE),
                            ("mapping", BlockedReason.Q1_MAPPING)):
        w = make_world()
        j = w.to_running()
        w.run(j, Q1Status.INCONCLUSIVE, reason)
        job = w.job(j)
        assert job.state is JobState.BLOCKED_OPERATOR
        assert job.state_reason == blocked.value
        assert len(w.agents.requests) == 2      # analysis and planning


def test_unsupported_attribution_is_a_remote_kcov_gap(world):
    j = world.to_running()
    gap = GapRef(gap_class=GapClass.REMOTE_KCOV_ATTRIBUTION,
                 missing_capability_id="remote_kcov.context.softirq")
    world.run(j, Q1Status.INCONCLUSIVE, "unsupported_attribution", gap)
    job = world.job(j)
    assert job.state is JobState.BLOCKED_HARNESS_GAP and job.gap == gap


def test_issue_resolved_rebinds_and_resumes(world):
    j = world.submit(function_submission(commit=OTHER_COMMIT))
    gap = world.job(j).gap
    world.registry.put(binding(commit=OTHER_COMMIT))
    world.c.on_issue(gap, "resolved")
    job = world.job(j)
    states = [t.to_state for t in world.store.transitions(j)]
    assert JobState.RETRY_PENDING in states
    assert job.state is JobState.S1_ANALYSIS
    assert job.binding == binding(commit=OTHER_COMMIT)


def test_issue_deferred_parks_and_reopened_blocks_again(world):
    j = world.submit(function_submission(commit=OTHER_COMMIT))
    gap = world.job(j).gap
    world.c.on_issue(gap, "deferred")
    assert world.job(j).state is JobState.PARKED
    world.c.on_issue(gap, "reopened")
    assert world.job(j).state is JobState.BLOCKED_HARNESS_GAP
    world.c.on_issue(gap, "deferred")
    world.c.on_issue(gap, "wont_fix", "out of scope")
    job = world.job(j)
    assert job.state is JobState.CLOSED_UNSUPPORTED
    assert job.state_reason == "out of scope"


def test_resolved_gap_with_no_harness_still_blocks(world):
    j = world.submit(function_submission(commit=OTHER_COMMIT))
    gap = world.job(j).gap
    world.c.on_issue(gap, "resolved")
    job = world.job(j)
    assert job.state is JobState.BLOCKED_HARNESS_GAP and job.gap == gap


def test_operator_close_and_cancel(world):
    a = world.to_running()
    running = world.job(a).pending_task.task_id
    world.c.operator(a, "cancel")
    job = world.job(a)
    assert job.state is JobState.CLOSED and job.state_reason == "cancelled"
    assert world.runner.cancel_calls[running] == 1
    assert job.cancelling_tasks == ()
    b = world.submit()
    world.c.operator(b, "close")
    assert world.job(b).state_reason == "operator_closed"


def test_operator_resume_resets_the_exhausted_counter(make_world):
    w = make_world(stage1_repair_budget=1)
    j = w.to_running()
    w.run(j, Q1Status.NOT_REACHED)          # repair 1 of 1
    w.plan(j, "plan-2")
    w.run(j, Q1Status.NOT_REACHED)          # budget exhausted
    job = w.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == BlockedReason.STAGE1_REPAIR_BUDGET.value
    assert job.counters.agent_repair_stage1 == 1
    w.c.operator(j, "resume")
    job = w.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.pending_task.repair.cause is RepairCause.Q1_NOT_REACHED
    assert job.counters.agent_repair_stage1 == 1  # reset, then this repair


def test_policy_change_applies_to_later_transitions(world):
    world.store.save_policy(policy("p2", approval_required=True))
    j = world.submit()
    world.analysis(j)
    world.c.set_policy(j, "p2")
    world.plan(j)
    job = world.job(j)
    assert job.job_policy_id == "p2"
    assert job.state is JobState.S1_APPROVAL
    assert world.store.transitions(j)[-1].job_policy_id == "p2"
