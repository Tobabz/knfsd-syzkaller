"""07 §5.3: the promotion of a staged harness.

The generation Agent, the validation and campaign Runners and the CAS reads
are fakes; what is checked is the Controller path: the candidate programs
it withholds, one campaign per changed capability, the review, the registry
that ends a promotion, the issue it resolves, and a rejection that sends
the jobs back to the gap.  The jobs' own path never waits on any of it.
"""

import pytest

from agent_pipeline.contracts import (GapClass, GapRef, Q1Status,
                                     UnsupportedOutput)
from agent_pipeline.controller.generation import (ExtensionOutput,
                                                  GenerationState)
from agent_pipeline.controller.promotion import PromotionState
from agent_pipeline.controller.records import JobState

from .fakes import (FakeCampaigner, FakeGenerator, FakeValidator, binding,
                    sha)

GAP = GapRef(gap_class=GapClass.SYZLANG,
             missing_capability_id="syzlang.nfs4.op_lock")
STAGED = binding(execution="build-g1", hcap="hcap-g1")
PROMOTED = binding(execution="build-g1", hcap="hcap-promoted")


def _world(make_world, *, campaigns=True, **kw):
    w = make_world(harness_generation_budget=2, **kw)
    w.generator = FakeGenerator()
    w.validator = FakeValidator()
    w.campaigner = FakeCampaigner() if campaigns else None
    w.promotion_inputs.changed["hcap-g1"] = ("CAP-lock",)
    w.controller = w._controller()
    return w


def _to_gap(w, j=None) -> str:
    if j is None:
        j = w.submit()
        w.analysis(j)
    w.agent_ok(j, UnsupportedOutput(
        gap_class=GAP.gap_class,
        missing_capability_id=GAP.missing_capability_id,
        reason="no LOCK op", proposal_ref=None))
    return j


def _staged(w) -> str:
    j = _to_gap(w)
    r = w.generator.requests[-1]
    w.c.on_generation_result(r.task_id, r.attempt,
                             ExtensionOutput(patch_set_ref=sha("ps-1")))
    w.validator.finish(w.validator.submitted[-1], "passed", binding=STAGED)
    w.c.poll()
    assert w.job(j).binding == STAGED
    return j


def _promotion(w):
    (p,) = w.store.promotions()
    return p


def _finish(w, state, task_id=None, **kw):
    task_id = task_id or w.campaigner.submitted[-1]
    w.campaigner.finish(task_id, state, **kw)
    w.c.poll()
    return task_id


def _reached(w, j) -> None:
    """The job ends Stage 1 on the staged harness: where a person decides
    the promotion."""
    w.run(j, Q1Status.REACHED)
    assert w.job(j).state is JobState.S1_REACHED


def _evidence(w, name="ev-1", programs=("gen-1", "gen-2")):
    return _finish(w, "evidence", evidence_ref=sha(name),
                   record_ref=sha("record", name),
                   program_sha256s=tuple(sha(p) for p in programs))


def test_a_pass_campaigns_without_the_candidate_program_and_waits_for_review(
        make_world):
    w = _world(make_world)
    j = _staged(w)
    p = _promotion(w)
    # Planning on the staged binding: the candidate program is not known.
    assert w.job(j).state is JobState.S1_PLANNING
    assert p.state is PromotionState.COLLECTING
    assert p.staged_binding == STAGED and p.base_binding == binding()
    assert w.campaigner.submitted == []
    w.plan(j)
    assert w.job(j).state is JobState.S1_RUNNING
    w.c.poll()
    p = _promotion(w)
    program = sha("program", sha("plan-1"))
    assert p.state is PromotionState.CAMPAIGNING
    assert p.withheld_program_sha256s == (program,)
    (task_id,) = w.campaigner.submitted
    assert task_id == f"{p.promotion_id}.c0.r1"
    task = w.campaigner.inputs[task_id]
    assert task.capability_id == "CAP-lock" and task.binding == STAGED
    assert task.withheld_program_sha256s == (program,)
    _evidence(w)
    p = _promotion(w)
    assert p.state is PromotionState.REVIEW
    assert p.evidence_refs == (sha("ev-1"),)
    # The job went its own way the whole time.
    assert w.job(j).state is JobState.S1_RUNNING
    assert w.job(j).binding == STAGED
    assert [t.to_state for t in w.store.promotion_transitions(
        p.promotion_id)] == [PromotionState.COLLECTING,
                             PromotionState.CAMPAIGNING,
                             PromotionState.REVIEW]


def test_a_person_decides_only_at_the_end_of_stage_1(make_world):
    """User decision 2026-10-27: no human approval in the middle of a
    stage.  The evidence waits for a job on the staged harness to end
    Stage 1, and the decision is shown with that job."""
    w = _world(make_world)
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    _evidence(w)
    pid = _promotion(w).promotion_id
    assert w.job(j).state is JobState.S1_RUNNING
    assert w.c.promotion_due(w.job(j)) is None
    for decide in (w.c.approve_promotion, w.c.reject_promotion):
        with pytest.raises(ValueError, match="end of Stage 1"):
            decide(pid, "review-1")
    assert _promotion(w).state is PromotionState.REVIEW
    _reached(w, j)
    assert w.c.promotion_due(w.job(j)).promotion_id == pid
    assert w.c.approve_promotion(pid, "review-1").state is \
        PromotionState.APPROVED
    assert w.c.promotion_due(w.job(j)) is None


def test_campaigns_are_not_rejected_while_they_run(make_world):
    w = _world(make_world)
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    pid = _promotion(w).promotion_id
    _reached(w, j)
    assert _promotion(w).state is PromotionState.CAMPAIGNING
    with pytest.raises(ValueError, match="campaigning"):
        w.c.reject_promotion(pid, "review-1")


def test_an_approved_promotion_ends_when_the_registry_carries_it(make_world):
    w = _world(make_world)
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    _evidence(w)
    pid = _promotion(w).promotion_id
    _reached(w, j)
    p = w.c.approve_promotion(pid, "review-7", "looks general")
    assert p.state is PromotionState.APPROVED
    assert p.review.decision_id == "review-7"
    assert p.review.evidence_refs == (sha("ev-1"),)
    assert p.review.job_ids == (j,)
    # The registry moves to a build that does not carry the evidence.
    w.registry.put(binding(execution="build-g1", hcap="hcap-other"))
    w.c.on_registry_changed()
    assert _promotion(w).state is PromotionState.APPROVED
    # The host promoted: the registry's HCAP has the capability with it.
    w.promotion_inputs.carried["hcap-promoted"] = {("CAP-lock", sha("ev-1"))}
    w.registry.put(PROMOTED)
    w.c.on_registry_changed()
    p = _promotion(w)
    assert p.state is PromotionState.PROMOTED and p.issue_resolved
    assert w.job(j).binding == PROMOTED and w.job(j).staged is None
    with pytest.raises(ValueError):
        w.c.reject_promotion(pid, "late", "")


def test_a_promotion_resolves_its_issue_through_a_recording_tracker(
        make_world):
    w = _world(make_world)
    changes = []
    w.issues.change = lambda issue, status, resolution: changes.append(
        (issue, status, resolution))
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    _evidence(w)
    pid = _promotion(w).promotion_id
    _reached(w, j)
    w.c.approve_promotion(pid, "review-7")
    w.promotion_inputs.carried["hcap-promoted"] = {("CAP-lock", sha("ev-1"))}
    w.registry.put(PROMOTED)
    w.c.poll()
    assert changes == [("gap-1", "resolved", f"promoted:{pid}")]
    assert _promotion(w).issue_resolved
    w.c.poll()
    assert len(changes) == 1


def test_a_failed_issue_resolution_is_sent_again(make_world):
    w = _world(make_world)
    calls = []

    def change(issue, status, resolution):
        calls.append(issue)
        if len(calls) == 1:
            raise OSError("tracker down")
    w.issues.change = change
    w.expected_failures = 1
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    _evidence(w)
    _reached(w, j)
    w.c.approve_promotion(_promotion(w).promotion_id, "review-7")
    w.promotion_inputs.carried["hcap-promoted"] = {("CAP-lock", sha("ev-1"))}
    w.registry.put(PROMOTED)
    w.c.on_registry_changed()
    p = _promotion(w)
    assert p.state is PromotionState.PROMOTED and not p.issue_resolved
    w.c.poll()
    assert _promotion(w).issue_resolved and len(calls) == 2


def test_a_refused_campaign_keeps_the_staged_binding_and_can_run_again(
        make_world):
    w = _world(make_world)
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    _finish(w, "refused", reason="criteria_not_met")
    p = _promotion(w)
    assert p.state is PromotionState.NOT_MET
    assert p.reason == "CAP-lock:criteria_not_met"
    assert w.job(j).binding == STAGED
    with pytest.raises(ValueError):
        w.c.approve_promotion(p.promotion_id, "review-1")
    p = w.c.retry_promotion(p.promotion_id)
    assert p.state is PromotionState.CAMPAIGNING
    assert w.campaigner.submitted[-1] == f"{p.promotion_id}.c0.r2"
    assert w.campaigner.inputs[w.campaigner.submitted[-1]].seed == 2
    _evidence(w)
    assert _promotion(w).state is PromotionState.REVIEW


def test_an_inconclusive_campaign_runs_again_then_fails(make_world):
    w = _world(make_world, runtime_retry_limit=1)
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    first = _finish(w, "inconclusive", reason="vm_boot_failed")
    second = w.campaigner.submitted[-1]
    assert first.endswith(".r1") and second.endswith(".r2")
    p = _promotion(w)
    assert p.state is PromotionState.CAMPAIGNING
    _finish(w, "inconclusive", reason="vm_boot_failed")
    p = _promotion(w)
    assert p.state is PromotionState.FAILED
    assert p.reason == "runtime_retry_exhausted:CAP-lock:vm_boot_failed"
    assert w.job(j).binding == STAGED


def test_every_changed_capability_has_its_own_campaign(make_world):
    w = _world(make_world)
    w.promotion_inputs.changed["hcap-g1"] = ("CAP-lock", "CAP-unlock")
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    pid = _promotion(w).promotion_id
    assert sorted(w.campaigner.submitted) == [f"{pid}.c0.r1", f"{pid}.c1.r1"]
    _finish(w, "evidence", task_id=f"{pid}.c1.r1", evidence_ref=sha("ev-u"))
    assert _promotion(w).state is PromotionState.CAMPAIGNING
    _finish(w, "evidence", task_id=f"{pid}.c0.r1", evidence_ref=sha("ev-l"))
    p = _promotion(w)
    assert p.state is PromotionState.REVIEW
    assert p.evidence_refs == (sha("ev-l"), sha("ev-u"))


def test_a_later_candidate_program_the_campaign_ran_is_not_met(make_world):
    w = _world(make_world)
    a = _staged(w)
    w.plan(a)
    w.c.poll()
    _evidence(w, programs=("gen-1", "candidate-b"))
    assert _promotion(w).state is PromotionState.REVIEW
    # A second job of the key takes the staged binding and plans the
    # program the campaign generated.
    b = _to_gap(w)
    assert w.job(b).binding == STAGED
    w.promotion_inputs.plan_programs[sha("plan-b")] = (sha("candidate-b"),)
    w.plan(b, "plan-b")
    w.c.poll()
    p = _promotion(w)
    assert p.state is PromotionState.NOT_MET
    assert p.reason == "candidate_program_ran:CAP-lock"
    assert sha("candidate-b") in p.candidate_program_sha256s


def test_evidence_that_ran_a_withheld_program_is_refused(make_world):
    w = _world(make_world)
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    w.campaigner.finish(w.campaigner.submitted[-1], "evidence",
                        evidence_ref=sha("ev-1"),
                        program_sha256s=(sha("program", sha("plan-1")),))
    w.c.poll()
    p = _promotion(w)
    assert p.state is PromotionState.NOT_MET
    assert p.reason == "CAP-lock:candidate_program_ran"


def test_a_rejected_promotion_sends_the_jobs_back_to_the_gap(make_world):
    w = _world(make_world)
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    _evidence(w)
    pid = _promotion(w).promotion_id
    _reached(w, j)
    p = w.c.reject_promotion(pid, "review-9", "targets the candidate")
    assert p.state is PromotionState.REJECTED
    assert p.review.decision == "rejected"
    job = w.job(j)
    assert job.binding == binding() and job.staged is None
    # The job runs again on the registry's binding (09 §5), where the gap
    # is open.  A job that meets it waits on the issue: the generation
    # passed, but its staged harness was rejected.
    assert w.job(j).state is JobState.S1_RUNNING
    k = _to_gap(w)
    job = w.job(k)
    assert job.state is JobState.BLOCKED_HARNESS_GAP
    assert [t.reason for t in w.store.transitions(k)][-1] == \
        "generation_promotion_rejected"
    (g,) = w.store.generations()
    assert job.generation_refused == g.generation_id
    # An operator starts generation again.
    w.c.retry_generation(k)
    assert w.job(k).state is JobState.HARNESS_GENERATING
    assert len(w.store.generations()) == 2
    assert w.store.generations()[-1].state is GenerationState.GENERATING


def test_restart_reattaches_the_campaign_tasks(make_world):
    w = _world(make_world)
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    (task_id,) = w.campaigner.submitted
    w.restart()
    assert w.campaigner.submitted == [task_id, task_id]
    assert _promotion(w).state is PromotionState.CAMPAIGNING
    _evidence(w)
    assert _promotion(w).state is PromotionState.REVIEW


def test_a_lost_campaign_task_is_submitted_again(make_world):
    w = _world(make_world)
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    (task_id,) = w.campaigner.submitted
    del w.campaigner.tasks[task_id]
    w.c.poll()
    assert w.campaigner.submitted == [task_id, task_id]


def test_a_host_without_a_campaign_runner_promotes_nothing(make_world):
    w = _world(make_world, campaigns=False)
    j = _staged(w)
    w.plan(j)
    w.c.poll()
    assert w.store.promotions() == []
    # Configured later, the passed generation gets its promotion.
    w.campaigner = FakeCampaigner()
    w.restart()
    w.c.poll()
    assert _promotion(w).state is PromotionState.CAMPAIGNING


def test_a_staged_hcap_without_a_gap_capability_fails_its_promotion(
        make_world):
    w = _world(make_world)
    w.promotion_inputs.changed.clear()
    j = _staged(w)
    p = _promotion(w)
    assert p.state is PromotionState.FAILED
    assert p.reason == "no_capability_fills_gap"
    with pytest.raises(ValueError):
        w.c.retry_promotion(p.promotion_id)
    assert w.job(j).binding == STAGED
