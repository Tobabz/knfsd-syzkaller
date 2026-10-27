"""M7 stage 2 in the Controller (03-nfs-proxy/06 §30, 07 §5.3 item 7).

A Stage 2 job meets a ``mutation_engine`` gap; its generation passes with a
staged HCAP that pins a semantic subset with crash survival pending.  The
semantic promotion has no probe campaign: a natural crash of the job's
Stage 2 campaign on the staged binding, once replayed, goes to the
recorder, and a person decides at the end of Stage 2 (crash review).
Fakes for the judges, the Runner and the recorder; no VM.
"""

from __future__ import annotations

import pytest

from agent_pipeline.contracts import (CompileRejected, GapClass, GapRef,
                                      Q1Status)
from agent_pipeline.controller.generation import ExtensionOutput
from agent_pipeline.controller.promotion import (PromotionState,
                                                 SemanticStatus)
from agent_pipeline.controller.records import JobState

from .fakes import (FakeCampaigner, FakeGenerator, FakeSemanticRecorder,
                    FakeValidator, binding, sha)
from .test_stage2_gate import passed, pending, replay, segment, stage2
from .test_stage2_strategy import reached, rule_set

CAP = "semantic.nfs4.open_reply"
GAP = GapRef(gap_class=GapClass.MUTATION_ENGINE, missing_capability_id=CAP)
STAGED = binding(execution="build-g1", hcap="hcap-g1")
SHARED = binding(execution="build-g1", hcap="hcap-shared")
SUBSET = "semantic.generated"


def _world(make_world, *, semantic=True, campaigns=False):
    w = make_world(harness_generation_budget=2)
    w.generator = FakeGenerator()
    w.validator = FakeValidator()
    w.campaigner = FakeCampaigner() if campaigns else None
    w.semantic = FakeSemanticRecorder() if semantic else None
    w.promotion_inputs.pending["hcap-g1"] = (SUBSET,)
    w.controller = w._controller()
    stage2(w)
    w.compiler.refusals[(sha("rules-1"), "hcap-1")] = CompileRejected(
        reason="unsupported_capability", missing_capability_id=CAP)
    return w


def _staged(w) -> str:
    """A Stage 2 job on the generation's staged binding, in its
    campaign."""
    job_id = reached(w)
    w.hcap.vocabulary.add(CAP)
    w.c.start_stage2(job_id)
    rule_set(w, job_id)
    assert w.job(job_id).gap == GAP
    r = w.generator.requests[-1]
    w.c.on_generation_result(r.task_id, r.attempt,
                             ExtensionOutput(patch_set_ref=sha("ps-1")))
    w.validator.finish(w.validator.submitted[-1], "passed", binding=STAGED)
    w.c.poll()
    # A new execution harness: Stage 1 again, then Stage 2 on it.
    assert w.job(job_id).binding == STAGED
    w.run(job_id, Q1Status.REACHED)
    w.c.start_stage2(job_id)
    if w.job(job_id).state is JobState.S2_STRATEGY:
        rule_set(w, job_id)
    assert w.job(job_id).state is JobState.S2_GATE, w.job(job_id).state
    passed(w, job_id)
    return job_id


def _crash(w, job_id) -> str:
    """A natural crash of the campaign, replayed: crash review."""
    segment(w, job_id, q2="observed", applied=("r000",))
    name = f"replay-{pending(w, job_id).task_id}"
    return name


def _promotion(w):
    (p,) = w.store.promotions()
    return w.store.promotion(p.promotion_id)


def _evidence(run="run-1"):
    return SemanticStatus(state="evidence", subset_id=SUBSET,
                          run_ref=sha(run), record_ref=sha("registry", run),
                          hcap_revision="hcap-candidate")


def test_a_natural_crash_replayed_equivalent_is_review(make_world):
    w = _world(make_world)
    job_id = _staged(w)
    p = _promotion(w)
    assert (p.kind, p.state) == ("semantic", PromotionState.COLLECTING)
    assert [c.capability_id for c in p.capabilities] == [SUBSET]
    # No probe campaign, and nothing withheld.
    assert p.withheld_program_sha256s == ()
    name = _crash(w, job_id)
    w.semantic.answers[name] = _evidence()
    replay(w, job_id)
    j = w.job(job_id)
    assert j.state is JobState.CRASH_REVIEW and j.replay.bundle_ref == name
    assert w.semantic.calls == [(p.promotion_id, name)]
    p = _promotion(w)
    assert p.state is PromotionState.REVIEW
    assert p.examined == (name,)
    assert p.candidate_hcap_revision == "hcap-candidate"
    assert p.evidence_refs == (sha("run-1"),)
    assert p.capabilities[0].record_ref == sha("registry", "run-1")
    # Judged once: poll() does not ask again.
    w.c.poll()
    assert len(w.semantic.calls) == 1
    assert w.c.replay(job_id) == w.job(job_id)


def test_a_replay_that_is_not_evidence_keeps_collecting(make_world):
    w = _world(make_world)
    job_id = _staged(w)
    name = _crash(w, job_id)
    replay(w, job_id, "replay_diverged")
    p = _promotion(w)
    assert p.state is PromotionState.COLLECTING and p.examined == (name,)
    # The campaign goes on; the next crash is judged in turn.
    w.c.operator(job_id, "resume")
    second = _crash(w, job_id)
    w.semantic.answers[second] = _evidence("run-2")
    replay(w, job_id)
    p = _promotion(w)
    assert p.state is PromotionState.REVIEW
    assert p.examined == tuple(sorted((name, second)))


def test_a_crash_without_its_delta_refuses_the_subset(make_world):
    w = _world(make_world)
    job_id = _staged(w)
    name = _crash(w, job_id)
    w.semantic.answers[name] = SemanticStatus(
        state="unreproducible", subset_id=SUBSET, run_ref=sha("run-1"),
        record_ref=sha("unreproducible"))
    replay(w, job_id)
    p = _promotion(w)
    assert (p.state, p.reason) == (PromotionState.NOT_MET,
                                   f"{SUBSET}:unreproducible_crash")
    c = p.capabilities[0]
    assert (c.result, c.reason, c.record_ref, c.evidence_ref) == (
        "refused", "unreproducible_crash", sha("unreproducible"), None)
    # The staged binding stays; an operator may collect again.
    assert w.job(job_id).binding == STAGED
    p = w.c.retry_promotion(p.promotion_id)
    assert p.state is PromotionState.COLLECTING
    assert p.capabilities[0].result is None and p.examined == (name,)


def test_an_unavailable_recorder_is_asked_again(make_world):
    w = _world(make_world)
    job_id = _staged(w)
    name = _crash(w, job_id)
    w.semantic.answers[name] = SemanticStatus(
        state="unavailable", reason="staged_proxy_missing")
    replay(w, job_id)
    assert _promotion(w).examined == ()
    w.semantic.answers[name] = _evidence()
    w.c.poll()
    assert _promotion(w).state is PromotionState.REVIEW


def test_a_failing_recorder_is_recorded_and_sent_again(make_world):
    w = _world(make_world)
    job_id = _staged(w)
    name = _crash(w, job_id)
    w.semantic.answers[name] = OSError("cas unreadable")
    replay(w, job_id)
    assert w.job(job_id).state is JobState.CRASH_REVIEW
    assert any(f.effect == "promotion" for f in w.c.failures)
    w.expected_failures += 1
    w.semantic.answers[name] = _evidence()
    w.c.poll()
    assert _promotion(w).state is PromotionState.REVIEW


def test_a_person_decides_only_at_the_end_of_stage_2(make_world):
    w = _world(make_world)
    job_id = _staged(w)
    name = _crash(w, job_id)
    w.semantic.answers[name] = _evidence()
    p = _promotion(w)
    # In the middle of Stage 2 (the replay runs) there is nothing to
    # decide, and the promotion is not yet in review.
    with pytest.raises(ValueError, match="end of Stage 2"):
        w.c.approve_promotion(p.promotion_id, "d-1")
    replay(w, job_id)
    assert w.c.promotion_due(w.job(job_id)).promotion_id == p.promotion_id
    p = w.c.approve_promotion(p.promotion_id, "d-1", "natural crash")
    assert p.state is PromotionState.APPROVED
    assert p.review.job_ids == (job_id,)
    assert p.review.evidence_refs == (sha("run-1"),)


def test_an_approved_promotion_ends_when_the_registry_pins_it_passed(
        make_world):
    w = _world(make_world)
    job_id = _staged(w)
    name = _crash(w, job_id)
    w.semantic.answers[name] = _evidence()
    replay(w, job_id)
    p = w.c.approve_promotion(_promotion(w).promotion_id, "d-1")
    # The host registers the candidate revision on the shared binding.
    w.registry.put(SHARED)
    w.c.on_registry_changed()
    assert _promotion(w).state is PromotionState.APPROVED
    w.promotion_inputs.subsets["hcap-shared"] = {(SUBSET, sha("run-1"))}
    w.c.on_registry_changed()
    p = _promotion(w)
    assert p.state is PromotionState.PROMOTED and p.issue_resolved


def test_a_rejected_semantic_promotion_sends_the_job_back_to_the_gap(
        make_world):
    w = _world(make_world)
    job_id = _staged(w)
    name = _crash(w, job_id)
    w.semantic.answers[name] = _evidence()
    replay(w, job_id)
    p = w.c.reject_promotion(_promotion(w).promotion_id, "d-1")
    assert p.state is PromotionState.REJECTED
    assert w.job(job_id).binding != STAGED


def test_a_host_without_a_recorder_promotes_no_semantic_subset(make_world):
    w = _world(make_world, semantic=False, campaigns=True)
    _staged(w)
    assert list(w.store.promotions()) == []
    assert w.campaigner.submitted == []


def test_a_staged_hcap_without_a_pending_subset_fails(make_world):
    w = _world(make_world)
    w.promotion_inputs.pending.clear()
    _staged(w)
    p = _promotion(w)
    assert (p.kind, p.state, p.reason) == (
        "semantic", PromotionState.FAILED, "no_pending_subset")
