"""09 §3.2: a gap starts Harness Generation instead of stopping the job.

The generation Agent and the validation Runner are fakes; what is checked is
the Controller path: one generation per gap key, its budget and limits, the
staged binding a passed one gives every waiting job, and the
blocked_harness_gap fallback with the operator's retry_generation.
"""

import pytest

from agent_pipeline.contracts import GapClass, GapRef, UnsupportedOutput
from agent_pipeline.controller.generation import (ExtensionOutput,
                                                  GenerationState,
                                                  InfeasibleOutput)
from agent_pipeline.controller.records import JobState, TaskKind

from .fakes import FakeGenerator, FakeValidator, binding, sha

GAP = GapRef(gap_class=GapClass.SYZLANG,
             missing_capability_id="syzlang.nfs4.op_lock")
STAGED = binding(hcap="hcap-g1")


def _generating(make_world, budget=2, configured=True, **kw):
    w = make_world(harness_generation_budget=budget, **kw)
    if configured:
        w.generator = FakeGenerator()
        w.validator = FakeValidator()
        w.controller = w._controller()
    return w


def _to_gap(w) -> str:
    j = w.submit()
    w.analysis(j)
    w.agent_ok(j, UnsupportedOutput(
        gap_class=GAP.gap_class, missing_capability_id=GAP.missing_capability_id,
        reason="no LOCK op", proposal_ref=None))
    return j


def _answer(w, output, request=None):
    r = request or w.generator.requests[-1]
    w.c.on_generation_result(r.task_id, r.attempt, output)
    return r


def _extension(w, name="ps-1"):
    return _answer(w, ExtensionOutput(patch_set_ref=sha(name)))


def _validate(w, state, **kw):
    task_id = w.validator.submitted[-1]
    w.validator.finish(task_id, state, **kw)
    w.c.poll()
    return task_id


def _reasons(w, j):
    return [t.reason for t in w.store.transitions(j)]


def test_no_budget_keeps_the_fallback(make_world):
    w = _generating(make_world, budget=0)
    j = _to_gap(w)
    assert w.job(j).state is JobState.BLOCKED_HARNESS_GAP
    assert w.generator.requests == []
    assert w.store.generations() == []


def test_a_host_without_a_generator_falls_back(make_world):
    w = _generating(make_world, configured=False)
    j = _to_gap(w)
    job = w.job(j)
    assert job.state is JobState.BLOCKED_HARNESS_GAP and job.gap == GAP
    assert _reasons(w, j)[-1] == "generation_unavailable"
    assert w.issues.links[GAP] == [j]
    # Retrying on that host ends the same way.
    w.c.retry_generation(j)
    assert w.job(j).state is JobState.BLOCKED_HARNESS_GAP


def test_a_gap_starts_generation_and_a_pass_resumes_on_the_staged_binding(
        make_world):
    w = _generating(make_world)
    j = _to_gap(w)
    job = w.job(j)
    assert job.state is JobState.HARNESS_GENERATING
    assert job.gap == GAP and job.pending_task is None
    assert w.issues.links[GAP] == [j]
    (req,) = w.generator.requests
    assert req.gap == GAP and req.attempt == 1 and req.previous == ()
    assert req.candidate == job.candidate
    assert req.analysis_ref == job.analysis_ref
    assert req.base_binding == binding()
    _extension(w)
    (task_id,) = w.validator.submitted
    v = w.validator.inputs[task_id]
    assert v.patch_set_ref == sha("ps-1") and v.base_binding == binding()
    assert w.job(j).state is JobState.HARNESS_GENERATING
    _validate(w, "passed", binding=STAGED)
    job = w.job(j)
    # Resumed where the gap stopped it: Planning, on the staged revision.
    assert job.state is JobState.S1_PLANNING
    assert job.binding == STAGED and job.gap is None
    assert job.staged.binding == STAGED
    assert w.agents.requests[-1].hcap_revision == "hcap-g1"
    assert _reasons(w, j)[-2:] == ["generation_passed", "rebind"]
    (g,) = w.store.generations()
    assert g.state is GenerationState.PASSED and g.staged_binding == STAGED
    assert w.c.replay(j) == job


def test_jobs_of_one_gap_key_share_one_generation(make_world):
    w = _generating(make_world)
    a = _to_gap(w)
    b = _to_gap(w)
    assert len(w.generator.requests) == 1
    assert len(w.store.generations()) == 1
    _extension(w)
    _validate(w, "passed", binding=STAGED)
    for j in (a, b):
        assert w.job(j).state is JobState.S1_PLANNING
        assert w.job(j).binding == STAGED
    # A later job of the key takes the staged harness without a generation.
    c = _to_gap(w)
    assert w.job(c).state is JobState.S1_PLANNING
    assert w.job(c).binding == STAGED
    assert len(w.generator.requests) == 1


def test_a_rejection_regenerates_until_the_budget_is_spent(make_world):
    w = _generating(make_world, budget=2)
    j = _to_gap(w)
    _extension(w, "ps-1")
    _validate(w, "rejected", reason="regression:HCAP-01",
              evidence_ref=sha("bundle-1"))
    assert w.job(j).state is JobState.HARNESS_GENERATING
    second = w.generator.requests[-1]
    assert second.task_id.endswith(".a2") and second.attempt == 1
    (prior,) = second.previous
    assert prior.patch_set_ref == sha("ps-1")
    assert prior.rejection == "regression:HCAP-01"
    assert prior.evidence_ref == sha("bundle-1")
    _extension(w, "ps-2")
    _validate(w, "rejected", reason="not_reached")
    job = w.job(j)
    assert job.state is JobState.BLOCKED_HARNESS_GAP and job.gap == GAP
    assert job.state_reason == GAP.gap_class.value
    assert _reasons(w, j)[-1] == "generation_exhausted"
    (g,) = w.store.generations()
    assert g.state is GenerationState.EXHAUSTED
    assert job.generation_refused == g.generation_id
    assert job.resume_point.kind.value == "planning"


def test_retry_generation_starts_a_new_budget(make_world):
    w = _generating(make_world, budget=1)
    j = _to_gap(w)
    _extension(w)
    _validate(w, "rejected", reason="not_reached")
    assert w.job(j).state is JobState.BLOCKED_HARNESS_GAP
    w.c.retry_generation(j)
    assert w.job(j).state is JobState.HARNESS_GENERATING
    first, second = w.store.generations()
    assert first.state is GenerationState.EXHAUSTED
    assert second.state is GenerationState.GENERATING
    assert w.generator.requests[-1].generation_id == second.generation_id
    # Polling again does not start a third.
    w.c.poll()
    assert len(w.store.generations()) == 2
    _extension(w)
    _validate(w, "passed", binding=STAGED)
    assert w.job(j).state is JobState.S1_PLANNING
    assert w.c.replay(j) == w.job(j)


def test_a_retry_joins_a_newer_generation_another_job_started(make_world):
    w = _generating(make_world, budget=1)
    a = _to_gap(w)
    b = _to_gap(w)
    _answer(w, InfeasibleOutput(reason="needs a kernel change"))
    assert w.job(a).state is JobState.BLOCKED_HARNESS_GAP
    assert w.job(b).state is JobState.BLOCKED_HARNESS_GAP
    w.c.retry_generation(a)
    w.c.retry_generation(b)
    assert len(w.store.generations()) == 2
    _extension(w)
    _validate(w, "passed", binding=STAGED)
    assert w.job(a).state is JobState.S1_PLANNING
    assert w.job(b).state is JobState.S1_PLANNING


def test_infeasible_blocks_and_a_later_job_of_the_key_waits_on_the_issue(
        make_world):
    w = _generating(make_world)
    a = _to_gap(w)
    _answer(w, InfeasibleOutput(reason="needs a kernel change"))
    assert w.job(a).state is JobState.BLOCKED_HARNESS_GAP
    assert _reasons(w, a)[-1] == "generation_infeasible"
    b = _to_gap(w)
    # The key's generation refused already: no second one by itself.
    assert w.job(b).state is JobState.BLOCKED_HARNESS_GAP
    assert len(w.generator.requests) == 1
    assert w.issues.links[GAP] == [a, b]


def test_agent_failures_retry_then_fail_the_generation(make_world):
    w = _generating(make_world, agent_retry_limit=1)
    j = _to_gap(w)
    r = w.generator.requests[-1]
    w.c.on_generation_failure(r.task_id, r.attempt, "timeout")
    again = w.generator.requests[-1]
    assert again.task_id == r.task_id and again.attempt == r.attempt + 1
    # A late answer of the failed try is not taken.
    _answer(w, ExtensionOutput(patch_set_ref=sha("late")), request=r)
    assert w.validator.submitted == []
    w.c.on_generation_failure(again.task_id, again.attempt, "timeout")
    assert w.job(j).state is JobState.BLOCKED_HARNESS_GAP
    assert _reasons(w, j)[-1] == "generation_failed"
    (g,) = w.store.generations()
    assert g.reason == "agent_failure:timeout"


def test_an_inconclusive_validation_runs_again_then_fails(make_world):
    w = _generating(make_world, runtime_retry_limit=1)
    j = _to_gap(w)
    _extension(w)
    first = _validate(w, "inconclusive", reason="vm_lost")
    second = w.validator.submitted[-1]
    assert first.endswith(".v1") and second.endswith(".v2")
    assert w.job(j).state is JobState.HARNESS_GENERATING
    _validate(w, "inconclusive", reason="vm_lost")
    assert w.job(j).state is JobState.BLOCKED_HARNESS_GAP
    (g,) = w.store.generations()
    assert g.state is GenerationState.FAILED
    assert g.reason == "runtime_retry_exhausted:vm_lost"


def test_a_registry_change_during_generation_moves_only_the_resume_point(
        make_world):
    w = _generating(make_world)
    j = _to_gap(w)
    sent = len(w.agents.requests)
    w.registry.put(binding(execution="build-2"))
    w.c.on_registry_changed()
    job = w.job(j)
    assert job.state is JobState.HARNESS_GENERATING
    assert job.binding == binding(execution="build-2")
    assert job.pending_task is None and len(w.agents.requests) == sent
    assert job.resume_point.kind.value == "planning"
    assert len(w.generator.requests) == 1
    # Its pass was built on a base the registry no longer has: the job
    # does not take it, a new generation starts on the new base.
    _extension(w)
    _validate(w, "passed", binding=STAGED)
    assert w.job(j).state is JobState.HARNESS_GENERATING
    _, second = w.store.generations()
    assert second.base_binding == binding(execution="build-2")


def test_an_issue_resolved_during_generation_rebinds_from_the_registry(
        make_world):
    w = _generating(make_world)
    j = _to_gap(w)
    w.registry.put(binding(hcap="hcap-2"))
    w.c.on_issue(GAP, "resolved")
    job = w.job(j)
    assert job.state is JobState.S1_PLANNING
    assert job.binding == binding(hcap="hcap-2") and job.staged is None


def test_a_deferred_issue_parks_a_generating_job(make_world):
    w = _generating(make_world)
    j = _to_gap(w)
    w.c.on_issue(GAP, "deferred")
    assert w.job(j).state is JobState.PARKED
    # The generation goes on; its pass does not take a parked job.
    _extension(w)
    _validate(w, "passed", binding=STAGED)
    assert w.job(j).state is JobState.PARKED
    w.c.retry_generation(j)
    assert w.job(j).state is JobState.S1_PLANNING
    assert w.job(j).binding == STAGED


def test_the_staged_binding_holds_until_the_registry_moves(make_world):
    w = _generating(make_world)
    j = _to_gap(w)
    _extension(w)
    _validate(w, "passed", binding=STAGED)
    w.c.on_registry_changed()
    w.restart()
    assert w.job(j).binding == STAGED
    # A promotion changes the registry: the job follows it.
    promoted = binding(hcap="hcap-3")
    w.registry.put(promoted)
    w.c.on_registry_changed()
    job = w.job(j)
    assert job.binding == promoted and job.staged is None


def test_a_staged_binding_that_still_meets_the_gap_is_not_used_again(
        make_world):
    w = _generating(make_world)
    j = _to_gap(w)
    _extension(w)
    _validate(w, "passed", binding=STAGED)
    w.agent_ok(j, UnsupportedOutput(
        gap_class=GAP.gap_class, missing_capability_id=GAP.missing_capability_id,
        reason="still no LOCK op"))
    job = w.job(j)
    assert job.state is JobState.BLOCKED_HARNESS_GAP
    assert _reasons(w, j)[-1] == "generation_not_filled"
    # retry_generation starts a new one, on the registry's base.
    w.c.retry_generation(j)
    _, second = w.store.generations()
    assert second.state is GenerationState.GENERATING


def test_restart_sends_a_new_agent_try_and_reattaches_validation(make_world):
    w = _generating(make_world)
    j = _to_gap(w)
    old = w.generator.requests[-1]
    w.restart()
    new = w.generator.requests[-1]
    assert new.task_id == old.task_id and new.attempt == old.attempt + 1
    _answer(w, ExtensionOutput(patch_set_ref=sha("old")), request=old)
    assert w.validator.submitted == []
    _extension(w)
    task_id = w.validator.submitted[-1]
    w.restart()
    assert w.validator.submitted[-1] == task_id     # same task, re-attached
    _validate(w, "passed", binding=STAGED)
    assert w.job(j).state is JobState.S1_PLANNING


def test_a_failed_agent_send_is_sent_again_by_poll(make_world):
    w = _generating(make_world)

    def refuse(request):
        raise OSError("executor down")
    start = w.generator.start
    w.generator.start = refuse
    j = _to_gap(w)
    w.expected_failures = 1
    assert w.job(j).state is JobState.HARNESS_GENERATING
    w.generator.start = start
    w.c.poll()
    (req,) = w.generator.requests
    assert req.attempt == 2
    _extension(w)
    _validate(w, "passed", binding=STAGED)
    assert w.job(j).state is JobState.S1_PLANNING


def test_a_staged_binding_for_another_build_key_fails_the_generation(
        make_world):
    w = _generating(make_world)
    j = _to_gap(w)
    _extension(w)
    _validate(w, "passed", binding=binding(commit="c" * 40, hcap="x"))
    assert w.job(j).state is JobState.BLOCKED_HARNESS_GAP
    (g,) = w.store.generations()
    assert g.reason == "validation_binding_mismatch"


@pytest.mark.parametrize("state", [JobState.BLOCKED_OPERATOR,
                                   JobState.S1_PLANNING])
def test_retry_generation_needs_a_gap_wait(make_world, state):
    w = _generating(make_world)
    j = w.submit()
    w.analysis(j)
    if state is JobState.BLOCKED_OPERATOR:
        w.agent_ok(j, UnsupportedOutput(gap_class=GapClass.SYZLANG,
                                        missing_capability_id="syzlang.x",
                                        reason="?"))
    assert w.job(j).state is state
    assert w.c.retry_generation(j) is None
    assert w.job(j).pending_task is None or \
        w.job(j).pending_task.kind is TaskKind.AGENT


def test_the_default_budget_is_three_and_a_legacy_policy_keeps_it_off(
        tmp_path):
    import json

    from agent_pipeline.contracts import JobPolicy, Sanitizer
    from agent_pipeline.controller.store import Store

    assert JobPolicy(policy_id="new",
                     sanitizer=Sanitizer.KASAN).harness_generation_budget == 3
    store = Store(tmp_path / "jobs.sqlite")
    legacy = JobPolicy(policy_id="old", sanitizer=Sanitizer.KASAN)
    body = json.loads(legacy.model_dump_json())
    del body["harness_generation_budget"]
    store.db.execute("INSERT INTO policies VALUES (?, ?)",
                     ("old", json.dumps(body)))
    # Read with generation off, so its jobs replay what they did.
    assert store.policy("old").harness_generation_budget == 0
    # The same policy given again (a host restart) is still the same.
    store.save_policy(JobPolicy(policy_id="old", sanitizer=Sanitizer.KASAN))
    assert store.policy("old").harness_generation_budget == 0
    # Turning generation on needs a new policy identity.
    with pytest.raises(ValueError):
        store.save_policy(JobPolicy(policy_id="old", sanitizer=Sanitizer.KASAN,
                                    harness_generation_budget=3))
    store.save_policy(JobPolicy(policy_id="new", sanitizer=Sanitizer.KASAN))
    assert store.policy("new").harness_generation_budget == 3
