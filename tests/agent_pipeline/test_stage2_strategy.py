"""Stage 2 Mutation Strategy: the MutationRuleSet contract (08 §5-§11), the
Agent Task over a fixed-output model, and the Controller's s1_reached ->
s2_strategy -> Compiler rows (09 §4, §5).  No LLM, no VM."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_pipeline.agent_tasks.analysis import CandidateAnalysis
from agent_pipeline.agent_tasks.executor import Stage1AgentExecutor
from agent_pipeline.agent_tasks.mutation import (MutationRuleSet,
                                                 MutationStrategyOutput)
from agent_pipeline.agent_tasks.planning import (ReachabilityPlanningOutput,
                                                 completed_plan)
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import (AgentModelPolicy, AgentTask,
                                      CompileRejected, GapClass, GapRef,
                                      JudgeVersions, PlanOutput, Q1Status,
                                      RuleSetOutput,
                                      Stage2AgentPolicy, UnsupportedOutput)
from agent_pipeline.controller.records import (BlockedReason, JobState,
                                               RepairCause, Stage2Input,
                                               TargetKind)
from agent_pipeline.controller import events as ev
from agent_pipeline.controller.tasks import AgentRequest, agent_input_payload
from agent_pipeline.data import load_record, put_record

from .fakes import FakeCompiler, binding, sha
from .test_agent_tasks import (HCAP_REVISION, DeterministicFunctionRuntime,
                               Sink, analysis_data, candidate, planning_data,
                               toolbox)


def intent(intent_id: str = "forge-stateid", **over) -> dict:
    value = {
        "intent_id": intent_id,
        "traffic_scope": {"direction": "S2C", "backend": "knfsd",
                          "client": "client0"},
        "selector": {
            "rpc": {"message_type": "reply", "program": 100003,
                    "version": 4},
            "protocol": {"family": "nfs4", "minor_version": 1},
            "operation": "OPEN",
            "target": {"kind": "field",
                       "path": "nfs4.response.OPEN.result.ok.stateid",
                       "part": "value"},
            "predicates": [
                {"lhs": {"kind": "value_ref", "source": "current_message",
                         "path": "nfs4.response.OPEN.result.status"},
                 "op": "eq", "rhs": {"kind": "enum", "name": "NFS4_OK"}},
                {"lhs": {"kind": "value_ref", "source": "request_forwarded",
                         "path":
                         "nfs4.request.OPEN.args.claim.null.filename"},
                 "op": "eq",
                 "rhs": {"kind": "string", "value": "scenario-file"}},
            ],
        },
        "mutation": {
            "kind": "replace",
            "transform": {"kind": "builtin", "transform_id": "integer_xor",
                          "args": [{"kind": "uint", "value": 1}]},
            "structure_policy": "preserve",
        },
        "targets_baseline_traffic": True,
        "expected_effect": {
            "target_state": "forged stateid reaches the validation path",
            "rationale": "the candidate trusts the reply stateid",
        },
    }
    value.update(over)
    return value


def rule_set_data(candidate_id: str = "VC-stage1", **over) -> dict:
    value = {
        "candidate_id": candidate_id,
        "intents": [intent()],
        "hypotheses": [{"hypothesis_id": "h1", "intents": ["forge-stateid"],
                        "requirement": "all"}],
        "uncertainties": [{
            "description": "the OPEN reply may be cached",
            "impact": "the mutation may not reach the candidate"}],
    }
    value.update(over)
    return value


# ---------------------------------------------------------------- contract


def test_rule_set_takes_the_08_example():
    rs = MutationRuleSet.model_validate(rule_set_data())
    i = rs.intents[0]
    assert i.selector.rpc.message_type == "reply"
    assert i.traffic_scope.direction == "S2C"
    assert i.selector.predicates[0].rhs.kind == "enum"
    assert i.selector.predicates[1].lhs.source == "request_forwarded"


@pytest.mark.parametrize("drop", [
    ("targets_baseline_traffic",),
    ("mutation", "structure_policy"),
    ("selector", "rpc", "message_type"),
    ("traffic_scope", "direction"),
])
def test_execution_fields_have_no_default(drop):
    data = intent()
    node = data
    for key in drop[:-1]:
        node = node[key]
    del node[drop[-1]]
    with pytest.raises(ValidationError):
        MutationRuleSet.model_validate(rule_set_data(intents=[data]))


@pytest.mark.parametrize("extra", [
    {"offset": 12}, {"original_bytes": "00ff"}, {"command": "rm -rf /"},
    {"retry_budget": 3}, {"constraints": ["keep framing"]},
])
def test_rule_set_has_no_raw_or_budget_field(extra):
    with pytest.raises(ValidationError):
        MutationRuleSet.model_validate(rule_set_data(
            intents=[intent(**extra)]))
    with pytest.raises(ValidationError):
        MutationRuleSet.model_validate(rule_set_data(**extra))


def test_intents_and_hypotheses_are_consistent():
    with pytest.raises(ValidationError, match="duplicate intent_id"):
        MutationRuleSet.model_validate(rule_set_data(
            intents=[intent(), intent()]))
    with pytest.raises(ValidationError, match="unknown intent"):
        MutationRuleSet.model_validate(rule_set_data(hypotheses=[{
            "hypothesis_id": "h1", "intents": ["nope"],
            "requirement": "all"}]))
    with pytest.raises(ValidationError):
        MutationRuleSet.model_validate(rule_set_data(hypotheses=[]))


@pytest.mark.parametrize("mutation", [
    {"kind": "delete", "structure_policy": "raw",
     "transform": {"kind": "literal",
                   "value": {"kind": "uint", "value": 0}}},
    {"kind": "replace", "structure_policy": "preserve"},
    {"kind": "op_append", "structure_policy": "preserve",
     "transform": {"kind": "literal",
                   "value": {"kind": "uint", "value": 0}}},
    {"kind": "insert", "structure_policy": "preserve",
     "transform": {"kind": "operation", "operation": "GETATTR"}},
])
def test_transform_matches_mutation_kind(mutation):
    with pytest.raises(ValidationError):
        MutationRuleSet.model_validate(rule_set_data(
            intents=[intent(mutation=mutation)]))


def test_op_append_takes_a_typed_operation_and_delete_none():
    for mutation in (
            {"kind": "op_append", "structure_policy": "raw",
             "transform": {"kind": "operation", "operation": "GETATTR",
                           "arguments": [{
                               "path": "attr_request",
                               "value": {"kind": "opaque",
                                         "hex": "00000001"}}]}},
            {"kind": "delete", "structure_policy": "raw"}):
        MutationRuleSet.model_validate(rule_set_data(
            intents=[intent(mutation=mutation)]))


def test_value_ref_shape_and_literal_bounds():
    bad = intent()
    bad["selector"]["predicates"][0]["lhs"] = {
        "kind": "value_ref", "source": "target", "path": "x"}
    with pytest.raises(ValidationError):
        MutationRuleSet.model_validate(rule_set_data(intents=[bad]))
    bad = intent()
    bad["selector"]["predicates"][0]["lhs"] = {
        "kind": "value_ref", "source": "current_message"}
    with pytest.raises(ValidationError):
        MutationRuleSet.model_validate(rule_set_data(intents=[bad]))
    for literal in ({"kind": "uint", "value": -1},
                    {"kind": "int", "value": 1 << 31},
                    {"kind": "opaque", "hex": "0"},
                    {"kind": "opaque", "hex": "00" * 4097}):
        bad = intent()
        bad["selector"]["predicates"][0]["rhs"] = literal
        with pytest.raises(ValidationError):
            MutationRuleSet.model_validate(rule_set_data(intents=[bad]))


def test_unsupported_is_a_mutation_engine_gap_only():
    out = MutationStrategyOutput.model_validate({
        "variant": "unsupported", "gap_class": "mutation_engine",
        "missing_capability_id": "", "reason": "needs a stale stateid"})
    assert out.root.missing_capability_id == ""
    with pytest.raises(ValidationError):
        MutationStrategyOutput.model_validate({
            "variant": "unsupported", "gap_class": "syzlang",
            "missing_capability_id": "x", "reason": "r"})


# ---------------------------------------------------------------- Agent Task


def stage1_package(store: ArtifactStore) -> tuple[str, Stage2Input]:
    analysis_ref = put_record(
        store, CandidateAnalysis.model_validate(analysis_data()))
    draft = ReachabilityPlanningOutput.model_validate_json(
        json.dumps(planning_data())).root
    program_ref = store.put(draft.plan.program.text.encode())
    plan_ref = put_record(store, completed_plan(draft.plan, program_ref))
    return analysis_ref, Stage2Input(
        q1_verdict_id="q1-1", bundle_ref=sha("bundle"), plan_ref=plan_ref,
        harness_ref=sha("harness"), execution_harness_id=sha("build-1"))


def strategy_request(analysis_ref, s2, rule_set_ref=None) -> AgentRequest:
    return AgentRequest(
        job_id="job-stage2", task_id="job-stage2.t9", attempt=1,
        agent_task=AgentTask.MUTATION_STRATEGY,
        model_policy=AgentModelPolicy(provider="test-provider",
                                      model="strategist", output_retries=1),
        candidate=candidate(), hcap_revision=HCAP_REVISION,
        analysis_ref=analysis_ref, stage2_input=s2,
        rule_set_ref=rule_set_ref)


def test_strategy_stores_the_rule_set_and_returns_its_ref(tmp_path):
    store = ArtifactStore(tmp_path)
    analysis_ref, s2 = stage1_package(store)
    runtime = DeterministicFunctionRuntime(
        [{"variant": "rule_set", "rule_set": rule_set_data("VC-other")},
         {"variant": "rule_set", "rule_set": rule_set_data()}],
        actual_model="test-provider:strategist-2")
    sink = Sink()
    Stage1AgentExecutor(runtime, store, lambda r: toolbox(), sink).start(
        strategy_request(analysis_ref, s2))

    assert not sink.failures
    _, _, output, model_id = sink.results[0]
    assert isinstance(output, RuleSetOutput)
    assert model_id == "test-provider:strategist-2"
    assert runtime.attempts == 2        # wrong candidate_id was repaired
    assert load_record(store, output.rule_set_ref, MutationRuleSet) == \
        MutationRuleSet.model_validate(rule_set_data())
    prompt = runtime.requests[0].prompt
    assert "Trusted Stage2Input JSON" in prompt
    assert "syz_test$open()" in prompt              # the Stage 1 program
    assert runtime.requests[0].tools.names[-1] == "lookup_hcap"


def test_strategy_repair_sees_the_previous_rule_set(tmp_path):
    store = ArtifactStore(tmp_path)
    analysis_ref, s2 = stage1_package(store)
    previous = put_record(store, MutationRuleSet.model_validate(
        rule_set_data()))
    runtime = DeterministicFunctionRuntime([{
        "variant": "unsupported", "gap_class": "mutation_engine",
        "missing_capability_id": "state_lineage",
        "reason": "the stateid must come from an earlier OPEN"}])
    sink = Sink()
    Stage1AgentExecutor(runtime, store, lambda r: toolbox(), sink).start(
        strategy_request(analysis_ref, s2, rule_set_ref=previous))

    _, _, output, _ = sink.results[0]
    assert output == UnsupportedOutput(
        gap_class=GapClass.MUTATION_ENGINE,
        missing_capability_id="state_lineage",
        reason="the stateid must come from an earlier OPEN")
    assert "Previous MutationRuleSet data" in runtime.requests[0].prompt


def test_strategy_without_stage2_input_fails_without_a_model_call(tmp_path):
    store = ArtifactStore(tmp_path)
    analysis_ref, _ = stage1_package(store)
    runtime = DeterministicFunctionRuntime([])
    sink = Sink()
    Stage1AgentExecutor(runtime, store, lambda r: toolbox(), sink).start(
        strategy_request(analysis_ref, None))
    assert not runtime.requests and not sink.results
    assert "Stage2Input" in sink.failures[0][2]


# ---------------------------------------------------------------- Controller

GAP = GapRef(gap_class=GapClass.MUTATION_ENGINE,
             missing_capability_id="state_lineage")


def reached(w) -> str:
    w.hcap.vocabulary.add("state_lineage")
    w.hcap.vocabulary.add("semantic.nfs4.open_reply")
    job_id = w.to_running()
    w.run(job_id, Q1Status.REACHED)
    assert w.job(job_id).state is JobState.S1_REACHED
    return job_id


def in_strategy(w) -> str:
    job_id = reached(w)
    w.c.start_stage2(job_id)
    assert w.job(job_id).state is JobState.S2_STRATEGY
    return job_id


def use_compiler(w) -> FakeCompiler:
    w.compiler = FakeCompiler()
    w.c.machine.env.compiler = w.compiler
    return w.compiler


def rule_set(w, job_id, name="rules-1") -> str:
    ref = sha(name)
    w.agent_ok(job_id, RuleSetOutput(rule_set_ref=ref))
    return ref


def unsupported(w, job_id, cap="state_lineage",
                gap_class=GapClass.MUTATION_ENGINE) -> None:
    w.agent_ok(job_id, UnsupportedOutput(
        gap_class=gap_class, missing_capability_id=cap,
        reason="needs a value from an earlier transaction"))


def test_reached_job_waits_until_an_operator_starts_stage2(world):
    job_id = reached(world)
    j = world.job(job_id)
    assert j.pending_task is None and j.stage2_basis is None
    world.c.start_stage2(job_id)

    j = world.job(job_id)
    p = j.pending_task
    assert j.state is JobState.S2_STRATEGY and j.state_reason is None
    assert p.agent_task is AgentTask.MUTATION_STRATEGY
    assert j.stage2_basis is not None and j.stage2_input is None
    assert j.stage2_basis.execution_harness_id == \
        j.binding.execution_harness_id
    req = world.agents.requests[-1]
    assert req.agent_task is AgentTask.MUTATION_STRATEGY
    assert req.stage2_input == j.stage2_basis
    assert req.analysis_ref == j.analysis_ref
    assert req.model_policy == Stage2AgentPolicy().mutation_strategy
    assert world.c.replay(job_id) == world.job(job_id)


def test_stage2_model_policy_is_its_own(make_world):
    w = make_world(stage2_agents=Stage2AgentPolicy(
        mutation_strategy=AgentModelPolicy(provider="p2", model="m2")))
    in_strategy(w)
    assert w.agents.requests[-1].model_policy.requested_model_id == "p2:m2"


@pytest.mark.parametrize("status, reason", [
    (Q1Status.NOT_REACHED, None), (Q1Status.INCONCLUSIVE, "infra"),
    (Q1Status.INCONCLUSIVE, "evidence")])
def test_no_stage2_without_reached(world, status, reason):
    job_id = world.to_running()
    world.run(job_id, status, reason)
    state = world.job(job_id).state
    assert world.c.start_stage2(job_id) is None
    assert world.job(job_id).state is state
    assert not any(r.agent_task is AgentTask.MUTATION_STRATEGY
                   for r in world.agents.requests)


def test_start_on_another_identity_reestablishes_q1(world):
    job_id = reached(world)
    j = world.job(job_id)
    stale = j.model_copy(update={"stage2_input": j.stage2_input.model_copy(
        update={"execution_harness_id": sha("build-0")})})
    out = world.c.machine.handle(stale, ev.OperatorAction(
        action="start_stage2", action_id="op-x"))
    assert out.reason == "stage2_identity_changed"
    assert out.job.state is JobState.S1_RUNNING
    assert out.job.stage2_basis is None


def test_unsupported_waits_on_a_mutation_engine_gap(world):
    job_id = in_strategy(world)
    unsupported(world, job_id)
    j = world.job(job_id)
    assert j.state is JobState.BLOCKED_HARNESS_GAP
    assert j.gap == GAP
    assert j.resume_point.kind is TargetKind.STRATEGY
    assert world.issues.links[GAP] == [job_id]

    # The semantic runtime work lands; Mutation Strategy runs again.
    world.registry.put(binding(hcap="hcap-2"))
    n = len(world.agents.requests)
    world.c.on_issue(GAP, "resolved")
    j = world.job(job_id)
    assert j.state is JobState.S2_STRATEGY
    assert j.binding.hcap_revision == "hcap-2"
    assert world.agents.requests[n].agent_task is \
        AgentTask.MUTATION_STRATEGY
    assert world.agents.requests[n].hcap_revision == "hcap-2"
    assert world.c.replay(job_id) == world.job(job_id)


def test_unsupported_with_an_unknown_id_goes_to_the_operator(world):
    job_id = in_strategy(world)
    unsupported(world, job_id, cap="")
    j = world.job(job_id)
    assert (j.state, j.state_reason) == (JobState.BLOCKED_OPERATOR,
                                         BlockedReason.GAP_ID_UNKNOWN.value)
    assert j.resume_point.kind is TargetKind.STRATEGY


def test_unsupported_of_another_gap_class_is_unexpected(world):
    job_id = in_strategy(world)
    unsupported(world, job_id, gap_class=GapClass.SYZLANG,
                cap="syzlang.nfs4.op_lock")
    j = world.job(job_id)
    assert j.state_reason == BlockedReason.UNEXPECTED_EVENT.value


def test_stage1_variants_are_unexpected_from_strategy(world):
    job_id = in_strategy(world)
    world.agent_ok(job_id, PlanOutput(plan_ref=sha("plan-2")))
    assert world.job(job_id).state_reason == "unexpected_event"


def test_rule_set_without_a_compiler_waits_with_it(world):
    job_id = in_strategy(world)
    ref = rule_set(world, job_id)
    j = world.job(job_id)
    assert (j.state, j.state_reason) == (
        JobState.BLOCKED_OPERATOR,
        BlockedReason.STAGE2_COMPILER_UNAVAILABLE.value)
    assert j.rule_set_ref == ref and j.resume_point.kind is TargetKind.COMPILE

    # Once a compiler is configured, resume compiles the same rule set.
    fc = use_compiler(world)
    n = len(world.agents.requests)
    world.c.operator(job_id, "resume")
    j = world.job(job_id)
    assert j.state_reason == BlockedReason.STAGE2_GATE_UNAVAILABLE.value
    assert j.compiled.rule_set_ref == ref
    assert fc.calls == [(ref, j.stage2_basis.harness_ref, "hcap-1")]
    assert len(world.agents.requests) == n


def test_compiled_rule_set_waits_for_the_gate(world):
    use_compiler(world)
    job_id = in_strategy(world)
    ref = rule_set(world, job_id)
    j = world.job(job_id)
    assert j.state_reason == BlockedReason.STAGE2_GATE_UNAVAILABLE.value
    assert j.compiled.compiled_ref == sha("compiled", ref, j.harness.harness_ref,
                                          "hcap-1")
    t = world.store.transitions(job_id)[-1]
    assert ref in t.consumed and j.compiled.compiled_ref in t.consumed
    assert world.c.replay(job_id) == world.job(job_id)


@pytest.mark.parametrize("reason", sorted([
    "unknown_path", "type_mismatch", "message_type_inconsistent",
    "selector_mismatch", "missing_required_field"]))
def test_agent_fixable_refusal_repairs_the_strategy(world, reason):
    fc = use_compiler(world)
    job_id = in_strategy(world)
    fc.refusals[(sha("rules-1"), "hcap-1")] = CompileRejected(
        reason=reason, intent_id="forge-stateid", detail="d")
    ref = rule_set(world, job_id)
    j = world.job(job_id)
    p = j.pending_task
    assert (j.state, j.state_reason) == (
        JobState.S2_STRATEGY, RepairCause.COMPILER_REJECTED.value)
    assert j.counters.agent_repair_stage2 == 1
    assert j.counters.agent_repair_stage1 == 0
    r = p.repair
    assert r.agent_task is AgentTask.MUTATION_STRATEGY
    assert r.previous_outputs == (j.analysis_ref, j.plan_ref, ref)
    assert r.evidence_refs == (j.stage2_basis.bundle_ref,)
    assert CompileRejected.model_validate_json(r.findings[0]).reason == reason
    assert r.remaining_budget == 2
    req = world.agents.requests[-1]
    assert req.rule_set_ref == ref and req.repair == r


def test_stage2_repair_budget_blocks_and_resume_resets_it(make_world):
    w = make_world(stage2_repair_budget=1)
    fc = use_compiler(w)
    job_id = in_strategy(w)
    for name in ("rules-1", "rules-2"):
        fc.refusals[(sha(name), "hcap-1")] = CompileRejected(
            reason="unknown_path")
    rule_set(w, job_id, "rules-1")
    assert w.job(job_id).counters.agent_repair_stage2 == 1
    rule_set(w, job_id, "rules-2")
    j = w.job(job_id)
    assert (j.state, j.state_reason) == (
        JobState.BLOCKED_OPERATOR, BlockedReason.STAGE2_REPAIR_BUDGET.value)
    w.c.operator(job_id, "resume")
    j = w.job(job_id)
    assert j.state is JobState.S2_STRATEGY
    assert j.counters.agent_repair_stage2 == 1
    assert j.pending_task.repair.cause is RepairCause.COMPILER_REJECTED
    assert w.c.replay(job_id) == w.job(job_id)


def test_capability_refusal_waits_and_promotion_recompiles(world):
    fc = use_compiler(world)
    job_id = in_strategy(world)
    gap = GapRef(gap_class=GapClass.MUTATION_ENGINE,
                 missing_capability_id="semantic.nfs4.open_reply")
    fc.refusals[(sha("rules-1"), "hcap-1")] = CompileRejected(
        reason="unsupported_capability",
        missing_capability_id="semantic.nfs4.open_reply")
    ref = rule_set(world, job_id)
    j = world.job(job_id)
    assert j.state is JobState.BLOCKED_HARNESS_GAP and j.gap == gap
    assert j.resume_point.kind is TargetKind.COMPILE

    # A promotion is a new HCAP revision on the same build (07 §7).
    world.registry.put(binding(hcap="hcap-2"))
    n = len(world.agents.requests)
    world.c.on_issue(gap, "resolved")
    j = world.job(job_id)
    assert j.state_reason == BlockedReason.STAGE2_GATE_UNAVAILABLE.value
    assert j.compiled.hcap_revision == "hcap-2"
    assert fc.calls[-1] == (ref, j.stage2_basis.harness_ref, "hcap-2")
    assert len(world.agents.requests) == n      # no new Mutation Strategy
    assert world.c.replay(job_id) == world.job(job_id)


def test_state_lineage_refusal_names_its_gap(world):
    fc = use_compiler(world)
    job_id = in_strategy(world)
    fc.refusals[(sha("rules-1"), "hcap-1")] = CompileRejected(
        reason="requires_state_lineage")
    rule_set(world, job_id)
    assert world.job(job_id).gap == GAP


@pytest.mark.parametrize("refusal", [
    CompileRejected(reason="unsupported_capability"),
    CompileRejected(reason="unsupported_capability",
                    missing_capability_id="not.in.vocabulary")])
def test_capability_refusal_without_a_known_id_goes_to_the_operator(
        world, refusal):
    fc = use_compiler(world)
    job_id = in_strategy(world)
    fc.refusals[(sha("rules-1"), "hcap-1")] = refusal
    rule_set(world, job_id)
    j = world.job(job_id)
    assert j.state_reason == BlockedReason.GAP_ID_UNKNOWN.value
    assert j.resume_point.kind is TargetKind.COMPILE


def test_unknown_compiler_reason_is_unexpected(world):
    fc = use_compiler(world)
    job_id = in_strategy(world)
    fc.refusals[(sha("rules-1"), "hcap-1")] = CompileRejected(
        reason="schema_mismatch")
    rule_set(world, job_id)
    assert world.job(job_id).state_reason == "unexpected_event"


def test_agent_failure_retries_the_same_strategy_request(world):
    job_id = in_strategy(world)
    p = world.job(job_id).pending_task
    world.c.on_agent_failure(p.task_id, p.attempt, "provider timeout")
    j = world.job(job_id)
    assert j.state is JobState.S2_STRATEGY
    assert j.counters.agent_retry == 1
    assert j.pending_task.input_digest == p.input_digest


def test_restart_sends_a_new_attempt_of_the_strategy(world):
    job_id = in_strategy(world)
    p = world.job(job_id).pending_task
    world.restart()
    j = world.job(job_id)
    assert j.pending_task.task_id == p.task_id
    assert j.pending_task.attempt == p.attempt + 1
    assert world.agents.requests[-1].stage2_input == j.stage2_basis
    # The abandoned attempt's late output makes no transition.
    world.c.on_agent_result(p.task_id, p.attempt,
                            RuleSetOutput(rule_set_ref=sha("late")),
                            "test:fake")
    assert world.job(job_id).state is JobState.S2_STRATEGY
    assert world.c.replay(job_id) == world.job(job_id)


def test_hcap_change_restarts_strategy_when_the_plan_still_holds(world):
    job_id = in_strategy(world)
    old = world.job(job_id).pending_task
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    j = world.job(job_id)
    assert j.state is JobState.S2_STRATEGY
    assert j.pending_task.task_id != old.task_id
    assert world.agents.requests[-1].hcap_revision == "hcap-2"
    assert j.stage2_basis is not None


def test_hcap_change_that_breaks_the_plan_returns_to_planning(world):
    job_id = in_strategy(world)
    j = world.job(job_id)
    world.hcap.violations[(j.plan_ref, "hcap-2")] = ("capability_removed",)
    world.registry.put(binding(hcap="hcap-2"))
    world.c.on_registry_changed()
    j = world.job(job_id)
    assert (j.state, j.state_reason) == (JobState.S1_PLANNING,
                                         RepairCause.HCAP_CHANGED.value)
    assert j.stage2_basis is None and j.rule_set_ref is None
    assert world.agents.requests[-1].agent_task is \
        AgentTask.REACHABILITY_PLANNING


def test_identity_change_in_stage2_reestablishes_q1(world):
    job_id = in_strategy(world)
    world.registry.put(binding(execution="build-2"))
    world.c.on_registry_changed()
    j = world.job(job_id)
    assert j.state is JobState.S1_RUNNING
    assert j.stage2_basis is None
    assert j.harness.execution_harness_id == sha("build-2")
    # Q1 again on the new identity, then Stage 2 from the new package.
    world.run(job_id, Q1Status.REACHED)
    world.c.start_stage2(job_id)
    assert world.job(job_id).stage2_basis.execution_harness_id == \
        sha("build-2")
    assert world.c.replay(job_id) == world.job(job_id)


def test_judge_change_points_stage2_at_the_new_verdict(world):
    job_id = in_strategy(world)
    old = world.job(job_id).stage2_basis
    world.c.on_judge_versions(JudgeVersions(judge_profile_id="jp-2",
                                            support_boundary_id="sb-1"))
    j = world.job(job_id)
    assert j.state is JobState.S2_STRATEGY
    assert j.stage2_basis.q1_verdict_id != old.q1_verdict_id
    assert j.stage2_basis.bundle_ref == old.bundle_ref


def test_stage1_agent_digest_encoding_is_unchanged():
    payload = agent_input_payload(
        agent_task=AgentTask.CANDIDATE_ANALYSIS,
        model_policy=AgentModelPolicy(provider="p", model="m"),
        candidate=candidate(), hcap_revision="h", analysis_ref=None,
        plan_ref=None, repair=None)
    assert set(payload) == {"agent_task", "candidate", "hcap_revision",
                            "analysis_ref", "plan_ref", "repair",
                            "model_policy"}
    with pytest.raises(ValueError):
        agent_input_payload(
            agent_task=AgentTask.MUTATION_STRATEGY,
            model_policy=AgentModelPolicy(provider="p", model="m"),
            candidate=candidate(), hcap_revision="h", analysis_ref=None,
            plan_ref=None, repair=None)


def test_strategy_through_the_pydantic_ai_runtime(tmp_path):
    """The installed Agent graph takes the rule set schema as its output
    tool and repairs a wrong candidate_id inside one run."""
    pytest.importorskip("pydantic_ai")
    from pydantic_ai.models import override_allow_model_requests
    from .test_pydantic_ai_runtime import Script, response

    store = ArtifactStore(tmp_path)
    analysis_ref, s2 = stage1_package(store)
    script = Script(
        response({"variant": "rule_set", "rule_set": rule_set_data("VC-x")}),
        response({"variant": "rule_set", "rule_set": rule_set_data()}))
    sink = Sink()
    with override_allow_model_requests(False):
        Stage1AgentExecutor(script.runtime(), store, lambda r: toolbox(),
                            sink).start(strategy_request(analysis_ref, s2))
    assert not sink.failures, sink.failures
    _, _, output, model_id = sink.results[0]
    assert model_id == "function:actual-snapshot"
    assert len(script.calls) == 2
    assert load_record(store, output.rule_set_ref, MutationRuleSet) == \
        MutationRuleSet.model_validate(rule_set_data())
