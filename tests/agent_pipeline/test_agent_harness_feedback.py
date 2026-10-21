"""#75: what a Stage 1 repair sees of earlier attempts, the parser's own
message, and the read-only validate_program tool."""

from __future__ import annotations

import hashlib
import json

from agent_pipeline.agent_tasks.analysis import CandidateAnalysis
from agent_pipeline.agent_tasks.executor import (PinnedToolboxFactory,
                                                  Stage1AgentExecutor,
                                                  q1_finding_note)
from agent_pipeline.agent_tasks.planning import completed_plan, \
    ReachabilityPlanDraft
from agent_pipeline.agent_tasks.tools import (TOOL_DEFINITIONS,
                                              VALIDATE_PROGRAM_TOOL,
                                              ProgramValidation)
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import (AgentTask, MaterializeRejected,
                                      PlanOutput, Q1Result, Q1Status)
from agent_pipeline.controller.records import (JobState, RepairCause,
                                               RepairInput)
from agent_pipeline.data import put_record

from .fakes import binding, sha
from .test_agent_tasks import (DeterministicFunctionRuntime, FakeHcap,
                               FakeSource, Sink, analysis_data, candidate,
                               planning_data, request, toolbox)


def q1_result(status=Q1Status.NOT_REACHED, reason=None) -> Q1Result:
    return Q1Result(
        verdict_id="v1", candidate_id="VC-stage1",
        execution_harness_id="e" * 64, judge_profile_id="jp",
        support_boundary_id="sb", evidence_manifest_sha256="f" * 64,
        status=status, reason=reason)


def stored_plan(store, text: str):
    draft = ReachabilityPlanDraft.model_validate_json(json.dumps(
        {**planning_data()["plan"],
         "program": {"kind": "program", "text": text}}))
    ref = store.put(text.encode())
    return put_record(store, completed_plan(draft, ref)), ref


def repair(n, cause, findings, previous) -> RepairInput:
    return RepairInput(job_id="job-stage1", attempt=n,
                       agent_task=AgentTask.REACHABILITY_PLANNING,
                       cause=cause, previous_outputs=previous,
                       findings=findings, remaining_budget=3 - n)


def test_planning_repair_prompt_shows_previous_plan_program_and_history(
        tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    analysis_ref = put_record(
        store, CandidateAnalysis.model_validate(analysis_data()))
    first, first_program = stored_plan(store, "syz_test$open()\n")
    second, _ = stored_plan(store, "syz_test$open()\n# again\n")
    third, _ = stored_plan(store, "syz_test$open()\n")
    prior = (
        repair(1, RepairCause.MATERIALIZER_REJECTED,
               ("parse_failure", "scenario_strict_parse_failed",
                "line 1: unknown call"), (analysis_ref, first)),
        repair(2, RepairCause.Q1_NOT_REACHED,
               (q1_result().model_dump_json(),), (analysis_ref, second)),
    )
    prior_refs = tuple(store.put(r.model_dump_json().encode())
                       for r in prior)
    current = repair(3, RepairCause.Q1_NOT_REACHED,
                     (q1_result().model_dump_json(),),
                     (analysis_ref, third))
    runtime = DeterministicFunctionRuntime([planning_data()])
    sink = Sink()
    executor = Stage1AgentExecutor(runtime, store,
                                   lambda unused: toolbox(), sink)

    executor.start(request(AgentTask.REACHABILITY_PLANNING,
                           analysis_ref=analysis_ref).model_copy(update={
                               "plan_ref": third, "repair": current,
                               "prior_repairs": prior_refs}))

    assert not sink.failures
    prompt = runtime.requests[0].prompt
    assert "Previous ReachabilityPlan data" in prompt
    assert "Previous syz program text (untrusted):\nsyz_test$open()\n" \
        in prompt
    assert "Controller reading of the Q1 finding" in prompt
    section = prompt.split("rejected its plan (untrusted):\n")[1]
    history = json.loads(section.split("\n\n")[0])
    assert [row["repair"] for row in history] == [1, 2, 3]
    assert history[0]["findings"][2] == "line 1: unknown call"
    assert history[0]["program_sha256"] == first_program
    # The third plan resubmitted the first program.
    assert history[2]["same_program_as_repair"] == 1
    assert "same_program_as_repair" not in history[1]


def test_first_attempt_and_lost_history_add_no_repair_context(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    analysis_ref = put_record(
        store, CandidateAnalysis.model_validate(analysis_data()))
    runtime = DeterministicFunctionRuntime([planning_data(),
                                            planning_data()])
    executor = Stage1AgentExecutor(runtime, store,
                                   lambda unused: toolbox(), Sink())
    base = request(AgentTask.REACHABILITY_PLANNING,
                   analysis_ref=analysis_ref)
    executor.start(base)
    assert "Previous" not in runtime.requests[0].prompt

    # A repair whose plan and earlier record are gone still runs.
    executor.start(base.model_copy(update={
        "plan_ref": "d" * 64, "prior_repairs": ("e" * 64,),
        "repair": repair(1, RepairCause.HCAP_INVALID, ("x",),
                         (analysis_ref, "d" * 64))}))
    prompt = runtime.requests[1].prompt
    assert "Previous ReachabilityPlan" not in prompt
    assert "Stage 1 attempts of this job" not in prompt


def test_q1_note_reads_only_a_plain_not_reached():
    def note(result, cause=RepairCause.Q1_NOT_REACHED):
        return q1_finding_note(repair(1, cause, (result,), ()))
    assert "did not contain the" in note(q1_result().model_dump_json())
    assert note(q1_result(reason="loss").model_dump_json()) == ""
    assert note("not json") == ""
    assert note(q1_result().model_dump_json(),
                RepairCause.HCAP_INVALID) == ""


class Checker:
    def __init__(self, answer=None, error=None):
        self.answer, self.error, self.calls = answer, error, []

    def check_draft(self, plan, program, binding):
        self.calls.append((plan, program, binding))
        if self.error is not None:
            raise self.error
        return self.answer


def planning_request():
    return request(AgentTask.REACHABILITY_PLANNING).model_copy(
        update={"binding": binding()})


def test_validate_program_runs_the_draft_check_without_storing(tmp_path):
    checker = Checker()
    tools = PinnedToolboxFactory(FakeSource(), FakeHcap(),
                                 checker=checker)(planning_request())
    assert tools.definitions == TOOL_DEFINITIONS + (VALIDATE_PROGRAM_TOOL,)
    draft = planning_data()["plan"]

    assert tools.invoke("validate_program", {"plan": draft}) == \
        ProgramValidation(accepted=True)
    plan, program, bound = checker.calls[0]
    assert program == b"syz_test$open()\n"
    assert plan.program_proposal.artifact_ref == \
        hashlib.sha256(program).hexdigest()
    assert bound == binding()

    checker.answer = MaterializeRejected(
        reason="parse_failure", detail="scenario_strict_parse_failed",
        message="line 1: unknown call")
    refused = tools.invoke("validate_program", {"plan": draft})
    assert (refused.accepted, refused.stage, refused.reason,
            refused.message) == (False, "materializer", "parse_failure",
                                 "line 1: unknown call")

    checker.error = TimeoutError("bridge timed out")
    assert tools.invoke("validate_program", {"plan": draft}).stage == "host"


def test_validate_program_answers_schema_and_request_mistakes():
    checker = Checker()
    tools = PinnedToolboxFactory(FakeSource(), FakeHcap(),
                                 checker=checker)(planning_request())
    draft = planning_data()["plan"]

    schema = tools.invoke("validate_program",
                          {"plan": {**draft, "nfs_version": "3"}})
    assert (schema.accepted, schema.stage) == (False, "schema")
    other = tools.invoke("validate_program",
                         {"plan": {**draft, "candidate_id": "VC-other"}})
    assert (other.stage, other.reason) == ("request", "candidate_id_mismatch")
    assert checker.calls == []


def test_validate_program_only_for_bound_planning_with_a_checker():
    factory = PinnedToolboxFactory(FakeSource(), FakeHcap(),
                                   checker=Checker())
    assert factory(request(AgentTask.CANDIDATE_ANALYSIS).model_copy(
        update={"binding": binding()})).definitions == TOOL_DEFINITIONS
    assert factory(request(AgentTask.REACHABILITY_PLANNING)
                   ).definitions == TOOL_DEFINITIONS
    assert PinnedToolboxFactory(FakeSource(), FakeHcap())(
        planning_request()).definitions == TOOL_DEFINITIONS


def test_controller_sends_prior_repairs_binding_and_parser_message(world):
    j = world.to_running()
    world.run(j, Q1Status.NOT_REACHED)
    first = world.agents.requests[-1]
    assert first.repair.cause is RepairCause.Q1_NOT_REACHED
    assert first.prior_repairs == ()
    assert first.binding == world.job(j).binding

    world.materializer.refusals[(sha("plan-2"), sha("build-1"))] = \
        MaterializeRejected(reason="parse_failure",
                            detail="scenario_strict_parse_failed",
                            message="line 1: unknown call")
    world.plan(j, "plan-2")
    second = world.agents.requests[-1]
    assert second.repair.cause is RepairCause.MATERIALIZER_REJECTED
    assert second.repair.findings == (
        "parse_failure", "scenario_strict_parse_failed",
        "line 1: unknown call")
    assert [RepairInput.model_validate_json(world.artifacts.get(ref))
            for ref in second.prior_repairs] == [first.repair]

    world.plan(j, "plan-3")
    assert world.job(j).state is JobState.S1_RUNNING
    world.run(j, Q1Status.NOT_REACHED)
    third = world.agents.requests[-1]
    assert [RepairInput.model_validate_json(world.artifacts.get(ref)).attempt
            for ref in third.prior_repairs] == [1, 2]
    assert world.c.replay(j) == world.job(j)


def test_planning_result_is_unchanged_by_a_bound_validator(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    analysis_ref = put_record(
        store, CandidateAnalysis.model_validate(analysis_data()))
    runtime = DeterministicFunctionRuntime([planning_data()])
    sink = Sink()
    factory = PinnedToolboxFactory(FakeSource(), FakeHcap(),
                                   checker=Checker())
    Stage1AgentExecutor(runtime, store, factory, sink).start(
        planning_request().model_copy(update={"analysis_ref": analysis_ref}))
    assert isinstance(sink.results[0][2], PlanOutput)
    assert "validate_program" in runtime.requests[0].tools.names
    assert candidate().candidate_id in runtime.requests[0].prompt
