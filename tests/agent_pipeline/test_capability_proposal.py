"""#75 step 8: a typed capability proposal with an unsupported plan."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_pipeline.agent_tasks.analysis import CandidateAnalysis
from agent_pipeline.agent_tasks.executor import Stage1AgentExecutor
from agent_pipeline.agent_tasks.planning import (CapabilityProposal,
                                                 ReachabilityPlanningOutput)
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import GapClass, UnsupportedOutput
from agent_pipeline.controller.records import BlockedReason, JobState
from agent_pipeline.data import load_record, put_record

from .fakes import sha
from .test_agent_tasks import (DeterministicFunctionRuntime, Sink,
                               analysis_data, request, toolbox)
from agent_pipeline.contracts import AgentTask


def proposal(layer="syzlang") -> dict:
    return {
        "layer": layer,
        "summary": "Describe NLM TEST with a conflicting holder",
        "required_condition": "A second client holds a conflicting lock",
        "source_evidence": [{
            "source_path": "fs/lockd/svcproc.c",
            "symbol": "__nlmsvc_proc_test",
            "note": "Only a conflicting lock reaches the denied branch",
        }],
        "insufficient_capabilities": [{
            "capability_id": "HCAP-01",
            "reason": "One client per program cannot hold two locks",
        }],
        "proposed_interface": "A pseudo-syscall that sends TEST as client1",
        "promotion_evidence": [
            "KVM run where the denied branch is attributed to the program"],
    }


def unsupported(**extra) -> dict:
    return {"variant": "unsupported", "gap_class": "syzlang",
            "missing_capability_id": "syzlang.nfs4.op_lock",
            "reason": "No promoted call sends a conflicting TEST", **extra}


def test_planning_stores_the_proposal_and_points_to_it(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    analysis_ref = put_record(
        store, CandidateAnalysis.model_validate(analysis_data()))
    runtime = DeterministicFunctionRuntime(
        [unsupported(proposal=proposal())])
    sink = Sink()
    Stage1AgentExecutor(runtime, store, lambda unused: toolbox(), sink).start(
        request(AgentTask.REACHABILITY_PLANNING, analysis_ref=analysis_ref))
    output = sink.results[0][2]
    assert isinstance(output, UnsupportedOutput)
    stored = load_record(store, output.proposal_ref, CapabilityProposal)
    assert stored.layer == "syzlang"
    assert stored.insufficient_capabilities[0].capability_id == "HCAP-01"


def test_proposal_layer_must_match_gap_class():
    with pytest.raises(ValidationError):
        ReachabilityPlanningOutput.model_validate(
            unsupported(proposal=proposal("fixture_or_tool")))
    with pytest.raises(ValidationError):
        ReachabilityPlanningOutput.model_validate(unsupported(
            proposal={**proposal(), "promotion_evidence": []}))


def test_unsupported_without_proposal_keeps_its_encoding():
    out = UnsupportedOutput(gap_class=GapClass.SYZLANG,
                            missing_capability_id="x", reason="r")
    assert "proposal_ref" not in out.model_dump(mode="json")
    assert out.model_dump_json() == (
        '{"variant":"unsupported","gap_class":"syzlang",'
        '"missing_capability_id":"x","reason":"r"}')
    with_ref = out.model_copy(update={"proposal_ref": sha("p")})
    assert UnsupportedOutput.model_validate_json(
        with_ref.model_dump_json()) == with_ref


@pytest.mark.parametrize(("capability", "state"), [
    ("syzlang.nfs4.op_lock", JobState.BLOCKED_HARNESS_GAP),
    ("syzlang.new_thing", JobState.BLOCKED_OPERATOR)])
def test_controller_keeps_the_proposal_with_the_gap(world, capability,
                                                    state):
    j = world.submit()
    world.analysis(j)
    world.agent_ok(j, UnsupportedOutput(
        gap_class=GapClass.SYZLANG, missing_capability_id=capability,
        reason="r", proposal_ref=sha("proposal")))
    job = world.job(j)
    assert job.state is state
    assert job.gap_proposal_ref == sha("proposal")
    if state is JobState.BLOCKED_OPERATOR:
        assert job.state_reason == BlockedReason.GAP_ID_UNKNOWN.value
    assert world.c.replay(j) == job
