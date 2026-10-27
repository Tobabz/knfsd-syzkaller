"""#81 PR 2: the Mutation Strategy gap contract, the pipeline gap IDs in
every generated HCAP, and the campaign_mode host checks (D5, D6, D16)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_pipeline.agent_tasks.executor import Stage1AgentExecutor
from agent_pipeline.agent_tasks.mutation import MutationStrategyOutput
from agent_pipeline.agent_tasks.planning import CapabilityProposal
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import (MUTATION_UNLISTED_GAP_ID,
                                      PIPELINE_GAP_IDS, CampaignMode,
                                      GapClass, GapRef, UnsupportedOutput)
from agent_pipeline.controller.records import BlockedReason, JobState
from agent_pipeline.data import load_record
from agent_pipeline.semantic_promotion import UNPROMOTED_GAP_ID
from agent_pipeline.stage1.config import Stage2Config
from agent_pipeline.stage1.host.generate import (GenerationError, HostSpec,
                                                 _gap_vocabulary)

from .fakes import policy, sha
from .test_agent_tasks import DeterministicFunctionRuntime, Sink, toolbox
from .test_capability_proposal import proposal
from .test_stage2_host import _config
from .test_stage2_strategy import in_strategy, stage1_package, \
    strategy_request


def unsupported(cap: str, **extra) -> dict:
    return {"variant": "unsupported", "gap_class": "mutation_engine",
            "missing_capability_id": cap,
            "reason": "the change needs a CB_RECALL reply rewrite", **extra}


# ---------------------------------------------------------------- schema


def test_unlisted_needs_a_mutation_layer_proposal():
    out = MutationStrategyOutput.model_validate(unsupported(
        MUTATION_UNLISTED_GAP_ID, proposal=proposal("proxy"))).root
    assert out.proposal.layer == "proxy"
    with pytest.raises(ValidationError):
        MutationStrategyOutput.model_validate(
            unsupported(MUTATION_UNLISTED_GAP_ID))
    # A Planning layer is not a Mutation Strategy layer.
    with pytest.raises(ValidationError):
        MutationStrategyOutput.model_validate(unsupported(
            "state_lineage", proposal=proposal("syzlang")))


def test_planning_still_refuses_a_mutation_layer():
    from agent_pipeline.agent_tasks.planning import \
        ReachabilityPlanningOutput
    with pytest.raises(ValidationError):
        ReachabilityPlanningOutput.model_validate({
            "variant": "unsupported", "gap_class": "syzlang",
            "missing_capability_id": "syzlang.nfs4.op_lock", "reason": "r",
            "proposal": proposal("semantic_subset")})


# ---------------------------------------------------------------- executor


def test_empty_id_is_repaired_in_the_run_and_the_proposal_is_stored(
        tmp_path):
    store = ArtifactStore(tmp_path)
    analysis_ref, s2 = stage1_package(store)
    runtime = DeterministicFunctionRuntime([
        unsupported(""),
        unsupported(MUTATION_UNLISTED_GAP_ID,
                    proposal=proposal("compiler_lowering"))])
    sink = Sink()
    Stage1AgentExecutor(runtime, store, lambda r: toolbox(), sink).start(
        strategy_request(analysis_ref, s2))

    assert not sink.failures
    assert runtime.attempts == 2        # the empty ID was refused
    output = sink.results[0][2]
    assert isinstance(output, UnsupportedOutput)
    assert output.missing_capability_id == MUTATION_UNLISTED_GAP_ID
    stored = load_record(store, output.proposal_ref, CapabilityProposal)
    assert stored.layer == "compiler_lowering"
    assert "mutation_engine.unlisted" in runtime.requests[0].instructions


def test_a_listed_id_needs_no_proposal(tmp_path):
    store = ArtifactStore(tmp_path)
    analysis_ref, s2 = stage1_package(store)
    runtime = DeterministicFunctionRuntime([unsupported(UNPROMOTED_GAP_ID)])
    sink = Sink()
    Stage1AgentExecutor(runtime, store, lambda r: toolbox(), sink).start(
        strategy_request(analysis_ref, s2))
    output = sink.results[0][2]
    assert output.missing_capability_id == UNPROMOTED_GAP_ID
    assert output.proposal_ref is None


# ---------------------------------------------------------------- Controller


def test_unlisted_with_a_proposal_waits_on_its_gap(world):
    world.hcap.vocabulary.add(MUTATION_UNLISTED_GAP_ID)
    job_id = in_strategy(world)
    ref = sha("mutation-proposal")
    world.agent_ok(job_id, UnsupportedOutput(
        gap_class=GapClass.MUTATION_ENGINE,
        missing_capability_id=MUTATION_UNLISTED_GAP_ID,
        reason="needs a CB_RECALL reply rewrite", proposal_ref=ref))
    j = world.job(job_id)
    assert j.state is JobState.BLOCKED_HARNESS_GAP
    assert j.gap == GapRef(gap_class=GapClass.MUTATION_ENGINE,
                           missing_capability_id=MUTATION_UNLISTED_GAP_ID)
    assert j.gap_proposal_ref == ref


def test_a_stored_empty_id_still_goes_to_the_operator(world):
    job_id = in_strategy(world)
    world.agent_ok(job_id, UnsupportedOutput(
        gap_class=GapClass.MUTATION_ENGINE, missing_capability_id="",
        reason="legacy output"))
    j = world.job(job_id)
    assert (j.state, j.state_reason) == (JobState.BLOCKED_OPERATOR,
                                         BlockedReason.GAP_ID_UNKNOWN.value)


# ---------------------------------------------------------------- host


def test_pipeline_gap_ids_are_the_emitted_ones():
    assert UNPROMOTED_GAP_ID in PIPELINE_GAP_IDS
    assert set(PIPELINE_GAP_IDS) == {
        "semantic_mutation.unpromoted", "state_lineage",
        "mutation_engine.unlisted"}


def test_generation_adds_the_pipeline_gap_ids():
    spec = HostSpec.model_validate_json(
        (Path(__file__).parents[2] / "agent_pipeline" / "stage1" / "host"
         / "template" / "host-spec.json").read_text())
    vocabulary = _gap_vocabulary(spec)
    assert set(PIPELINE_GAP_IDS) <= set(vocabulary)
    assert set(spec.missing_capability_ids) <= set(vocabulary)
    assert list(vocabulary) == sorted(set(vocabulary))


def test_mutate_config_needs_stage2_and_proxy(tmp_path):
    base = _config(tmp_path)
    mutate = policy(campaign_mode=CampaignMode.MUTATE)
    stage2 = Stage2Config(
        argv=("/bin/true",), cwd=tmp_path, resource_key="test-kvm",
        replay_proxy=tmp_path / "proxy", m1_profile_ref=sha("m1"),
        q2_profile_ref=sha("q2"), replay_profile_ref=sha("replay"))
    values = base.model_dump()
    for extra, missing in (({}, "stage2 and nfs_proxy"),
                           ({"stage2": stage2}, "nfs_proxy"),
                           ({"nfs_proxy": tmp_path / "proxy"}, "stage2")):
        with pytest.raises(ValidationError, match=missing):
            type(base).model_validate(
                {**values, "policies": (mutate,), **extra})
    ok = type(base).model_validate({**values, "policies": (mutate,),
                                    "stage2": stage2,
                                    "nfs_proxy": tmp_path / "proxy"})
    assert ok.policies[0].campaign_mode is CampaignMode.MUTATE
    # none needs neither.
    assert type(base).model_validate(values).stage2 is None
