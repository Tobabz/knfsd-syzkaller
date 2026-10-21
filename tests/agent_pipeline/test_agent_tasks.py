"""Deterministic Stage 1 Agent Task tests; no provider or network access."""

from __future__ import annotations

from collections import deque
import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent_pipeline.agent_tasks.analysis import CandidateAnalysis
from agent_pipeline.agent_tasks.executor import (PinnedToolboxFactory,
                                                  Stage1AgentExecutor)
from agent_pipeline.agent_tasks import pydantic_ai_dependency
from agent_pipeline.agent_tasks.planning import ReachabilityPlanningOutput
from agent_pipeline.agent_tasks.runtime import RuntimeResult
from agent_pipeline.agent_tasks.tools import (MAX_SOURCE_BYTES, IndexedMatch,
                                              IndexedSource,
                                              TOOL_DEFINITIONS, Stage1Toolbox,
                                              ToolBoundaryError, _schema_paths)
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import (AgentModelPolicy, AgentTask,
                                      AnalysisOutput, CandidateLocation,
                                      LocationKind, PlanOutput,
                                      Stage1AgentPolicy,
                                      VulnerabilityCandidate)
from agent_pipeline.controller.tasks import (AgentRequest,
                                             agent_input_digest)
from agent_pipeline.data import load_record, put_record
from agent_pipeline.hcap import (Capability, CapabilityInterface, HcapCatalog,
                                 ReachabilityPlan)
from agent_pipeline.protocol_schema import load_schemas

from .fakes import COMMIT


HCAP_REVISION = "c" * 64


class FakeSource:
    def __init__(self) -> None:
        self.read_text = "int nfsd4_target(void) { return helper(); }\n"
        self.matches = [IndexedMatch(
            path="fs/nfsd/nfs4proc.c", line=10,
            text="nfsd4_target(rqstp);", symbol="nfsd4_target")]
        self.calls = []

    def read(self, commit, path, start_line, end_line, max_bytes):
        self.calls.append(("read", commit, path, start_line, end_line,
                           max_bytes))
        return self.read_text

    def search(self, commit, query, roots, max_results):
        self.calls.append(("search", commit, query, roots, max_results))
        return self.matches

    def callers(self, commit, symbol, roots, max_results):
        self.calls.append(("callers", commit, symbol, roots, max_results))
        return self.matches

    def callees(self, commit, path, symbol, max_results):
        self.calls.append(("callees", commit, path, symbol, max_results))
        return self.matches


def hcap_catalog() -> HcapCatalog:
    return HcapCatalog(capabilities=(Capability(
        id="HCAP-TEST",
        name="Synthetic Stage 1 capability",
        purpose="Test structured Agent reasoning only",
        usable_stage=("stage1",),
        usable_by=("agent_stage1",),
        interface=CapabilityInterface(
            syz_calls=("syz_test$open",),
            runtime_features=("remote_cover",)),
        status="validated",
        scope=("synthetic",),
    ),), missing_capability_ids=("state.synthetic",))


class FakeHcap:
    def __init__(self) -> None:
        self.revisions = []

    def load_catalog(self, revision):
        self.revisions.append(revision)
        return hcap_catalog()


def toolbox(source=None) -> Stage1Toolbox:
    return Stage1Toolbox(
        source or FakeSource(), FakeHcap(), kernel_commit=COMMIT,
        hcap_revision=HCAP_REVISION)


def candidate() -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        candidate_id="VC-stage1", kernel_commit=COMMIT,
        location=CandidateLocation(
            kind=LocationKind.FUNCTION, path="fs/nfsd/nfs4proc.c",
            symbol="nfsd4_target", start_line=10, end_line=20))


def analysis_data(candidate_id: str = "VC-stage1", *,
                  source_path: str = "fs/nfsd/nfs4proc.c",
                  symbol: str = "nfsd4_target") -> dict:
    return {
        "candidate_id": candidate_id,
        "code_role": {
            "summary": "Handles a synthetic NFSv4 operation.",
            "subsystem": "NFSv4 request handling",
            "relevant_objects": ["svc_rqst"],
        },
        "reachability_paths": [{
            "entry_surface": "nfs_request",
            "steps": [{
                "source_path": source_path,
                "symbol": symbol,
                "role": "Candidate operation handler",
            }],
            "required_state": [],
            "controllable_inputs": [{
                "direction": "C2S",
                "surface": "NFSv4 COMPOUND",
                "semantic_target": "Selected operation",
                "available_control": "existing syzlang",
            }],
        }],
        "harness_assessment": {
            "reusable": [{
                "capability_id": "HCAP-TEST",
                "purpose": "Send and observe the request",
            }],
            "gaps": [],
        },
        "observability_constraints": [{
            "description": "Use generation-attributed remote KCOV",
        }],
        "uncertainties": [],
    }


def planning_data() -> dict:
    return {
        "variant": "plan",
        "plan": {
            "candidate_id": "VC-stage1",
            "hcap_revision": HCAP_REVISION,
            "selected_path": {
                "entry_surface": "nfs_request",
                "path_summary": "Send the selected synthetic operation",
                "required_state": [],
            },
            "nfs_version": "4.1",
            "scenario_steps": [{
                "capability_id": "HCAP-TEST",
                "action": "Open the profile and send the operation",
                "parameters": {"client": 0},
                "expected_state_change": "The handler executes",
            }],
            "required_capabilities": ["HCAP-TEST"],
            "capability_uses": [{
                "capability_id": "HCAP-TEST",
                "status": "validated",
                "scope": ["synthetic"],
            }],
            "q1_observation": {
                "target": candidate().location.model_dump(mode="json"),
                "expected_context": "nfsd.request",
                "capability_id": "HCAP-TEST",
            },
            "program": {
                "kind": "program",
                "text": "syz_test$open()\n",
            },
            "runtime_selection": {
                "profile": "synthetic-v41",
                "nfs_version": "4.1",
                "fixture_mode": "single",
                "route": "synthetic-direct",
                "topology": "synthetic-one-lane",
                "enabled_interfaces": ["syz_test$open", "remote_cover"],
            },
            "execution_constraints": [{
                "description": "Remote coverage remains enabled",
            }],
            "uncertainties": [],
        },
    }


class DeterministicFunctionRuntime:
    """Safe FunctionModel equivalent with schema/validator repair."""

    def __init__(self, responses, *, actual_model="test:resolved-model"):
        self.responses = deque(responses)
        self.actual_model = actual_model
        self.requests = []
        self.attempts = 0

    def run(self, request):
        self.requests.append(request)
        last_error = None
        for _ in range(request.model_policy.output_retries + 1):
            self.attempts += 1
            raw = self.responses.popleft()
            try:
                value = request.output_type.model_validate_json(
                    json.dumps(raw, separators=(",", ":")))
                value = request.validate_output(value)
            except (ValidationError, ValueError) as exc:
                last_error = exc
                continue
            return RuntimeResult(output=value, model_id=self.actual_model)
        raise RuntimeError(f"structured output repair exhausted: {last_error}")


class Sink:
    def __init__(self) -> None:
        self.results = []
        self.failures = []
        self.usage = []

    def on_agent_result(self, task_id, attempt, output, model_id, *,
                        usage=None):
        self.results.append((task_id, attempt, output, model_id))
        self.usage.append(usage)

    def on_agent_failure(self, task_id, attempt, failure):
        self.failures.append((task_id, attempt, failure))


def request(task, *, analysis_ref=None, policy=None) -> AgentRequest:
    return AgentRequest(
        job_id="job-stage1", task_id=f"job-stage1.{task.value}", attempt=1,
        agent_task=task,
        model_policy=policy or AgentModelPolicy(
            provider="test-provider", model="requested-model",
            output_retries=1),
        candidate=candidate(), hcap_revision=HCAP_REVISION,
        analysis_ref=analysis_ref)


def test_invalid_structured_output_is_repaired_without_provider_access(tmp_path):
    runtime = DeterministicFunctionRuntime([
        analysis_data("VC-other"),
        analysis_data(),
    ], actual_model="function-model:actual-v2")
    sink = Sink()
    store = ArtifactStore(tmp_path / "artifacts")
    executor = Stage1AgentExecutor(
        runtime, store, lambda unused: toolbox(), sink)

    executor.start(request(AgentTask.CANDIDATE_ANALYSIS))

    assert runtime.attempts == 2
    assert runtime.requests[0].model_policy.requested_model_id == \
        "test-provider:requested-model"
    assert runtime.requests[0].tools.names == (
        "read_kernel_source", "search_kernel_source", "find_callers",
        "find_callees", "lookup_hcap", "lookup_semantic_scope",
        "lookup_semantic_paths")
    assert not sink.failures
    _, _, output, actual_model = sink.results[0]
    assert isinstance(output, AnalysisOutput)
    assert actual_model == "function-model:actual-v2"
    assert load_record(store, output.analysis_ref, CandidateAnalysis) == \
        CandidateAnalysis.model_validate(analysis_data())


def test_planning_stores_inline_program_and_emits_existing_plan_variant(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    analysis_ref = put_record(
        store, CandidateAnalysis.model_validate(analysis_data()))
    runtime = DeterministicFunctionRuntime(
        [planning_data()], actual_model="test-provider:actual-planner")
    sink = Sink()
    executor = Stage1AgentExecutor(
        runtime, store, lambda unused: toolbox(), sink)

    executor.start(request(AgentTask.REACHABILITY_PLANNING,
                           analysis_ref=analysis_ref))

    assert not sink.failures
    _, _, output, model_id = sink.results[0]
    assert isinstance(output, PlanOutput)
    assert model_id == "test-provider:actual-planner"
    plan = load_record(store, output.plan_ref, ReachabilityPlan)
    assert plan.candidate_id == "VC-stage1"
    assert plan.hcap_revision == HCAP_REVISION
    assert plan.q1_observation.target == candidate().location
    assert store.get(plan.program_proposal.artifact_ref) == \
        b"syz_test$open()\n"


def test_actual_model_id_is_required_and_never_filled_from_policy(tmp_path):
    runtime = DeterministicFunctionRuntime(
        [analysis_data()], actual_model="requested-model")
    sink = Sink()
    executor = Stage1AgentExecutor(
        runtime, ArtifactStore(tmp_path), lambda unused: toolbox(), sink)

    executor.start(request(AgentTask.CANDIDATE_ANALYSIS))

    assert not sink.results
    assert "actual provider:model id" in sink.failures[0][2]


def test_controller_records_runtime_model_id_not_requested_model(world):
    job_id = world.submit()
    queued = world.agents.requests[-1]
    location = queued.candidate.location
    runtime = DeterministicFunctionRuntime(
        [analysis_data(
            world.job(job_id).candidate.candidate_id,
            source_path=location.path, symbol=location.symbol)],
        actual_model="function-model:provider-resolved-2026-10-14")
    # submit() has already queued a request on FakeAgents. Execute
    # that same Controller attempt through the concrete adapter; subsequent
    # planning remains queued on FakeAgents.
    executor = Stage1AgentExecutor(
        runtime, world.artifacts, lambda unused: toolbox(), world.c)
    executor.start(queued)

    attempt = world.store.attempt(queued.task_id, queued.attempt)
    assert attempt.status == "succeeded"
    assert attempt.model_id == "function-model:provider-resolved-2026-10-14"
    assert queued.model_policy.requested_model_id == "openai:gpt-5"


def test_controller_selects_model_policy_per_agent_task(make_world):
    policies = Stage1AgentPolicy(
        candidate_analysis=AgentModelPolicy(
            provider="provider-a", model="analysis-model"),
        reachability_planning=AgentModelPolicy(
            provider="provider-b", model="planning-model"))
    world = make_world(stage1_agents=policies)
    job_id = world.submit()
    assert world.agents.requests[-1].model_policy == \
        policies.candidate_analysis
    world.analysis(job_id)
    assert world.agents.requests[-1].model_policy == \
        policies.reachability_planning


def test_agent_task_pins_model_policy_across_policy_change_and_recovery(
        make_world):
    original = Stage1AgentPolicy(
        candidate_analysis=AgentModelPolicy(
            provider="provider-a", model="analysis-v1"),
        reachability_planning=AgentModelPolicy(
            provider="provider-a", model="planning-v1"))
    replacement = Stage1AgentPolicy(
        candidate_analysis=AgentModelPolicy(
            provider="provider-b", model="analysis-v2"),
        reachability_planning=AgentModelPolicy(
            provider="provider-b", model="planning-v2"))
    world = make_world(stage1_agents=original)
    job_id = world.submit()
    first = world.job(job_id).pending_task
    assert first.model_policy == original.candidate_analysis

    new_policy = world.store.policy(world.job(job_id).job_policy_id).model_copy(
        update={"policy_id": "replacement", "stage1_agents": replacement})
    world.store.save_policy(new_policy)
    world.c.set_policy(job_id, new_policy.policy_id)
    assert world.job(job_id).pending_task.model_policy == \
        original.candidate_analysis

    # Recovery creates a new attempt of the same logical task. Its request
    # must retain the policy included in that task's input digest.
    world.c.recover()
    assert world.agents.requests[-1].model_policy == \
        original.candidate_analysis


def _rewrite_pending_as_legacy(world, job_id, *, input_digest=None):
    job = world.job(job_id)
    pending = job.pending_task
    if input_digest is None:
        input_digest = agent_input_digest(
            agent_task=pending.agent_task,
            model_policy=pending.model_policy,
            candidate=job.candidate,
            hcap_revision=job.binding.hcap_revision,
            analysis_ref=job.analysis_ref,
            plan_ref=job.plan_ref,
            repair=pending.repair,
            include_model_policy=False)

    def legacy(snapshot):
        task = snapshot.pending_task
        if task is None or task.task_id != pending.task_id:
            return snapshot
        return snapshot.model_copy(update={
            "pending_task": task.model_copy(update={
                "model_policy": None,
                "input_digest": input_digest,
            }),
        })

    current = legacy(job)
    world.store.db.execute(
        "UPDATE jobs SET body = ? WHERE job_id = ?",
        (current.model_dump_json(), job_id))
    for transition in world.store.transitions(job_id):
        changed = legacy(transition.job)
        if changed == transition.job:
            continue
        migrated = transition.model_copy(update={"job": changed})
        world.store.db.execute(
            "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = ?",
            (migrated.model_dump_json(), job_id, transition.seq))
    return pending


def test_legacy_agent_task_recovers_historical_policy_after_policy_change(
        make_world):
    original = Stage1AgentPolicy(candidate_analysis=AgentModelPolicy(
        provider="provider-a", model="analysis-v1"))
    replacement = Stage1AgentPolicy(candidate_analysis=AgentModelPolicy(
        provider="provider-b", model="analysis-v2"))
    world = make_world(stage1_agents=original)
    job_id = world.submit()
    pending = _rewrite_pending_as_legacy(world, job_id)
    new_policy = world.store.policy("p1").model_copy(update={
        "policy_id": "replacement", "stage1_agents": replacement})
    world.store.save_policy(new_policy)
    world.c.set_policy(job_id, new_policy.policy_id)

    world.c.recover()

    job = world.job(job_id)
    assert job.pending_task.task_id == pending.task_id
    assert job.pending_task.model_policy is None
    assert world.agents.requests[-1].attempt == 2
    assert world.agents.requests[-1].model_policy == \
        original.candidate_analysis


def test_legacy_agent_task_without_authenticated_policy_fails_closed(world):
    job_id = world.submit()
    pending = _rewrite_pending_as_legacy(
        world, job_id, input_digest="0" * 64)
    before_requests = len(world.agents.requests)

    failures = world.c.recover()

    assert [(failure.effect, "authenticated policy pin" in failure.error)
            for failure in failures] == [("dispatch", True)]
    job = world.job(job_id)
    assert job.pending_task.task_id == pending.task_id
    assert job.pending_task.attempt == 2
    assert len(world.agents.requests) == before_requests
    assert world.store.attempt(pending.task_id, 2) is None
    world.expected_failures += 1


def test_missing_pydantic_ai_dependency_fails_explicitly(monkeypatch):
    def missing(unused):
        raise pydantic_ai_dependency.PackageNotFoundError

    monkeypatch.setattr(pydantic_ai_dependency, "version", missing)
    with pytest.raises(
            pydantic_ai_dependency.PydanticAIDependencyUnavailable,
            match="pydantic-ai-slim==2.55.0 is not installed"):
        pydantic_ai_dependency.require_pydantic_ai()


def test_tool_dispatch_rejects_unregistered_and_unconfined_access():
    tools = toolbox()
    assert set(tools.names) == {
        "read_kernel_source", "search_kernel_source", "find_callers",
        "find_callees", "lookup_hcap", "lookup_semantic_scope",
        "lookup_semantic_paths"}
    with pytest.raises(ToolBoundaryError, match="not registered"):
        tools.invoke("shell", {"command": "id"})
    for path in ("/etc/passwd", "../fs/nfsd/file.c", "drivers/block/x.c"):
        with pytest.raises(ToolBoundaryError):
            tools.invoke("read_kernel_source", {
                "path": path, "start_line": 1, "end_line": 2})
    with pytest.raises(ToolBoundaryError, match="400 lines"):
        tools.invoke("read_kernel_source", {
            "path": "fs/nfsd/nfs4proc.c", "start_line": 1,
            "end_line": 401})
    # The revision is pinned in the toolbox and is not an accepted argument.
    with pytest.raises(ValidationError):
        tools.invoke("lookup_hcap", {"revision": "other"})


def test_semantic_path_lookup_is_promoted_bounded_and_canonical():
    schema = next(s for s in load_schemas().values() if s.minor == 1)

    class SemanticHcap(FakeHcap):
        def load_semantic_scope(self, revision):
            assert revision == HCAP_REVISION
            return SimpleNamespace(subsets=(SimpleNamespace(
                subset=SimpleNamespace(schema_ids=(schema.schema_id,))),))

    tools = Stage1Toolbox(
        FakeSource(), SemanticHcap(), kernel_commit=COMMIT,
        hcap_revision=HCAP_REVISION)
    result = tools.invoke("lookup_semantic_paths", {
        "schema_id": schema.schema_id, "message_type": "call",
        "operation": "CREATE_SESSION", "query": "clientid"})
    assert (result.family, result.rpc_program, result.rpc_version,
            result.minor_version) == ("nfs4", 100003, 4, 1)
    assert [item.path for item in result.paths] == [
        "nfs4.request.CREATE_SESSION.args.csa_clientid"]
    assert result.paths[0].value_kind == "uhyper"
    assert result.paths[0].enum_literals_truncated is False
    with pytest.raises(ToolBoundaryError, match="outside the pinned HCAP"):
        tools.invoke("lookup_semantic_paths", {
            "schema_id": "nfs3/sha256:" + "0" * 64,
            "message_type": "call", "operation": "WRITE"})
    with pytest.raises(ToolBoundaryError, match="absent from the schema"):
        tools.invoke("lookup_semantic_paths", {
            "schema_id": schema.schema_id, "message_type": "call",
            "operation": "NOT_AN_OPERATION"})


def test_semantic_path_lookup_separates_enum_and_path_truncation():
    schema = next(s for s in load_schemas().values() if s.minor == 2)

    class SemanticHcap(FakeHcap):
        def load_semantic_scope(self, revision):
            assert revision == HCAP_REVISION
            return SimpleNamespace(subsets=(SimpleNamespace(
                subset=SimpleNamespace(schema_ids=(schema.schema_id,))),))

    tools = Stage1Toolbox(
        FakeSource(), SemanticHcap(), kernel_commit=COMMIT,
        hcap_revision=HCAP_REVISION)
    path = "nfs4.response.WRITE.result.status"
    result = tools.invoke("lookup_semantic_paths", {
        "schema_id": schema.schema_id, "message_type": "reply",
        "operation": "WRITE", "query": path})

    assert [item.path for item in result.paths] == [path]
    assert result.truncated is False
    assert len(result.paths[0].enum_literals) == 32
    assert result.paths[0].enum_literals_truncated is True


def test_semantic_path_lookup_exact_query_avoids_unrelated_truncation(
        monkeypatch):
    schema = next(s for s in load_schemas().values() if s.minor == 1)

    class SemanticHcap(FakeHcap):
        def load_semantic_scope(self, revision):
            assert revision == HCAP_REVISION
            return SimpleNamespace(subsets=(SimpleNamespace(
                subset=SimpleNamespace(schema_ids=(schema.schema_id,))),))

    def bounded_traversal(*args, **kwargs):
        raise AssertionError("exact canonical queries must not enumerate")

    monkeypatch.setattr(
        "agent_pipeline.agent_tasks.tools._schema_paths", bounded_traversal)
    tools = Stage1Toolbox(
        FakeSource(), SemanticHcap(), kernel_commit=COMMIT,
        hcap_revision=HCAP_REVISION)
    path = "nfs4.response.WRITE.result.status"
    result = tools.invoke("lookup_semantic_paths", {
        "schema_id": schema.schema_id, "message_type": "reply",
        "operation": "WRITE", "query": path})

    assert [item.path for item in result.paths] == [path]
    assert result.truncated is False


def test_semantic_path_enumerator_handles_compound_and_resolves_every_path():
    for schema in load_schemas().values():
        for response in (False, True):
            mine = "response" if response else "request"
            operations = {
                procedure["name"] for procedure in schema.procedures
                if procedure["res" if response else "arg"] is not None
            }
            operations.update(
                arm["branch"]
                for ty in schema.types
                if schema._is_ops_union(ty) and ty["operations"] == mine
                for arm in schema._arms(ty) if arm.get("branch"))
            for operation in operations:
                values, unused = _schema_paths(
                    schema, response=response, operation=operation)
                assert values, (schema.schema_id, mine, operation)
                assert all(schema.resolve(response, path)[0].value == "found"
                           for path, node in values)
            if schema.minor is not None:
                compound, unused = _schema_paths(
                    schema, response=response, operation="COMPOUND")
                assert any(node.flags & 0x10 for path, node in compound)


@pytest.mark.parametrize("prefix", ["fs/nfsd", "fs/nfsd/", "fs/read_write.c",
                                    "fs/exportfs"])
def test_search_accepts_a_root_itself_and_vfs_entry_files(prefix):
    source = FakeSource()
    tools = toolbox(source)
    tools.invoke("search_kernel_source", {"query": "nfsd",
                                          "path_prefix": prefix})
    tools.invoke("read_kernel_source", {
        "path": "fs/read_write.c", "start_line": 1, "end_line": 2})
    with pytest.raises(ToolBoundaryError, match="fs/nfsd/"):
        tools.invoke("read_kernel_source", {
            "path": "fs/super.c", "start_line": 1, "end_line": 2})


def test_tool_descriptions_state_the_line_limit_and_roots():
    read = next(item for item in TOOL_DEFINITIONS
                if item.name == "read_kernel_source")
    assert "400 lines" in read.description
    assert "fs/read_write.c" in read.description


def test_tool_results_are_bounded_and_backend_paths_are_rechecked():
    source = FakeSource()
    source.read_text = "한" * MAX_SOURCE_BYTES
    tools = toolbox(source)
    excerpt = tools.invoke("read_kernel_source", {
        "path": "fs/nfsd/nfs4proc.c", "start_line": 1, "end_line": 2})
    assert len(excerpt.text.encode("utf-8")) <= MAX_SOURCE_BYTES
    assert excerpt.truncated is True
    assert source.calls[0][1] == COMMIT
    assert source.calls[0][-1] == MAX_SOURCE_BYTES

    source.matches = [IndexedMatch(
        path="drivers/block/secret.c", line=1, text="outside")]
    with pytest.raises(ToolBoundaryError, match="outside"):
        tools.invoke("search_kernel_source", {"query": "target"})


@pytest.mark.parametrize("text,truncated", [
    ("complete\n", False),
    (IndexedSource("short prefix", truncated=True), True),
    (IndexedSource("x" * (MAX_SOURCE_BYTES + 1)), True),
], ids=["plain-string", "adapter-cut", "toolbox-cut"])
def test_source_read_accepts_strings_and_preserves_adapter_cut(text, truncated):
    source = FakeSource()
    source.read_text = text
    excerpt = toolbox(source).invoke("read_kernel_source", {
        "path": "fs/nfsd/nfs4proc.c", "start_line": 10, "end_line": 11})
    assert excerpt.text == text[:MAX_SOURCE_BYTES]
    assert excerpt.truncated is truncated
    assert excerpt.end_line == 10


def test_toolbox_factory_binds_trusted_request_identity():
    source, hcap = FakeSource(), FakeHcap()
    factory = PinnedToolboxFactory(source, hcap)
    tools = factory(request(AgentTask.CANDIDATE_ANALYSIS))
    result = tools.invoke("lookup_hcap", {"capability_id": "HCAP-TEST"})
    assert hcap.revisions == [HCAP_REVISION]
    assert result.hcap_revision == HCAP_REVISION
    assert result.capabilities[0].capability_id == "HCAP-TEST"
