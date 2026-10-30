"""Exercise the installed Agent graph and provider adapter without live APIs."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import httpx2
import pytest
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
from pydantic_ai.messages import (ModelResponse, RetryPromptPart, TextPart,
                                  ToolCallPart, ToolReturnPart)
from pydantic_ai.models import override_allow_model_requests
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.models.wrapper import WrapperModel
from pydantic_ai.usage import RequestUsage

from agent_pipeline.agent_tasks.analysis import CandidateAnalysis
from agent_pipeline.agent_tasks.executor import Stage1AgentExecutor
from agent_pipeline.agent_tasks.pydantic_ai_runtime import (
    DEFAULT_OPENAI_BASE_URL, OUTPUT_TOOL, TOOL_RETRIES, PydanticAIRuntime,
    PydanticAIRuntimeError, RuntimeLimits, _openai_base_url)
from agent_pipeline.agent_tasks.runtime import (OutputRejected, RuntimeRequest,
                                              failure_usage)
from agent_pipeline.agent_tasks.tools import (BackendBoundaryError,
                                              IndexedMatch, Stage1Toolbox,
                                              ToolBoundaryError)
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import AgentModelPolicy, AgentTask, PlanOutput
from agent_pipeline.data import load_record, put_record
from agent_pipeline.hcap import ReachabilityPlan

from .test_agent_tasks import (FakeHcap, FakeSource, Sink, analysis_data,
                               planning_data, request, toolbox)


@pytest.fixture(autouse=True)
def no_live_models():
    with override_allow_model_requests(False):
        yield


def runtime_request(*, retries=2, max_tokens=8192, tools=None, validator=None):
    def validate(value):
        if value.candidate_id != "VC-stage1":
            raise OutputRejected("candidate_id differs from trusted request")
        return value

    return RuntimeRequest(
        task=AgentTask.CANDIDATE_ANALYSIS,
        model_policy=AgentModelPolicy(provider="openai", model="requested-model",
                                      output_retries=retries,
                                      max_output_tokens=max_tokens),
        instructions="Trusted Stage 1 instructions", prompt="Untrusted candidate data",
        output_type=CandidateAnalysis, tools=tools or toolbox(),
        validate_output=validator or validate)


def response(data=None, *, parts=None, provider="function", tokens=10):
    return ModelResponse(
        parts=parts if parts is not None else [ToolCallPart(
            OUTPUT_TOOL, json.dumps({"result": data if data is not None else analysis_data()}))],
        provider_name=provider, usage=RequestUsage(output_tokens=tokens))


class Script:
    def __init__(self, *responses):
        self.responses = responses
        self.calls = []
        self.policies = []

    def step(self, messages, info):
        self.calls.append((list(messages), info))
        item = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        if isinstance(item, Exception):
            raise item
        return item() if callable(item) else item

    def factory(self, policy):
        self.policies.append(policy)
        return FunctionModel(self.step, model_name="actual-snapshot")

    def runtime(self, **kwargs):
        return PydanticAIRuntime(self.factory, **kwargs)


def test_typed_result_exact_tools_policy_and_actual_identity():
    script = Script(response())
    req = runtime_request(max_tokens=1024)
    result = script.runtime().run(req)
    assert result.output == CandidateAnalysis.model_validate(analysis_data())
    assert result.model_id == "function:actual-snapshot"
    assert script.policies == [req.model_policy]
    messages, info = script.calls[0]
    assert tuple(tool.name for tool in info.function_tools) == req.tools.names
    assert len(info.output_tools) == 1
    assert info.output_tools[0].name == OUTPUT_TOOL
    assert info.allow_text_output is False
    assert info.instructions == req.instructions
    assert info.model_settings["max_tokens"] == 1024
    assert info.model_settings["parallel_tool_calls"] is False
    for actual, expected in zip(info.function_tools, req.tools.definitions):
        assert actual.parameters_json_schema == expected.arguments.model_json_schema()
    assert messages[0].parts[0].content == req.prompt


@pytest.mark.parametrize("bad", [{"invalid": 1}, analysis_data("VC-other")])
def test_schema_and_semantic_errors_repair_in_library(bad):
    script = Script(response(bad), response())
    assert script.runtime().run(runtime_request()).model_id == "function:actual-snapshot"
    assert len(script.calls) == 2
    assert any(isinstance(part, RetryPromptPart)
               for message in script.calls[1][0] for part in message.parts)


@pytest.mark.parametrize("retries", [0, 2])
@pytest.mark.parametrize("bad", [{"invalid": 1}, analysis_data("VC-other")])
def test_repair_exhaustion_exact_budget(retries, bad):
    script = Script(lambda: response(bad))
    with pytest.raises((UnexpectedModelBehavior, PydanticAIRuntimeError)):
        script.runtime().run(runtime_request(retries=retries))
    assert len(script.calls) == retries + 1


def test_text_and_output_tool_retries_share_one_budget():
    script = Script(response(parts=[TextPart("wrong output format")]),
                    response({"invalid": 1}), response(analysis_data("VC-other")),
                    response())
    with pytest.raises((UnexpectedModelBehavior, PydanticAIRuntimeError)):
        script.runtime().run(runtime_request(retries=2))
    assert len(script.calls) == 3


def test_valid_output_after_two_repairs():
    script = Script(response({"invalid": 1}),
                    response(analysis_data("VC-other")), response())
    assert script.runtime().run(runtime_request(retries=2)).output.candidate_id == "VC-stage1"
    assert len(script.calls) == 3


def test_wrong_output_validator_type_is_rejected():
    class Wrong(BaseModel):
        value: str

    script = Script(lambda: response())
    with pytest.raises(UnexpectedModelBehavior):
        script.runtime().run(runtime_request(retries=0, validator=lambda v: Wrong(value="x")))
    assert len(script.calls) == 1


@pytest.mark.parametrize("with_output", [False, True])
def test_unknown_tool_fails_even_beside_valid_output(with_output):
    parts = [ToolCallPart("execute_shell", {"command": "id"})]
    if with_output:
        parts.insert(0, ToolCallPart(OUTPUT_TOOL, {"result": analysis_data()}))
    script = Script(response(parts=parts), response())
    with pytest.raises(PydanticAIRuntimeError, match="not registered"):
        script.runtime().run(runtime_request())
    assert len(script.calls) == 1


@pytest.mark.parametrize("arguments", [
    {"path": "../../etc/passwd", "start_line": 1, "end_line": 2},
    {"path": "fs/nfsd/nfs4proc.c", "start_line": 0, "end_line": 2},
    {"path": "fs/nfsd/nfs4proc.c", "start_line": 1, "end_line": 2,
     "kernel_commit": "forged"},
    {"path": "fs/nfsd/nfs4proc.c", "start_line": 1, "end_line": 401},
])
def test_invalid_tool_arguments_never_reach_source(arguments):
    source = FakeSource()
    script = Script(response(parts=[ToolCallPart("read_kernel_source", arguments)]))
    with pytest.raises(UnexpectedModelBehavior, match="max retries"):
        script.runtime().run(runtime_request(tools=toolbox(source)))
    assert not source.calls
    assert len(script.calls) == TOOL_RETRIES + 1


@pytest.mark.parametrize("arguments,message", [
    ({"path": "fs/nfsd/nfs4proc.c", "start_line": 1, "end_line": 401},
     "400 lines"),
    ({"path": "include/linux/fs.h", "start_line": 1, "end_line": 2},
     "outside the Stage 1 roots"),
    ({"path": "fs/nfsd/nfs4proc.c", "start_line": 0, "end_line": 2},
     "start_line"),
])
def test_tool_call_mistake_is_returned_to_the_model(arguments, message):
    script = Script(response(parts=[ToolCallPart("read_kernel_source", arguments)]),
                    response())
    result = script.runtime().run(runtime_request())
    assert result.output == CandidateAnalysis.model_validate(analysis_data())
    assert len(script.calls) == 2
    retries = [part for part in script.calls[1][0][-1].parts
               if isinstance(part, RetryPromptPart)]
    assert len(retries) == 1 and message in str(retries[0].content)


def test_missing_source_file_is_returned_to_the_model():
    source = FakeSource()
    source.read_text = None
    script = Script(response(parts=[ToolCallPart("read_kernel_source", {
        "path": "fs/nfsd/nfs4state.h", "start_line": 1, "end_line": 2})]),
        response())
    script.runtime().run(runtime_request(tools=toolbox(source)))
    assert len(script.calls) == 2


def test_source_index_boundary_violation_is_not_retried():
    source = FakeSource()
    source.matches = [IndexedMatch(path="drivers/block/x.c", line=1,
                                   text="outside")]
    script = Script(response(parts=[ToolCallPart(
        "search_kernel_source", {"query": "target"})]))
    with pytest.raises(BackendBoundaryError):
        script.runtime().run(runtime_request(tools=toolbox(source)))
    assert len(script.calls) == 1


def test_backend_tool_failure_is_not_retried():
    source = FakeSource()

    def broken(*args):
        source.calls.append(args)
        raise OSError(5, "Input/output error")

    source.read = broken
    script = Script(response(parts=[ToolCallPart("read_kernel_source", {
        "path": "fs/nfsd/nfs4proc.c", "start_line": 1, "end_line": 2})]))
    with pytest.raises(OSError):
        script.runtime().run(runtime_request(tools=toolbox(source)))
    assert len(script.calls) == len(source.calls) == 1


def test_toolbox_bindings_and_histories_do_not_leak_between_runs():
    read = ToolCallPart("read_kernel_source", {
        "path": "fs/nfsd/nfs4proc.c", "start_line": 1, "end_line": 2})
    script = Script(response(parts=[read]),
                    response(parts=[ToolCallPart("lookup_hcap", {})]), response())
    runtime = script.runtime()
    for index in ("a", "b"):
        script.calls.clear()
        source, hcap = FakeSource(), FakeHcap()
        source.read_text = index
        tools = Stage1Toolbox(source, hcap, kernel_commit=index * 40,
                             hcap_revision=index * 64)
        runtime.run(runtime_request(tools=tools))
        assert source.calls[0][1] == index * 40
        assert hcap.revisions == [index * 64]
        assert len(script.calls[0][0]) == 1
        tool_returns = [p for m in script.calls[1][0] for p in m.parts
                        if isinstance(p, ToolReturnPart)]
        assert tool_returns[0].content.text == index


def test_provider_failure_surfaces_once():
    script = Script(RuntimeError("provider unavailable"), response())
    with pytest.raises(RuntimeError, match="provider unavailable"):
        script.runtime().run(runtime_request())
    assert len(script.calls) == 1


def test_concurrent_runs_have_independent_tool_bindings():
    barrier = threading.Barrier(2)
    sources = [FakeSource(), FakeSource()]

    def factory(policy):
        barrier.wait(timeout=5)
        calls = 0

        async def step(messages, info):
            nonlocal calls
            calls += 1
            if calls == 1:
                return response(parts=[ToolCallPart("read_kernel_source", {
                    "path": "fs/nfsd/nfs4proc.c", "start_line": 1, "end_line": 2})])
            return response()

        return FunctionModel(step, model_name="concurrent-model")

    runtime = PydanticAIRuntime(factory)
    requests = [runtime_request(tools=Stage1Toolbox(
        source, FakeHcap(), kernel_commit=str(index) * 40,
        hcap_revision=str(index) * 64)) for index, source in enumerate(sources)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(runtime.run, requests))
    assert len(results) == 2
    for index, source in enumerate(sources):
        assert len(source.calls) == 1
        assert source.calls[0][1] == str(index) * 40


@pytest.mark.parametrize("field,value", [
    ("provider_name", None), ("provider_name", ""), ("provider_name", "bad id"),
    ("model_name", None), ("model_name", ""), ("model_name", "bad id"),
])
def test_response_metadata_is_mandatory(field, value):
    script = Script(response())

    class MissingMetadata(WrapperModel):
        async def request(self, *args):
            result = await self.wrapped.request(*args)
            # FunctionModel sets model_name, so remove it after its request.
            setattr(result, field, value)
            return result

    runtime = PydanticAIRuntime(lambda policy: MissingMetadata(script.factory(policy)))
    with pytest.raises(PydanticAIRuntimeError, match="actual provider/model"):
        runtime.run(runtime_request())
    assert len(script.calls) == 1


def test_metadata_checked_before_dispatching_tools():
    source = FakeSource()
    script = Script(response(provider=None, parts=[ToolCallPart("read_kernel_source", {
        "path": "fs/nfsd/nfs4proc.c", "start_line": 1, "end_line": 2})]))
    with pytest.raises(PydanticAIRuntimeError):
        script.runtime().run(runtime_request(tools=toolbox(source)))
    assert not source.calls


@pytest.mark.parametrize("tokens,allowed", [(256, True), (257, False)])
def test_max_output_tokens_checked_on_response(tokens, allowed):
    script = Script(response(tokens=tokens))
    if allowed:
        script.runtime().run(runtime_request(max_tokens=256))
    else:
        with pytest.raises(UsageLimitExceeded, match="max_output_tokens"):
            script.runtime().run(runtime_request(max_tokens=256))
    assert len(script.calls) == 1


def test_refused_response_usage_is_kept():
    # One accepted 10-token response, then one refused at 257 tokens.
    script = Script(response(parts=[ToolCallPart("lookup_hcap", {})]),
                    response(tokens=257))
    with pytest.raises(UsageLimitExceeded) as raised:
        script.runtime().run(runtime_request(max_tokens=256))
    usage = failure_usage(raised.value)
    assert (usage.requests, usage.tool_calls, usage.output_tokens) == \
        (2, 1, 267)

    unknown = Script(response(parts=[ToolCallPart("not_a_tool", {})],
                              tokens=7))
    with pytest.raises(PydanticAIRuntimeError) as raised:
        unknown.runtime().run(runtime_request())
    usage = failure_usage(raised.value)
    assert (usage.requests, usage.output_tokens) == (1, 7)


def test_refused_response_usage_reaches_the_sink(tmp_path):
    script = Script(response(tokens=8193))
    sink = Sink()
    Stage1AgentExecutor(script.runtime(), ArtifactStore(tmp_path / "a"),
                        lambda req: toolbox(), sink).start(
        request(AgentTask.CANDIDATE_ANALYSIS).model_copy(update={
            "model_policy": request(AgentTask.CANDIDATE_ANALYSIS)
            .model_policy.model_copy(update={"max_output_tokens": 8192})}))
    assert sink.failures[0][2].startswith("UsageLimitExceeded")
    assert (sink.usage[0].requests, sink.usage[0].output_tokens) == \
        (1, 8193)


def test_model_loop_request_limit():
    script = Script(lambda: response(parts=[ToolCallPart("lookup_hcap", {})]))
    limits = RuntimeLimits(max_requests=2)
    with pytest.raises(UsageLimitExceeded) as raised:
        script.runtime(limits=limits).run(runtime_request())
    assert len(script.calls) == 2
    # What the failed run used stays on its exception.
    usage = failure_usage(raised.value)
    assert (usage.requests, usage.tool_calls) == (2, 2)
    assert usage.output_tokens == 20


def test_parallel_tool_batch_is_bounded_before_dispatch():
    hcap = FakeHcap()
    tools = Stage1Toolbox(FakeSource(), hcap, kernel_commit="a" * 40,
                         hcap_revision="b" * 64)
    script = Script(response(parts=[ToolCallPart("lookup_hcap", {}) for _ in range(3)]))
    with pytest.raises(UsageLimitExceeded):
        script.runtime(limits=RuntimeLimits(max_tool_calls=2)).run(runtime_request(tools=tools))
    assert not hcap.revisions


@pytest.mark.parametrize("scope", ["request", "run"])
def test_stalled_model_has_a_deadline(scope):
    async def stalled(messages, info):
        await asyncio.sleep(10)

    limits = RuntimeLimits(**{f"{scope}_timeout_seconds": 0.01})
    runtime = PydanticAIRuntime(lambda policy: FunctionModel(stalled), limits=limits)
    with pytest.raises(TimeoutError) as raised:
        runtime.run(runtime_request())
    assert failure_usage(raised.value) is not None


def test_failed_run_usage_reaches_the_sink(tmp_path):
    script = Script(lambda: response(parts=[ToolCallPart("lookup_hcap", {})]))
    sink = Sink()
    executor = Stage1AgentExecutor(
        script.runtime(limits=RuntimeLimits(max_requests=2)),
        ArtifactStore(tmp_path / "artifacts"), lambda req: toolbox(), sink)
    executor.start(request(AgentTask.CANDIDATE_ANALYSIS))
    assert sink.failures[0][2].startswith("UsageLimitExceeded")
    assert (sink.usage[0].requests, sink.usage[0].tool_calls) == (2, 2)


def test_testmodel_is_usable_and_does_not_fabricate_identity():
    model = TestModel(call_tools=[], custom_output_args={"result": analysis_data()})
    # The actual library TestModel labels its own response as test:test.
    assert PydanticAIRuntime(lambda policy: model).run(runtime_request()).model_id == "test:test"


def test_analysis_executor_integration_and_single_failure(tmp_path):
    script = Script(response(analysis_data("VC-other")), response())
    sink, artifacts = Sink(), ArtifactStore(tmp_path / "artifacts")
    executor = Stage1AgentExecutor(script.runtime(), artifacts,
                                   lambda req: toolbox(), sink)
    executor.start(request(AgentTask.CANDIDATE_ANALYSIS))
    assert not sink.failures
    assert len(sink.results) == 1
    assert sink.results[0][3] == "function:actual-snapshot"
    assert load_record(artifacts, sink.results[0][2].analysis_ref,
                       CandidateAnalysis).candidate_id == "VC-stage1"
    failing = Script(RuntimeError("provider failed"))
    Stage1AgentExecutor(failing.runtime(), artifacts, lambda req: toolbox(), sink).start(
        request(AgentTask.CANDIDATE_ANALYSIS))
    assert len(sink.failures) == len(failing.calls) == 1
    assert len(sink.results) == 1


def test_planning_executor_rootmodel_output(tmp_path):
    artifacts, sink = ArtifactStore(tmp_path / "artifacts"), Sink()
    analysis_ref = put_record(artifacts, CandidateAnalysis.model_validate(analysis_data()))
    script = Script(response(planning_data()))
    Stage1AgentExecutor(script.runtime(), artifacts, lambda req: toolbox(), sink).start(
        request(AgentTask.REACHABILITY_PLANNING, analysis_ref=analysis_ref))
    assert not sink.failures
    assert isinstance(sink.results[0][2], PlanOutput)
    plan = load_record(artifacts, sink.results[0][2].plan_ref, ReachabilityPlan)
    assert artifacts.get(plan.program_proposal.artifact_ref) == b"syz_test$open()\n"


def test_base_import_does_not_load_optional_dependencies():
    code = '''
import sys
class Block:
    def find_spec(self, fullname, *args):
        if fullname.split('.')[0] in {'pydantic_ai', 'openai'}:
            raise ImportError('optional runtime unavailable')
sys.meta_path.insert(0, Block())
import agent_pipeline.agent_tasks
assert 'pydantic_ai' not in sys.modules
'''
    subprocess.run([sys.executable, "-c", code], check=True,
                   cwd=Path(__file__).resolve().parents[2])


@pytest.mark.parametrize("limits", [
    {"max_requests": 0}, {"max_tool_calls": True},
    {"run_timeout_seconds": float("inf")}, {"request_timeout_seconds": -1},
])
def test_invalid_host_limits(limits):
    with pytest.raises(ValueError):
        RuntimeLimits(**limits)


def test_default_rejects_unsupported_policy_before_provider_access():
    req = runtime_request()
    req = replace(req, model_policy=AgentModelPolicy(provider="unreviewed", model="model"))
    with pytest.raises(PydanticAIRuntimeError, match="supports only openai"):
        PydanticAIRuntime().run(req)


def test_runtime_does_not_change_environment():
    before = dict(os.environ)
    Script(response()).runtime().run(runtime_request())
    assert dict(os.environ) == before


def test_instrumentation_disabled_even_with_global_default(monkeypatch):
    import pydantic_ai.agent

    class UnexpectedInstrumentation(pydantic_ai.agent.InstrumentationCap):
        def __init__(self, **kwargs):
            pytest.fail("runtime enabled tracing")

    monkeypatch.setattr(Agent, "_instrument_default", True)
    monkeypatch.setattr(pydantic_ai.agent, "InstrumentationCap", UnexpectedInstrumentation)
    script = Script(response())
    script.runtime().run(runtime_request())
    assert len(script.calls) == 1


@pytest.mark.parametrize("status", [200, 400, 429, 500])
def test_default_openai_http_mock_has_no_retries_or_model_fallback(monkeypatch, status):
    import openai

    requests, clients = [], []
    real_client = openai.AsyncOpenAI

    def handler(req):
        requests.append(req)
        if status != 200:
            return httpx2.Response(status, json={"error": {"message": "unavailable", "type": "server_error"}})
        return httpx2.Response(200, json={
            "id": "resp_test", "object": "response", "created_at": 1,
            "status": "completed", "model": "actual-provider-snapshot",
            "output": [{"type": "function_call", "name": OUTPUT_TOOL,
                        "arguments": json.dumps({"result": analysis_data()}), "call_id": "call_test",
                        "id": "fc_test", "status": "completed"}],
            "usage": {"input_tokens": 15, "output_tokens": 10, "total_tokens": 25},
            "parallel_tool_calls": False, "tools": [],
        })

    def factory(**kwargs):
        assert kwargs["max_retries"] == 0
        client = real_client(api_key="local-test", http_client=httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler)), **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(openai, "AsyncOpenAI", factory)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://untrusted.invalid/v1")
    monkeypatch.delenv("KNFSD_OPENAI_BASE_URL", raising=False)
    with override_allow_model_requests(True):
        if status == 200:
            result = PydanticAIRuntime().run(runtime_request(max_tokens=1024))
            assert result.model_id == "openai:actual-provider-snapshot"
        else:
            with pytest.raises(Exception, match="unavailable"):
                PydanticAIRuntime().run(runtime_request())
    assert len(requests) == 1
    assert requests[0].url.host == "api.openai.com"
    body = json.loads(requests[0].content)
    assert body["model"] == "requested-model"
    assert body["max_output_tokens"] == (1024 if status == 200 else 8192)
    assert body["store"] is False
    assert body["background"] is False
    assert {tool["name"] for tool in body["tools"]} == set(toolbox().names) | {OUTPUT_TOOL}
    assert clients[0].is_closed()


def test_default_openai_accepts_explicit_pipeline_base_url(monkeypatch):
    import openai

    captured = {}
    real_client = openai.AsyncOpenAI

    def factory(**kwargs):
        captured.update(kwargs)
        return real_client(api_key="local-test", **kwargs)

    monkeypatch.setattr(openai, "AsyncOpenAI", factory)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://untrusted.invalid/v1")
    monkeypatch.setenv("KNFSD_OPENAI_BASE_URL", "https://reviewed.invalid/v1")
    _, client = PydanticAIRuntime._openai_model(
        AgentModelPolicy(provider="openai", model="requested-model"))
    assert str(captured["base_url"]) == "https://reviewed.invalid/v1"
    asyncio.run(client.close())


@pytest.mark.parametrize("configured, expected", [
    ("", DEFAULT_OPENAI_BASE_URL),
    ("http://localhost:4000/v1", "http://localhost:4000/v1"),
    ("http://127.0.0.1:4000/v1", "http://127.0.0.1:4000/v1"),
    ("http://[::1]:4000/v1", "http://[::1]:4000/v1"),
    ("http://100.99.59.97:4000/v1", "http://100.99.59.97:4000/v1"),
])
def test_pipeline_base_url_allows_empty_and_trusted_http(
        monkeypatch, configured, expected):
    monkeypatch.setenv("KNFSD_OPENAI_BASE_URL", configured)
    assert _openai_base_url() == expected


@pytest.mark.parametrize("configured", [
    "http://example.com/v1", "ftp://127.0.0.1/v1",
    "https:///v1",
    "https://user@example.com/v1", "https://example.com/v1?redirect=1",
])
def test_pipeline_base_url_rejects_untrusted_forms(monkeypatch, configured):
    monkeypatch.setenv("KNFSD_OPENAI_BASE_URL", configured)
    with pytest.raises(PydanticAIRuntimeError, match="KNFSD_OPENAI_BASE_URL"):
        _openai_base_url()


def test_validate_program_tool_is_registered_and_dispatched():
    from agent_pipeline.agent_tasks.tools import ProgramValidation
    from .test_agent_tasks import planning_data

    seen = []

    def validator(draft):
        seen.append(draft)
        return ProgramValidation(accepted=False, stage="materializer",
                                 reason="parse_failure",
                                 message="line 1: unknown call")

    tools = Stage1Toolbox(FakeSource(), FakeHcap(), kernel_commit="a" * 40,
                          hcap_revision="b" * 64,
                          program_validator=validator)
    script = Script(response(parts=[ToolCallPart(
        "validate_program", {"plan": planning_data()["plan"]})]), response())
    script.runtime().run(runtime_request(tools=tools))
    assert len(seen) == 1 and seen[0].candidate_id == "VC-stage1"
    returned = [p for m in script.calls[1][0] for p in m.parts
                if isinstance(p, ToolReturnPart)]
    assert returned[0].content.message == "line 1: unknown call"
    # The model is offered the eighth tool only when it is bound.
    assert "validate_program" in {t.name for t in
                                  script.calls[0][1].function_tools}


@pytest.mark.parametrize(("provider", "effort", "expected"), [
    ("openai", "high", "high"), ("openai", None, None),
    ("other", "high", None)])
def test_reasoning_effort_setting_and_usage(provider, effort, expected):
    script = Script(response(parts=[ToolCallPart("lookup_hcap", {})]),
                    response())
    req = runtime_request()
    req = replace(req, model_policy=req.model_policy.model_copy(update={
        "provider": provider, "reasoning_effort": effort}))
    result = script.runtime().run(req)
    settings = script.calls[0][1].model_settings
    assert settings.get("openai_reasoning_effort") == expected
    assert (result.usage.requests, result.usage.tool_calls) == (2, 1)
    assert result.usage.output_tokens == 20


def test_knowledge_tools_are_offered_and_dispatched():
    from .test_agent_knowledge import FakeKnowledge

    tools = Stage1Toolbox(FakeSource(), FakeHcap(), kernel_commit="a" * 40,
                          hcap_revision="b" * 64, knowledge=FakeKnowledge())
    script = Script(response(parts=[ToolCallPart(
        "search_syzlang", {"query": "call$two"})]), response())
    script.runtime().run(runtime_request(tools=tools))
    offered = {t.name for t in script.calls[0][1].function_tools}
    assert {"search_syzlang", "read_syzlang", "read_harness_patch",
            "lookup_reference_programs"} <= offered
    returned = [p for m in script.calls[1][0] for p in m.parts
                if isinstance(p, ToolReturnPart)]
    assert returned[0].content.blocks[0].path == "sys/linux/a.txt"
