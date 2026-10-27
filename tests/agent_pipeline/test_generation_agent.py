"""The Harness Generation Agent Task (07 §5.1): its worktree, tools,
patch set and runtime, with scripted models and no live API."""

from __future__ import annotations

import asyncio
import json
import subprocess

import pytest
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models import override_allow_model_requests
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.usage import RequestUsage

from agent_pipeline.agent_tasks.executor import PROXY_ROLE, TRIGGER_RULE
from agent_pipeline.agent_tasks.generation import (
    GENERATION_INSTRUCTIONS, GenerationAgentExecutor, GenerationAnswer,
    GenerationResult, GenerationSandbox, HarnessPatchSet,
    QueuedGenerationExecutor, Worktrees)
from agent_pipeline.agent_tasks.pydantic_ai_generation import (
    OUTPUT_TOOL, PydanticAIGenerationRuntime)
from agent_pipeline.agent_tasks.tools import ToolBoundaryError
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import AgentModelPolicy, GapClass, GapRef
from agent_pipeline.controller.generation import (ExtensionOutput,
                                                  GenerationRequest,
                                                  InfeasibleOutput,
                                                  PriorAttempt)

from .fakes import binding, sha
from .test_agent_tasks import candidate

GAP = GapRef(gap_class=GapClass.SYZLANG,
             missing_capability_id="syzlang.nfs4.op_lock")
POLICY = AgentModelPolicy(provider="openai", model="requested")


@pytest.fixture(autouse=True)
def no_live_models():
    with override_allow_model_requests(False):
        yield


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    (r / "bundle").mkdir(parents=True)
    (r / "agent_pipeline").mkdir()
    (r / "bundle" / "calls.txt").write_text("syz_a()\n")
    (r / "agent_pipeline" / "judge.py").write_text("JUDGE = 1\n")
    _git(r, "init", "-q", "-b", "main")
    _git(r, "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    _git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm",
         "base")
    return r


@pytest.fixture
def sandbox(repo, tmp_path):
    return GenerationSandbox(repo=repo, worktree_root=tmp_path / "wt",
                             unsandboxed=True, env={"GEN_MARK": "1"},
                             allowed_paths=("bundle/",))


def request(attempt=1, task="gen-1.a1", previous=()):
    return GenerationRequest(
        generation_id="gen-1", task_id=task, attempt=attempt, gap=GAP,
        model_policy=POLICY, candidate=candidate(),
        base_binding=binding(), previous=previous)


class Sink:
    def __init__(self):
        self.results, self.failures = [], []

    def on_generation_result(self, task_id, attempt, output):
        self.results.append((task_id, attempt, output))

    def on_generation_failure(self, task_id, attempt, failure):
        self.failures.append((task_id, attempt, failure))


class Scripted:
    """A runtime that calls tools, then answers, through the real
    validator."""

    def __init__(self, calls, answer, validate=True):
        self.calls, self.answer, self.validate = calls, answer, validate
        self.runs = []
        self.results = []

    def run(self, run):
        self.runs.append(run)
        for name, args in self.calls:
            self.results.append(asyncio.run(run.tools.invoke(name, args)))
        answer = GenerationAnswer.model_validate(self.answer)
        if self.validate:
            answer = run.validate_output(answer)
        return GenerationResult(answer=answer, model_id="fake:model")


def executor(sandbox, tmp_path, runtime, **kw):
    sink = Sink()
    ex = GenerationAgentExecutor(runtime, ArtifactStore(tmp_path / "art"),
                                 sandbox, sink, **kw)
    return ex, sink


EXTENSION = {"variant": "extension", "summary": "adds syz_lock"}
WRITE = ("write_file", {"path": "bundle/calls.txt",
                        "content": "syz_a()\nsyz_lock()\n"})


def test_an_extension_becomes_a_patch_set_of_the_worktree_diff(
        sandbox, tmp_path, repo):
    rt = Scripted([WRITE], EXTENSION)
    ex, sink = executor(sandbox, tmp_path, rt)
    ex.start(request())
    ((task, attempt, out),) = sink.results
    assert (task, attempt) == ("gen-1.a1", 1) and sink.failures == []
    assert isinstance(out, ExtensionOutput)
    ps = HarnessPatchSet.model_validate_json(ex.artifacts.get(
        out.patch_set_ref))
    assert ps.files == ("bundle/calls.txt",) and ps.gap == GAP
    assert ps.base_commit == _git(repo, "rev-parse", "HEAD")
    assert ps.summary == "adds syz_lock"
    # The patch applies to the base on its own.
    patch = tmp_path / "p.diff"
    patch.write_bytes(ex.artifacts.get(ps.patch_ref))
    _git(repo, "apply", "--check", str(patch))


def test_infeasible_passes_through(sandbox, tmp_path):
    rt = Scripted([], {"variant": "infeasible", "reason": "kernel change"})
    ex, sink = executor(sandbox, tmp_path, rt)
    ex.start(request())
    assert sink.results[0][2] == InfeasibleOutput(reason="kernel change")


def test_an_empty_or_out_of_bounds_change_goes_back_to_the_model(
        sandbox, tmp_path):
    rt = Scripted([], EXTENSION)
    ex, sink = executor(sandbox, tmp_path, rt)
    ex.start(request())
    assert "no change" in sink.failures[0][2]
    # A command can change any file; the diff check still refuses it.
    rt = Scripted([("run_command", {"argv": ["sh", "-c",
                                             "echo 2 > agent_pipeline/judge.py"
                                             ]})], EXTENSION)
    ex, sink = executor(sandbox, tmp_path, rt)
    ex.start(request(task="gen-1.a2"))
    assert "agent_pipeline/judge.py" in sink.failures[0][2]
    assert sink.results == []


def test_an_answer_the_runtime_did_not_validate_is_validated(
        sandbox, tmp_path):
    rt = Scripted([], EXTENSION, validate=False)
    ex, sink = executor(sandbox, tmp_path, rt)
    ex.start(request())
    assert sink.results == [] and "no change" in sink.failures[0][2]


def test_no_launcher_refuses_to_run(repo, tmp_path):
    sb = GenerationSandbox(repo=repo, worktree_root=tmp_path / "wt")
    rt = Scripted([WRITE], EXTENSION)
    ex, sink = executor(sb, tmp_path, rt)
    ex.start(request())
    assert "no generation launcher" in sink.failures[0][2]
    assert rt.runs == []


def test_the_worktree_is_kept_across_attempts(sandbox, tmp_path):
    ex, _ = executor(sandbox, tmp_path, Scripted([WRITE], EXTENSION))
    ex.start(request())
    rt = Scripted([("read_file", {"path": "bundle/calls.txt"})], EXTENSION)
    ex.runtime = rt
    ex.start(request(task="gen-1.a2"))
    assert "syz_lock" in rt.results[0].content


def test_tools_stay_in_the_worktree(sandbox, tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "leak")
    rt = Scripted([("list_dir", {"path": "."}),
                   ("run_command", {"argv": ["printenv"]})], EXTENSION)
    ex, _ = executor(sandbox, tmp_path, Scripted([WRITE], EXTENSION))
    ex.start(request())
    root, _ = Worktrees(sandbox).open("gen-1")
    tools = None

    def capture(run):
        nonlocal tools
        tools = run.tools
        return rt.run(run)
    ex.runtime = type("R", (), {"run": staticmethod(capture)})()
    ex.start(request(task="gen-1.a2"))
    listing, env = rt.results
    assert "bundle/" in listing.entries and ".git" not in listing.entries
    assert "GEN_MARK=1" in env.stdout and "SECRET_TOKEN" not in env.stdout
    for bad in ("../repo/bundle/calls.txt", "/etc/passwd", ".git/config"):
        with pytest.raises(ToolBoundaryError):
            asyncio.run(tools.invoke("read_file", {"path": bad}))
    with pytest.raises(ToolBoundaryError):
        asyncio.run(tools.invoke("write_file", {
            "path": "agent_pipeline/judge.py", "content": "x"}))
    assert (root / "agent_pipeline" / "judge.py").read_text() == "JUDGE = 1\n"


def test_commands_run_through_the_launcher(repo, tmp_path):
    sb = GenerationSandbox(repo=repo, worktree_root=tmp_path / "wt",
                           launcher=("env", "LAUNCHED=yes"),
                           allowed_paths=("bundle/",))
    rt = Scripted([("run_command", {"argv": ["printenv", "LAUNCHED"]}),
                   WRITE], EXTENSION)
    ex, sink = executor(sb, tmp_path, rt)
    ex.start(request())
    assert rt.results[0].stdout.strip() == "yes"
    assert isinstance(sink.results[0][2], ExtensionOutput)


def test_a_redirected_git_file_does_not_redirect_the_diff(sandbox, tmp_path):
    other = tmp_path / "evil"
    rt = Scripted([WRITE, ("run_command", {"argv": [
        "sh", "-c", f"echo 'gitdir: {other}' > .git"]})], EXTENSION)
    ex, sink = executor(sandbox, tmp_path, rt)
    ex.start(request())
    ps = HarnessPatchSet.model_validate_json(ex.artifacts.get(
        sink.results[0][2].patch_set_ref))
    assert "bundle/calls.txt" in ps.files


def test_the_prompt_carries_the_gap_contract_and_earlier_attempts(
        sandbox, tmp_path):
    from agent_pipeline.hcap import (CapabilityContract, EntryPoint,
                                     GapContract)

    contract = GapContract(
        missing_capability_id=GAP.missing_capability_id,
        contract=CapabilityContract(
            entry_points=(EntryPoint(kind="syz_call", name="syz_lock"),),
            boundary_functions=("nfsd4_lock",)))
    store = ArtifactStore(tmp_path / "art")
    earlier = store.put(b'{"summary": "first try"}')
    rt = Scripted([], {"variant": "infeasible", "reason": "x"})
    ex = GenerationAgentExecutor(
        rt, store, sandbox, Sink(),
        contract_for=lambda gap, rev: contract if rev == "hcap-1" else None)
    ex.start(request(previous=(PriorAttempt(
        patch_set_ref=earlier, rejection="regression:HCAP-01",
        evidence_ref=sha("b")),)))
    (run,) = rt.runs
    data = json.loads(run.prompt.split("\n", 1)[1])
    assert data["gap"]["missing_capability_id"] == GAP.missing_capability_id
    assert data["gap_contract"]["contract"]["boundary_functions"] == [
        "nfsd4_lock"]
    (prior,) = data["previous_attempts"]
    assert prior["patch_set"] == {"summary": "first try"}
    assert prior["rejection"] == "regression:HCAP-01"
    assert TRIGGER_RULE in run.instructions
    assert PROXY_ROLE in run.instructions
    assert run.instructions.startswith(GENERATION_INSTRUCTIONS)
    assert "Allowed paths: bundle/" in run.instructions


def test_the_queue_delivers_on_the_controller_thread(sandbox, tmp_path):
    sink = Sink()
    inner = GenerationAgentExecutor(Scripted([WRITE], EXTENSION),
                                    ArtifactStore(tmp_path / "art"), sandbox,
                                    None)
    q = QueuedGenerationExecutor(inner, sink)
    q.start(request())
    assert q.deliver(block=True, timeout=30) == 1
    q.close()
    assert isinstance(sink.results[0][2], ExtensionOutput)


# ---------------------------------------------------------------- runtime


def _call(name, args, provider="function"):
    return ModelResponse(parts=[ToolCallPart(name, json.dumps(args))],
                         provider_name=provider,
                         usage=RequestUsage(output_tokens=10))


def test_the_pydantic_ai_runtime_writes_then_answers(sandbox, tmp_path):
    steps = [_call("write_file", WRITE[1]),
             _call(OUTPUT_TOOL, {"result": EXTENSION})]
    seen = []

    def step(messages, info):
        seen.append(info)
        return steps[len(seen) - 1]

    rt = PydanticAIGenerationRuntime(
        lambda policy: FunctionModel(step, model_name="snap"))
    ex, sink = executor(sandbox, tmp_path, rt)
    ex.start(request())
    assert sink.failures == []
    assert isinstance(sink.results[0][2], ExtensionOutput)
    names = tuple(t.name for t in seen[0].function_tools)
    assert names == ("read_file", "write_file", "list_dir", "run_command")


def test_the_pydantic_ai_runtime_sends_an_empty_change_back(sandbox,
                                                            tmp_path):
    steps = [_call(OUTPUT_TOOL, {"result": EXTENSION}),
             _call("write_file", WRITE[1]),
             _call(OUTPUT_TOOL, {"result": EXTENSION})]
    n = []

    def step(messages, info):
        n.append(1)
        return steps[len(n) - 1]

    rt = PydanticAIGenerationRuntime(
        lambda policy: FunctionModel(step, model_name="snap"))
    ex, sink = executor(sandbox, tmp_path, rt)
    ex.start(request())
    assert len(n) == 3 and sink.failures == []
    assert isinstance(sink.results[0][2], ExtensionOutput)


def test_an_unregistered_tool_ends_the_run(sandbox, tmp_path):
    rt = PydanticAIGenerationRuntime(lambda policy: FunctionModel(
        lambda m, i: _call("delete_everything", {}), model_name="snap"))
    ex, sink = executor(sandbox, tmp_path, rt)
    ex.start(request())
    assert "not registered" in sink.failures[0][2]
