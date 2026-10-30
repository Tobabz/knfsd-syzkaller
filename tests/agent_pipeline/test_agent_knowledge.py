"""#75 steps 5 and 6: harness knowledge tools, model settings and usage."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from agent_pipeline.agent_tasks.executor import PinnedToolboxFactory
from agent_pipeline.agent_tasks.knowledge import (HarnessKnowledge,
                                                  ReferenceProgram,
                                                  rebuild_syzlang,
                                                  series_patches,
                                                  split_series)
from agent_pipeline.agent_tasks.tools import (KNOWLEDGE_TOOLS,
                                              TOOL_DEFINITIONS,
                                              VALIDATE_PROGRAM_TOOL,
                                              BackendBoundaryError,
                                              Stage1Toolbox,
                                              ToolBoundaryError,
                                              known_tool_set)
from agent_pipeline.contracts import (AgentModelPolicy, AgentTask,
                                      AgentUsage, Stage1AgentPolicy)
from agent_pipeline.controller.tasks import agent_input_digest
from agent_pipeline.stage1.host.generate import series_fingerprint

from .test_agent_tasks import FakeHcap, FakeSource, candidate, request

REPO = Path(__file__).resolve().parents[2]
SERIES = REPO / "bundle" / "patches" / "syzkaller"


def series_bytes(patches) -> bytes:
    return b"".join(name.encode() + b"\0" + text.encode() + b"\0"
                    for name, text in patches)


def checked_in_series() -> list[tuple[str, str]]:
    return [(p.name, p.read_text())
            for p in sorted(SERIES.glob("*.patch"))]


def checked_in_patch_stacks() -> list[tuple[str, str]]:
    patch_root = REPO / "bundle" / "patches"
    return [(p.name, p.read_text())
            for directory in (patch_root / "syzkaller",
                              patch_root / "kcsan" / "syzkaller")
            for p in sorted(directory.glob("*.patch"))]


def test_series_bytes_match_the_pinned_fingerprint():
    stacks = checked_in_patch_stacks()
    data = series_bytes(stacks)
    assert hashlib.sha256(data).hexdigest() == series_fingerprint("syzkaller")
    assert split_series(data) == stacks
    with pytest.raises(ValueError):
        split_series(b"name-without-patch\0")


def test_checked_in_descriptions_are_rebuilt_whole():
    files = rebuild_syzlang(checked_in_series())
    nfs = files["sys/linux/fs_nfs_fuzz.txt"]
    assert nfs.complete
    text = "\n".join(nfs.lines)
    # Added by 0020, after 0015 created the file.
    assert "syz_open_nfs_lane_profile$client0_knfsd_v41(profile const[2], " \
        "client const[0]) fd_nfs_dir" in text
    assert "resource fd_nfs_dir[fd_dir]" in text
    assert files["sys/linux/socket_inet_nfs.txt"].complete
    assert not any(path.endswith(".go") for path in files)


PATCH_1 = """From 1 Mon Sep 17 00:00:00 2001
Subject: [PATCH] sys/linux: add a call

Why the call exists.
---
 sys/linux/a.txt | 2 ++

diff --git a/sys/linux/a.txt b/sys/linux/a.txt
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/sys/linux/a.txt
@@ -0,0 +1,3 @@
+# comment
+call$one(a int32)
+
diff --git a/sys/linux/upstream.txt b/sys/linux/upstream.txt
index 2222222..3333333 100644
--- a/sys/linux/upstream.txt
+++ b/sys/linux/upstream.txt
@@ -10,2 +10,3 @@ context
 kept
+added$upstream()
 kept
--
2.43.0
"""

PATCH_2 = """From 2 Mon Sep 17 00:00:00 2001
Subject: [PATCH] sys/linux: change the call

---
diff --git a/sys/linux/a.txt b/sys/linux/a.txt
index 1111111..4444444 100644
--- a/sys/linux/a.txt
+++ b/sys/linux/a.txt
@@ -1,3 +1,4 @@
 # comment
-call$one(a int32)
+call$one(a int64)
+call$two()

--
2.43.0
"""


def test_series_hunks_apply_in_order_and_ignore_mail_trailers():
    series = [("0001-a.patch", PATCH_1), ("0002-b.patch", PATCH_2)]
    files = rebuild_syzlang(series)
    assert files["sys/linux/a.txt"].lines == (
        "# comment", "call$one(a int64)", "call$two()", "")
    assert files["sys/linux/a.txt"].complete
    upstream = files["sys/linux/upstream.txt"]
    assert (upstream.lines, upstream.complete) == (
        ("added$upstream()",), False)
    patches = series_patches(series)
    assert (patches[0].subject, patches[0].message) == (
        "sys/linux: add a call", "Why the call exists.")
    assert patches[1].message == ""
    assert [path for path, _ in patches[0].syzlang_hunks] == [
        "sys/linux/a.txt", "sys/linux/upstream.txt"]


class FakeKnowledge:
    def __init__(self) -> None:
        series = [("0001-a.patch", PATCH_1), ("0002-b.patch", PATCH_2)]
        self.files = rebuild_syzlang(series)
        self.series = series_patches(series)
        self.texts = {"r" * 64: b"syz_open_nfs_lane_profile$x()\n"}
        self.revisions = []

    def syzlang(self, revision):
        self.revisions.append(revision)
        return self.files

    def patches(self, revision):
        return self.series

    def reference_programs(self, revision):
        return [ReferenceProgram(
            program_id="neutral:0", kind="neutral_control",
            program_ref="r" * 64, runtime_selections=({"profile": "p"},),
            required_capability_ids=("HCAP-01",))]

    def program_text(self, ref, max_bytes):
        return self.texts[ref]


def knowledge_toolbox(knowledge=None) -> Stage1Toolbox:
    return Stage1Toolbox(FakeSource(), FakeHcap(), kernel_commit="a" * 40,
                         hcap_revision="c" * 64,
                         knowledge=knowledge or FakeKnowledge())


def test_syzlang_tools_search_list_and_read():
    knowledge = FakeKnowledge()
    tools = knowledge_toolbox(knowledge)
    found = tools.invoke("search_syzlang", {"query": "call$two"})
    assert [(b.path, b.line) for b in found.blocks] == [
        ("sys/linux/a.txt", 1)]
    assert "call$one(a int64)" in found.blocks[0].text
    assert knowledge.revisions == ["c" * 64]

    listed = tools.invoke("read_syzlang", {})
    assert [(f.path, f.complete) for f in listed.files] == [
        ("sys/linux/a.txt", True), ("sys/linux/upstream.txt", False)]
    excerpt = tools.invoke("read_syzlang", {
        "path": "sys/linux/a.txt", "start_line": 2, "end_line": 3})
    assert excerpt.text == "call$one(a int64)\ncall$two()"
    with pytest.raises(ToolBoundaryError):
        tools.invoke("read_syzlang", {"path": "sys/linux/none.txt"})
    with pytest.raises(ToolBoundaryError):
        tools.invoke("read_syzlang", {"path": "sys/linux/a.txt",
                                      "start_line": 1, "end_line": 401})


@pytest.mark.parametrize("ref", ["0002", "0002-b.patch",
                                 "bundle/patches/syzkaller/0002-*"])
def test_harness_patch_opens_a_source_ref(ref):
    patch = knowledge_toolbox().invoke("read_harness_patch", {"patch": ref})
    assert patch.name == "0002-b.patch"
    assert patch.subject == "sys/linux: change the call"
    assert "+call$two()" in patch.syzlang_hunks


def test_harness_patch_needs_one_match():
    with pytest.raises(ToolBoundaryError):
        knowledge_toolbox().invoke("read_harness_patch", {"patch": "0009"})


def test_reference_programs_list_and_read():
    tools = knowledge_toolbox()
    listed = tools.invoke("lookup_reference_programs", {})
    assert [p.program_id for p in listed.programs] == ["neutral:0"]
    assert listed.programs[0].runtime_selections == ({"profile": "p"},)
    assert listed.text == ""
    read = tools.invoke("lookup_reference_programs",
                        {"program_id": "neutral:0"})
    assert read.text == "syz_open_nfs_lane_profile$x()\n"
    with pytest.raises(ToolBoundaryError):
        tools.invoke("lookup_reference_programs",
                     {"program_id": "seed:none"})


def test_artifact_knowledge_reads_only_hcap_selected_authorities(tmp_path):
    from .test_materializer import materializer_world
    w = materializer_world(tmp_path)
    knowledge = HarnessKnowledge(w.store)
    programs = knowledge.reference_programs(w.hcap_ref)
    assert [(p.program_id, p.program_ref) for p in programs] == [
        ("neutral:0", w.neutral_ref), ("seed:seed-1", w.scenario_ref)]
    assert knowledge.program_text(w.neutral_ref, 1024) == w.neutral_bytes
    # The synthetic world pins bytes that are not a patch series.
    tools = Stage1Toolbox(FakeSource(), FakeHcap(), kernel_commit="a" * 40,
                          hcap_revision=w.hcap_ref, knowledge=knowledge)
    with pytest.raises(BackendBoundaryError):
        tools.invoke("search_syzlang", {"query": "call"})


def test_a_seed_lists_every_admitted_runtime_selection(tmp_path):
    from agent_pipeline.data import load_record, put_record
    from agent_pipeline.hcap import AuthorityRef, HcapCatalog
    from agent_pipeline.materializer import (NormalFlowSeed,
                                             NormalFlowSeedManifest)
    from .test_materializer import materializer_world
    w = materializer_world(tmp_path)
    catalog = load_record(w.store, w.hcap_ref, HcapCatalog)
    old_ref = next(ref.artifact_ref for ref in catalog.authority_refs
                   if ref.kind == "NormalFlowSeedManifest")
    manifest = load_record(w.store, old_ref, NormalFlowSeedManifest)
    base = manifest.seeds[0].runtime_selections[0]
    selections = tuple(sorted(
        (base, base.model_copy(update={"nfs_version": "4.2"})),
        key=lambda s: s.model_dump_json()))
    seeds_ref = put_record(w.store, manifest.model_copy(update={"seeds": (
        NormalFlowSeed(seed_id="seed-1", program_ref=w.scenario_ref,
                       runtime_selections=selections),)}))
    hcap_ref = put_record(w.store, catalog.model_copy(update={
        "authority_refs": tuple(
            AuthorityRef(kind=ref.kind, artifact_ref=seeds_ref)
            if ref.kind == "NormalFlowSeedManifest" else ref
            for ref in catalog.authority_refs)}))

    seed = HarnessKnowledge(w.store).reference_programs(hcap_ref)[-1]
    assert seed.program_id == "seed:seed-1"
    assert [s["nfs_version"] for s in seed.runtime_selections] == \
        [s.nfs_version for s in selections]
    assert len(seed.runtime_selections) == 2


def test_factory_binds_knowledge_to_stage1_tasks_only():
    factory = PinnedToolboxFactory(FakeSource(), FakeHcap(),
                                   knowledge=FakeKnowledge())
    for task in (AgentTask.CANDIDATE_ANALYSIS,
                 AgentTask.REACHABILITY_PLANNING):
        assert factory(request(task)).definitions == \
            TOOL_DEFINITIONS + KNOWLEDGE_TOOLS
    mutation = request(AgentTask.CANDIDATE_ANALYSIS).model_copy(
        update={"agent_task": AgentTask.MUTATION_STRATEGY})
    assert factory(mutation).definitions == TOOL_DEFINITIONS


def test_runtime_accepts_only_known_tool_sets():
    validate = (VALIDATE_PROGRAM_TOOL,)
    for extra in ((), KNOWLEDGE_TOOLS, validate, KNOWLEDGE_TOOLS + validate):
        assert known_tool_set(TOOL_DEFINITIONS + extra)
    assert not known_tool_set(TOOL_DEFINITIONS + validate + KNOWLEDGE_TOOLS)
    assert not known_tool_set(TOOL_DEFINITIONS[:-1])
    assert not known_tool_set(TOOL_DEFINITIONS + KNOWLEDGE_TOOLS[:1])


def test_reasoning_effort_is_left_out_unless_set():
    plain = AgentModelPolicy(provider="openai", model="gpt-5")
    assert "reasoning_effort" not in plain.model_dump(mode="json")
    effort = plain.model_copy(update={"reasoning_effort": "high"})
    assert effort.model_dump(mode="json")["reasoning_effort"] == "high"
    assert AgentModelPolicy.model_validate_json(
        effort.model_dump_json()) == effort
    # A task digest computed before the field existed is unchanged.
    inputs = dict(agent_task=AgentTask.CANDIDATE_ANALYSIS,
                  candidate=candidate(), hcap_revision="c" * 64,
                  analysis_ref=None, plan_ref=None, repair=None)
    legacy = {"provider": "openai", "model": "gpt-5", "output_retries": 2,
              "max_output_tokens": 8192}
    assert agent_input_digest(model_policy=plain, **inputs) == \
        agent_input_digest(
            model_policy=AgentModelPolicy.model_validate(legacy), **inputs)
    assert agent_input_digest(model_policy=plain, **inputs) != \
        agent_input_digest(model_policy=effort, **inputs)
    assert "reasoning_effort" not in Stage1AgentPolicy().model_dump_json()


def test_host_template_uses_new_ids_for_gpt56_policies():
    import json
    spec = json.loads((REPO / "agent_pipeline" / "stage1" / "host" /
                       "template" / "host-spec.json").read_text())
    policies = {p["policy_id"]: p for p in spec["policies"]}
    assert "kasan-default" not in policies
    assert "kasan-agent-effort" not in policies
    default = policies["kasan-default-gpt56"]["stage1_agents"]
    assert "reasoning_effort" not in default["reachability_planning"]
    assert {entry["model"] for entry in default.values()} == {
        "gpt-5.6-sol"}
    effort = policies["kasan-agent-effort-gpt56"]["stage1_agents"]
    assert AgentModelPolicy.model_validate(
        effort["reachability_planning"]).reasoning_effort == "high"
    assert {entry["model"] for entry in effort.values()} == {
        "gpt-5.6-sol"}


def test_controller_keeps_usage_on_the_attempt_only(world):
    from agent_pipeline.contracts import AnalysisOutput
    from .fakes import sha
    j = world.submit()
    p = world.job(j).pending_task
    usage = AgentUsage(requests=3, tool_calls=5, input_tokens=100,
                       output_tokens=40)
    world.c.on_agent_result(p.task_id, p.attempt,
                            AnalysisOutput(analysis_ref=sha("a")),
                            "test:fake", usage=usage)
    assert world.store.attempt(p.task_id, p.attempt).usage == usage
    assert world.c.replay(j) == world.job(j)


def test_controller_keeps_failed_run_usage_on_the_attempt(world):
    j = world.submit()
    p = world.job(j).pending_task
    usage = AgentUsage(requests=32, tool_calls=96, input_tokens=900,
                       output_tokens=300)
    world.c.on_agent_failure(p.task_id, p.attempt,
                             "UsageLimitExceeded: request limit",
                             usage=usage)
    failed = world.store.attempt(p.task_id, p.attempt)
    assert (failed.status, failed.usage) == ("failed", usage)
    assert world.c.replay(j) == world.job(j)


def test_queued_executor_delivers_failed_run_usage(tmp_path):
    from agent_pipeline.agent_tasks.queued import QueuedAgentExecutor
    from agent_pipeline.agent_tasks.runtime import attach_usage
    from agent_pipeline.artifacts import ArtifactStore
    from .test_agent_tasks import Sink, toolbox

    usage = AgentUsage(requests=2, tool_calls=1, input_tokens=5,
                       output_tokens=7)

    class Failing:
        def run(self, req):
            exc = TimeoutError("run deadline")
            attach_usage(exc, usage)
            raise exc

    sink = Sink()
    agents = QueuedAgentExecutor(Failing(), ArtifactStore(tmp_path / "a"),
                                 lambda req: toolbox(), sink)
    agents.start(request(AgentTask.CANDIDATE_ANALYSIS))
    assert agents.deliver(block=True, timeout=5) == 1
    agents.close()
    assert sink.failures[0][2] == "TimeoutError: run deadline"
    assert sink.usage == [usage]
