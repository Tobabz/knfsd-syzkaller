"""Stage 2 through the wired service, end to end on one host, without a VM
or LLM: s1_reached -> Mutation Strategy -> compile -> gate -> campaign ->
replay -> crash_review.

Real: everything ``test_stage1_service`` runs, plus StepRoutingBackend,
StreamingSealingBackend, the bundles DurableRunner adds while a task
runs, Stage2CommandEngine (its replay plan included), the Stage 2
authority publisher and ArtifactStage2Judge over the real M1, Q1, Q2 and
replay kernels.  Synthetic: the model responses, the rule compiler's
NFSPRUL1 bytes, the ``--check-rules`` answer, and the host command, which
writes each step's segments (journal, barriers, coverage, crash report)
instead of booting guests.
"""

from __future__ import annotations

import json
import sys

import pytest

from agent_pipeline.agent_tasks.mutation import MutationRuleSet
from agent_pipeline.contracts import CompiledRuleSet
from agent_pipeline.controller.records import JobState
from agent_pipeline.data import load_record, put_record
from agent_pipeline.m1 import M1JudgeProfile
from agent_pipeline.q2 import default_q2_profile
from agent_pipeline.replay_runner import Compatibility
from agent_pipeline.rule_compiler import CompiledMutationRuleSet, CompiledRule
from agent_pipeline.runner.process_supervisor import ProcessLimits, ProcessSupervisor
from agent_pipeline.semantic_replay import InvalidReason, ReplayJudgeProfile
from agent_pipeline.stage1 import Stage1Service
from agent_pipeline.stage1.cli import _job_summary
from agent_pipeline.stage1.service import Stage2Parts
from agent_pipeline.stage2.authority import Stage2Profiles
from agent_pipeline.stage2.engine import Stage2CommandEngine, Stage2EngineConfig
from agent_pipeline.stage2.judge import UnknownStage2Execution

from .fakes import policy, sha
from .stage2_host import RULE_ID, rules_bytes
from .test_runner_q1_receipts import build, versions  # noqa: F401
from .test_materializer import world as materializer_world  # noqa: F401
from .test_stage1_service import (COMMAND as STAGE1_COMMAND, REPO,
                                  ScriptedRuntime, make_service,
                                  register_mapping, submit)
from .test_stage2_strategy import rule_set_data

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="Linux process supervision")

# Stage 1's command and the Stage 2 one share a script: the engine input
# says which step runs.
STAGE2_COMMAND = r'''
import hashlib, json, os, sys
from pathlib import Path
from agent_pipeline.data import canonical_json
from agent_pipeline.q1 import (CounterDelta, ExecutionCorrelation,
    GenerationCounters, KernelIdentity, RemoteKcovObservation)
from agent_pipeline.sealed_q1 import (COVERAGE_TYPE, OBSERVATION_ID,
    OBSERVATION_TYPE, PublishedCoverage)
from agent_pipeline.sealed_q2 import (CONSOLE_LOG_TYPE, MANAGER_REPORT_TYPE,
    Q2_EVIDENCE_ID, Q2_EVIDENCE_TYPE, SealedArtifactRef, SealedQ2Evidence)
from agent_pipeline.q2 import Q2CollectionWindow
from agent_pipeline.stage2.evidence import (CRASH_LOG_ID, CRASH_LOG_TYPE,
    EXECPROG_TYPE, GENERATION_COVERAGE_TYPE, JOURNAL_TYPE,
    NEUTRAL_COVERAGE_ID, NEUTRAL_COVERAGE_TYPE, NEUTRAL_EXECPROG_ID,
    REPLAY_EXECPROG_ID, SCENARIO_EXECPROG_ID)
from tests.agent_pipeline.stage2_host import (KASAN_REPORT, crash_log,
    execprog_output, program_digest, write_journal)

inp, out = Path(sys.argv[1]), Path(sys.argv[2])
execution = json.loads((inp / "execution.json").read_text())
harness = json.loads((inp / "harness.json").read_text())
assert hashlib.sha256((inp / "hcap.json").read_bytes()).hexdigest() == \
    harness["hcap_revision"]
assert hashlib.sha256((inp / "admission.json").read_bytes()).hexdigest() == \
    harness["call_admission_profile_ref"]
step = execution["step"]
candidate = harness["candidate_id"]
rules = (inp / "rules.nfsprul1").read_bytes()
pcs = tuple(int(x) for x in os.environ["TEST_PCS"].split(",") if x)


def correlation(vm, generation):
    return ExecutionCorrelation(
        job_id=execution["job_id"], task_id=execution["task_id"],
        execution_harness_id=execution["execution_harness_id"],
        vm_instance_id=vm, lane=0, generation_id=generation)


def segment(n, vm, host, files):
    tmp = out / "segments" / f".{n:06d}.tmp"
    tmp.mkdir()
    artifacts = []
    for i, (identity, type_, data) in enumerate(files):
        (tmp / f"a{i}").write_bytes(data)
        artifacts.append({"identity": identity, "type": type_,
                          "path": f"a{i}"})
    (tmp / "capture.json").write_text(json.dumps({
        "vm_instance_id": vm, "lane": 0, "generation_id": 1,
        "host": host, "artifacts": artifacts}))
    os.rename(tmp, out / "segments" / f"{n:06d}")


def journal(name, vm, generations):
    files = []
    for path in write_journal(out / ("j-" + name), name, vm=vm, lane=0,
                              candidate_id=candidate, rules=rules,
                              generations=generations):
        files.append(("journal/" + path.name, JOURNAL_TYPE, path.read_bytes()))
    return files


def q1(vm):
    descriptor = json.loads((inp / "descriptor.json").read_text())
    builds = {a["name"]: a["artifact_ref"]
              for a in descriptor["build_artifacts"]}
    identity = KernelIdentity(
        execution_harness_id=execution["execution_harness_id"],
        kernel_commit=descriptor["kernel_commit"],
        instrumentation_sha256=builds["instrumentation"],
        vmlinux_sha256=builds["kernel"], kaslr_enabled=False, kaslr_offset=0)
    c = correlation(vm, 1)
    coverage = canonical_json(PublishedCoverage(correlation=c, pcs=pcs))
    observation = RemoteKcovObservation(
        candidate_id=candidate, identity=identity, correlation=c,
        boot_ok=True, fixture_ok=True, lane_ok=True, runner_completed=True,
        collection_started=True, collection_completed=True,
        generation_attributed=True, channel="remote_kcov",
        lane_trace_mode=harness["runtime_selection"]["trace_mode"],
        coverage_artifacts=(hashlib.sha256(coverage).hexdigest(),),
        published_pcs=pcs,
        generation=GenerationCounters(generation_begin=1, remote_start_ok=1,
            aggregate_published=1, generation_aborted=0, scratch_overflow=0,
            merge_truncation=0, outstanding_tokens=0, remote_refs=0),
        counter_deltas=(CounterDelta(counter="lane_owner_failed",
                                     window="generation-plus-drain",
                                     value=0),))
    return [(OBSERVATION_ID, OBSERVATION_TYPE, canonical_json(observation)),
            ("coverage", COVERAGE_TYPE, coverage)]


D1, D2, D5 = program_digest(1), program_digest(2), program_digest(5)
mode = os.environ.get("TEST_MODE", "")
if step == "gate":
    for n in range(execution["gate_repetitions"] - (mode == "short_gate")):
        vm = f"vm-gate-{n}"
        neutral = PublishedCoverage(correlation=correlation(vm, 1),
                                    pcs=(8192,))
        segment(n, vm, {"journal_name": "gate"}, q1(vm) + [
            (NEUTRAL_COVERAGE_ID, NEUTRAL_COVERAGE_TYPE,
             canonical_json(neutral)),
            (SCENARIO_EXECPROG_ID, EXECPROG_TYPE,
             execprog_output((1, D1)).encode()),
            (NEUTRAL_EXECPROG_ID, EXECPROG_TYPE,
             execprog_output((2, D2)).encode()),
        ] + journal("gate", vm, [(1, D1, True), (2, D2, False)]))
elif step == "campaign":
    vm = "vm-campaign"
    c = correlation(vm, 1)
    console = b"[ 12.0] BUG: KASAN: slab-use-after-free\n"
    window = Q2CollectionWindow(start_marker="start", end_marker="end")
    index = SealedQ2Evidence(
        execution_harness_id=execution["execution_harness_id"],
        correlation=c.model_dump(), console_log_identity="console",
        console_log_ref=hashlib.sha256(console).hexdigest(),
        console_log_completeness="complete",
        manager_crash_reports=(SealedArtifactRef(
            identity="report-0",
            sha256=hashlib.sha256(KASAN_REPORT).hexdigest()),),
        vm_termination="guest_crashed", collection_window=window)
    reached = PublishedCoverage(correlation=correlation(vm, 5), pcs=pcs)
    segment(0, vm, {
        "journal_name": "campaign", "executions": 100,
        "console_log_identity": "console",
        "console_log_completeness": "complete",
        "manager_crash_report_identities": ["report-0"],
        "vm_termination": "guest_crashed",
        "collection_window": window.model_dump(mode="json")}, [
        (Q2_EVIDENCE_ID, Q2_EVIDENCE_TYPE, canonical_json(index)),
        ("console", CONSOLE_LOG_TYPE, console),
        ("report-0", MANAGER_REPORT_TYPE, KASAN_REPORT),
        (CRASH_LOG_ID, CRASH_LOG_TYPE, crash_log(0, 5, D5).encode()),
        ("generation-coverage/0.5", GENERATION_COVERAGE_TYPE,
         canonical_json(reached)),
    ] + journal("campaign", vm, [(5, D5, True)]))
else:
    plan = json.loads((inp / "replay" / "plan.json").read_text())
    assert (inp / "replay" / "rules.bin").read_bytes() == rules
    digest = plan["positions"][0]["program_digest"]
    vm = "vm-replay"
    segment(0, vm, {"journal_name": "replay", "replay_end": "guest_crash"}, [
        (REPLAY_EXECPROG_ID, EXECPROG_TYPE,
         execprog_output((1, digest)).encode()),
    ] + journal("replay", vm, [(1, digest, True)]))
print("stage2", step, execution["task_id"])
'''


class Stage2Runtime(ScriptedRuntime):
    """Also answers Mutation Strategy with one rule set."""

    def run(self, request):
        if request.task.value != "mutation_strategy":
            return super().run(request)
        from agent_pipeline.agent_tasks.runtime import RuntimeResult
        candidate = self._candidate(request.prompt)
        self.calls.append(request.task.value)
        data = {"variant": "rule_set",
                "rule_set": rule_set_data(candidate["candidate_id"])}
        value = request.output_type.model_validate_json(json.dumps(data))
        return RuntimeResult(output=request.validate_output(value),
                             model_id="test:scripted")


class RuleCompiler:
    """A compiler whose NFSPRUL1 bytes are synthetic; one rule per intent."""

    def __init__(self, store) -> None:
        self.store = store

    def compile(self, rule_set_ref, harness_ref, binding):
        rs = load_record(self.store, rule_set_ref, MutationRuleSet)
        compiled = CompiledMutationRuleSet(
            rule_set_ref=rule_set_ref, harness_ref=harness_ref,
            hcap_revision=binding.hcap_revision,
            promoted_registry_ref=sha("registry"), subset_id="subset",
            proxy_sha256=sha("proxy"), registry_digest=sha("digest"),
            schema_id="nfs4.1", semantic_runtime_version=1,
            candidate_id=rs.candidate_id,
            rules=(CompiledRule(rule_id=RULE_ID,
                                intent_id=rs.intents[0].intent_id),),
            nfsprul1_ref=self.store.put(rules_bytes(rs.candidate_id)))
        return CompiledRuleSet(rule_set_ref=rule_set_ref,
                               compiled_ref=put_record(self.store, compiled),
                               hcap_revision=binding.hcap_revision)


def _argv(tmp_path, script):
    return (sys.executable, "-I", "-c",
            "import sys; sys.path.insert(0, sys.argv.pop(1)); "
            "exec(open(sys.argv.pop(1)).read())",
            str(REPO), str(tmp_path / script), "{input}", "{output}")


def stage2_parts(tmp_path, store, *, check=None, mode="") -> Stage2Parts:
    (tmp_path / "stage2.py").write_text(STAGE2_COMMAND)
    config = Stage2EngineConfig(
        argv=_argv(tmp_path, "stage2.py"), cwd=tmp_path,
        work_root=tmp_path / "state" / "stage2-runs",
        resource_key="test-lane-0", collector_id="test-stage2",
        replay_proxy=tmp_path / "nfs-proxy", crash_window_bound=4,
        env={"LANG": "C.UTF-8", "TEST_PCS": "4096", "TEST_MODE": mode},
        limits=ProcessLimits(timeout_s=60), poll_interval_s=0.05,
        state_dir=tmp_path / "state")

    def check_rules(proxy, rule_set, work):
        return check or Compatibility(True, None, "rules ok")

    def engine(artifacts, receipts, evidence):
        return Stage2CommandEngine(
            config, artifacts,
            ProcessSupervisor(tmp_path / "state" / "processes"),
            receipts=receipts, evidence=evidence, check_rules=check_rules)

    return Stage2Parts(engine_factory=engine, profiles=Stage2Profiles(
        m1_profile_ref=put_record(store, M1JudgeProfile(name="m1",
                                                        revision="1")),
        q2_profile_ref=put_record(store, default_q2_profile()),
        replay_profile_ref=put_record(store, ReplayJudgeProfile(
            name="replay", revision="1")),
        crash_window_bound=4))


def make_stage2_service(tmp_path, build, *, stage2=True, check=None,
                        mode="", **kw) -> Stage1Service:
    return make_service(
        tmp_path, build, command=STAGE1_COMMAND, runtime=Stage2Runtime(build),
        compiler=RuleCompiler(build.store),
        stage2=stage2_parts(tmp_path, build.store, check=check, mode=mode)
        if stage2 else None,
        policies=(policy(run_stage2=True, **kw),))


def until(service, job_id, *states):
    return lambda: service.job(job_id).state in set(states)


WAITS = (JobState.CRASH_REVIEW, JobState.BLOCKED_OPERATOR, JobState.PARKED,
         JobState.BLOCKED_HARNESS_GAP)


def run_job(service, build, timeout_s=120):
    job_id = submit(service, build)
    register_mapping(service, build, job_id)
    service.start_worker(idle_s=0.05)
    assert service.run(until(service, job_id, *WAITS), interval_s=0.05,
                       timeout_s=timeout_s)
    return service.job(job_id)


def test_reached_job_runs_stage2_to_crash_review(tmp_path, build):
    with make_stage2_service(tmp_path, build) as service:
        job_id = submit(service, build)
        register_mapping(service, build, job_id)
        service.start_worker(idle_s=0.05)
        seen = []

        def track(report):
            state = service.job(job_id).state
            if not seen or seen[-1] is not state:
                seen.append(state)
            for p in report.publications:
                assert p.outcome != "rejected", p

        assert service.run(until(service, job_id, JobState.CRASH_REVIEW,
                                 JobState.BLOCKED_OPERATOR, JobState.PARKED,
                                 JobState.BLOCKED_HARNESS_GAP),
                           interval_s=0.05, timeout_s=120, on_step=track)
        job = service.job(job_id)
        assert job.state is JobState.CRASH_REVIEW, (
            job.state, job.state_reason, seen,
            service.store.effect_failures(job_id), service.worker_errors)
        for state in (JobState.S2_GATE, JobState.S2_CAMPAIGN,
                      JobState.S2_REPLAYING):
            assert state in seen
        executions = list((tmp_path / "state" / "stage2-runs").glob(
            "*/input/execution.json"))
        assert executions
        assert all(json.loads(path.read_text())["state_dir"] == str(tmp_path / "state")
                   for path in executions)
        gate = job.gate_runs[0]
        assert gate.q1.status.value == "reached"
        assert [(r.rule_id, r.status) for r in gate.rules] == [
            (RULE_ID, "applied")]
        # The neutral run's coverage misses the target and applied nothing.
        assert gate.ambient == ()
        tally = job.campaign.tally
        assert (tally.reached_generations, tally.hypothesis_applied,
                tally.applied_crashes) == (1, 1, 1)
        assert job.triage[0].q2_status == "observed"
        assert job.triage[0].crash_window_applied == (RULE_ID,)
        assert job.replay.outcome.status == "replay_equivalent", \
            job.replay.outcome
        assert service.parts.runtime.calls[-1] == "mutation_strategy"
        # A replay of the stored events reaches the same job.
        assert service.controller.replay(job_id) == job
        summary = _job_summary(service, job_id)
        assert summary["replay"]["outcome"]["status"] == "replay_equivalent"
        assert summary["campaign"]["applied_crashes"] == 1
        assert summary["gate_runs"][0]["rules"] == {RULE_ID: "applied"}

        # The published authority: the judges refuse what it does not bind.
        judge = service.stage2_judge.snapshot
        gate_bundle = gate.bundle_ref
        assert not judge.matches_execution(gate_bundle, job_id=job_id,
                                           task_id="another")
        with pytest.raises(UnknownStage2Execution):
            judge.judge_campaign(sha("unpublished"), candidate_id="x",
                                 compiled=job.compiled)
        other = job.compiled.model_copy(update={"compiled_ref": sha("other")})
        run = judge.judge_gate(gate_bundle, plan_ref=job.plan_ref,
                               candidate_id=job.candidate.candidate_id,
                               compiled=other, versions=job.judge_versions)
        assert [r.status for r in run.rules] == ["inconclusive"]
        assert run.ambient == ("ambient_control_unavailable",)
        publication = service.stage2_store.publication(gate_bundle)
        assert publication.execution.q1.plan_ref == job.plan_ref
        assert publication.task_input.step == "gate"


def test_incompatible_recorded_rule_set_is_judged_replay_invalid(
        tmp_path, build):
    check = Compatibility(False, InvalidReason.RULE_SET_INCOMPATIBLE,
                          "unknown semantic path")
    with make_stage2_service(tmp_path, build, check=check) as service:
        job = run_job(service, build)
        assert job.state is JobState.CRASH_REVIEW, (job.state,
                                                   job.state_reason)
        assert job.replay.outcome.status == "replay_invalid"
        assert "rule_set_incompatible" in job.replay.outcome.reason


def test_a_gate_short_of_its_repetitions_is_a_runtime_failure(
        tmp_path, build):
    with make_stage2_service(tmp_path, build, mode="short_gate",
                             gate_repetitions=2) as service:
        job = run_job(service, build)
        assert job.state is JobState.BLOCKED_OPERATOR
        assert job.state_reason == "runtime_retry_exhausted"
        assert job.gate_runs == ()
        runs = [r for r in service.worker_runs
                if r.status.state == "ended_unsealed"]
        assert runs and all(r.status.reason == "capture_failed"
                            for r in runs)
        # Each short gate still sealed the repetition it finished.
        assert all(len(r.status.bundles) == 1 for r in runs)


def test_without_a_stage2_backend_the_rule_set_waits_for_an_operator(
        tmp_path, build):
    with make_stage2_service(tmp_path, build, stage2=False) as service:
        assert service.stage2_judge is None
        job = run_job(service, build)
        assert job.state is JobState.BLOCKED_OPERATOR
        assert job.state_reason == "stage2_gate_unavailable"
