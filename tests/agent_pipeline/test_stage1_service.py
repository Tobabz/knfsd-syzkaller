"""The wired Stage 1 service, end to end on one host, without a VM or LLM.

Real: Controller and Store, QueuedAgentExecutor and Stage1AgentExecutor,
HCAP checker, Materializer, DurableRunner, RunnerWorker, ProcessSupervisor,
EvidenceSealingBackend, RunnerQ1ReceiptBridge and ArtifactQ1Judge.
Synthetic: the model responses, the parser, and the host command, which
writes a capture instead of booting a guest.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agent_pipeline.components import InMemoryRegistry
from agent_pipeline.contracts import (CandidateSubmission, LocationKind,
                                      LocationRequest, Q1Status)
from agent_pipeline.controller.records import JobState, TaskKind
from agent_pipeline.q1 import CandidateTarget, KernelIdentity, TargetPcMapping
from agent_pipeline.runner.process_supervisor import ProcessLimits, ProcessSupervisor
from agent_pipeline.stage1 import (CommandEngineConfig, CommandExecutionEngine,
                                   DescriptorKernelIdentity, Stage1Parts,
                                   Stage1Service)
from agent_pipeline.stage1.cli import STOP_STATES
from agent_pipeline.agent_tasks.runtime import RuntimeResult

from .fakes import FakeTree, policy
from .test_agent_tasks import analysis_data, toolbox
from .test_materializer import world as materializer_world  # noqa: F401
from .test_runner_q1_receipts import build, versions  # noqa: F401

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="Linux process supervision")

REPO = Path(__file__).resolve().parents[2]
SOURCE = {"fs/nfsd/synthetic.c": "void target(void) {\n}\n"}

# The host command: reads the engine's input directory and writes the
# capture a lane collector would, with generation-attributed coverage.
COMMAND = r'''
import hashlib, json, os, sys
from pathlib import Path
from agent_pipeline.data import canonical_json
from agent_pipeline.q1 import (CounterDelta, ExecutionCorrelation,
    GenerationCounters, KernelIdentity, RemoteKcovObservation)
from agent_pipeline.sealed_q1 import (COVERAGE_TYPE, OBSERVATION_ID,
    OBSERVATION_TYPE, PublishedCoverage)

inp, out = Path(sys.argv[1]), Path(sys.argv[2])
execution = json.loads((inp / "execution.json").read_text())
harness = json.loads((inp / "harness.json").read_text())
descriptor = json.loads((inp / "descriptor.json").read_text())
assert (inp / "program.syz").read_bytes()
builds = {a["name"]: a["artifact_ref"] for a in descriptor["build_artifacts"]}
identity = KernelIdentity(
    execution_harness_id=execution["execution_harness_id"],
    kernel_commit=descriptor["kernel_commit"],
    instrumentation_sha256=builds["instrumentation"],
    vmlinux_sha256=builds["kernel"], kaslr_enabled=False, kaslr_offset=0)
correlation = ExecutionCorrelation(
    job_id=execution["job_id"], task_id=execution["task_id"],
    execution_harness_id=execution["execution_harness_id"],
    vm_instance_id="vm-test", lane=0, generation_id=1)
pcs = tuple(int(x) for x in os.environ["TEST_PCS"].split(",") if x)
coverage = canonical_json(PublishedCoverage(correlation=correlation, pcs=pcs))
observation = RemoteKcovObservation(
    candidate_id=harness["candidate_id"], identity=identity,
    correlation=correlation, boot_ok=True, fixture_ok=True, lane_ok=True,
    runner_completed=True, collection_started=True, collection_completed=True,
    generation_attributed=True, channel="remote_kcov",
    lane_trace_mode=harness["runtime_selection"]["trace_mode"],
    coverage_artifacts=(hashlib.sha256(coverage).hexdigest(),),
    published_pcs=pcs,
    generation=GenerationCounters(generation_begin=1, remote_start_ok=1,
        aggregate_published=1, generation_aborted=0, scratch_overflow=0,
        merge_truncation=0, outstanding_tokens=0, remote_refs=0),
    counter_deltas=(CounterDelta(counter="lane_owner_failed",
                                 window="generation-plus-drain", value=0),))
(out / "reachability.json").write_bytes(canonical_json(observation))
(out / "coverage.json").write_bytes(coverage)
(out / "capture.json").write_text(json.dumps({
    "vm_instance_id": "vm-test", "lane": 0, "generation_id": 1,
    "artifacts": [
        {"identity": OBSERVATION_ID, "type": OBSERVATION_TYPE,
         "path": "reachability.json"},
        {"identity": "coverage", "type": COVERAGE_TYPE,
         "path": "coverage.json"}]}))
print("captured", execution["task_id"])
'''


class ScriptedRuntime:
    """Answers each Agent Task from the trusted candidate in its prompt."""

    def __init__(self, build) -> None:
        self.build = build
        self.calls = []

    @staticmethod
    def _candidate(prompt: str) -> dict:
        return json.loads(prompt.split("\n", 1)[1].split("\n\n", 1)[0])

    def run(self, request):
        candidate = self._candidate(request.prompt)
        self.calls.append(request.task.value)
        if request.task.value == "candidate_analysis":
            data = analysis_data(candidate["candidate_id"],
                                 source_path="fs/nfsd/synthetic.c",
                                 symbol="target")
        else:
            plan = self.build.plan.model_dump(
                mode="json", exclude={"program_proposal", "schema_version"})
            plan["candidate_id"] = candidate["candidate_id"]
            plan["selected_path"]["entry_surface"] = "nfs_request"
            plan["q1_observation"]["target"] = candidate["location"]
            plan["program"] = {"kind": "program",
                               "text": self.build.scenario_bytes.decode()}
            data = {"variant": "plan", "plan": plan}
        value = request.output_type.model_validate_json(json.dumps(data))
        return RuntimeResult(output=request.validate_output(value),
                             model_id="test:scripted")


class Ids:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> str:
        self.n += 1
        return f"{self.n:04d}"


def make_service(tmp_path, build, *, pcs="4096", ids=None, command=COMMAND,
                 run_agents=True, registry=None, engine_factory=None,
                 runtime=None, policies=None, slots=None, **extra):
    b = build
    if registry is None:
        registry = InMemoryRegistry()
        registry.put(b.binding)
    config = CommandEngineConfig(
        argv=(sys.executable, "-I", "-c",
              "import sys; sys.path.insert(0, sys.argv.pop(1)); "
              "exec(open(sys.argv.pop(1)).read())",
              str(REPO), str(tmp_path / "command.py"), "{input}", "{output}"),
        cwd=tmp_path, work_root=tmp_path / "state" / "runs",
        resource_key="test-lane-0", collector_id="test-collector",
        env={"LANG": "C.UTF-8", "TEST_PCS": pcs},
        limits=ProcessLimits(timeout_s=60))
    (tmp_path / "command.py").write_text(command)

    def engine(store):
        return CommandExecutionEngine(
            config, store, ProcessSupervisor(tmp_path / "state" / "processes"),
            slots=slots)

    parts = Stage1Parts(
        state_dir=tmp_path / "state", artifacts=b.store,
        tree=FakeTree({b.binding.kernel_commit: SOURCE}), registry=registry,
        materializer=b.materializer, runtime=runtime or ScriptedRuntime(b),
        tools=lambda request: toolbox(),
        engine_factory=engine_factory or engine,
        judge_versions=versions(b),
        identities=DescriptorKernelIdentity("kernel", "instrumentation"),
        policies=policies or (policy(),), new_id=ids or Ids(),
        lease_duration_ns=30_000_000_000, run_agents=run_agents, **extra)
    return Stage1Service(parts)


def submit(service, build) -> str:
    return service.controller.submit(CandidateSubmission(
        kernel_commit=build.binding.kernel_commit, location=LocationRequest(
            kind=LocationKind.FUNCTION, path="fs/nfsd/synthetic.c",
            symbol="target")), "p1")


def register_mapping(service, build, job_id, pcs=(4096,)) -> str:
    job = service.job(job_id)
    candidate = job.candidate
    identity = KernelIdentity(
        execution_harness_id=build.binding.execution_harness_id,
        kernel_commit=candidate.kernel_commit,
        instrumentation_sha256=build.instrumentation,
        vmlinux_sha256=next(a.artifact_ref for a in build.descriptor.build_artifacts
                            if a.name == "kernel"),
        kaslr_enabled=False, kaslr_offset=0)
    target = CandidateTarget(candidate_id=candidate.candidate_id,
                             kernel_commit=candidate.kernel_commit,
                             **candidate.location.model_dump(mode="json"))
    return service.mappings.add(TargetPcMapping(
        mapping_method="synthetic test mapping", verified=True, target=target,
        identity=identity, target_pcs=pcs))


def stopped(service, job_id):
    return lambda: service.job(job_id).state in STOP_STATES


def test_candidate_runs_end_to_end_to_reached(tmp_path, build):
    with make_service(tmp_path, build) as service:
        job_id = submit(service, build)
        register_mapping(service, build, job_id)
        service.start_worker(idle_s=0.05)
        assert service.run(stopped(service, job_id), interval_s=0.05,
                           timeout_s=60)
        job = service.job(job_id)
        assert job.state is JobState.S1_REACHED, (
            job, service.store.effect_failures(job_id), service.worker_errors)
        assert job.last_verdict.result.status is Q1Status.REACHED
        assert service.parts.runtime.calls == ["candidate_analysis",
                                               "reachability_planning"]
        completion = service.runner.receipt(_runner_task(service, job_id))
        assert completion.final_state == "sealed"
        assert completion.bundle_ref == job.last_verdict.bundle_ref
        publication = service.bridge.publication(completion.bundle_ref)
        assert publication.context.correlation.job_id == job_id
        assert service.controller.replay(job_id) == job
        runs = list((tmp_path / "state" / "runs").iterdir())
        assert len(runs) == 1
        assert b"captured" in (runs[0] / "process.log").read_bytes()


def _runner_task(service, job_id) -> str:
    for t in service.store.transitions(job_id):
        p = t.job.pending_task
        if p is not None and p.kind is TaskKind.RUNNER:
            return p.task_id
    raise AssertionError("no Runner task")


def test_missing_mapping_keeps_the_verdict_pending_until_registered(
        tmp_path, build):
    with make_service(tmp_path, build) as service:
        job_id = submit(service, build)
        service.start_worker(idle_s=0.05)

        def sealed() -> bool:
            job = service.job(job_id)
            p = job.pending_task
            return p is not None and p.kind is TaskKind.RUNNER and \
                service.runner.status(p.task_id).state == "sealed"

        assert service.run(sealed, interval_s=0.05, timeout_s=60)
        report = service.step()
        assert [p.outcome for p in report.publications] == ["pending"]
        assert "mapping" in report.publications[0].detail
        assert service.job(job_id).state is JobState.S1_RUNNING
        assert service.job(job_id).last_verdict is None
        register_mapping(service, build, job_id)
        assert service.run(stopped(service, job_id), interval_s=0.05,
                           timeout_s=30)
        assert service.job(job_id).state is JobState.S1_REACHED


def test_target_not_in_coverage_is_not_reached_and_replans(tmp_path, build):
    with make_service(tmp_path, build, pcs="8192") as service:
        job_id = submit(service, build)
        register_mapping(service, build, job_id)
        service.start_worker(idle_s=0.05)

        def judged() -> bool:
            return service.job(job_id).last_verdict is not None

        assert service.run(judged, interval_s=0.05, timeout_s=60)
        verdict = service.job(job_id).last_verdict.result
        assert verdict.status is Q1Status.NOT_REACHED
        # A miss goes back to planning as a repair (09 §3).
        job = service.job(job_id)
        assert (job.state, job.state_reason) == (JobState.S1_PLANNING,
                                                 "q1_not_reached")


def test_restart_reattaches_and_finishes_the_job(tmp_path, build):
    ids = Ids()
    service = make_service(tmp_path, build, ids=ids)
    job_id = submit(service, build)
    register_mapping(service, build, job_id)
    # Planning was requested but its result is never delivered: the
    # process stops with the Agent task in flight.
    assert service.run(lambda: service.job(job_id).state is
                       JobState.S1_PLANNING, interval_s=0.05, timeout_s=30)
    service.close()
    with make_service(tmp_path, build, ids=ids) as again:
        again.recover()
        again.start_worker(idle_s=0.05)
        assert again.run(stopped(again, job_id), interval_s=0.05,
                         timeout_s=60)
        job = again.job(job_id)
        assert job.state is JobState.S1_REACHED
        assert again.controller.replay(job_id) == job


def test_open_stage1_builds_the_production_composition(tmp_path, build):
    """Config-driven assembly: catalog registry, CAS approvals, Git source
    tree and the default Git toolbox, with only the model and the parser
    injected."""
    import subprocess
    from contextlib import ExitStack

    from agent_pipeline.data import put_record
    from agent_pipeline.materializer import (ArtifactHarnessMaterializer,
                                             ExecutionHarnessApproval,
                                             StaticExecutionHarnessAuthority,
                                             descriptor_id)
    from agent_pipeline.registry import HarnessCatalog, HarnessRegistration
    from agent_pipeline.stage1.cli import open_stage1
    from agent_pipeline.stage1.config import EngineConfig, Stage1Config

    repo = tmp_path / "linux"
    (repo / "fs" / "nfsd").mkdir(parents=True)
    (repo / "fs" / "nfsd" / "synthetic.c").write_text(SOURCE["fs/nfsd/synthetic.c"])
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "synthetic"], check=True)
    commit = subprocess.run([*git, "rev-parse", "HEAD"], check=True,
                            capture_output=True, text=True).stdout.strip()

    b = build
    b.descriptor = b.descriptor.model_copy(update={"kernel_commit": commit})
    put_record(b.store, b.descriptor)
    b.binding = b.binding.model_copy(update={
        "kernel_commit": commit,
        "execution_harness_id": descriptor_id(b.descriptor)})
    approval = ExecutionHarnessApproval(descriptor=b.descriptor,
                                        approved_hcap_revisions=(b.hcap_ref,))
    b.materializer = ArtifactHarnessMaterializer(
        b.store, StaticExecutionHarnessAuthority((approval,)), b.parser)
    catalog = HarnessCatalog(registrations=(HarnessRegistration(
        binding=b.binding, evidence_refs=(b.store.put(b"approval notes"),)),))
    (tmp_path / "command.py").write_text(COMMAND)
    config = Stage1Config(
        state_dir=tmp_path / "state", artifact_root=b.store.root,
        kernel_repo=repo, harness_catalog_ref=put_record(b.store, catalog),
        execution_harness_approvals=(put_record(b.store, approval),),
        syzkaller_bundle=tmp_path / "unused-bundle",
        syzkaller_identity=b.identity, policies=(policy(),),
        judge_versions=versions(b), lease_duration_s=30,
        engine=EngineConfig(
            argv=(sys.executable, "-I", "-c",
                  "import sys; sys.path.insert(0, sys.argv.pop(1)); "
                  "exec(open(sys.argv.pop(1)).read())",
                  str(REPO), str(tmp_path / "command.py"),
                  "{input}", "{output}"),
            cwd=tmp_path, resource_key="test-lane-0",
            env={"LANG": "C.UTF-8", "TEST_PCS": "4096"}, timeout_s=60))
    config = Stage1Config.model_validate_json(config.model_dump_json())
    with ExitStack() as stack:
        service = open_stage1(config, stack, runtime=ScriptedRuntime(b),
                              parser=b.parser)
        job_id = submit(service, b)
        register_mapping(service, b, job_id)
        service.start_worker(idle_s=0.05)
        assert service.run(stopped(service, job_id), interval_s=0.05,
                           timeout_s=60)
        assert service.job(job_id).state is JobState.S1_REACHED, (
            service.job(job_id), service.store.effect_failures(job_id))


def wait_for(predicate, timeout_s=30.0) -> bool:
    import time
    deadline = time.monotonic() + timeout_s
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


def test_fifo_capture_ends_the_lease_instead_of_hanging(tmp_path, build):
    fifo = "import os, sys; os.mkfifo(sys.argv[2] + '/capture.json')\n"
    with make_service(tmp_path, build, command=fifo) as service:
        job_id = submit(service, build)
        service.start_worker(idle_s=0.05)
        assert service.run(lambda: bool(service.worker_runs),
                           interval_s=0.05, timeout_s=30)
        run = service.worker_runs[0]
        assert run.disposition == "completed"
        assert service.runner.receipt(run.task_id).reason == "capture_failed"
        assert service.job(job_id).last_verdict is None


def test_one_shot_command_leaves_agent_tasks_to_the_running_service(
        tmp_path, build):
    ids = Ids()
    with make_service(tmp_path, build, ids=ids, run_agents=False) as once:
        job_id = submit(once, build)
        p = once.job(job_id).pending_task
        assert once.store.attempt(p.task_id, p.attempt).status == "sending"
        register_mapping(once, build, job_id)
    # A service already running picks the job up in poll(), without
    # recover(), and calls the model once per Agent Task.
    with make_service(tmp_path, build, ids=ids) as service:
        service.start_worker(idle_s=0.05)
        assert service.run(stopped(service, job_id), interval_s=0.05,
                           timeout_s=60)
        assert service.job(job_id).state is JobState.S1_REACHED
        assert service.parts.runtime.calls == ["candidate_analysis",
                                               "reachability_planning"]


def test_close_keeps_runner_open_for_a_worker_still_cleaning_up(
        tmp_path, build):
    import threading

    from agent_pipeline.runner.worker import ExecutionNotStopped

    entered, release = threading.Event(), threading.Event()

    class StuckEngine:
        def capture(self, lease, control):
            entered.set()
            assert release.wait(30)
            raise ExecutionNotStopped("payload still alive")

    service = make_service(tmp_path, build,
                           engine_factory=lambda store: StuckEngine())
    job_id = submit(service, build)
    service.start_worker(idle_s=0.05)
    assert service.run(entered.is_set, interval_s=0.05, timeout_s=60)
    task_id = service.job(job_id).pending_task.task_id
    assert service.close(worker_timeout_s=0) is False
    release.set()
    service._worker_threads[0].join(30)
    try:
        assert service.worker_errors == []
        assert [r.disposition for r in service.worker_runs] == ["not_stopped"]
        assert service.runner.status(task_id).state == "running"
    finally:
        service.receipts.close()
        service.runner.close()


def test_resolved_gap_issue_resumes_the_blocked_job(tmp_path, build):
    registry = InMemoryRegistry()        # no harness for this commit yet
    with make_service(tmp_path, build, registry=registry) as service:
        job_id = submit(service, build)
        assert service.job(job_id).state is JobState.BLOCKED_HARNESS_GAP
        [issue] = service.issues.issues()
        assert issue["jobs"] == [job_id]
        registry.put(build.binding)
        service.issues.change(issue["issue"], "resolved", "harness built")
        register_mapping(service, build, job_id)
        report = service.step()
        assert report.errors == []
        assert service.issues.pending_events() == []
        assert service.job(job_id).state is JobState.S1_ANALYSIS
        service.start_worker(idle_s=0.05)
        assert service.run(stopped(service, job_id), interval_s=0.05,
                           timeout_s=60)
        assert service.job(job_id).state is JobState.S1_REACHED


def _fail_once(obj, name, error=OSError("synthetic transient failure")):
    real = getattr(obj, name)
    calls = []

    def flaky(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise error
        return real(*args, **kwargs)

    setattr(obj, name, flaky)
    return calls


def test_issue_event_retry_does_not_reach_jobs_of_a_later_issue(
        tmp_path, build):
    with make_service(tmp_path, build, registry=InMemoryRegistry()) as service:
        a = submit(service, build)
        [issue] = service.issues.issues()
        service.issues.change(issue["issue"], "wont_fix", "out of scope")
        _fail_once(service.issues, "mark_delivered")
        assert service.deliver_issue_events() != []
        assert service.job(a).state is JobState.CLOSED_UNSUPPORTED
        # The gap returns for another job: a new issue, still open.
        b = submit(service, build)
        assert service.job(b).state is JobState.BLOCKED_HARNESS_GAP
        assert [i["jobs"] for i in service.issues.issues()] == [[a], [b]]
        assert service.deliver_issue_events() == []
        assert service.job(b).state is JobState.BLOCKED_HARNESS_GAP
        assert service.issues.pending_events() == []


def test_failed_issue_event_is_not_overtaken_by_a_later_one(tmp_path, build):
    with make_service(tmp_path, build, registry=InMemoryRegistry()) as service:
        job_id = submit(service, build)
        [issue] = service.issues.issues()
        service.issues.change(issue["issue"], "deferred")
        service.issues.change(issue["issue"], "reopened")
        _fail_once(service.controller, "on_issue")
        assert len(service.deliver_issue_events()) == 1
        assert service.job(job_id).state is JobState.BLOCKED_HARNESS_GAP
        assert [e[3] for e in service.issues.pending_events()] == [
            "deferred", "reopened"]
        assert service.deliver_issue_events() == []
        assert service.job(job_id).state is JobState.BLOCKED_HARNESS_GAP
        assert [t.reason for t in service.store.transitions(job_id)][-2:] == [
            "issue_deferred", "issue_reopened"]


def test_redelivered_issue_event_does_not_release_a_later_wait(
        tmp_path, build):
    registry = InMemoryRegistry()
    with make_service(tmp_path, build, registry=registry) as service:
        job_id = submit(service, build)
        [first] = service.issues.issues()
        service.issues.change(first["issue"], "resolved", "harness built")
        # Still no binding: the job waits on the same gap again, under a
        # new issue; the delivery record of the first event is lost.
        _fail_once(service.issues, "mark_delivered")
        assert service.deliver_issue_events() != []
        assert service.job(job_id).state is JobState.BLOCKED_HARNESS_GAP
        second = service.issues.issues()[1]
        assert (second["status"], second["jobs"]) == ("open", [job_id])
        registry.put(build.binding)
        assert service.deliver_issue_events() == []
        assert service.issues.pending_events() == []
        assert service.job(job_id).state is JobState.BLOCKED_HARNESS_GAP
        assert service.store.job_issue(job_id) == second["issue"]


def test_failed_rebind_after_a_resolved_issue_is_retried_by_poll(
        tmp_path, build):
    registry = InMemoryRegistry()
    with make_service(tmp_path, build, registry=registry) as service:
        job_id = submit(service, build)
        [issue] = service.issues.issues()
        registry.put(build.binding)
        service.issues.change(issue["issue"], "resolved", "harness built")
        # The event commits (retry_pending), then the rebind fails once.
        _fail_once(registry, "lookup")
        assert service.deliver_issue_events() == []
        assert service.issues.pending_events() == []
        assert service.job(job_id).state is JobState.RETRY_PENDING
        assert [f[1] for f in service.store.effect_failures(job_id)] == [
            "rebind"]
        report = service.step()
        assert report.errors == [] and report.failures == []
        assert service.job(job_id).state is JobState.S1_ANALYSIS


def test_wait_linked_before_per_job_issues_still_takes_its_event(
        tmp_path, build):
    with make_service(tmp_path, build, registry=InMemoryRegistry()) as service:
        job_id = submit(service, build)
        [issue] = service.issues.issues()
        # A Store written before job_issues existed has only gap_links.
        service.store.db.execute("DELETE FROM job_issues")
        assert service.store.job_issue(job_id) == issue["issue"]
        service.issues.change(issue["issue"], "deferred")
        assert service.deliver_issue_events() == []
        assert service.job(job_id).state is JobState.PARKED


def test_concurrent_deliverers_apply_each_issue_event_once_in_order(
        tmp_path, build):
    ids = Ids()
    with make_service(tmp_path, build, ids=ids, registry=InMemoryRegistry(),
                      run_agents=False) as service:
        job_id = submit(service, build)
        [issue] = service.issues.issues()
        service.issues.change(issue["issue"], "deferred")
        service.issues.change(issue["issue"], "reopened")
        with make_service(tmp_path, build, ids=ids,
                          registry=InMemoryRegistry(),
                          run_agents=False) as other:
            real = service.issues.pending_events

            def read_then_other_delivers():
                events = real()
                # A one-shot command delivers both events while this
                # process still holds the list it read.
                assert other.deliver_issue_events() == []
                return events

            service.issues.pending_events = read_then_other_delivers
            assert service.deliver_issue_events() == []
        assert service.job(job_id).state is JobState.BLOCKED_HARNESS_GAP
        assert [t.reason for t in service.store.transitions(job_id)
                if (t.reason or "").startswith("issue_")] == [
            "issue_deferred", "issue_reopened"]
        assert service.store.issue_mark(job_id) is not None


def test_recover_applies_an_issue_event_stored_before_restart(tmp_path, build):
    ids = Ids()
    registry = InMemoryRegistry()
    with make_service(tmp_path, build, ids=ids, registry=registry,
                      run_agents=False) as once:
        job_id = submit(once, build)
        [issue] = once.issues.issues()
        # Stored, then the command stops before delivering it.
        once.issues.change(issue["issue"], "resolved", "harness built")
    registry.put(build.binding)
    with make_service(tmp_path, build, ids=ids, registry=registry) as service:
        service.recover()
        assert service.recover_errors == []
        assert service.issues.pending_events() == []
        assert service.job(job_id).state is JobState.S1_ANALYSIS


def test_resubmit_binds_an_earlier_location_to_another_commit(tmp_path, build):
    from agent_pipeline.stage1.cli import _job_summary, resubmit
    with make_service(tmp_path, build) as service:
        old = submit(service, build)
        new = resubmit(service, old, build.binding.kernel_commit)
        assert new != old
        before, after = service.job(old), service.job(new)
        assert after.submission.location == before.submission.location
        assert after.submission.kernel_commit == build.binding.kernel_commit
        assert after.job_policy_id == before.job_policy_id
        # The new job went through intake like any submission.
        assert after.state is before.state
        assert after.candidate.kernel_commit == build.binding.kernel_commit
        # The summary names jobs and states, never the private location.
        assert "synthetic" not in json.dumps(_job_summary(service, new))
        missing = resubmit(service, old, "0" * 40)
        assert service.job(missing).state is JobState.REJECTED


def test_a_fixed_campaign_runs_its_attempts_on_the_host_slots(tmp_path,
                                                              build):
    """09 §3.1, §8: the attempts of a fixed campaign run on two workers
    that share two VM slots, and each gets its own Q1 authority."""
    from agent_pipeline.runner.slots import SlotPool
    service = make_service(
        tmp_path, build, slots=SlotPool("test-lane", 2), runner_workers=2,
        policies=(policy(campaign_mode="fixed", fixed_attempts=3,
                         fixed_parallelism=2),))
    with service:
        job_id = submit(service, build)
        register_mapping(service, build, job_id)
        service.start_worker(idle_s=0.05)
        assert len(service._worker_threads) == 2
        assert service.run(stopped(service, job_id), interval_s=0.05,
                           timeout_s=120)
        job = service.job(job_id)
        assert (job.state, job.state_reason) == (
            JobState.S1_REACHED, "fixed_no_signal"), (
            job, service.store.effect_failures(job_id),
            service.worker_errors)
        assert (job.fixed.sent, job.fixed.reached) == (3, 3)
        attempts = {a.task_id for t in service.store.transitions(job_id)
                    if t.job.fixed is not None for a in t.job.fixed.in_flight}
        assert len(attempts) == 3
        for task_id in attempts:
            completion = service.runner.receipt(task_id)
            assert completion.final_state == "sealed"
            assert service.bridge.publication(
                completion.bundle_ref).context.correlation.task_id == task_id
        assert service.controller.replay(job_id) == job
        assert len(list((tmp_path / "state" / "runs").iterdir())) == 4
