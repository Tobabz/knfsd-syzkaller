"""The Stage 1 service: Controller, Agent Tasks and the Runner, wired.

One process owns the Controller and its SQLite Store on the calling thread.
Agent Tasks run on ``QueuedAgentExecutor`` workers and come back through
``deliver()``.  A Runner worker thread claims leases from ``DurableRunner``
and runs them through ``EvidenceSealingBackend``, or, for a Stage 2 step
when ``Stage1Parts.stage2`` is configured, through
``StreamingSealingBackend`` with the Stage 2 engine.  After a task seals
(a Stage 2 one: after each bundle), the service publishes its host
authority and installs the new Judge snapshot before the Controller
polls, so the verdict is consumed on the next ``step``.

Each ``step``:

1. deliver finished Agent results to the Controller;
2. publish Q1 authority for sealed Runner tasks and Stage 2 authority
   for every bundle a Stage 2 task added;
3. ``Controller.poll()``: take Runner statuses, resend lost calls.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from ..agent_tasks.executor import PinnedToolboxFactory, ToolboxFactory
from ..agent_tasks.queued import QueuedAgentExecutor
from ..agent_tasks.runtime import AgentRuntime
from ..artifacts import ArtifactStore
from ..components import (HarnessRegistry, IssueTracker, Materializer,
                          MutationRuleCompiler)
from ..contracts import JudgeVersions
from ..controller.machine import Env
from ..controller.records import Job
from ..controller.service import Controller, EffectFailure
from ..controller.store import Store
from ..evidence import EvidenceStore
from ..hcap import ArtifactHcapChecker
from ..intake import SourceTree
from ..runner.evidence_backend import (EvidenceSealingBackend, ExecutionEngine,
                                       RunnerEvidenceReceiptStore,
                                       StepRoutingBackend,
                                       StreamingExecutionEngine,
                                       StreamingSealingBackend)
from ..runner.q1_receipts import RunnerQ1ReceiptBridge
from ..runner.service import DurableRunner
from ..runner.worker import RunnerWorker, WorkerRun
from .authority import (DescriptorKernelIdentity, MappingCatalog, Publication,
                        PublishedQ1Judge, Q1AuthorityPublisher)
from .issues import SqliteIssueTracker

if TYPE_CHECKING:
    from ..stage2.authority import Stage2Profiles


@dataclass
class StepReport:
    delivered: int = 0
    publications: list[Publication] = field(default_factory=list)
    failures: list[EffectFailure] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Stage2Parts:
    """The Stage 2 execution backend: the engine that runs gate, campaign
    and replay leases, and the profiles its bundles are judged with."""

    engine_factory: Callable[[ArtifactStore, RunnerEvidenceReceiptStore,
                              EvidenceStore], StreamingExecutionEngine]
    profiles: Stage2Profiles


@dataclass(frozen=True)
class Stage1Parts:
    """Injected components; production values come from ``open_stage1``."""

    state_dir: Path
    artifacts: ArtifactStore
    tree: SourceTree
    registry: HarnessRegistry
    materializer: Materializer
    runtime: AgentRuntime | None
    tools: ToolboxFactory | None
    engine_factory: Callable[[ArtifactStore], ExecutionEngine]
    judge_versions: JudgeVersions
    identities: DescriptorKernelIdentity
    policies: tuple = ()
    sealer_id: str = "stage1-host"
    worker_id: str = "stage1-worker"
    lease_duration_ns: int = 120_000_000_000
    agent_workers: int = 2
    issues: IssueTracker | None = None
    new_id: Callable[[], str] | None = None
    #: False for one-shot commands: Agent Tasks are recorded but not run,
    #: and the service loop (``run``) sends them.
    run_agents: bool = True
    #: Optional host preparation after candidate intake; not part of Q1 execution.
    prepare_candidate: Callable[[Store, Path], Callable[[str], object]] | None = None
    #: None until a Proxy build is configured: a Stage 2 rule set then waits
    #: in blocked_operator(stage2_compiler_unavailable).
    compiler: MutationRuleCompiler | None = None
    #: None until a Stage 2 engine and profiles are configured: a compiled
    #: rule set then waits in blocked_operator(stage2_gate_unavailable).
    stage2: Stage2Parts | None = None


class AgentDispatchDeferred(RuntimeError):
    """This process does not run Agent Tasks; the service loop sends them."""


class _DeferredAgents:
    """The Agent executor of a one-shot command.

    ``start`` refuses, so the attempt stays ``sending``: a running service's
    ``poll()`` or the next ``recover()`` sends a new attempt (09 §8).  No
    model call is made by a process that would exit before storing it.
    """

    sink = None

    def start(self, request) -> None:
        raise AgentDispatchDeferred(
            f"{request.task_id} is left to the service loop")

    def deliver(self, **kwargs) -> int:
        return 0

    def close(self, **kwargs) -> None:
        pass


class Stage1Service:
    def __init__(self, parts: Stage1Parts) -> None:
        state = Path(parts.state_dir)
        state.mkdir(parents=True, exist_ok=True)
        self.parts = parts
        self.artifacts = parts.artifacts
        self.evidence = EvidenceStore(self.artifacts)
        self.store = Store(state / "controller.sqlite")
        for policy in parts.policies:
            self.store.save_policy(policy)
        self.runner = DurableRunner(state / "runner.sqlite",
                                    lease_duration_ns=parts.lease_duration_ns)
        self.receipts = RunnerEvidenceReceiptStore(state / "receipts.sqlite")
        self.bridge = RunnerQ1ReceiptBridge(
            state / "q1-publications.sqlite", runner=self.runner,
            receipts=self.receipts, artifacts=self.artifacts,
            evidence=self.evidence)
        self.mappings = MappingCatalog(self.artifacts, state / "mappings")
        self._own_issues = parts.issues is None
        self.issues = parts.issues or SqliteIssueTracker(state / "issues.sqlite")
        self.judge = PublishedQ1Judge(self.bridge.snapshot())
        # stage2.authority builds on stage1.authority: import it here.
        from ..stage2.authority import (PublishedStage2Judge,
                                        Stage2AuthorityPublisher,
                                        Stage2AuthorityStore)
        self.stage2_store = Stage2AuthorityStore(
            state / "stage2-publications.sqlite", artifacts=self.artifacts,
            evidence=self.evidence)
        self.stage2_judge = None if parts.stage2 is None else \
            PublishedStage2Judge(self.stage2_store.snapshot())
        hcap = ArtifactHcapChecker(self.artifacts)
        # The Controller is the executor's sink, and the executor is the
        # Controller's Agent executor: bind the sink after both exist.
        if parts.run_agents:
            tools = parts.tools or PinnedToolboxFactory(
                _source_index(parts.tree), _hcap_source(hcap))
            self.agents = QueuedAgentExecutor(
                parts.runtime, self.artifacts, tools, sink=None,
                max_workers=parts.agent_workers)
        else:
            self.agents = _DeferredAgents()
        env = Env(policy=self.store.policy, hcap=hcap,
                  materializer=parts.materializer, judge=self.judge,
                  compiler=parts.compiler, stage2=self.stage2_judge)
        extra = {} if parts.new_id is None else {"new_id": parts.new_id}
        preparer = (parts.prepare_candidate(self.store, state)
                    if parts.prepare_candidate is not None else None)
        self.controller = Controller(
            self.store, env, self.runner, self.agents, self.issues,
            parts.registry, parts.tree, self.artifacts, parts.judge_versions,
            prepare_candidate=preparer, **extra)
        self.agents.sink = self.controller
        self.publisher = Q1AuthorityPublisher(
            self.store, self.runner, self.receipts, self.bridge,
            self.artifacts, parts.identities, self.mappings, self.judge)
        self.stage2_publisher = None
        stage2_backend = None
        if parts.stage2 is not None:
            self.stage2_publisher = Stage2AuthorityPublisher(
                self.store, self.runner, self.receipts, self.stage2_store,
                self.bridge, self.artifacts, parts.identities, self.mappings,
                parts.stage2.profiles, self.stage2_judge)
            stage2_backend = StreamingSealingBackend(
                parts.stage2.engine_factory(self.artifacts, self.receipts,
                                            self.evidence),
                self.evidence, self.receipts, self.runner,
                sealer_id=parts.sealer_id)
        self.backend = StepRoutingBackend(EvidenceSealingBackend(
            parts.engine_factory(self.artifacts), self.evidence, self.receipts,
            sealer_id=parts.sealer_id), stage2_backend)
        self.worker = RunnerWorker(self.runner, self.backend,
                                   worker_id=parts.worker_id)
        self.worker_runs: list[WorkerRun] = []
        self.worker_errors: list[str] = []
        self.recover_errors: list[str] = []
        self._stop = threading.Event()
        self._worker_thread: threading.Thread | None = None

    # ------------------------------------------------------------ loop

    def recover(self) -> list[EffectFailure]:
        """After a restart: settle cancels, re-attach Runner tasks and send
        a new attempt of any Agent task that was in flight (09 §8)."""
        failures = self.controller.recover()
        # An issue change stored before the restart is applied before the
        # caller looks at job states.
        self.recover_errors = self.deliver_issue_events()
        return failures

    def start_worker(self, *, idle_s: float = 0.5) -> None:
        if self._worker_thread is not None:
            return

        def loop() -> None:
            while not self._stop.is_set():
                try:
                    run = self.worker.run_once()
                except Exception as exc:     # keep the worker alive
                    self.worker_errors.append(f"{type(exc).__name__}: {exc}")
                    run = None
                if run is None:
                    self._stop.wait(idle_s)
                else:
                    self.worker_runs.append(run)

        self._worker_thread = threading.Thread(
            target=loop, name="stage1-runner-worker", daemon=True)
        self._worker_thread.start()

    def step(self, *, wait_s: float = 0.0) -> StepReport:
        report = StepReport()
        try:
            report.delivered = self.agents.deliver(
                block=wait_s > 0, timeout=wait_s or None)
        except Exception as exc:
            # The result stays queued and is offered again next step.
            report.errors.append(f"deliver: {type(exc).__name__}: {exc}")
        report.errors.extend(self.deliver_issue_events())
        report.publications = self.publisher.publish_ready()
        if self.stage2_publisher is not None:
            report.publications += self.stage2_publisher.publish_ready()
        report.failures = self.controller.poll()
        return report

    def deliver_issue_events(self) -> list[str]:
        """Pass recorded issue status changes to the Controller (07 §7).

        Events go in recording order, each only to the jobs linked to its
        issue when it was recorded.  A delivery is recorded after the
        Controller applied it.  The first failure stops this pass, so a
        later event never overtakes an earlier one; the next call resumes
        with the failed delivery.  The Controller commits each event with
        the job's record of it and checks the job's current issue, so an
        event delivered twice (after a lost delivery record, or by another
        process at the same time) or to a later wait changes nothing."""
        pending = getattr(self.issues, "pending_events", None)
        if pending is None:
            return []
        for event_id, issue, gap, status, resolution, job_ids in pending():
            for job_id in job_ids:
                try:
                    self.controller.on_issue(gap, status, resolution,
                                             job_ids={job_id}, issue=issue,
                                             event_id=event_id)
                    self.issues.mark_delivered(event_id, job_id)
                except Exception as exc:
                    return [f"issue {status} for {job_id}: "
                            f"{type(exc).__name__}: {exc}"]
        return []

    def run(self, until: Callable[[], bool], *, interval_s: float = 1.0,
            timeout_s: float | None = None,
            on_step: Callable[[StepReport], None] | None = None) -> bool:
        """Step until ``until()`` holds.  False when the timeout passed."""
        deadline = None if timeout_s is None else time.monotonic() + timeout_s
        while not until():
            if deadline is not None and time.monotonic() >= deadline:
                return False
            report = self.step(wait_s=interval_s)
            if on_step is not None:
                on_step(report)
        return True

    def job(self, job_id: str) -> Job:
        return self.store.job(job_id)

    def close(self, *, worker_timeout_s: float | None = None) -> bool:
        """Stop the loop.  By default wait for a running lease to finish,
        so its completion or unconfirmed-cleanup report is stored.

        With a timeout, a worker still running keeps the Runner and receipt
        databases open (returns False): closing them under it would lose
        its ``stop_unconfirmed`` report.  Agent results that finish while
        closing are stored before the Store closes."""
        self._stop.set()
        worker_done = True
        if self._worker_thread is not None:
            self._worker_thread.join(worker_timeout_s)
            worker_done = not self._worker_thread.is_alive()
        self.agents.close()
        try:
            self.agents.deliver()
        except Exception as exc:     # the next recover() sends it again
            self.worker_errors.append(f"deliver on close: {exc}")
        self.bridge.close()
        self.stage2_store.close()
        if worker_done:
            self.receipts.close()
            self.runner.close()
        if self._own_issues:
            self.issues.close()
        self.store.close()
        return worker_done

    def __enter__(self) -> Stage1Service:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _source_index(tree: SourceTree):
    from ..agent_tasks.source_index import GitKernelSourceIndex
    from ..intake import GitSourceTree
    if not isinstance(tree, GitSourceTree):
        raise TypeError("the default Agent toolbox needs a GitSourceTree; "
                        "inject Stage1Parts.tools otherwise")
    return GitKernelSourceIndex(tree.repo)


def _hcap_source(hcap: ArtifactHcapChecker):
    from ..agent_tasks.tools import ArtifactHcapSource
    return ArtifactHcapSource(hcap)
