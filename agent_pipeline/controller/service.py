"""The Controller service: intake, binding, events in, tasks out.

Every change to a job goes through Machine.handle and one Store.commit.
Tasks are sent after the commit (09 §8): an Agent request, a Runner submit
(only once the job has no cancelling Runner task left), or a cancel.  A
restarted Controller calls recover(), which re-attaches to Runner tasks by
task_id instead of starting them again.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Callable

from ..artifacts import ArtifactStore
from ..components import HarnessRegistry, IssueTracker
from ..contracts import (AgentOutput, CandidateSubmission, GapRef,
                         JudgeVersions)
from ..intake import IntakeRejected, SourceTree, validate
from . import events as ev
from .machine import Env, Machine, Outcome
from .records import (TERMINAL, AgentAttempt, Job, JobState, TaskKind,
                      Transition)
from .store import Store
from .tasks import AgentExecutor, AgentRequest, Runner, RunnerInput

FINAL = ("sealed", "ended_unsealed")


class ReplayMismatch(Exception):
    pass


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Controller:
    def __init__(self, store: Store, env: Env, runner: Runner,
                 agents: AgentExecutor, issues: IssueTracker,
                 registry: HarnessRegistry, tree: SourceTree,
                 artifacts: ArtifactStore, judge_versions: JudgeVersions,
                 clock: Callable[[], str] = _utc_now,
                 new_id: Callable[[], str] = lambda: uuid.uuid4().hex[:12]
                 ) -> None:
        self.store = store
        self.machine = Machine(env)
        self.runner = runner
        self.agents = agents
        self.issues = issues
        self.registry = registry
        self.tree = tree
        self.artifacts = artifacts
        self.judge_versions = judge_versions
        self.clock = clock
        self.new_id = new_id

    # ------------------------------------------------------------ intake

    def submit(self, submission: CandidateSubmission, policy_id: str) -> str:
        self.store.policy(policy_id)            # must exist
        job = Job(job_id=f"job-{self.new_id()}", submission=submission,
                  job_policy_id=policy_id)
        self.store.create(job, Transition(
            job_id=job.job_id, seq=0, from_state=None, to_state=job.state,
            reason="submitted", event={"type": "submitted"},
            job_policy_id=policy_id, at=self.clock(), job=job))
        self._intake(job.job_id)
        return job.job_id

    def _intake(self, job_id: str) -> None:
        job = self.store.job(job_id)
        result = validate(job.submission, self.tree, candidate_id=job_id)
        if isinstance(result, IntakeRejected):
            event = ev.IntakeChecked(
                rejection=f"{result.reason}:{result.detail}",
                judge_versions=self.judge_versions)
        else:
            policy = self.store.policy(job.job_policy_id)
            event = ev.IntakeChecked(
                candidate=result,
                binding=self.registry.lookup(result.kernel_commit,
                                             policy.sanitizer),
                judge_versions=self.judge_versions)
        self._apply(job_id, event)

    # ------------------------------------------------------------ inputs

    def on_agent_result(self, task_id: str, attempt: int,
                        output: AgentOutput, model_id: str) -> None:
        """Every output is stored; only the job's pending attempt makes a
        transition (09 §2)."""
        ref = self.artifacts.put(output.model_dump_json().encode())
        job_id = job_of(task_id)
        a = self.store.attempt(task_id, attempt)
        if a is not None and a.status == "running":
            self.store.save_attempt(a.model_copy(update={
                "status": "succeeded", "model_id": model_id,
                "output_ref": ref}))
        self._apply(job_id, ev.AgentSucceeded(task_id=task_id,
                                              attempt=attempt, output=output,
                                              model_id=model_id))

    def on_agent_failure(self, task_id: str, attempt: int,
                         failure: str) -> None:
        a = self.store.attempt(task_id, attempt)
        if a is not None and a.status == "running":
            self.store.save_attempt(a.model_copy(update={
                "status": "failed", "failure": failure}))
        self._apply(job_of(task_id), ev.AgentFailed(
            task_id=task_id, attempt=attempt, failure=failure))

    def approve(self, job_id: str, task_id: str, review_manifest_sha256: str,
                decision_id: str) -> None:
        self._apply(job_id, ev.ApprovalGiven(
            task_id=task_id, review_manifest_sha256=review_manifest_sha256,
            decision_id=decision_id))

    def deny(self, job_id: str, task_id: str, note: str) -> None:
        self._apply(job_id, ev.ApprovalDenied(task_id=task_id, note=note))

    def on_issue(self, gap: GapRef, status: str, resolution: str = "") -> None:
        for job in self.store.jobs({JobState.BLOCKED_HARNESS_GAP,
                                    JobState.PARKED}):
            if job.gap != gap:
                continue
            out = self._apply(job.job_id, ev.IssueChanged(
                gap=gap, status=status, resolution=resolution))
            if out and out.job.state is JobState.RETRY_PENDING:
                self._rebind(out.job)

    def on_registry_changed(self) -> None:
        """A harness build or HCAP revision changed: look every live job's
        binding up again (09 §5)."""
        for job in self.store.jobs():
            if job.state in TERMINAL or job.candidate is None or \
                    job.state is JobState.SUBMITTED:
                continue
            policy = self.store.policy(job.job_policy_id)
            b = self.registry.lookup(job.candidate.kernel_commit,
                                     policy.sanitizer)
            if b != job.binding:
                self._apply(job.job_id, ev.BindingChanged(binding=b))

    def on_judge_versions(self, versions: JudgeVersions) -> None:
        self.judge_versions = versions
        for job in self.store.jobs():
            if job.state not in TERMINAL and job.judge_versions != versions:
                self._apply(job.job_id, ev.JudgeVersionsChanged(
                    judge_versions=versions))

    def set_policy(self, job_id: str, policy_id: str) -> None:
        self.store.policy(policy_id)
        self._apply(job_id, ev.PolicyChanged(job_policy_id=policy_id))

    def operator(self, job_id: str, action: str) -> Outcome | None:
        return self._apply(job_id, ev.OperatorAction(
            action=action, action_id=f"op-{self.new_id()}"))

    def poll(self) -> None:
        """Ask the Runner about every job's pending Runner task."""
        for job in self.store.jobs():
            p = job.pending_task
            if p is not None and p.kind is TaskKind.RUNNER and \
                    not job.cancelling_tasks:
                self._take_status(job.job_id, p.task_id,
                                  self.runner.status(p.task_id))

    # ------------------------------------------------------------ restart

    def recover(self) -> None:
        """09 §8: settle cancels first, then re-attach to the Runner task by
        task_id, send a new attempt of an Agent task, and process the
        queue states."""
        for job in list(self.store.jobs()):
            for task_id in job.cancelling_tasks:
                self._cancel(job.job_id, task_id)
            job = self.store.job(job.job_id)
            p = job.pending_task
            if p is None:
                if job.state is JobState.SUBMITTED:
                    self._intake(job.job_id)
                elif job.state is JobState.RETRY_PENDING:
                    self._rebind(job)
                continue
            if p.kind is TaskKind.RUNNER:
                self._dispatch(job.job_id)
            elif p.kind is TaskKind.AGENT:
                self._apply(job.job_id, ev.AgentAttemptRestarted(
                    task_id=p.task_id, attempt=p.attempt + 1))

    def replay(self, job_id: str) -> Job:
        """Apply every stored event again from the first record; each step
        must give the job its transition stored (09 §8, oracle 4)."""
        ts = self.store.transitions(job_id)
        job = ts[0].job
        for t in ts[1:]:
            out = self.machine.handle(job, ev.EVENT.validate_python(t.event))
            if out is None or out.job != t.job:
                raise ReplayMismatch(f"{job_id} seq {t.seq}")
            job = out.job
        if job != self.store.job(job_id):
            raise ReplayMismatch(f"{job_id}: stored job differs")
        return job

    # ------------------------------------------------------------ internals

    def _rebind(self, job: Job) -> None:
        policy = self.store.policy(job.job_policy_id)
        b = self.registry.lookup(job.candidate.kernel_commit,
                                 policy.sanitizer)
        self._apply(job.job_id, ev.BindingChanged(binding=b))

    def _apply(self, job_id: str, event) -> Outcome | None:
        job = self.store.job(job_id)
        out = self.machine.handle(job, event)
        if out is None:
            return None
        self.store.commit(job.seq, out.job, Transition(
            job_id=job_id, seq=out.job.seq, from_state=job.state,
            to_state=out.job.state, reason=out.reason,
            event=event.model_dump(mode="json"),
            consumed=tuple(out.consumed), job_policy_id=out.job.job_policy_id,
            at=self.clock(), job=out.job), out.verdicts)
        self._after(job, out)
        return out

    def _after(self, old: Job, out: Outcome) -> None:
        new = out.job
        if out.abandoned_attempt:
            a = self.store.attempt(*out.abandoned_attempt)
            if a is not None and a.status == "running":
                self.store.save_attempt(a.model_copy(
                    update={"status": "abandoned"}))
        if new.state is JobState.BLOCKED_HARNESS_GAP and \
                (old.state is not new.state or old.gap != new.gap):
            # 07 §2: the Controller creates or links the issue.
            self.store.link_issue(new.gap, self.issues.open_or_link(
                new.gap, new.job_id))
        for task_id in new.cancelling_tasks:
            if task_id not in old.cancelling_tasks:
                self._cancel(new.job_id, task_id)
        self._dispatch(new.job_id)

    def _dispatch(self, job_id: str) -> None:
        job = self.store.job(job_id)
        p = job.pending_task
        if p is None:
            return
        if p.kind is TaskKind.AGENT:
            if self.store.attempt(p.task_id, p.attempt) is not None:
                return
            self.store.save_attempt(AgentAttempt(
                task_id=p.task_id, attempt=p.attempt, job_id=job_id,
                agent_task=p.agent_task, input_digest=p.input_digest,
                repair_input_digest=None if p.repair is None else
                self.artifacts.put(p.repair.model_dump_json().encode()),
                status="running"))
            self.agents.start(AgentRequest(
                job_id=job_id, task_id=p.task_id, attempt=p.attempt,
                agent_task=p.agent_task, candidate=job.candidate,
                hcap_revision=job.binding.hcap_revision,
                analysis_ref=job.analysis_ref, plan_ref=job.plan_ref,
                repair=p.repair))
        elif p.kind is TaskKind.RUNNER and not job.cancelling_tasks:
            # Idempotent by task_id: sending it again never starts a second
            # run (09 §8).
            st = self.runner.submit(p.task_id, RunnerInput(
                job_id=job_id, harness_ref=job.harness.harness_ref,
                execution_harness_id=job.harness.execution_harness_id))
            self._take_status(job_id, p.task_id, st)

    def _cancel(self, job_id: str, task_id: str) -> None:
        st = self.runner.cancel(task_id)
        if st.state in FINAL:
            self._apply(job_id, ev.CancelConfirmed(task_id=task_id))

    def _take_status(self, job_id: str, task_id: str, st) -> None:
        if st.state in FINAL:
            self._apply(job_id, ev.RunnerFinished(
                task_id=task_id, state=st.state,
                bundle_ref=st.bundles[-1] if st.bundles and
                st.state == "sealed" else None, reason=st.reason))


def job_of(task_id: str) -> str:
    return task_id.rsplit(".t", 1)[0]
