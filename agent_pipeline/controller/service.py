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
from dataclasses import dataclass
from typing import Callable

from pydantic import TypeAdapter

from ..artifacts import ArtifactStore
from ..components import HarnessRegistry, IssueTracker
from ..contracts import (AgentOutput, CandidateSubmission, GapRef,
                         JudgeVersions, LocationRequest,
                         VulnerabilityCandidate)
from ..intake import IntakeRejected, SourceTree, validate
from . import events as ev
from .machine import Env, Machine, Outcome
from .records import (TERMINAL, AgentAttempt, Job, JobState, TaskKind,
                      Transition)
from .store import Store
from .tasks import AgentExecutor, AgentRequest, Runner, RunnerInput

FINAL = ("sealed", "ended_unsealed")
#: Agent attempt states that can still give a result.
LIVE = ("sending", "running")
AGENT_OUTPUT = TypeAdapter(AgentOutput)


class ReplayMismatch(Exception):
    pass


@dataclass(frozen=True)
class EffectFailure:
    """A call sent after commit that failed.  The job keeps it due."""

    job_id: str
    effect: str
    error: str


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
        self.failures: list[EffectFailure] = []

    # ------------------------------------------------------------ intake

    def register(self, submission: CandidateSubmission
                 ) -> VulnerabilityCandidate | IntakeRejected:
        """Intake only (02 §3): store the candidate, or say why not.  The
        same target always gets the same candidate_id."""
        result = validate(submission, self.tree,
                          candidate_id=f"VC-{self.new_id()}")
        if isinstance(result, IntakeRejected):
            return result
        return self.store.register_candidate(result)

    def start_job(self, candidate_id: str, policy_id: str) -> str:
        """A new job for a registered candidate, e.g. under another
        sanitizer's policy."""
        c = self.store.candidate(candidate_id)
        loc = c.location
        return self.submit(CandidateSubmission(
            kernel_commit=c.kernel_commit, location=LocationRequest(
                kind=loc.kind, path=loc.path, symbol=loc.symbol,
                start_line=loc.start_line, end_line=loc.end_line)),
            policy_id)

    def submit(self, submission: CandidateSubmission, policy_id: str) -> str:
        """Register the candidate and start a job for it.  A submission
        intake refuses still gets a job, which ends rejected (09 §3)."""
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
        result = self.register(job.submission)
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
        if a is not None and a.status in LIVE:
            self.store.save_attempt(a.model_copy(update={
                "status": "succeeded", "model_id": model_id,
                "output_ref": ref}))
        # Stored first: if this transition fails, poll() applies it from
        # the stored attempt.
        self._guard(job_id, "agent_result", lambda: self._apply(
            job_id, ev.AgentSucceeded(task_id=task_id, attempt=attempt,
                                      output=output, model_id=model_id)))

    def on_agent_failure(self, task_id: str, attempt: int,
                         failure: str) -> None:
        a = self.store.attempt(task_id, attempt)
        if a is not None and a.status in LIVE:
            self.store.save_attempt(a.model_copy(update={
                "status": "failed", "failure": failure}))
        job_id = job_of(task_id)
        self._guard(job_id, "agent_result", lambda: self._apply(
            job_id, ev.AgentFailed(task_id=task_id, attempt=attempt,
                                   failure=failure)))

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
        policy = self.store.policy(policy_id)
        job = self.store.job(job_id)
        binding = None if job.candidate is None else self.registry.lookup(
            job.candidate.kernel_commit, policy.sanitizer)
        self._apply(job_id, ev.PolicyChanged(job_policy_id=policy_id,
                                             binding=binding))

    def operator(self, job_id: str, action: str) -> Outcome | None:
        return self._apply(job_id, ev.OperatorAction(
            action=action, action_id=f"op-{self.new_id()}"))

    def poll(self) -> list[EffectFailure]:
        """Ask the Runner about every job's Runner tasks and finish what a
        lost answer left undone (09 §8): a cancel not yet confirmed is sent
        again, a pending task the Runner does not know is submitted again
        with its task_id, and a gap job not linked to its issue is
        linked.  A failing call is recorded for its job and the other jobs
        go on; returns this call's failures."""
        self.failures = []
        for job in list(self.store.jobs()):
            self._settle(job.job_id)
        return self.failures

    def _settle(self, job_id: str) -> None:
        job = self.store.job(job_id)
        for task_id in job.cancelling_tasks:
            self._guard(job_id, f"cancel:{task_id}",
                        lambda t=task_id: self._recancel(job_id, t))
        self._guard(job_id, "link_issue",
                    lambda: self._link_gap(self.store.job(job_id)))
        self._guard(job_id, "pending_task",
                    lambda: self._poll_pending(job_id))

    def _recancel(self, job_id: str, task_id: str) -> None:
        if self.runner.status(task_id).state in FINAL:
            self._apply(job_id, ev.CancelConfirmed(task_id=task_id))
        else:
            self._cancel(job_id, task_id)

    def _poll_pending(self, job_id: str) -> None:
        job = self.store.job(job_id)
        p = job.pending_task
        if p is not None and p.kind is TaskKind.AGENT:
            a = self.store.attempt(p.task_id, p.attempt)
            if a is None or a.status == "sending":
                # start() failed or never ran: whether the executor took it
                # is unknown, so send a new attempt, as recover() does; a
                # late result of this one makes no transition (09 §8).
                self._apply(job_id, ev.AgentAttemptRestarted(
                    task_id=p.task_id, attempt=p.attempt + 1))
            elif a.status == "succeeded":
                # The result was stored but its transition did not commit.
                self._apply(job_id, ev.AgentSucceeded(
                    task_id=p.task_id, attempt=p.attempt,
                    output=AGENT_OUTPUT.validate_json(
                        self.artifacts.get(a.output_ref)),
                    model_id=a.model_id or ""))
            elif a.status == "failed":
                self._apply(job_id, ev.AgentFailed(
                    task_id=p.task_id, attempt=p.attempt,
                    failure=a.failure or ""))
            return
        if p is None or p.kind is not TaskKind.RUNNER or \
                job.cancelling_tasks:
            return
        st = self.runner.status(p.task_id)
        if st.state == "unknown":
            self._dispatch(job_id)
        else:
            self._take_status(job_id, p.task_id, st)

    # ------------------------------------------------------------ restart

    def recover(self) -> list[EffectFailure]:
        """09 §8: settle cancels first, then re-attach to the Runner task by
        task_id, send a new attempt of an Agent task, and process the
        queue states.  Failures are recorded per job, as in poll()."""
        self.failures = []
        for job in list(self.store.jobs()):
            self._guard(job.job_id, "recover",
                        lambda j=job.job_id: self._recover(j))
        return self.failures

    def _recover(self, job_id: str) -> None:
        job = self.store.job(job_id)
        for task_id in job.cancelling_tasks:
            self._guard(job_id, f"cancel:{task_id}",
                        lambda t=task_id: self._cancel(job_id, t))
        self._guard(job_id, "link_issue",
                    lambda: self._link_gap(self.store.job(job_id)))
        job = self.store.job(job_id)
        p = job.pending_task
        if p is None:
            if job.state is JobState.SUBMITTED:
                self._intake(job_id)
            elif job.state is JobState.RETRY_PENDING:
                self._rebind(job)
            return
        if p.kind is TaskKind.RUNNER:
            self._dispatch(job_id)
        elif p.kind is TaskKind.AGENT:
            self._apply(job_id, ev.AgentAttemptRestarted(
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
            if a is not None and a.status in LIVE:
                self.store.save_attempt(a.model_copy(
                    update={"status": "abandoned"}))
        # Committed already: a failing call is recorded and sent again by
        # poll() or recover(), and does not stop the next one.
        j = new.job_id
        for task_id in new.cancelling_tasks:
            if task_id not in old.cancelling_tasks:
                self._guard(j, f"cancel:{task_id}",
                            lambda t=task_id: self._cancel(j, t))
        self._guard(j, "dispatch", lambda: self._dispatch(j))
        self._guard(j, "link_issue",
                    lambda: self._link_gap(self.store.job(j)))

    def _guard(self, job_id: str, effect: str,
               call: Callable[[], None]) -> bool:
        try:
            call()
            return True
        except Exception as e:      # any failure of the outside call
            f = EffectFailure(job_id=job_id, effect=effect, error=repr(e))
            self.store.record_failure(job_id, effect, f.error, self.clock())
            self.failures.append(f)
            return False

    def _link_gap(self, job: Job) -> None:
        """07 §2: the Controller creates or links the issue.  Idempotent,
        so poll() and recover() send it again until it is recorded."""
        if job.state in (JobState.BLOCKED_HARNESS_GAP, JobState.PARKED) \
                and job.gap is not None and \
                not self.store.is_linked(job.job_id, job.gap):
            self.store.link_issue(job.gap, self.issues.open_or_link(
                job.gap, job.job_id), job.job_id)

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
                status="sending"))
            self.agents.start(AgentRequest(
                job_id=job_id, task_id=p.task_id, attempt=p.attempt,
                agent_task=p.agent_task, candidate=job.candidate,
                hcap_revision=job.binding.hcap_revision,
                analysis_ref=job.analysis_ref, plan_ref=job.plan_ref,
                repair=p.repair))
            a = self.store.attempt(p.task_id, p.attempt)
            if a.status == "sending":
                self.store.save_attempt(a.model_copy(
                    update={"status": "running"}))
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
