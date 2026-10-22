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
from typing import Callable, Collection

from pydantic import TypeAdapter

from ..artifacts import ArtifactStore
from ..components import HarnessRegistry, IssueTracker
from ..contracts import (AgentOutput, AgentTask, AgentUsage,
                         CandidateSubmission, GapRef,
                         HarnessBinding, JudgeVersions, LocationRequest,
                         VulnerabilityCandidate)
from ..intake import IntakeRejected, SourceTree, validate
from . import events as ev
from .machine import Env, Machine, Outcome, harness_authority_stale
from .records import (TERMINAL, AgentAttempt, Job, JobState, RepairInput,
                      TaskKind, Transition)
from .store import StaleIssueEvent, Store
from .tasks import (CLEANUP_UNCONFIRMED, AgentExecutor, AgentRequest, Runner,
                    RunnerInput,
                    agent_input_digest, legacy_runner_input_digest,
                    runner_input_digest)

FINAL = ("sealed", "ended_unsealed")
#: Agent attempt states that can still give a result.
LIVE = ("sending", "running")
AGENT_OUTPUT = TypeAdapter(AgentOutput)


class ReplayMismatch(Exception):
    pass


class LegacyTaskPolicyUnavailable(RuntimeError):
    """A legacy logical Agent task has no authenticated historical policy."""


class RunnerInputDigestMismatch(RuntimeError):
    """A pending Runner digest is neither canonical nor exactly legacy."""


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
                 new_id: Callable[[], str] = lambda: uuid.uuid4().hex[:12],
                 prepare_candidate: Callable[[str], object] | None = None
                 ) -> None:
        self.store = store
        self.machine = Machine(env)
        self.hcap = env.hcap
        self.materializer = env.materializer
        self.runner = runner
        self.agents = agents
        self.issues = issues
        self.registry = registry
        self.tree = tree
        self.artifacts = artifacts
        # An adopted fallback outlives the process; the constructor value is
        # only the first default (09 §5).
        self.judge_versions = store.judge_versions() or judge_versions
        self.clock = clock
        self.new_id = new_id
        self.prepare_candidate = prepare_candidate
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
            binding = self.registry.lookup(result.kernel_commit,
                                           policy.sanitizer)
            event = ev.IntakeChecked(
                candidate=result,
                binding=binding,
                judge_versions=self._versions_for(binding))
        self._apply(job_id, event)

    def _versions_for(self, binding: HarnessBinding | None) -> JudgeVersions:
        """Resolve the immutable Q1 authorities selected by this binding."""
        if binding is not None:
            selected = self.hcap.judge_versions(binding.hcap_revision)
            if selected is not None:
                return selected
        return self.judge_versions

    # ------------------------------------------------------------ inputs

    def on_agent_result(self, task_id: str, attempt: int,
                        output: AgentOutput, model_id: str, *,
                        usage: AgentUsage | None = None) -> None:
        """Every output is stored; only the job's pending attempt makes a
        transition (09 §2).  ``usage`` is kept on the attempt record only;
        it never enters a transition."""
        ref = self.artifacts.put(output.model_dump_json().encode())
        job_id = job_of(task_id)
        a = self.store.attempt(task_id, attempt)
        if a is not None and a.status in LIVE:
            self.store.save_attempt(a.model_copy(update={
                "status": "succeeded", "model_id": model_id,
                "output_ref": ref, "usage": usage}))
        # Stored first: if this transition fails, poll() applies it from
        # the stored attempt.
        self._guard(job_id, "agent_result", lambda: self._apply(
            job_id, ev.AgentSucceeded(task_id=task_id, attempt=attempt,
                                      output=output, model_id=model_id)))

    def on_agent_failure(self, task_id: str, attempt: int,
                         failure: str, *,
                         usage: AgentUsage | None = None) -> None:
        """``usage``, what the failed run used, is kept like a result's."""
        a = self.store.attempt(task_id, attempt)
        if a is not None and a.status in LIVE:
            self.store.save_attempt(a.model_copy(update={
                "status": "failed", "failure": failure, "usage": usage}))
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

    def on_issue(self, gap: GapRef, status: str, resolution: str = "",
                 job_ids: Collection[str] | None = None, *,
                 issue: str | None = None,
                 event_id: int | None = None) -> None:
        """Apply an issue status change to the jobs waiting on `gap`, or
        only to `job_ids` when the caller knows which jobs the issue
        covers.

        With `issue`, a job takes the change only while its current wait is
        linked to that issue: a later wait on the same gap belongs to a new
        issue.  With `event_id` (increasing per tracker), the change commits
        together with the job's record of it, so it is applied at most once
        per job and never after a later event, whichever process delivers
        it."""
        for job in self.store.jobs({JobState.BLOCKED_HARNESS_GAP,
                                    JobState.PARKED}):
            if job.gap != gap or (job_ids is not None and
                                  job.job_id not in job_ids):
                continue
            if issue is not None and \
                    self.store.job_issue(job.job_id) != issue:
                continue
            if event_id is not None:
                mark = self.store.issue_mark(job.job_id)
                if mark is not None and mark >= event_id:
                    continue
            try:
                out = self._apply(job.job_id, ev.IssueChanged(
                    gap=gap, status=status, resolution=resolution),
                    issue_event=event_id)
            except StaleIssueEvent:
                continue    # another deliverer applied it, or a later one
            if out and out.job.state is JobState.RETRY_PENDING:
                # The event is taken; a failed rebind stays due and poll()
                # or recover() sends it again.
                self._guard(out.job.job_id, "rebind",
                            lambda j=out.job: self._rebind(j))

    def on_registry_changed(self) -> None:
        """A harness build or HCAP revision changed: look every live job's
        binding up again (09 §5)."""
        for job in list(self.store.jobs()):
            self._reconcile_registry(job.job_id)

    def on_judge_versions(self, versions: JudgeVersions) -> None:
        self.store.save_judge_versions(versions)
        self.judge_versions = versions
        for job in self.store.jobs():
            if job.state in TERMINAL:
                continue
            selected = self._versions_for(job.binding)
            if job.judge_versions != selected:
                self._apply(job.job_id, ev.JudgeVersionsChanged(
                    judge_versions=selected, consume_same_verdict=True))

    def set_policy(self, job_id: str, policy_id: str) -> None:
        policy = self.store.policy(policy_id)
        job = self.store.job(job_id)
        binding = None if job.candidate is None else self.registry.lookup(
            job.candidate.kernel_commit, policy.sanitizer)
        self._apply(job_id, ev.PolicyChanged(
            job_policy_id=policy_id, binding=binding,
            judge_versions=self._versions_for(binding),
            rematerialize_authority=True,
            harness_authority_current=self._authority_current(job, binding)))

    def route(self, job_id: str, to: str) -> Outcome | None:
        """09 §5 route(to) on blocked_operator(gate_regression): `to` is
        "gate" or "strategy"."""
        return self.operator(job_id, f"route_{to}")

    def start_stage2(self, job_id: str) -> Outcome | None:
        """09 §4: an operator starts Stage 2 of a job in s1_reached.  Until
        JobPolicy.run_stage2 may be true this is the only way in."""
        return self.operator(job_id, "start_stage2")

    def operator(self, job_id: str, action: str) -> Outcome | None:
        return self._apply(job_id, ev.OperatorAction(
            action=action, action_id=f"op-{self.new_id()}"))

    def poll(self) -> list[EffectFailure]:
        """Ask the Runner about every job's Runner tasks and finish what a
        lost answer left undone (09 §8): a cancel not yet confirmed is sent
        again, a pending task the Runner does not know is submitted again
        with its task_id, a gap job not linked to its issue is linked, and
        a retry_pending job is bound again.  A failing call is recorded for its job and the other jobs
        go on; returns this call's failures."""
        self.failures = []
        self._late_cleanup_reports()
        for job in list(self.store.jobs()):
            self._settle(job.job_id)
        return self.failures

    def _late_cleanup_reports(self) -> None:
        """09 §8: an execution reported not confirmed stopped after its task
        ended is recorded on the job before the report is acknowledged."""
        try:
            reports = self.runner.cleanup_reports()
        except Exception as e:      # any failure of the outside call
            f = EffectFailure(job_id="", effect="cleanup_reports",
                              error=repr(e))
            self.failures.append(f)
            return
        for task_id, generation in reports:
            job_id = job_of(task_id)
            self._guard(job_id, f"cleanup:{task_id}:{generation}",
                        lambda j=job_id, t=task_id, g=generation:
                        self._late_cleanup(j, t, g))

    def _late_cleanup(self, job_id: str, task_id: str,
                      generation: int) -> None:
        try:
            self.store.job(job_id)
        except KeyError:
            pass        # no job of this Controller owns the task
        else:
            # Idempotent per (task_id, generation): a report re-sent after
            # a failed acknowledgement makes no second transition.
            self._apply(job_id, ev.CleanupUnconfirmed(
                task_id=task_id, generation=generation))
        self.runner.acknowledge_cleanup_report(task_id, generation)

    def _settle(self, job_id: str) -> None:
        job = self.store.job(job_id)
        for task_id in job.cancelling_tasks:
            self._guard(job_id, f"cancel:{task_id}",
                        lambda t=task_id: self._recancel(job_id, t))
        self._guard(job_id, "link_issue",
                    lambda: self._link_gap(self.store.job(job_id)))
        self._guard(job_id, "pending_task",
                    lambda: self._poll_pending(job_id))
        self._guard(job_id, "rebind", lambda: self._retry_rebind(job_id))

    def _retry_rebind(self, job_id: str) -> None:
        """A job left in retry_pending (its issue resolved, the binding
        lookup or its commit failed) is bound again."""
        job = self.store.job(job_id)
        if job.state is JobState.RETRY_PENDING and job.pending_task is None:
            self._rebind(job)

    def _recancel(self, job_id: str, task_id: str) -> None:
        st = self.runner.status(task_id)
        if st.state in FINAL:
            self._confirm_cancel(job_id, task_id, st)
        else:
            self._take_bundles(job_id, task_id, st)
            self._cancel(job_id, task_id)

    def _confirm_cancel(self, job_id: str, task_id: str, st) -> None:
        # Bundles sealed before the task ended are taken first (09 §4).
        self._take_bundles(job_id, task_id, st)
        self._apply(job_id, ev.CancelConfirmed(
            task_id=task_id,
            cleanup_unconfirmed=st.reason == CLEANUP_UNCONFIRMED))

    def _poll_pending(self, job_id: str) -> None:
        job = self.store.job(job_id)
        p = job.pending_task
        if p is not None and p.kind is TaskKind.AGENT:
            a = self.store.attempt(p.task_id, p.attempt)
            if a is None or a.status == "sending":
                # start() failed or never ran: whether the executor took it
                # is unknown, so send a new attempt, as recover() does; a
                # late result of this one makes no transition (09 §8).
                self._prepare_candidate(job)
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
        if self._migrate_runner_input_digest(job):
            return
        job = self.store.job(job_id)
        p = job.pending_task
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
        self._late_cleanup_reports()
        for job in list(self.store.jobs()):
            self._guard(job.job_id, "recover",
                        lambda j=job.job_id: self._recover(j))
        return self.failures

    def _recover(self, job_id: str) -> None:
        # Reconcile authority before touching pending tasks. In particular,
        # never reconnect a legacy Runner task whose harness cannot prove it
        # was materialized under the binding now stored for the job.
        self._reconcile_registry(job_id)
        job = self.store.job(job_id)
        for task_id in job.cancelling_tasks:
            self._guard(job_id, f"cancel:{task_id}",
                        lambda t=task_id: self._cancel(job_id, t))
        self._prepare_candidate(job)
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
            if out is None:
                raise ReplayMismatch(f"{job_id} seq {t.seq}")
            replayed = self._legacy_materialized_provenance(out.job, t.job)
            if not self._replay_job_matches(replayed, t.job):
                raise ReplayMismatch(f"{job_id} seq {t.seq}")
            # Continue from the exact historical snapshot.  Before the
            # migration event exists, this may carry an authenticated old
            # Runner digest or an unpinned Agent task into later transitions.
            job = t.job
        if job != self.store.job(job_id):
            raise ReplayMismatch(f"{job_id}: stored job differs")
        return job

    # ------------------------------------------------------------ internals

    @staticmethod
    def _legacy_materialized_provenance(actual: Job, expected: Job) -> Job:
        """Normalize only the field absent from pre-migration snapshots.

        A current record that explicitly stores null is not accepted as a
        legacy snapshot. Every other field must still match exactly.
        """

        old = expected.harness
        current = actual.harness
        if old is None or current is None or \
                "hcap_revision" in old.model_fields_set:
            return actual
        without_provenance = current.model_copy(
            update={"hcap_revision": None})
        if without_provenance != old:
            return actual
        return actual.model_copy(update={"harness": old})

    def _reconcile_registry(self, job_id: str) -> None:
        """Append binding facts, including same-binding stale authority."""

        job = self.store.job(job_id)
        if job.state in TERMINAL or job.candidate is None or \
                job.state is JobState.SUBMITTED:
            return
        policy = self.store.policy(job.job_policy_id)
        binding = self.registry.lookup(job.candidate.kernel_commit,
                                       policy.sanitizer)
        stale = binding == job.binding and \
            harness_authority_stale(job, binding)
        if binding != job.binding or stale:
            out = self._apply(job_id, ev.BindingChanged(
                binding=binding,
                judge_versions=self._versions_for(binding),
                rematerialize_authority=True,
                harness_authority_current=self._authority_current(
                    job, binding)))
            if out is None:
                raise RuntimeError(
                    f"materialization authority migration refused for "
                    f"{job_id}")

    def _rebind(self, job: Job) -> None:
        policy = self.store.policy(job.job_policy_id)
        b = self.registry.lookup(job.candidate.kernel_commit,
                                 policy.sanitizer)
        self._apply(job.job_id, ev.BindingChanged(
            binding=b, judge_versions=self._versions_for(b),
            rematerialize_authority=True,
            harness_authority_current=self._authority_current(job, b)))

    def _authority_current(self, job: Job,
                           binding: HarnessBinding | None) -> bool:
        """Does the job's harness keep its HCAP-derived authority refs
        under `binding`?  Only then may an HCAP-only change keep it
        (09 §5).  Infrastructure errors propagate."""
        h = job.harness
        if binding is None or h is None or h.hcap_revision is None or \
                h.execution_harness_id != binding.execution_harness_id:
            return False
        if not harness_authority_stale(job, binding):
            return True
        return self.materializer.harness_authority_current(
            h.harness_ref, binding)

    def _apply(self, job_id: str, event,
               issue_event: int | None = None) -> Outcome | None:
        job = self.store.job(job_id)
        out = self.machine.handle(job, event)
        if out is None:
            return None
        self.store.commit(job.seq, out.job, Transition(
            job_id=job_id, seq=out.job.seq, from_state=job.state,
            to_state=out.job.state, reason=out.reason,
            event=event.model_dump(mode="json"),
            consumed=tuple(out.consumed), job_policy_id=out.job.job_policy_id,
            at=self.clock(), job=out.job), out.verdicts,
            issue_event=issue_event)
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
        self._prepare_candidate(job)
        p = job.pending_task
        if p is None:
            return
        if p.kind is TaskKind.AGENT:
            if self.store.attempt(p.task_id, p.attempt) is not None:
                return
            model_policy = p.model_policy
            if model_policy is None:
                model_policy = self._legacy_model_policy(job, p)
            self.store.save_attempt(AgentAttempt(
                task_id=p.task_id, attempt=p.attempt, job_id=job_id,
                agent_task=p.agent_task, input_digest=p.input_digest,
                repair_input_digest=None if p.repair is None else
                self.artifacts.put(p.repair.model_dump_json().encode()),
                status="sending"))
            self.agents.start(AgentRequest(
                job_id=job_id, task_id=p.task_id, attempt=p.attempt,
                agent_task=p.agent_task, candidate=job.candidate,
                model_policy=model_policy,
                hcap_revision=job.binding.hcap_revision,
                analysis_ref=job.analysis_ref, plan_ref=job.plan_ref,
                repair=p.repair, binding=job.binding,
                prior_repairs=self._prior_repairs(job_id, p),
                **(dict(stage2_input=job.stage2_basis,
                        rule_set_ref=job.rule_set_ref)
                   if p.agent_task is AgentTask.MUTATION_STRATEGY else {})))
            a = self.store.attempt(p.task_id, p.attempt)
            if a.status == "sending":
                self.store.save_attempt(a.model_copy(
                    update={"status": "running"}))
        elif p.kind is TaskKind.RUNNER and not job.cancelling_tasks:
            if self._migrate_runner_input_digest(job):
                return
            job = self.store.job(job_id)
            p = job.pending_task
            # Idempotent by task_id: sending it again never starts a second
            # run (09 §8).  A Stage 2 task carries its own input.
            st = self.runner.submit(
                p.task_id, p.runner_input or RunnerInput(
                    job_id=job_id, harness_ref=job.harness.harness_ref,
                    execution_harness_id=job.harness.execution_harness_id))
            self._take_status(job_id, p.task_id, st)

    def _prepare_candidate(self, job: Job) -> None:
        if self.prepare_candidate is not None and job.candidate is not None \
                and job.state not in TERMINAL:
            self.prepare_candidate(job.job_id)

    def _prior_repairs(self, job_id: str, p) -> tuple[str, ...]:
        """The stored RepairInputs of the job's earlier Stage 1 repairs,
        ordered by repair count, without the one this attempt carries.  A
        restarted attempt of the same task stores the same RepairInput, so
        each appears once."""
        if p.repair is None or p.agent_task is AgentTask.MUTATION_STRATEGY:
            return ()
        current = self.artifacts.put(p.repair.model_dump_json().encode())
        seen: dict[str, int] = {}
        for a in self.store.attempts(job_id):
            ref = a.repair_input_digest
            if ref is None or ref == current or ref in seen or \
                    a.agent_task is AgentTask.MUTATION_STRATEGY:
                continue
            try:
                seen[ref] = RepairInput.model_validate_json(
                    self.artifacts.get(ref)).attempt
            except (OSError, ValueError):
                continue        # context only: a lost record is skipped
        return tuple(sorted(seen, key=seen.get))

    @staticmethod
    def _runner_input(job: Job) -> RunnerInput:
        if job.harness is None:
            raise RunnerInputDigestMismatch(
                f"pending Runner task for {job.job_id} has no harness")
        return RunnerInput(
            job_id=job.job_id, harness_ref=job.harness.harness_ref,
            execution_harness_id=job.harness.execution_harness_id)

    def _migrate_runner_input_digest(self, job: Job) -> bool:
        """Commit an authenticated legacy-to-canonical digest transition.

        Returns true when the transition was committed.  Its normal
        post-commit dispatch performs the Runner side effect, so the caller
        must stop rather than submit a second time.
        """

        pending = job.pending_task
        if pending is None or pending.kind is not TaskKind.RUNNER or \
                pending.runner_input is not None:
            return False
        task_input = self._runner_input(job)
        canonical = runner_input_digest(task_input)
        if pending.input_digest == canonical:
            return False
        legacy = legacy_runner_input_digest(task_input)
        if pending.input_digest != legacy:
            raise RunnerInputDigestMismatch(
                f"pending Runner task {pending.task_id} has an "
                "unauthenticated input digest")
        out = self._apply(job.job_id, ev.RunnerInputDigestMigrated(
            task_id=pending.task_id, legacy_digest=legacy,
            canonical_digest=canonical))
        if out is None:
            raise RunnerInputDigestMismatch(
                f"pending Runner task {pending.task_id} migration refused")
        return True

    @classmethod
    def _replay_job_matches(cls, actual: Job, stored: Job) -> bool:
        """Compare a replay result, recognizing exact historical encodings.

        A pre-pin Agent task omitted model_policy and hashed only its other
        inputs. Authenticate both digests against the replayed inputs before
        normalizing those two fields. Explicit null or a different policy is
        not that historical encoding. Every other field must match exactly.
        """

        if actual == stored:
            return True
        actual_pending = actual.pending_task
        stored_pending = stored.pending_task
        if actual_pending is None or stored_pending is None or \
                actual_pending.kind is not stored_pending.kind:
            return False
        if actual_pending.kind is TaskKind.AGENT:
            if "model_policy" in stored_pending.model_fields_set or \
                    actual_pending.model_policy is None or \
                    actual.candidate is None or actual.binding is None:
                return False
            inputs = dict(
                agent_task=actual_pending.agent_task,
                model_policy=actual_pending.model_policy,
                candidate=actual.candidate,
                hcap_revision=actual.binding.hcap_revision,
                analysis_ref=actual.analysis_ref,
                plan_ref=actual.plan_ref,
                repair=actual_pending.repair)
            if actual_pending.input_digest != agent_input_digest(**inputs) or \
                    stored_pending.input_digest != agent_input_digest(
                        **inputs, include_model_policy=False):
                return False
            reproduced = actual.model_copy(update={
                "pending_task": actual_pending.model_copy(update={
                    "input_digest": stored_pending.input_digest,
                    "model_policy": None,
                }),
            })
            return reproduced == stored
        if actual_pending.kind is not TaskKind.RUNNER:
            return False
        task_input = cls._runner_input(actual)
        if actual_pending.input_digest != runner_input_digest(task_input) or \
                stored_pending.input_digest != \
                legacy_runner_input_digest(task_input):
            return False
        reproduced = actual.model_copy(update={
            "pending_task": actual_pending.model_copy(update={
                "input_digest": stored_pending.input_digest,
            }),
        })
        return reproduced == stored

    @staticmethod
    def _model_policy_for(policy, agent_task: AgentTask):
        if agent_task is AgentTask.CANDIDATE_ANALYSIS:
            return policy.stage1_agents.candidate_analysis
        if agent_task is AgentTask.REACHABILITY_PLANNING:
            return policy.stage1_agents.reachability_planning
        if agent_task is AgentTask.MUTATION_STRATEGY:
            return policy.stage2_agents.mutation_strategy
        raise LegacyTaskPolicyUnavailable(
            f"no model policy for legacy task {agent_task}")

    def _legacy_model_policy(self, job: Job, pending):
        """Recover a pre-pin task from the transition that minted its ID.

        Policies are immutable by ID.  The first transition containing this
        task therefore supplies the historical policy, while the task digest
        authenticates both the modern and pre-model-policy input encodings.
        Consulting the job's current policy here would reinterpret the same
        logical task after a same-sanitizer policy update.
        """

        for transition in self.store.transitions(job.job_id):
            snapshot = transition.job
            historical = snapshot.pending_task
            if historical is None or historical.kind is not TaskKind.AGENT or \
                    historical.task_id != pending.task_id:
                continue
            if historical.agent_task is not pending.agent_task or \
                    historical.input_digest != pending.input_digest or \
                    snapshot.candidate is None or snapshot.binding is None:
                break
            try:
                policy = self.store.policy(transition.job_policy_id)
                model_policy = self._model_policy_for(
                    policy, historical.agent_task)
                common = dict(
                    agent_task=historical.agent_task,
                    model_policy=model_policy,
                    candidate=snapshot.candidate,
                    hcap_revision=snapshot.binding.hcap_revision,
                    analysis_ref=snapshot.analysis_ref,
                    plan_ref=snapshot.plan_ref,
                    repair=historical.repair)
                valid = {
                    agent_input_digest(**common),
                    agent_input_digest(
                        **common, include_model_policy=False),
                }
            except (KeyError, TypeError, ValueError):
                break
            if pending.input_digest in valid:
                return model_policy
            break
        raise LegacyTaskPolicyUnavailable(
            f"legacy task {pending.task_id} has no authenticated policy pin")

    def _cancel(self, job_id: str, task_id: str) -> None:
        st = self.runner.cancel(task_id)
        if st.state in FINAL:
            self._confirm_cancel(job_id, task_id, st)

    def _take_status(self, job_id: str, task_id: str, st) -> None:
        self._take_bundles(job_id, task_id, st)
        if st.state in FINAL:
            job = self.store.job(job_id)
            stage2 = job.state in (JobState.S2_GATE, JobState.S2_CAMPAIGN)
            self._apply(job_id, ev.RunnerFinished(
                task_id=task_id, state=st.state,
                bundle_ref=st.bundles[-1] if st.bundles and
                st.state == "sealed" else None, reason=st.reason,
                bundle_refs=tuple(st.bundles) if stage2 else ()))

    def _take_bundles(self, job_id: str, task_id: str, st) -> None:
        """Hand a campaign task's bundles to the job in order, each once
        (09 §8).  A transition can stop the campaign and settle the task
        in between; the job's cursor says what is still to take."""
        while True:
            job = self.store.job(job_id)
            cursor = next((x for x in job.bundle_cursors
                           if x.task_id == task_id), None)
            if cursor is None or cursor.delivered >= len(st.bundles):
                return
            if self._apply(job_id, ev.RunnerBundleSealed(
                    task_id=task_id, index=cursor.delivered,
                    bundle_ref=st.bundles[cursor.delivered])) is None:
                return


def job_of(task_id: str) -> str:
    return task_id.rsplit(".t", 1)[0]
