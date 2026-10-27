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
                         CandidateSubmission, GapClass, GapRef,
                         HarnessBinding, JudgeVersions, LocationRequest,
                         VulnerabilityCandidate)
from ..intake import IntakeRejected, SourceTree, validate
from . import events as ev
from .generation import (ACTIVE, GenerationAttempt, GenerationDriver,
                         GenerationOutput, GenerationState,
                         HarnessGeneration, HarnessGenerator,
                         HarnessValidator, generation_of)
from .promotion import (OPEN, REJECTABLE, ArtifactPromotionInputs, HarnessPromotion,
                        ProbeCampaigner, PromotionDriver, PromotionInputs,
                        PromotionState, approve, issue_resolved,
                        new_promotion, on_registry, reject, retry)
from .machine import Env, Machine, Outcome, harness_authority_stale
from .records import (GAP_STATES, TERMINAL, AgentAttempt, Job, JobState,
                      RepairInput, SeedPlan, TaskKind, Transition)
from .store import StaleIssueEvent, Store
from .tasks import (CLEANUP_UNCONFIRMED, AgentExecutor, AgentRequest, Runner,
                    RunnerInput,
                    agent_input_digest, legacy_runner_input_digest,
                    runner_input_digest)

FINAL = ("sealed", "ended_unsealed")
#: A job past the end of Stage 1: where a person decides the promotion of
#: the staged harness it ran on (07 §5.3).
STAGE1_ENDED = TERMINAL | {JobState.S1_REACHED, JobState.S2_STRATEGY,
                           JobState.S2_GATE, JobState.S2_CAMPAIGN,
                           JobState.S2_REPLAYING, JobState.CRASH_REVIEW}
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
                 generator: HarnessGenerator | None = None,
                 validator: HarnessValidator | None = None,
                 campaigner: ProbeCampaigner | None = None,
                 promotion_inputs: PromotionInputs | None = None
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
        self.failures: list[EffectFailure] = []
        #: 09 §3.2.  None until a Harness Generation Agent and a validation
        #: Runner are configured; a gap then ends generation_unavailable.
        self.generations = None if generator is None or validator is None \
            else GenerationDriver(store, generator, validator, clock=clock,
                                  on_end=self._generation_ended)
        #: 07 §5.3.  None until a probe campaign Runner is configured: a
        #: passed generation's staged binding then stays unpromoted.
        self.promotions = None if self.generations is None or \
            campaigner is None else PromotionDriver(
                store, campaigner, clock=clock,
                on_end=self._promotion_ended)
        self.promotion_inputs = promotion_inputs or \
            ArtifactPromotionInputs(artifacts)

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

    def submit(self, submission: CandidateSubmission, policy_id: str, *,
               seed: SeedPlan | None = None) -> str:
        """Register the candidate and start a job for it.  A submission
        intake refuses still gets a job, which ends rejected (09 §3)."""
        self.store.policy(policy_id)            # must exist
        job = Job(job_id=f"job-{self.new_id()}", submission=submission,
                  job_policy_id=policy_id, seed=seed)
        self.store.create(job, Transition(
            job_id=job.job_id, seq=0, from_state=None, to_state=job.state,
            reason="submitted", event={"type": "submitted"},
            job_policy_id=policy_id, at=self.clock(), job=job))
        self._intake(job.job_id)
        return job.job_id

    def seed(self, job_id: str, policy_id: str) -> str:
        """#81 R5: a new job for ``job_id``'s candidate under another
        policy (another sanitizer), started from its plan instead of
        Analysis and Planning.  The plan is re-validated against the new
        binding's HCAP before it is materialized."""
        src = self.store.job(job_id)
        if src.candidate is None or src.analysis_ref is None or \
                src.plan_ref is None:
            raise ValueError(f"{job_id} has no plan to seed a job with")
        return self.submit(src.submission, policy_id, seed=SeedPlan(
            from_job=job_id, analysis_ref=src.analysis_ref,
            plan_ref=src.plan_ref))

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

    def on_generation_result(self, task_id: str, attempt: int,
                             output: GenerationOutput) -> None:
        """A Harness Generation Agent answer (09 §3.2).  Only the
        generation's current try makes a step."""
        gid = generation_of(task_id)
        self._guard(gid, "generation_result", lambda:
                    self.generations.on_result(task_id, attempt, output))

    def on_generation_failure(self, task_id: str, attempt: int,
                              failure: str) -> None:
        gid = generation_of(task_id)
        self._guard(gid, "generation_result", lambda:
                    self.generations.on_failure(task_id, attempt, failure))

    def retry_generation(self, job_id: str) -> Outcome | None:
        """09 §3.2: an operator starts Harness Generation of the job's gap
        again, with a new budget, on blocked_harness_gap or parked."""
        return self.operator(job_id, "retry_generation")

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
        for job in self.store.jobs(set(GAP_STATES)):
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
        binding up again (09 §5).  An approved promotion the new registry
        carries ends promoted first."""
        if self.promotions is not None:
            for p in self.store.promotions({PromotionState.APPROVED}):
                self._guard(p.promotion_id, "promotion",
                            lambda i=p.promotion_id: self._promoted(i))
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
        """09 §4: an operator starts Stage 2 of a job in s1_reached.  Unless
        JobPolicy.campaign_mode is mutate this is the only way in."""
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
        if self.generations is not None:
            for g in self.store.generations(set(ACTIVE)):
                self._guard(g.generation_id, "generation",
                            lambda i=g.generation_id:
                            self.generations.poll(i))
        self._poll_promotions()
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
        self._guard(job_id, "fixed_attempts",
                    lambda: self._attempts(job_id, poll=True))
        self._guard(job_id, "rebind", lambda: self._retry_rebind(job_id))
        self._guard(job_id, "generation",
                    lambda: self._join_generation(job_id))

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
        if self.generations is not None:
            for g in self.store.generations(set(ACTIVE)):
                self._guard(g.generation_id, "generation",
                            lambda i=g.generation_id:
                            self.generations.recover(i))
        self._poll_promotions(recover=True)
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
        self._guard(job_id, "link_issue",
                    lambda: self._link_gap(self.store.job(job_id)))
        job = self.store.job(job_id)
        p = job.pending_task
        self._attempts(job_id)
        if p is None:
            if job.state is JobState.SUBMITTED:
                self._intake(job_id)
            elif job.state is JobState.RETRY_PENDING:
                self._rebind(job)
            elif job.state is JobState.HARNESS_GENERATING:
                self._join_generation(job_id)
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
        binding = self._binding_for(job)
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
        b = self._binding_for(job)
        self._apply(job.job_id, ev.BindingChanged(
            binding=b, judge_versions=self._versions_for(b),
            rematerialize_authority=True,
            harness_authority_current=self._authority_current(job, b)))

    def _binding_for(self, job: Job) -> HarnessBinding | None:
        """The registry's binding for the job's build key, or the staged
        binding a passed generation gave the job while the registry still
        has the binding that generation started from (09 §3.2).  A registry
        change (a promotion, a new build) moves the job to the registry."""
        policy = self.store.policy(job.job_policy_id)
        b = self.registry.lookup(job.candidate.kernel_commit,
                                 policy.sanitizer)
        s = job.staged
        if s is not None and s.binding.sanitizer is policy.sanitizer and \
                self.store.generation(s.generation_id).base_binding == b \
                and not self._promotion_rejected(s.generation_id):
            return s.binding
        return b

    def _promotion_rejected(self, generation_id: str) -> bool:
        p = self.store.promotion_for(generation_id)
        return p is not None and p.state is PromotionState.REJECTED

    # ------------------------------------------------------------ generation

    def _join_generation(self, job_id: str) -> None:
        """09 §3.2, the gap rows: a job in harness_generating takes the
        result of its gap key's generation, starting one when there is none,
        when the operator asked to retry the one that refused it, or when the
        passed one started from a binding the registry no longer has.
        Idempotent, so poll() and recover() send it again."""
        job = self.store.job(job_id)
        if job.state is not JobState.HARNESS_GENERATING or job.gap is None:
            return
        policy = self.store.policy(job.job_policy_id)
        if self.generations is None or not policy.harness_generation_budget:
            self._apply(job_id, ev.GenerationEnded(
                gap=job.gap, outcome="unavailable",
                reason="no_generator" if self.generations is None
                else "policy"))
            return
        commit = job.candidate.kernel_commit
        base = self.registry.lookup(commit, policy.sanitizer)
        g = self.store.latest_generation(job.gap, commit, policy.sanitizer)
        if g is None or g.generation_id == job.generation_retry or (
                g.state is GenerationState.PASSED and
                g.base_binding != base):
            g = self._start_generation(job, policy, base, g)
        if g.state in ACTIVE:
            return
        if g.state is GenerationState.PASSED and \
                self._promotion_rejected(g.generation_id):
            self._apply(job_id, ev.GenerationEnded(
                gap=job.gap, generation_id=g.generation_id,
                outcome="promotion_rejected", reason="review_rejected"))
            return
        if g.state is GenerationState.PASSED and \
                job.binding == g.staged_binding:
            self._apply(job_id, ev.GenerationEnded(
                gap=job.gap, generation_id=g.generation_id,
                outcome="not_filled", reason="staged_binding_still_gapped"))
            return
        out = self._apply(job_id, ev.GenerationEnded(
            gap=job.gap, generation_id=g.generation_id, outcome=g.state.value,
            binding=g.staged_binding, reason=g.reason))
        if out is not None and out.job.state is JobState.RETRY_PENDING:
            self._rebind(out.job)

    def _start_generation(self, job: Job, policy, base: HarnessBinding | None,
                          latest: HarnessGeneration | None
                          ) -> HarnessGeneration:
        gid = f"gen-{self.new_id()}"
        g = self.generations.create(HarnessGeneration(
            generation_id=gid, gap=job.gap,
            kernel_commit=job.candidate.kernel_commit,
            sanitizer=policy.sanitizer, base_binding=base,
            origin_job=job.job_id, candidate=job.candidate,
            analysis_ref=job.analysis_ref, proposal_ref=job.gap_proposal_ref,
            model_policy=policy.harness_generation_agent,
            budget=policy.harness_generation_budget,
            agent_retry_limit=policy.agent_retry_limit,
            runtime_retry_limit=policy.runtime_retry_limit,
            attempts=(GenerationAttempt(number=1,
                                        agent_task_id=f"{gid}.a1"),)),
            after=latest.generation_id if latest else None)
        if g.generation_id == gid:
            # A failed send stays due; poll() sends a new try.
            self._guard(gid, "generation",
                        lambda: self.generations.dispatch(gid))
        return self.store.generation(g.generation_id)

    def _generation_ended(self, g: HarnessGeneration) -> None:
        """Every job waiting on the generation's key takes its end.  A
        passed one's staged harness goes to promotion (07 §5.3); a Stage 2
        gap's promotion is the M7 gate's, not a probe campaign's."""
        if g.state is GenerationState.PASSED and \
                self.promotions is not None and \
                g.gap.gap_class is not GapClass.MUTATION_ENGINE:
            self._guard(g.generation_id, "promotion",
                        lambda: self._create_promotion(g))
        for job in self.store.jobs({JobState.HARNESS_GENERATING}):
            if job.gap == g.gap and job.candidate is not None and \
                    job.candidate.kernel_commit == g.kernel_commit:
                self._guard(job.job_id, "generation",
                            lambda j=job.job_id: self._join_generation(j))

    # ------------------------------------------------------------ promotion

    def approve_promotion(self, promotion_id: str, decision_id: str,
                          note: str = "") -> HarnessPromotion:
        """07 §5.3: a person approves the evidence of a promotion in
        review, at the end of Stage 1 of a job on its staged harness.  The
        host then promotes; the registry change ends it."""
        jobs = self._stage1_ended(promotion_id)
        return self._decide(promotion_id, lambda p: approve(
            p, decision_id, note, self.clock(), jobs), "approved",
            decision_id)

    def reject_promotion(self, promotion_id: str, decision_id: str,
                         note: str = "") -> HarnessPromotion:
        """07 §5.3, at a Stage 1 end as approve_promotion: the jobs leave
        the staged binding and meet the gap again."""
        jobs = self._stage1_ended(promotion_id)
        return self._decide(promotion_id, lambda p: reject(
            p, decision_id, note, self.clock(), jobs), "rejected",
            decision_id)

    def promotion_due(self, job: Job) -> HarnessPromotion | None:
        """The promotion a person decides with this job's Stage 1 end: the
        job ran on its staged harness, reached the end of Stage 1, and the
        promotion waits on a decision."""
        if self.promotions is None or job.staged is None or \
                job.state not in STAGE1_ENDED:
            return None
        p = self.store.promotion_for(job.staged.generation_id)
        if p is None or p.state not in (PromotionState.REVIEW, *REJECTABLE):
            return None
        return p

    def _stage1_ended(self, promotion_id: str) -> tuple[str, ...]:
        """The jobs on the promotion's staged harness at the end of Stage
        1.  A person decides a promotion only there, never in the middle of
        a stage (user decision 2026-10-27)."""
        p = self.store.promotion(promotion_id)
        jobs = tuple(sorted(
            j.job_id for j in self.store.jobs(set(STAGE1_ENDED))
            if j.staged is not None and
            j.staged.generation_id == p.generation_id))
        if not jobs:
            raise ValueError(f"{promotion_id}: no job on its staged harness "
                             "has reached the end of Stage 1")
        return jobs

    def retry_promotion(self, promotion_id: str) -> HarnessPromotion:
        """Run the campaigns of a promotion not met or failed again."""
        return self._decide(promotion_id, retry, "retried", None)

    def _decide(self, promotion_id: str, reduce, kind: str,
                decision_id: str | None) -> HarnessPromotion:
        if self.promotions is None:
            raise ValueError("no probe campaign Runner is configured")
        before = self.store.promotion(promotion_id)
        if not self.promotions.step(promotion_id, reduce, {
                "type": kind, "decision_id": decision_id}, send=False):
            raise ValueError(f"{promotion_id} is {before.state.value}")
        # Committed: a failed send (a one-shot command) is sent by poll().
        self._guard(promotion_id, "promotion",
                    lambda: self.promotions.dispatch(promotion_id))
        return self.store.promotion(promotion_id)

    def _create_promotion(self, g: HarnessGeneration) -> None:
        if self.store.promotion_for(g.generation_id) is None:
            self.promotions.create(new_promotion(
                g, self.promotion_inputs.capabilities(g)))

    def _poll_promotions(self, recover: bool = False) -> None:
        """Create the promotion a lost call left out, take the candidate
        programs, ask the campaigns, look for the promoted registry
        binding and resolve the issue of a promoted one."""
        if self.promotions is None:
            return
        for g in self.store.generations({GenerationState.PASSED}):
            if g.gap.gap_class is not GapClass.MUTATION_ENGINE:
                self._guard(g.generation_id, "promotion",
                            lambda x=g: self._create_promotion(x))
        for p in self.store.promotions():
            if p.state in OPEN:
                self._guard(p.promotion_id, "promotion",
                            lambda i=p.promotion_id:
                            self._poll_promotion(i, recover))
            elif p.state is PromotionState.PROMOTED and \
                    not p.issue_resolved:
                self._guard(p.promotion_id, "promotion",
                            lambda x=p: self._resolve_issue(x))

    def _poll_promotion(self, promotion_id: str, recover: bool) -> None:
        programs, waiting = self._candidate_programs(
            self.store.promotion(promotion_id))
        self.promotions.programs(promotion_id, programs, waiting)
        if recover:
            self.promotions.dispatch(promotion_id)
        else:
            self.promotions.poll(promotion_id)
        self._promoted(promotion_id)

    def _candidate_programs(self, p: HarnessPromotion
                            ) -> tuple[set[str], bool]:
        """The plan programs of the jobs on the staged binding, and whether
        a live one there has no plan yet."""
        programs, waiting = set(), False
        for job in self.store.jobs():
            if job.staged is None or \
                    job.staged.generation_id != p.generation_id:
                continue
            if job.plan_ref is None:
                waiting = waiting or job.state not in TERMINAL
            else:
                programs.update(self.promotion_inputs.programs(job.plan_ref))
        return programs, waiting

    def _promoted(self, promotion_id: str) -> None:
        p = self.store.promotion(promotion_id)
        if p.state is not PromotionState.APPROVED:
            return
        b = self.registry.lookup(p.kernel_commit, p.sanitizer)
        carried = b is not None and all(
            c.evidence_ref is not None and self.promotion_inputs.carries(
                b, c.capability_id, c.evidence_ref)
            for c in p.capabilities)
        self.promotions.step(promotion_id,
                             lambda x: on_registry(x, carried),
                             {"type": "registry", "binding": None if b is None
                              else b.model_dump(mode="json")})

    def _promotion_ended(self, p: HarnessPromotion) -> None:
        if p.state is PromotionState.PROMOTED:
            self._guard(p.promotion_id, "promotion",
                        lambda: self._resolve_issue(p))
        elif p.state is PromotionState.REJECTED:
            # 09 §5: off the staged binding, back to the registry's.
            for job in list(self.store.jobs()):
                if job.staged is not None and \
                        job.staged.generation_id == p.generation_id:
                    self._guard(job.job_id, "rebind",
                                lambda j=job.job_id:
                                self._reconcile_registry(j))
                elif job.state is JobState.HARNESS_GENERATING:
                    self._guard(job.job_id, "generation",
                                lambda j=job.job_id:
                                self._join_generation(j))

    def _resolve_issue(self, p: HarnessPromotion) -> None:
        """07 §5.3: a promotion resolves its gap's issue.  A tracker that
        records status events gets one (the service delivers it);
        otherwise the jobs on the issue take it here.  Sent again by poll()
        until recorded."""
        issue = self.store.issue_ref(p.gap)
        resolution = f"promoted:{p.promotion_id}"
        change = getattr(self.issues, "change", None)
        if issue is not None and change is not None:
            change(issue, "resolved", resolution)
        else:
            self.on_issue(p.gap, "resolved", resolution, issue=issue)
        self.promotions.step(p.promotion_id, issue_resolved,
                             {"type": "issue_resolved", "issue": issue})

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
        if new.state is JobState.HARNESS_GENERATING:
            self._guard(j, "generation", lambda: self._join_generation(j))

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
        if job.state in GAP_STATES and job.gap is not None and \
                not self.store.is_linked(job.job_id, job.gap):
            self.store.link_issue(job.gap, self.issues.open_or_link(
                job.gap, job.job_id), job.job_id)

    def _attempts(self, job_id: str, poll: bool = False) -> None:
        """09 §3.1: send each fixed attempt in flight (idempotent by
        task_id), or with `poll` ask for it first, and take a final one."""
        job = self.store.job(job_id)
        if job.state is not JobState.S1_FIXED or job.fixed is None:
            return
        for a in job.fixed.in_flight:
            job = self.store.job(job_id)
            if job.cancelling_tasks or job.fixed is None or \
                    a not in job.fixed.in_flight:
                continue
            st = self.runner.status(a.task_id) if poll else None
            if st is None or st.state == "unknown":
                st = self.runner.submit(a.task_id, self._runner_input(job))
            self._take_status(job_id, a.task_id, st)

    def _dispatch(self, job_id: str) -> None:
        job = self.store.job(job_id)
        p = job.pending_task
        if p is None:
            self._attempts(job_id)
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
