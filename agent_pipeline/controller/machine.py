"""The job state machine (09 §2-§6): Stage 1 and Stage 2.

handle(job, event) is a function of the job, the event, the job's JobPolicy
and the deterministic components.  It returns the next job and what the
transition consumed, or None when the event makes no transition (a stale
result, an action the state does not take).  It sends nothing: the service
commits the transition, then sends the tasks it names (09 §8).

Routing reads only verdict status and reason, typed refusal reasons and the
Agent output variant (09 §2).  A value the tables do not name goes to
blocked_operator(unexpected_event); nothing is mapped to the nearest row.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..components import (HcapChecker, Materializer, MutationRuleCompiler,
                          Q1Judge, Stage2Judge)
from ..crash import signature
from ..contracts import (COMPILER_AGENT_FIXABLE, COMPILER_GAP,
                         HOST_AUTHORITY_UNAVAILABLE, M1_STATUSES,
                         Q2_STATUSES, REPLAY_EVIDENCE_REJECTED,
                         REPLAY_STATUSES, CampaignSegment, CompiledRuleSet,
                         GateRun, HcapCheck,
                         NEUTRAL_CONTROL_UNAVAILABLE, TASK_VARIANTS, AgentTask,
                         CampaignMode, GapClass, GapRef, HarnessBinding,
                         JobPolicy, STATE_LINEAGE_GAP_ID,
                         MaterializationHcapAuthority, MaterializeRejected,
                         Q1Result, Q1Status, kernel_revision_gap)
from . import events as ev
from .records import (GAP_STATES, HOLDING, STAGE2_CAUSES, TERMINAL,
                      BlockedReason, StagedHarness,
                      BundleCursor, Campaign, CampaignTally, ConsumedVerdict,
                      AttemptTask, CrashFinding, CrashRef, FixedCampaign,
                      Job, JobState, PendingTask, RepairCause, RepairInput,
                      Replay, ReplayRun, S1Replay, Stage2Input, Target,
                      TargetKind, TaskKind, TriageItem)
from .tasks import (CLEANUP_UNCONFIRMED, RunnerInput, agent_input_digest,
                    legacy_runner_input_digest, runner_input_digest)

AGENT_STATES = {JobState.S1_ANALYSIS: AgentTask.CANDIDATE_ANALYSIS,
                JobState.S1_PLANNING: AgentTask.REACHABILITY_PLANNING,
                JobState.S2_STRATEGY: AgentTask.MUTATION_STRATEGY}
AGENT_KINDS = {AgentTask.CANDIDATE_ANALYSIS: TargetKind.ANALYSIS,
               AgentTask.REACHABILITY_PLANNING: TargetKind.PLANNING,
               AgentTask.MUTATION_STRATEGY: TargetKind.STRATEGY}
TASK_OF_KIND = {k: t for t, k in AGENT_KINDS.items()}
STATE_OF_TASK = {t: s for s, t in AGENT_STATES.items()}
WAITING_KINDS = {TargetKind.BLOCKED_OPERATOR, TargetKind.BLOCKED_HARNESS_GAP}
#: States that wait on a Runner task, and the target that re-enters each.
RUNNER_STATES = {JobState.S1_RUNNING: TargetKind.RUNNING,
                 JobState.S1_FIXED: TargetKind.FIXED,
                 JobState.S1_REPLAYING: TargetKind.S1_REPLAY,
                 JobState.S2_GATE: TargetKind.GATE,
                 JobState.S2_CAMPAIGN: TargetKind.CAMPAIGN,
                 JobState.S2_REPLAYING: TargetKind.REPLAY}
RERUN_KINDS = frozenset(RUNNER_STATES.values())
#: Mutation Strategy repairs a campaign stop starts; a late APPLIED crash of
#: that campaign stops them for review (01 §12).
CAMPAIGN_REPAIRS = frozenset({RepairCause.CAMPAIGN_NOT_APPLIED,
                              RepairCause.CAMPAIGN_NO_SIGNAL})

#: Counter an operator `resume` puts back to 0 (09 §5, §6).
RESET_ON_RESUME = {
    BlockedReason.STAGE1_REPAIR_BUDGET: "agent_repair_stage1",
    BlockedReason.STAGE2_REPAIR_BUDGET: "agent_repair_stage2",
    BlockedReason.AGENT_FAILURE: "agent_retry",
    BlockedReason.RUNTIME_RETRY_EXHAUSTED: "runtime_retry",
}
#: Campaign tally counts an operator `resume` puts back to 0: the count
#: that stopped the campaign would otherwise stop it again at once.
TALLY_RESET_ON_RESUME = {
    BlockedReason.EVIDENCE_PATH: "hypothesis_inconclusive",
    BlockedReason.CAMPAIGN_BUDGET_EXHAUSTED: "executions",
}


def _plan_check_target(chk: HcapCheck, cause: RepairCause) -> Target:
    """A failed plan check: Agent repair, unless the host catalog itself is
    corrupt, which no plan change can fix (no LLM repair, no charge)."""
    if chk.host_authority:
        return Target(kind=TargetKind.BLOCKED_OPERATOR,
                      reason=BlockedReason.HOST_AUTHORITY,
                      inner=Target(kind=TargetKind.MATERIALIZE))
    return Target(kind=TargetKind.PLANNING, cause=cause,
                  findings=chk.violations)


def harness_authority_stale(j: Job, binding: HarnessBinding | None) -> bool:
    """The job's harness was neither built nor re-validated under
    `binding`'s HCAP revision."""
    if binding is None or j.harness is None:
        return False
    h = j.harness
    return binding.hcap_revision not in (h.hcap_revision,
                                         h.authority_hcap_revision)


@dataclass
class Env:
    policy: Callable[[str], JobPolicy]
    hcap: HcapChecker
    materializer: Materializer
    judge: Q1Judge
    #: None until a Mutation Rule Compiler is configured; a rule set then
    #: waits in blocked_operator(stage2_compiler_unavailable).
    compiler: MutationRuleCompiler | None = None
    #: None until a Stage 2 execution backend (Runner steps and their
    #: judges) is configured; a compiled rule set then waits in
    #: blocked_operator(stage2_gate_unavailable).
    stage2: Stage2Judge | None = None


@dataclass
class Outcome:
    job: Job
    reason: str | None
    consumed: list[str]
    verdicts: list[Q1Result]
    abandoned_attempt: tuple[str, int] | None


@dataclass
class _Call:
    job: Job
    policy: JobPolicy
    reason: str | None = None
    consumed: list[str] = field(default_factory=list)
    verdicts: list[Q1Result] = field(default_factory=list)
    abandoned: tuple[str, int] | None = None
    #: The gap of this call's unsupported answer, which its proposal explains.
    proposed_gap: GapRef | None = None


class Machine:
    def __init__(self, env: Env) -> None:
        self.env = env

    # ------------------------------------------------------------ entry

    def handle(self, job: Job, event) -> Outcome | None:
        j = job.model_copy(deep=True)
        if j.state in TERMINAL and not isinstance(
                event, (ev.RunnerFinished, ev.CancelConfirmed,
                        ev.CleanupUnconfirmed, ev.RunnerBundleSealed)):
            return None
        c = _Call(j, self.env.policy(j.job_policy_id))
        if not getattr(self, "_on_" + event.type)(c, event):
            return None
        if j.state is not JobState.S1_REACHED:
            j.stage2_input = None
        if j.s1_replay is not None and not self._in_s1_replay(j):
            self._abandon_s1_replay(j)
        if j.staged is not None and j.state is not JobState.RETRY_PENDING \
                and j.binding != j.staged.binding:
            j.staged = None
        if j.state not in GAP_STATES:
            j.generation_refused = None
            j.generation_retry = None
        j.seq += 1
        return Outcome(j, c.reason, c.consumed, c.verdicts, c.abandoned)

    # ------------------------------------------------------------ events

    def _on_intake_checked(self, c: _Call, e: ev.IntakeChecked) -> bool:
        j = c.job
        if j.state is not JobState.SUBMITTED:
            return False
        j.judge_versions = e.judge_versions
        if e.rejection or e.candidate is None:
            j.state = JobState.REJECTED
            j.state_reason = e.rejection or "no_candidate"
            return True
        j.candidate = e.candidate
        start = Target(kind=TargetKind.ANALYSIS)
        if j.seed is not None:
            # #81 R5: the seeded plan, re-validated on this binding.
            j.analysis_ref = j.seed.analysis_ref
            j.plan_ref = j.seed.plan_ref
            start = Target(kind=TargetKind.MATERIALIZE)
        binding = self._usable(c, e.binding)
        if binding is None:
            self._goto(c, Target(kind=TargetKind.BLOCKED_HARNESS_GAP,
                                 gap=kernel_revision_gap(
                                     e.candidate.kernel_commit),
                                 inner=start))
        else:
            j.binding = binding
            if j.seed is not None:
                c.reason = "seeded_plan"
            self._goto(c, start)
        return True

    def _on_agent_succeeded(self, c: _Call, e: ev.AgentSucceeded) -> bool:
        j = c.job
        p = j.pending_task
        if not self._is_pending(p, TaskKind.AGENT, e.task_id, e.attempt):
            return False
        here = self._here(j)
        j.pending_task = None
        j.counters = j.counters.model_copy(update={"agent_retry": 0})
        out = e.output
        if out.variant not in TASK_VARIANTS[p.agent_task]:
            return self._unexpected(c, here)
        if out.variant == "analysis":
            j.analysis_ref = out.analysis_ref
            c.consumed.append(out.analysis_ref)
            self._goto(c, Target(kind=TargetKind.PLANNING))
        elif out.variant == "plan":
            j.plan_ref = out.plan_ref
            j.harness = None
            c.consumed.append(out.plan_ref)
            self._goto(c, self._materialize(c, require_revision=True))
        elif out.variant == "rule_set":
            j.rule_set_ref = out.rule_set_ref
            j.compiled = None
            c.consumed.append(out.rule_set_ref)
            self._goto(c, self._compile(c))
        elif out.variant == "unsupported":
            again = Target(kind=AGENT_KINDS[p.agent_task])
            if p.agent_task is AgentTask.MUTATION_STRATEGY and \
                    out.gap_class is not GapClass.MUTATION_ENGINE:
                # 09 §2: Mutation Strategy's gap is mutation_engine only.
                return self._unexpected(c, here)
            gap = GapRef(gap_class=out.gap_class,
                         missing_capability_id=out.missing_capability_id)
            # The latest answer's proposal, or none: never an older one.
            j.gap_proposal_ref = out.proposal_ref
            c.proposed_gap = gap
            if out.proposal_ref is not None:
                c.consumed.append(out.proposal_ref)
            if not out.missing_capability_id or \
                    not self.env.hcap.knows_capability(
                        j.binding.hcap_revision, out.missing_capability_id):
                self._block(c, BlockedReason.GAP_ID_UNKNOWN, again)
            else:
                self._goto(c, Target(kind=TargetKind.BLOCKED_HARNESS_GAP,
                                     gap=gap, inner=again))
        else:
            self._goto(c, Target(kind=TargetKind.ANALYSIS,
                                 cause=RepairCause.REANALYSIS_REQUESTED,
                                 findings=(out.reason,)))
        return True

    def _on_runner_input_digest_migrated(
            self, c: _Call, e: ev.RunnerInputDigestMigrated) -> bool:
        """Migrate exactly one authenticated legacy pending Runner task."""

        j = c.job
        p = j.pending_task
        if not self._is_pending(p, TaskKind.RUNNER, e.task_id) or \
                j.harness is None:
            return False
        task_input = RunnerInput(
            job_id=j.job_id, harness_ref=j.harness.harness_ref,
            execution_harness_id=j.harness.execution_harness_id)
        legacy = legacy_runner_input_digest(task_input)
        canonical = runner_input_digest(task_input)
        if legacy == canonical or p.input_digest != legacy or \
                e.legacy_digest != legacy or \
                e.canonical_digest != canonical:
            return False
        j.pending_task = p.model_copy(update={"input_digest": canonical})
        c.reason = "runner_input_digest_migrated"
        return True

    def _on_agent_failed(self, c: _Call, e: ev.AgentFailed) -> bool:
        j = c.job
        p = j.pending_task
        if not self._is_pending(p, TaskKind.AGENT, e.task_id, e.attempt):
            return False
        j.pending_task = None
        c.reason = "agent_failed"
        if j.counters.agent_retry >= c.policy.agent_retry_limit:
            # The same request again on resume, already charged.
            self._block(c, BlockedReason.AGENT_FAILURE,
                        self._agent_target(p, charged=True))
            return True
        j.counters = j.counters.model_copy(
            update={"agent_retry": j.counters.agent_retry + 1})
        self._start_agent(c, p.agent_task, p.repair, retry=True)
        return True

    def _on_agent_attempt_restarted(self, c: _Call,
                                    e: ev.AgentAttemptRestarted) -> bool:
        j = c.job
        p = j.pending_task
        if p is None or p.kind is not TaskKind.AGENT or \
                p.task_id != e.task_id or e.attempt <= p.attempt:
            return False
        c.abandoned = (p.task_id, p.attempt)
        j.pending_task = p.model_copy(update={"attempt": e.attempt})
        c.reason = "agent_attempt_restarted"
        return True

    def _on_runner_finished(self, c: _Call, e: ev.RunnerFinished) -> bool:
        j = c.job
        if e.task_id in j.cancelling_tasks:
            j.cancelling_tasks = tuple(t for t in j.cancelling_tasks
                                       if t != e.task_id)
            self._end_stream(j, e.task_id)
            c.reason = "cancel_settled"
            if e.reason == CLEANUP_UNCONFIRMED:
                self._cleanup_unconfirmed(c, e.task_id)
            return True
        if j.state is JobState.S1_FIXED and j.fixed is not None and \
                any(a.task_id == e.task_id for a in j.fixed.in_flight):
            return self._attempt_finished(c, e)
        p = j.pending_task
        if not self._is_pending(p, TaskKind.RUNNER, e.task_id) or \
                j.state not in RUNNER_STATES:
            return False
        j.pending_task = None
        cursor = self._end_stream(j, e.task_id)
        if e.reason == CLEANUP_UNCONFIRMED:
            # Not a runtime failure to retry: the execution may still run.
            self._cleanup_unconfirmed(c, e.task_id)
            return True
        if j.state is JobState.S2_GATE:
            return self._gate_finished(c, p, e)
        if j.state is JobState.S2_CAMPAIGN:
            return self._campaign_finished(c, cursor, e)
        if j.state is JobState.S2_REPLAYING:
            return self._replay_finished(c, e)
        if j.state is JobState.S1_REPLAYING:
            return self._s1_replay_finished(c, e)
        if e.state == "ended_unsealed" or not e.bundle_ref:
            c.reason = f"runner_ended_unsealed:{e.reason or ''}"
            self._goto(c, Target(kind=TargetKind.RUNNING, rerun=True))
            return True
        if not self.env.judge.matches_execution(e.bundle_ref, job_id=j.job_id,
                                                task_id=e.task_id):
            c.reason = "q1_execution_mismatch"
            self._block(c, BlockedReason.Q1_EVIDENCE,
                        Target(kind=TargetKind.RUNNING))
            return True
        r = self.env.judge.judge(e.bundle_ref, j.plan_ref,
                                 j.candidate.candidate_id, j.judge_versions)
        c.verdicts.append(r)
        c.consumed.append(r.verdict_id)
        j.last_verdict = ConsumedVerdict(result=r, bundle_ref=e.bundle_ref,
                                         binding=j.binding,
                                         plan_ref=j.plan_ref,
                                         harness_ref=j.harness.harness_ref)
        t = self._q1_target(c, r)
        i = self._add_finding(c, e, r)
        if i is not None:
            # #81 R2, R3: the crash does not stop the job.  It is replayed,
            # then the verdict routes the job (09 §3, §3.1).
            c.reason = "crash_finding"
            j.s1_replay = S1Replay(queue=(i,), after=t)
            self._goto(c, Target(kind=TargetKind.S1_REPLAY))
            return True
        self._goto(c, t)
        return True

    def _on_approval_given(self, c: _Call, e: ev.ApprovalGiven) -> bool:
        j = c.job
        if j.state is not JobState.S1_APPROVAL or \
                not self._is_pending(j.pending_task, TaskKind.HUMAN,
                                     e.task_id):
            return False
        c.consumed.append(e.decision_id)
        if e.review_manifest_sha256 != j.harness.review_manifest_sha256:
            # 09 §3: not an approval of this harness; keep waiting.
            c.reason = "approval_hash_mismatch"
            return True
        j.approved_manifests = j.approved_manifests + (
            e.review_manifest_sha256,)
        j.pending_task = None
        self._goto(c, Target(kind=TargetKind.RUNNING))
        return True

    def _on_approval_denied(self, c: _Call, e: ev.ApprovalDenied) -> bool:
        j = c.job
        if j.state is not JobState.S1_APPROVAL or \
                not self._is_pending(j.pending_task, TaskKind.HUMAN,
                                     e.task_id):
            return False
        j.pending_task = None
        self._goto(c, Target(kind=TargetKind.PLANNING,
                             cause=RepairCause.REVIEWER_DENIED,
                             findings=(e.note,)))
        return True

    def _on_issue_changed(self, c: _Call, e: ev.IssueChanged) -> bool:
        j = c.job
        if j.state not in GAP_STATES or j.gap != e.gap:
            return False
        c.reason = f"issue_{e.status}"
        if e.status == "resolved":
            # A generation in progress goes on for the other jobs of the
            # gap key (09 §3.2).
            j.state = JobState.RETRY_PENDING
        elif e.status == "deferred" and j.state is not JobState.PARKED:
            j.state = JobState.PARKED
        elif e.status == "reopened" and j.state is JobState.PARKED:
            j.state = JobState.BLOCKED_HARNESS_GAP
        elif e.status == "wont_fix":
            j.state = JobState.CLOSED_UNSUPPORTED
            j.state_reason = e.resolution or "wont_fix"
            j.resume_point = None
        else:
            return False
        return True

    def _on_binding_changed(self, c: _Call, e: ev.BindingChanged) -> bool:
        if c.job.state is JobState.SUBMITTED:
            return False
        # Events written before the authority-migration flag existed used the
        # old reduction order: assign judge versions, then rebind, without
        # re-judging an already consumed bundle. Preserve that exact behavior
        # for replay; all current producers explicitly set the flag.
        if "rematerialize_authority" not in e.model_fields_set:
            if e.judge_versions is not None:
                c.job.judge_versions = e.judge_versions
            return self._binding_change(c, e.binding)
        binding_changed = self._binding_change(
            c, e.binding,
            rematerialize_authority=e.rematerialize_authority,
            authority_current=e.harness_authority_current)
        versions_changed = e.judge_versions is not None and \
            e.judge_versions != c.job.judge_versions
        if versions_changed:
            self._change_judge_versions(
                c, e.judge_versions,
                set_reason=not binding_changed)
        return binding_changed or versions_changed

    def _binding_change(self, c: _Call, binding: HarnessBinding | None, *,
                        rematerialize_authority: bool = False,
                        authority_current: bool = False) -> bool:
        j = c.job
        new = self._usable(c, binding)
        if j.state is JobState.RETRY_PENDING:
            base = j.resume_point
            t = self._rebind(
                c, new, base,
                rematerialize_authority=rematerialize_authority,
                authority_current=authority_current)
            j.gap = None
            j.gap_proposal_ref = None
            j.resume_point = None
            c.reason = "rebind"
            self._goto(c, t)
            return True
        if new == j.binding and (not rematerialize_authority or
                                 not harness_authority_stale(j, new)):
            return False
        base = self._waiting_base(j) if j.state in HOLDING else None
        if j.state is JobState.S2_REPLAYING or (
                j.replay is not None and base is not None and
                base.kind is TargetKind.REPLAY):
            # 09 §5: the replay finishes on the crash's identity and its
            # recorded rule set; the new binding only moves where the
            # job goes after crash_review.
            j.replay = j.replay.model_copy(update={"resume": self._rebind(
                c, new, j.replay.resume,
                rematerialize_authority=rematerialize_authority,
                authority_current=authority_current)})
            c.reason = "binding_changed"
            return True
        if j.state in HOLDING:
            base = self._waiting_base(j)
            self._set_resume(c, self._rebind(
                c, new, base,
                rematerialize_authority=rematerialize_authority,
                authority_current=authority_current), base)
            c.reason = "binding_changed"
            return True
        old = j.binding
        here = self._here(j)
        c.reason = "binding_changed"
        if new is not None and old is not None and \
                new.execution_harness_id == old.execution_harness_id and \
                new.hcap_revision != old.hcap_revision and \
                not rematerialize_authority:
            # Preserve historical HCAP-only events exactly. A current
            # recovery detects their stale harness and emits a flagged,
            # same-binding BindingChanged migration.
            j.binding = new
            if j.state in AGENT_STATES:
                self._goto(c, self._agent_target(j.pending_task,
                                                 charged=True))
                return True
            if j.plan_ref:
                chk = self.env.hcap.revalidate_plan(j.plan_ref,
                                                    new.hcap_revision)
                if not chk.ok:
                    self._goto(c, _plan_check_target(
                        chk, RepairCause.HCAP_CHANGED))
            return True
        t = self._rebind(
            c, new, here,
            rematerialize_authority=rematerialize_authority,
            authority_current=authority_current)
        if t is not here or j.state in AGENT_STATES:
            # An Agent task is pinned to the HCAP revision and restarts.
            # Otherwise `here` itself means the job stays where it is
            # (09 §5); entering it again would restart a Runner task.
            self._goto(c, t)
        return True

    def _on_judge_versions_changed(self, c: _Call,
                                   e: ev.JudgeVersionsChanged) -> bool:
        return self._change_judge_versions(
            c, e.judge_versions,
            consume_same_verdict=e.consume_same_verdict)

    def _change_judge_versions(self, c: _Call, versions, *,
                               set_reason: bool = True,
                               consume_same_verdict: bool = True) -> bool:
        j = c.job
        j.judge_versions = versions
        if set_reason:
            c.reason = "judge_versions_changed"
        lv = j.last_verdict
        if lv is None or j.state is JobState.SUBMITTED:
            return True
        # Routes only under the binding the verdict was consumed with, and
        # only while the job still runs that plan and harness (09 §5).
        same_binding = lv.binding == j.binding and \
            lv.plan_ref == j.plan_ref and j.harness is not None and \
            lv.harness_ref == j.harness.harness_ref
        if not self.env.judge.has_required_evidence(lv.bundle_ref, versions):
            if not same_binding:
                return True
            t = Target(kind=TargetKind.RUNNING, rerun=True)
        else:
            r = self.env.judge.judge(lv.bundle_ref, lv.plan_ref,
                                     j.candidate.candidate_id,
                                     versions)
            c.verdicts.append(r)
            if not same_binding:
                return True
            previous_reason = c.reason
            old_target = self._q1_target(c, lv.result)
            c.reason = previous_reason
            new_target = self._q1_target(c, r)
            c.consumed.append(r.verdict_id)
            j.last_verdict = lv.model_copy(update={"result": r})
            # Consume the new authority's verdict even when its route is the
            # same.  A reached job must then expose the new verdict in its
            # Stage2Input instead of retaining the old authority's identity.
            same_decision = (r.status, r.reason, r.gap_signal) == \
                (lv.result.status, lv.result.reason, lv.result.gap_signal)
            if same_decision and old_target == new_target:
                if not consume_same_verdict:
                    # Historical reduction: only the versions changed.
                    c.consumed.pop()
                    c.verdicts.pop()
                    j.last_verdict = lv
                    return True
                if j.state is JobState.S1_REACHED:
                    self._goto(c, Target(kind=TargetKind.REACHED))
                elif j.stage2_basis is not None:
                    # Stage 2 works from the new authority's verdict too.
                    j.stage2_basis = j.stage2_basis.model_copy(
                        update={"q1_verdict_id": r.verdict_id})
                    p = j.pending_task
                    if j.state is JobState.S2_STRATEGY and p is not None:
                        # The basis is part of the task's logical input:
                        # reissue it, its repair already charged.
                        self._goto(c, self._agent_target(p, charged=True))
                return True
            t = new_target
            # A NOT_REACHED re-judge replaces the evidence embedded in the
            # current repair task.  Reissue that logical input without
            # charging the Stage 1 repair budget a second time.
            pending = j.pending_task
            if t.kind is TargetKind.PLANNING and \
                    j.state is JobState.S1_PLANNING and \
                    pending is not None and pending.kind is TaskKind.AGENT and \
                    pending.repair is not None and pending.repair.cause is \
                    RepairCause.Q1_NOT_REACHED:
                t = t.model_copy(update={"charged": True})
        # 09 §5, §6: a rerun this event asks for spends no budget, also
        # when it waits in a resume point first.
        t = self._external(t)
        if j.state is JobState.S2_REPLAYING:
            # The replay finishes; the re-judge decides where the job
            # goes after crash_review (09 §5).
            j.replay = j.replay.model_copy(update={"resume": t})
        elif j.state is JobState.S1_REPLAYING and \
                j.s1_replay.after is not None:
            # The crash's replay finishes; the re-judge decides the row
            # the run goes to after it (09 §3.1).
            j.s1_replay = j.s1_replay.model_copy(update={"after": t})
        elif j.state in HOLDING or j.state is JobState.RETRY_PENDING:
            self._set_resume(c, t, self._waiting_base(j))
        else:
            self._goto(c, t)
        return True

    @classmethod
    def _external(cls, t: Target) -> Target:
        if t.kind in RERUN_KINDS and t.rerun:
            return t.model_copy(update={"external": True})
        if t.inner is not None:
            return t.model_copy(update={"inner": cls._external(t.inner)})
        return t

    def _on_policy_changed(self, c: _Call, e: ev.PolicyChanged) -> bool:
        """Later transitions only (09 §5), but the binding belongs to the
        sanitizer the policy selects (01 §11.2): a sanitizer change is a
        binding change, with the binding the service looked up for it."""
        j = c.job
        if e.job_policy_id == j.job_policy_id:
            return False
        old = c.policy
        j.job_policy_id = e.job_policy_id
        c.policy = self.env.policy(e.job_policy_id)
        if c.policy.sanitizer is not old.sanitizer and \
                j.state is not JobState.SUBMITTED:
            if "rematerialize_authority" not in e.model_fields_set:
                if e.judge_versions is not None:
                    j.judge_versions = e.judge_versions
                self._binding_change(c, e.binding)
            else:
                self._binding_change(
                    c, e.binding,
                    rematerialize_authority=e.rematerialize_authority,
                    authority_current=e.harness_authority_current)
                if e.judge_versions is not None and \
                        e.judge_versions != j.judge_versions:
                    self._change_judge_versions(c, e.judge_versions,
                                                set_reason=False)
        c.reason = "policy_changed"
        return True

    def _on_operator(self, c: _Call, e: ev.OperatorAction) -> bool:
        j = c.job
        c.consumed.append(e.action_id)
        if e.action == "start_stage2":
            if j.state is not JobState.S1_REACHED:
                return False
            self._start_stage2(c)
            return True
        if e.action == "start_fixed":
            if j.state is not JobState.S1_REACHED:
                return False
            self._start_fixed(c)
            return True
        if e.action in ("route_gate", "route_strategy"):
            return self._route(c, e.action)
        if e.action == "retry_generation":
            if j.state not in (JobState.BLOCKED_HARNESS_GAP,
                               JobState.PARKED) or \
                    not c.policy.harness_generation_budget:
                return False
            # The service starts a new generation only when the latest one
            # of the gap key is the one that refused this job (09 §3.2).
            j.state = JobState.HARNESS_GENERATING
            j.generation_retry = j.generation_refused
            c.reason = "operator_retry_generation"
            return True
        if e.action == "resume" and j.state is JobState.CRASH_REVIEW:
            t = j.resume_point
            if t is None:
                return False
            j.resume_point = None
            j.state_reason = None
            c.reason = "operator_resume"
            if j.crash_queue:
                # 09 §4: an APPLIED crash that arrived during the review is
                # replayed and reviewed before the campaign goes on.
                crash, j.crash_queue = j.crash_queue[0], j.crash_queue[1:]
                self._enter_replay(c, crash, t)
            else:
                self._goto(c, t)
            return True
        if e.action == "resume":
            if j.state is not JobState.BLOCKED_OPERATOR:
                return False
            blocked = BlockedReason(j.state_reason)
            counter = RESET_ON_RESUME.get(blocked)
            if counter:
                j.counters = j.counters.model_copy(update={counter: 0})
            tally = TALLY_RESET_ON_RESUME.get(blocked)
            if tally and j.campaign is not None:
                j.campaign = j.campaign.model_copy(update={
                    "tally": j.campaign.tally.model_copy(
                        update={tally: 0})})
            if blocked is BlockedReason.FIXED_NOT_REACHING and \
                    j.fixed is not None:
                j.fixed = j.fixed.model_copy(
                    update={"consecutive_not_reached": 0})
            if blocked is BlockedReason.EXECUTION_CLEANUP:
                # The operator confirmed the executions are gone.
                j.uncleaned_tasks = ()
            t = j.resume_point
            if t is None:
                return False
            j.resume_point = None
            j.state_reason = None
            c.reason = "operator_resume"
            self._goto(c, t)
            return True
        if e.action not in ("close", "cancel"):
            return False
        reviewed = j.state is JobState.CRASH_REVIEW and e.action == "close"
        self._drop_task(c)
        j.state = JobState.CLOSED
        j.state_reason = "crash_reported" if reviewed else \
            "operator_closed" if e.action == "close" else "cancelled"
        j.resume_point = None
        c.reason = j.state_reason
        return True

    def _on_generation_ended(self, c: _Call, e: ev.GenerationEnded) -> bool:
        """09 §3.2.  A passed generation rebinds the job like a resolved
        issue (retry_pending), on the staged binding; any other end leaves
        it on the issue, with its resume_point."""
        j = c.job
        if j.state is not JobState.HARNESS_GENERATING or j.gap != e.gap:
            return False
        c.reason = f"generation_{e.outcome}"
        if e.outcome == "passed":
            if e.generation_id is None or self._usable(c, e.binding) is None:
                return self._unexpected(c, Target(
                    kind=TargetKind.BLOCKED_HARNESS_GAP, gap=j.gap,
                    inner=j.resume_point))
            j.state = JobState.RETRY_PENDING
            j.staged = StagedHarness(generation_id=e.generation_id,
                                     binding=e.binding)
            return True
        j.state = JobState.BLOCKED_HARNESS_GAP
        j.generation_refused = e.generation_id
        j.generation_retry = None
        return True

    def _on_cancel_confirmed(self, c: _Call, e: ev.CancelConfirmed) -> bool:
        j = c.job
        if e.task_id not in j.cancelling_tasks:
            return False
        j.cancelling_tasks = tuple(t for t in j.cancelling_tasks
                                   if t != e.task_id)
        self._end_stream(j, e.task_id)
        c.reason = "cancel_settled"
        if e.cleanup_unconfirmed:
            self._cleanup_unconfirmed(c, e.task_id)
        return True

    def _on_cleanup_unconfirmed(self, c: _Call,
                                e: ev.CleanupUnconfirmed) -> bool:
        j = c.job
        key = f"{e.task_id}:{e.generation}"
        if not e.task_id.startswith(j.job_id + ".t") or \
                key in j.cleanup_reports_applied:
            return False
        # Applied once, even after the operator confirmed this cleanup.
        j.cleanup_reports_applied = j.cleanup_reports_applied + (key,)
        j.cancelling_tasks = tuple(t for t in j.cancelling_tasks
                                   if t != e.task_id)
        if self._is_pending(j.pending_task, TaskKind.RUNNER, e.task_id):
            j.pending_task = None
        self._cleanup_unconfirmed(c, e.task_id)
        return True

    def _cleanup_unconfirmed(self, c: _Call, task_id: str) -> None:
        """A Runner task ended without confirmed cleanup (09 §8): keep it
        tracked and hand a live job to the operator.  A terminal job stays
        closed; its record still names the task."""
        j = c.job
        if task_id not in j.uncleaned_tasks:
            j.uncleaned_tasks = j.uncleaned_tasks + (task_id,)
        c.reason = "cleanup_unconfirmed"
        if j.state not in TERMINAL and j.state not in HOLDING:
            self._block(c, BlockedReason.EXECUTION_CLEANUP, self._here(j))

    # ------------------------------------------------------------ targets

    def _goto(self, c: _Call, t: Target, external: bool = False) -> None:
        j = c.job
        if not (t.kind in RERUN_KINDS and t.rerun) and \
                t.kind is not TargetKind.S1_REPLAY:
            # 09 §6: runtime_retry ends with any row that is not a rerun.
            # A Stage 1 replay sits between a run and the row its verdict
            # chose, so it keeps the run's count.
            j.counters = j.counters.model_copy(update={"runtime_retry": 0})
        if t.kind in TASK_OF_KIND:
            task = TASK_OF_KIND[t.kind]
            stage2 = task is AgentTask.MUTATION_STRATEGY
            if stage2 and j.stage2_basis is None:
                # No Q1 package to work from: never enter Stage 2.
                c.reason = "unexpected_event"
                self._block(c, BlockedReason.UNEXPECTED_EVENT,
                            Target(kind=TargetKind.RUNNING))
                return
            if t.cause is not None and \
                    (t.cause in STAGE2_CAUSES) is not stage2:
                c.reason = "unexpected_event"
                self._block(c, BlockedReason.UNEXPECTED_EVENT,
                            Target(kind=t.kind))
                return
            repair = None
            if t.cause is not None:
                charged = t.charged or t.cause is RepairCause.HCAP_CHANGED
                if stage2:
                    counter, budget, exhausted = (
                        "agent_repair_stage2", c.policy.stage2_repair_budget,
                        BlockedReason.STAGE2_REPAIR_BUDGET)
                    previous = (j.analysis_ref, j.plan_ref, j.rule_set_ref)
                    evidence = (j.stage2_basis.bundle_ref,) + t.evidence
                else:
                    counter, budget, exhausted = (
                        "agent_repair_stage1", c.policy.stage1_repair_budget,
                        BlockedReason.STAGE1_REPAIR_BUDGET)
                    previous = (j.analysis_ref, j.plan_ref)
                    evidence = (j.last_verdict.bundle_ref,) \
                        if j.last_verdict else ()
                n = getattr(j.counters, counter)
                if not charged:
                    if n >= budget:
                        self._block(c, exhausted, t)
                        return
                    n += 1
                    j.counters = j.counters.model_copy(update={counter: n})
                repair = RepairInput(
                    job_id=j.job_id, attempt=n, agent_task=task,
                    cause=t.cause,
                    previous_outputs=tuple(r for r in previous if r),
                    findings=t.findings,
                    evidence_refs=evidence,
                    remaining_budget=budget - n)
            self._start_agent(c, task, repair)
        elif t.kind is TargetKind.COMPILE:
            self._goto(c, self._compile(c), external)
        elif t.kind is TargetKind.MATERIALIZE:
            self._goto(c, self._materialize(c), external)
        elif t.kind is TargetKind.RUNNING:
            self._enter_running(c, t.rerun, external or t.external)
        elif t.kind is TargetKind.GATE:
            self._enter_gate(c, t.rerun, external or t.external)
        elif t.kind is TargetKind.CAMPAIGN:
            self._enter_campaign(c, t.rerun, external or t.external)
        elif t.kind is TargetKind.REPLAY:
            if j.replay is None:
                self._unexpected(c, Target(kind=TargetKind.COMPILE))
                return
            self._enter_replay(c, j.replay.crash, j.replay.resume, t.rerun,
                               external or t.external)
        elif t.kind is TargetKind.FIXED:
            self._enter_fixed(c)
        elif t.kind is TargetKind.S1_REPLAY:
            self._enter_s1_replay(c, t.rerun, external or t.external)
        elif t.kind is TargetKind.REACHED:
            self._reached(c)
            mode = c.policy.campaign_mode
            if mode is CampaignMode.MUTATE:
                self._start_stage2(c)
            elif mode is CampaignMode.FIXED and not self._fixed_ran(j):
                self._start_fixed(c)
            elif mode is CampaignMode.FIXED:
                # This harness had its campaign: a re-judge that reaches
                # again does not start another (an operator can).
                j.state_reason = self._fixed_result(j.fixed)
            else:
                # #81: Q1 is the deliverable; nothing starts by itself.
                j.state_reason = "evidence_only"
        elif t.kind is TargetKind.BLOCKED_OPERATOR:
            self._drop_task(c)
            j.state = JobState.BLOCKED_OPERATOR
            j.state_reason = t.reason.value
            j.resume_point = t.inner
        else:
            self._drop_task(c)
            if t.gap != j.gap:
                j.generation_refused = None
                j.generation_retry = None
            # 09 §3.2: a gap starts Harness Generation when the policy asks
            # for it; blocked_harness_gap is the fallback.
            j.state = JobState.HARNESS_GENERATING \
                if c.policy.harness_generation_budget else \
                JobState.BLOCKED_HARNESS_GAP
            j.state_reason = t.gap.gap_class.value
            if t.gap != c.proposed_gap:
                j.gap_proposal_ref = None
            j.gap = t.gap
            j.resume_point = t.inner

    def _block(self, c: _Call, reason: BlockedReason, resume: Target) -> None:
        self._goto(c, Target(kind=TargetKind.BLOCKED_OPERATOR, reason=reason,
                             inner=resume))

    def _unexpected(self, c: _Call, resume: Target) -> bool:
        c.reason = "unexpected_event"
        self._block(c, BlockedReason.UNEXPECTED_EVENT, resume)
        return True

    def _materialize(self, c: _Call,
                     failure_cause: RepairCause | None = None, *,
                     require_revision: bool = False) -> Target:
        """HCAP check, then the Materializer, on the stored plan (09 §3).
        Stores the harness on success. Only a newly returned Agent plan must
        name the selected revision; later catalog revalidation checks its
        declarations against the replacement catalog."""
        j = c.job
        # A failed authority check or materialization must never leave an old
        # harness available to a later Runner dispatch.
        j.harness = None
        check = self.env.hcap.check_plan if require_revision else \
            self.env.hcap.revalidate_plan
        chk = check(j.plan_ref, j.binding.hcap_revision)
        if not chk.ok:
            return _plan_check_target(
                chk, failure_cause or RepairCause.HCAP_INVALID)
        authority = MaterializationHcapAuthority(
            effective_hcap_revision=j.binding.hcap_revision,
            validation="exact_plan_revision" if require_revision else
            "compatible_replacement")
        m = self.env.materializer.materialize(
            j.plan_ref, j.binding, hcap_authority=authority)
        if isinstance(m, MaterializeRejected):
            if m.reason == NEUTRAL_CONTROL_UNAVAILABLE:
                if not m.profile:
                    return self._unexpected_target(TargetKind.MATERIALIZE)
                return Target(kind=TargetKind.BLOCKED_HARNESS_GAP,
                              gap=GapRef(
                                  gap_class=GapClass.FIXTURE_OR_TOOL,
                                  missing_capability_id=
                                  f"neutral_control.{m.profile}"),
                              inner=Target(kind=TargetKind.MATERIALIZE))
            if m.reason == HOST_AUTHORITY_UNAVAILABLE:
                # No plan change can fix host authority: no LLM repair, no
                # charge; the operator resumes once it is fixed (09 §3).
                return Target(kind=TargetKind.BLOCKED_OPERATOR,
                              reason=BlockedReason.HOST_AUTHORITY,
                              inner=Target(kind=TargetKind.MATERIALIZE))
            return Target(kind=TargetKind.PLANNING,
                          cause=failure_cause or
                          RepairCause.MATERIALIZER_REJECTED,
                          findings=(m.reason, m.detail) +
                          ((m.message,) if m.message else ()))
        if m.execution_harness_id != j.binding.execution_harness_id or \
                m.hcap_revision != j.binding.hcap_revision:
            return self._unexpected_target(TargetKind.MATERIALIZE)
        j.harness = m
        return Target(kind=TargetKind.RUNNING)

    def _start_stage2(self, c: _Call) -> None:
        """09 §4, the s1_reached rows.  Stage 2 starts from the Stage2Input
        only when its Q1 evidence ran on the job's bound identity and
        harness; otherwise Q1 is established again (01 §5.1, §11.2)."""
        j = c.job
        s2 = j.stage2_input
        if s2 is None or j.binding is None:
            self._unexpected(c, Target(kind=TargetKind.REACHED))
            return
        if j.harness is None or \
                s2.execution_harness_id != j.binding.execution_harness_id or \
                s2.harness_ref != j.harness.harness_ref:
            c.reason = "stage2_identity_changed"
            j.harness = None
            self._goto(c, self._materialize(c, RepairCause.HCAP_CHANGED))
            return
        c.reason = "stage2_started"
        j.stage2_basis = s2
        j.rule_set_ref = None
        j.compiled = None
        self._goto(c, Target(kind=TargetKind.STRATEGY))

    def _reached(self, c: _Call) -> None:
        """s1_reached with the Q1 package of the last verdict (09 §3)."""
        j = c.job
        self._drop_task(c)
        lv = j.last_verdict
        j.state = JobState.S1_REACHED
        j.state_reason = None
        j.stage2_input = Stage2Input(
            q1_verdict_id=lv.result.verdict_id, bundle_ref=lv.bundle_ref,
            plan_ref=lv.plan_ref, harness_ref=lv.harness_ref,
            execution_harness_id=lv.result.execution_harness_id)
        self._leave_stage2(j)

    @staticmethod
    def _leave_stage2(j: Job) -> None:
        j.stage2_basis = None
        j.rule_set_ref = None
        j.compiled = None
        j.gate_runs = ()
        j.campaign = None
        j.replay = None
        j.crash_queue = ()

    # ------------------------------------------------------------ fixed

    @staticmethod
    def _fixed_ran(j: Job) -> bool:
        return j.fixed is not None and j.harness is not None and \
            j.fixed.harness_ref == j.harness.harness_ref

    def _fixed_result(self, k: FixedCampaign) -> str:
        return "fixed_no_signal" if k.crashes == 0 else "fixed_complete"

    def _start_fixed(self, c: _Call) -> None:
        """09 §3.1, the s1_reached rows: a new fixed campaign on the Q1
        harness, with the identity check of the Stage 2 start."""
        j = c.job
        s2 = j.stage2_input
        if s2 is None or j.binding is None:
            self._unexpected(c, Target(kind=TargetKind.REACHED))
            return
        if j.harness is None or \
                s2.execution_harness_id != j.binding.execution_harness_id or \
                s2.harness_ref != j.harness.harness_ref:
            c.reason = "fixed_identity_changed"
            j.harness = None
            self._goto(c, self._materialize(c, RepairCause.HCAP_CHANGED))
            return
        c.reason = "fixed_started"
        j.task_seq += 1
        j.fixed = FixedCampaign(
            campaign_id=f"{j.job_id}.f{j.task_seq}",
            harness_ref=j.harness.harness_ref,
            execution_harness_id=j.harness.execution_harness_id,
            binding=j.binding)
        self._goto(c, Target(kind=TargetKind.FIXED))

    def _enter_fixed(self, c: _Call) -> None:
        """s1_fixed: the campaign's attempts, started or continued."""
        j = c.job
        here = Target(kind=TargetKind.FIXED)
        k = j.fixed
        if k is None or j.harness is None or \
                j.harness.harness_ref != k.harness_ref:
            self._unexpected(c, Target(kind=TargetKind.RUNNING))
            return
        if not self._runner_free(c, here):
            return
        self._drop_task(c)
        j.state = JobState.S1_FIXED
        j.state_reason = None
        j.resume_point = None
        j.gap = None
        j.gap_proposal_ref = None
        self._fill(c)

    def _fixed_waiting(self, j: Job) -> tuple[int, ...]:
        """The campaign's crashes waiting for replay, by finding index."""
        k = j.fixed
        return tuple(i for i, f in enumerate(j.crash_findings)
                     if f.source == "fixed" and
                     f.campaign_id == k.campaign_id and f.replay == "pending")

    def _fill(self, c: _Call) -> None:
        """09 §3.1: attempt tasks up to fixed_parallelism, none while a
        crash waits; with none left in flight, the replay or the end."""
        j = c.job
        k = j.fixed
        p = c.policy
        waiting = self._fixed_waiting(j)
        in_flight = list(k.in_flight)
        retry = list(k.retry)
        sent = k.sent
        digest = runner_input_digest(RunnerInput(
            job_id=j.job_id, harness_ref=k.harness_ref,
            execution_harness_id=k.execution_harness_id))
        while not waiting and len(in_flight) < p.fixed_parallelism:
            if retry:
                n = retry.pop(0)
            elif sent < p.fixed_attempts:
                sent += 1
                n = sent
            else:
                break
            in_flight.append(AttemptTask(task_id=self._mint(j), attempt=n,
                                         input_digest=digest))
        j.fixed = k = k.model_copy(update={
            "in_flight": tuple(in_flight), "retry": tuple(retry),
            "sent": sent})
        if in_flight:
            return
        if waiting:
            c.reason = "fixed_crash"
            j.s1_replay = S1Replay(queue=waiting)
            self._goto(c, Target(kind=TargetKind.S1_REPLAY))
            return
        j.counters = j.counters.model_copy(update={"runtime_retry": 0})
        self._reached(c)
        j.state_reason = c.reason = self._fixed_result(k)

    def _attempt_finished(self, c: _Call, e: ev.RunnerFinished) -> bool:
        """09 §3.1, the s1_fixed rows: one attempt's result."""
        j = c.job
        k = j.fixed
        a = next(x for x in k.in_flight if x.task_id == e.task_id)
        j.fixed = k = k.model_copy(update={"in_flight": tuple(
            x for x in k.in_flight if x.task_id != e.task_id)})
        here = Target(kind=TargetKind.FIXED)
        if e.reason == CLEANUP_UNCONFIRMED:
            self._retry(j, a)
            self._cleanup_unconfirmed(c, e.task_id)
            return True
        if e.state == "ended_unsealed" or not e.bundle_ref:
            c.reason = f"runner_ended_unsealed:{e.reason or ''}"
            return self._attempt_again(c, a)
        if not self.env.judge.matches_execution(e.bundle_ref, job_id=j.job_id,
                                                task_id=e.task_id):
            self._retry(j, a)
            c.reason = "q1_execution_mismatch"
            self._block(c, BlockedReason.Q1_EVIDENCE, here)
            return True
        r = self.env.judge.judge(e.bundle_ref, j.plan_ref,
                                 j.candidate.candidate_id, j.judge_versions)
        c.verdicts.append(r)
        c.consumed.append(r.verdict_id)
        if self._add_finding(c, e, r, a) is not None or \
                self.env.judge.crash_report(e.bundle_ref) is not None:
            # D12, D13: a crash whatever the verdict; the campaign sends no
            # new attempt until it is replayed (unless it was already).
            k = k.model_copy(update={"crashes": k.crashes + 1})
            c.reason = "fixed_attempt_crash"
        else:
            t = self._q1_target(c, r)
            if t.kind is TargetKind.REACHED:
                k = k.model_copy(update={"reached": k.reached + 1,
                                         "consecutive_not_reached": 0})
                c.reason = "fixed_attempt_reached"
            elif t.kind is TargetKind.PLANNING:
                k = k.model_copy(update={
                    "not_reached": k.not_reached + 1,
                    "consecutive_not_reached":
                        k.consecutive_not_reached + 1})
                c.reason = "fixed_attempt_not_reached"
            elif t.kind is TargetKind.RUNNING and t.rerun:
                c.reason = f"fixed_attempt_rerun:{r.reason}"
                return self._attempt_again(c, a)
            else:
                # Evidence, mapping, attribution or identity: §3's row,
                # resuming this campaign.
                self._retry(j, a)
                self._goto(c, t.model_copy(update={"inner": here}))
                return True
        j.fixed = k
        j.counters = j.counters.model_copy(update={"runtime_retry": 0})
        if k.consecutive_not_reached >= c.policy.fixed_not_reached_limit:
            c.reason = "fixed_not_reaching"
            self._block(c, BlockedReason.FIXED_NOT_REACHING, here)
            return True
        self._fill(c)
        return True

    @staticmethod
    def _retry(j: Job, a: AttemptTask) -> None:
        """The attempt is sent again under its number."""
        j.fixed = j.fixed.model_copy(update={
            "retry": tuple(sorted(j.fixed.retry + (a.attempt,)))})

    def _attempt_again(self, c: _Call, a: AttemptTask) -> bool:
        """An attempt without a counted outcome: runtime_retry (09 §6)."""
        j = c.job
        self._retry(j, a)
        n = j.counters.runtime_retry
        if n >= c.policy.runtime_retry_limit:
            self._block(c, BlockedReason.RUNTIME_RETRY_EXHAUSTED,
                        Target(kind=TargetKind.FIXED))
            return True
        j.counters = j.counters.model_copy(update={"runtime_retry": n + 1})
        self._fill(c)
        return True

    # ------------------------------------------------------------ S1 replay

    def _add_finding(self, c: _Call, e: ev.RunnerFinished, r: Q1Result,
                     a: AttemptTask | None = None) -> int | None:
        """Record the bundle's crash, if any (#81 §3, 09 §3.1).  Returns
        its index when it is to be replayed: a crash of the same harness
        and signature replayed already is a duplicate."""
        j = c.job
        crash = self.env.judge.crash_report(e.bundle_ref)
        if crash is None:
            return None
        sig = signature(crash.kind, crash.title)
        duplicate = any(f.harness_ref == j.harness.harness_ref and
                        f.signature == sig and
                        f.replay in ("pending", "done")
                        for f in j.crash_findings)
        j.crash_findings = j.crash_findings + (CrashFinding(
            source="q1" if a is None else "fixed",
            campaign_id=None if a is None else j.fixed.campaign_id,
            attempt=None if a is None else a.attempt,
            task_id=e.task_id, bundle_ref=e.bundle_ref,
            harness_ref=j.harness.harness_ref,
            execution_harness_id=r.execution_harness_id,
            plan_ref=j.plan_ref, q1_verdict_id=r.verdict_id,
            q1_status=r.status.value, q1_reason=r.reason,
            kind=crash.kind.value, title=crash.title,
            panicked=crash.panicked, signature=sig,
            replay="duplicate" if duplicate else "pending"),)
        return None if duplicate else len(j.crash_findings) - 1

    def _enter_s1_replay(self, c: _Call, rerun: bool = False,
                         external: bool = False) -> None:
        """s1_replaying: one run of the first crash in the queue, on the
        harness it crashed (09 §3.1)."""
        j = c.job
        again = Target(kind=TargetKind.S1_REPLAY, rerun=rerun,
                       external=external)
        q = j.s1_replay
        f = None if q is None else j.crash_findings[q.queue[0]]
        if f is None or j.harness is None or \
                j.harness.harness_ref != f.harness_ref:
            self._unexpected(c, Target(kind=TargetKind.RUNNING))
            return
        if not self._runner_free(c, again) or \
                not self._charge_rerun(c, rerun, external, again):
            return
        self._drop_task(c)
        j.pending_task = PendingTask(
            task_id=self._mint(j), kind=TaskKind.RUNNER,
            input_digest=runner_input_digest(RunnerInput(
                job_id=j.job_id, harness_ref=f.harness_ref,
                execution_harness_id=f.execution_harness_id)))
        j.state = JobState.S1_REPLAYING
        j.state_reason = "rerun" if rerun else None
        j.resume_point = None
        j.gap = None
        j.gap_proposal_ref = None

    def _s1_replay_finished(self, c: _Call, e: ev.RunnerFinished) -> bool:
        """09 §3.1, the s1_replaying rows."""
        j = c.job
        if e.state == "ended_unsealed" or not e.bundle_ref:
            c.reason = f"runner_ended_unsealed:{e.reason or ''}"
            self._goto(c, Target(kind=TargetKind.S1_REPLAY, rerun=True))
            return True
        if not self.env.judge.matches_execution(e.bundle_ref, job_id=j.job_id,
                                                task_id=e.task_id):
            c.reason = "replay_execution_mismatch"
            self._block(c, BlockedReason.REPLAY_EVIDENCE,
                        Target(kind=TargetKind.S1_REPLAY))
            return True
        q = j.s1_replay
        i = q.queue[0]
        f = j.crash_findings[i]
        crash = self.env.judge.crash_report(e.bundle_ref)
        runs = f.replay_runs + (ReplayRun(
            task_id=e.task_id, bundle_ref=e.bundle_ref,
            kind=None if crash is None else crash.kind.value,
            title=None if crash is None else crash.title,
            reproduced=crash is not None and
            signature(crash.kind, crash.title) == f.signature),)
        f = f.model_copy(update={"replay_runs": runs})
        queue = q.queue
        if len(runs) >= c.policy.fixed_replays:
            # D14: k/M, and k=0 is reviewed too (reproduced false).
            f = f.model_copy(update={
                "replay": "done", "replays": len(runs),
                "reproduced": sum(x.reproduced for x in runs),
                "review": "queued"})
            queue = queue[1:]
        j.crash_findings = j.crash_findings[:i] + (f,) + \
            j.crash_findings[i + 1:]
        c.reason = "s1_replay_run"
        if queue:
            j.s1_replay = q.model_copy(update={"queue": queue})
            self._enter_s1_replay(c)
            return True
        j.s1_replay = None
        if q.after is not None:
            self._goto(c, q.after)
            return True
        c.reason = "fixed_crash_replayed"
        j.state = JobState.CRASH_REVIEW
        j.state_reason = "fixed_crash"
        j.resume_point = Target(kind=TargetKind.FIXED)
        j.gap = None
        j.gap_proposal_ref = None
        return True

    @staticmethod
    def _in_s1_replay(j: Job) -> bool:
        """The job replays, or waits to replay again."""
        if j.state is JobState.S1_REPLAYING:
            return True
        t = j.resume_point if j.state in HOLDING or \
            j.state is JobState.RETRY_PENDING else None
        while t is not None:
            if t.kind is TargetKind.S1_REPLAY:
                return True
            t = t.inner
        return False

    @staticmethod
    def _abandon_s1_replay(j: Job) -> None:
        """The job left the replay before it ended (09 §3.1)."""
        findings = list(j.crash_findings)
        for i in j.s1_replay.queue:
            if findings[i].replay == "pending":
                findings[i] = findings[i].model_copy(
                    update={"replay": "abandoned"})
        j.crash_findings = tuple(findings)
        j.s1_replay = None

    def _compile(self, c: _Call) -> Target:
        """The Mutation Rule Compiler on the stored rule set (09 §4, the
        s2_strategy rows; 08 §12)."""
        j = c.job
        j.compiled = None
        here = Target(kind=TargetKind.COMPILE)
        if j.stage2_basis is None or j.rule_set_ref is None:
            return self._unexpected_target(TargetKind.STRATEGY)
        compiler = self.env.compiler
        if compiler is None:
            return Target(kind=TargetKind.BLOCKED_OPERATOR,
                          reason=BlockedReason.STAGE2_COMPILER_UNAVAILABLE,
                          inner=here)
        r = compiler.compile(j.rule_set_ref, j.stage2_basis.harness_ref,
                             j.binding)
        if isinstance(r, CompiledRuleSet):
            if r.rule_set_ref != j.rule_set_ref or \
                    r.hcap_revision != j.binding.hcap_revision:
                return self._unexpected_target(TargetKind.COMPILE)
            j.compiled = r
            c.consumed.append(r.compiled_ref)
            if self.env.stage2 is None:
                # No Stage 2 execution backend on this host.
                return Target(kind=TargetKind.BLOCKED_OPERATOR,
                              reason=BlockedReason.STAGE2_GATE_UNAVAILABLE,
                              inner=here)
            return Target(kind=TargetKind.GATE)
        if r.reason in COMPILER_AGENT_FIXABLE:
            return Target(kind=TargetKind.STRATEGY,
                          cause=RepairCause.COMPILER_REJECTED,
                          findings=(r.model_dump_json(),))
        if r.reason in COMPILER_GAP:
            cap = r.missing_capability_id
            if cap is None and r.reason == "requires_state_lineage":
                cap = STATE_LINEAGE_GAP_ID      # 08 §15, 07 §4
            if not cap or not self.env.hcap.knows_capability(
                    j.binding.hcap_revision, cap):
                return Target(kind=TargetKind.BLOCKED_OPERATOR,
                              reason=BlockedReason.GAP_ID_UNKNOWN,
                              inner=here)
            # resume_point: compile the same rule set again (09 §4).
            return Target(kind=TargetKind.BLOCKED_HARNESS_GAP,
                          gap=GapRef(gap_class=GapClass.MUTATION_ENGINE,
                                     missing_capability_id=cap),
                          inner=here)
        c.reason = "unexpected_event"
        return Target(kind=TargetKind.BLOCKED_OPERATOR,
                      reason=BlockedReason.UNEXPECTED_EVENT, inner=here)

    def _q1_target(self, c: _Call, r: Q1Result) -> Target:
        """09 §3, the s1_running rows."""
        j = c.job
        running = Target(kind=TargetKind.RUNNING)
        if r.candidate_id != j.candidate.candidate_id or \
                r.execution_harness_id != j.binding.execution_harness_id:
            return Target(kind=TargetKind.BLOCKED_OPERATOR,
                          reason=BlockedReason.Q1_EVIDENCE, inner=running)
        if r.status is Q1Status.REACHED:
            return Target(kind=TargetKind.REACHED)
        if r.status is Q1Status.NOT_REACHED:
            return Target(kind=TargetKind.PLANNING,
                          cause=RepairCause.Q1_NOT_REACHED,
                          findings=(r.model_dump_json(),))
        if r.reason in ("infra", "loss"):
            return Target(kind=TargetKind.RUNNING, rerun=True)
        if r.reason in ("evidence", "mapping"):
            return Target(kind=TargetKind.BLOCKED_OPERATOR,
                          reason=BlockedReason("q1_" + r.reason),
                          inner=running)
        g = r.gap_signal
        if r.reason == "unsupported_attribution" and g is not None and \
                g.gap_class is GapClass.REMOTE_KCOV_ATTRIBUTION and \
                g.missing_capability_id.startswith("remote_kcov.context."):
            return Target(kind=TargetKind.BLOCKED_HARNESS_GAP, gap=g,
                          inner=running)
        c.reason = "unexpected_event"
        return Target(kind=TargetKind.BLOCKED_OPERATOR,
                      reason=BlockedReason.UNEXPECTED_EVENT, inner=running)

    @staticmethod
    def _unexpected_target(kind: TargetKind) -> Target:
        return Target(kind=TargetKind.BLOCKED_OPERATOR,
                      reason=BlockedReason.UNEXPECTED_EVENT,
                      inner=Target(kind=kind))

    def _rebind(self, c: _Call, new: HarnessBinding | None,
                base: Target, *,
                rematerialize_authority: bool = False,
                authority_current: bool = False) -> Target:
        """Where a binding change sends a job whose base point is `base`
        (09 §5, the identity re-establishment point).

        An HCAP-only change rebuilds the harness only when the
        HCAP-derived authority refs changed (`authority_current` False).
        Otherwise the plan is re-validated and the state is kept."""
        j = c.job
        old = j.binding
        stale = harness_authority_stale(j, new)
        keep = authority_current and j.harness is not None
        if new is None:
            j.binding = None
            return Target(kind=TargetKind.BLOCKED_HARNESS_GAP,
                          gap=kernel_revision_gap(j.candidate.kernel_commit),
                          inner=base)
        j.binding = new
        if old is None or new.execution_harness_id != \
                old.execution_harness_id:
            j.harness = None
            if j.plan_ref:
                return self._materialize(c, RepairCause.HCAP_CHANGED)
            if j.analysis_ref:
                return Target(kind=TargetKind.PLANNING)
            return Target(kind=TargetKind.ANALYSIS)
        if new.hcap_revision != old.hcap_revision and j.plan_ref and \
                base.kind not in (TargetKind.ANALYSIS, TargetKind.PLANNING):
            chk = self.env.hcap.revalidate_plan(j.plan_ref,
                                                new.hcap_revision)
            if not chk.ok:
                if rematerialize_authority:
                    j.harness = None
                return _plan_check_target(chk, RepairCause.HCAP_CHANGED)
            if rematerialize_authority and keep:
                self._keep_harness(j, new)
                return self._recompile(base)
            if rematerialize_authority:
                j.harness = None
                return self._materialize(c, RepairCause.HCAP_CHANGED)
            return self._recompile(base)
        if rematerialize_authority and stale and base.kind in (
                TargetKind.ANALYSIS, TargetKind.PLANNING):
            # The active Agent task will replace this inert harness.
            j.harness = None
            return base
        if rematerialize_authority and stale and j.plan_ref:
            chk = self.env.hcap.revalidate_plan(j.plan_ref,
                                                new.hcap_revision)
            if not chk.ok:
                j.harness = None
                return _plan_check_target(chk, RepairCause.HCAP_CHANGED)
            if keep:
                self._keep_harness(j, new)
                return base
            j.harness = None
            return self._materialize(c, RepairCause.HCAP_CHANGED)
        if rematerialize_authority and stale:
            j.harness = None
            return self._unexpected_target(TargetKind.MATERIALIZE)
        return base

    @staticmethod
    def _recompile(base: Target) -> Target:
        """09 §5: after an HCAP change a point that runs the compiled rule
        set compiles the stored rule set again and goes through the gate."""
        if base.kind in (TargetKind.GATE, TargetKind.CAMPAIGN):
            return Target(kind=TargetKind.COMPILE)
        return base

    @staticmethod
    def _keep_harness(j: Job, binding: HarnessBinding) -> None:
        if j.harness.hcap_revision != binding.hcap_revision:
            j.harness = j.harness.model_copy(
                update={"authority_hcap_revision": binding.hcap_revision})

    @staticmethod
    def _waiting_base(j: Job) -> Target:
        rp = j.resume_point
        if rp is not None and rp.kind in WAITING_KINDS:
            return rp.inner
        return rp

    def _set_resume(self, c: _Call, t: Target, base: Target) -> None:
        """09 §5: a re-evaluation event on a waiting job moves only its
        resume_point.  A result that is a waiting state resumes where that
        result resumes, not at the base point an earlier re-evaluation may
        have moved (rationale 16)."""
        j = c.job
        if j.state is JobState.BLOCKED_OPERATOR:
            here = Target(kind=TargetKind.BLOCKED_OPERATOR,
                          reason=BlockedReason(j.state_reason))
        elif j.state is JobState.CRASH_REVIEW:
            here = None
        else:
            here = Target(kind=TargetKind.BLOCKED_HARNESS_GAP, gap=j.gap)
        place = t.model_copy(update={"inner": None})
        if t == base:
            j.resume_point = base
        elif place == here:
            # Already waiting there: ending the wait goes where the result
            # goes.
            j.resume_point = t.inner
        else:
            j.resume_point = t


    # ------------------------------------------------------------ Stage 2

    def _route(self, c: _Call, action: str) -> bool:
        """09 §5 operator route(to) on blocked_operator(gate_regression).
        Refused, and recorded, once a re-evaluation event moved the resume
        point away from the gate it blocked at."""
        j = c.job
        if j.state is not JobState.BLOCKED_OPERATOR or \
                j.state_reason != BlockedReason.GATE_REGRESSION.value:
            return False
        if j.resume_point != Target(kind=TargetKind.GATE):
            c.reason = "route_refused"
            return True
        j.resume_point = None
        j.state_reason = None
        c.reason = action
        self._goto(c, Target(kind=TargetKind.GATE if action == "route_gate"
                             else TargetKind.STRATEGY))
        return True

    @staticmethod
    def _end_stream(j: Job, task_id: str) -> BundleCursor | None:
        """The task's bundle list is final: stop tracking it."""
        found = None
        rest = []
        for cur in j.bundle_cursors:
            if cur.task_id == task_id:
                found = cur
            else:
                rest.append(cur)
        j.bundle_cursors = tuple(rest)
        return found

    def _runner_free(self, c: _Call, resume: Target) -> bool:
        """09 §8: no Runner work while an earlier execution may still run,
        however the job got here."""
        if c.job.uncleaned_tasks:
            self._block(c, BlockedReason.EXECUTION_CLEANUP, resume)
            return False
        return True

    def _charge_rerun(self, c: _Call, rerun: bool, external: bool,
                      resume: Target) -> bool:
        """09 §6 runtime_retry for a rerun row; False when exhausted."""
        j = c.job
        if not rerun or external:
            return True
        n = j.counters.runtime_retry
        if n >= c.policy.runtime_retry_limit:
            self._block(c, BlockedReason.RUNTIME_RETRY_EXHAUSTED, resume)
            return False
        j.counters = j.counters.model_copy(update={"runtime_retry": n + 1})
        return True

    def _runner_task(self, c: _Call, task_input: RunnerInput,
                     state: JobState, rerun: bool) -> str:
        j = c.job
        self._drop_task(c)
        task_id = self._mint(j)
        j.pending_task = PendingTask(
            task_id=task_id, kind=TaskKind.RUNNER,
            input_digest=runner_input_digest(task_input),
            runner_input=task_input)
        j.state = state
        j.state_reason = "rerun" if rerun else None
        j.resume_point = None
        j.gap = None
        j.gap_proposal_ref = None
        return task_id

    def _enter_gate(self, c: _Call, rerun: bool, external: bool) -> None:
        """09 §4 s2_gate: the Stage 1 scenario and its neutral run with the
        compiled rule set installed (01 §3)."""
        j = c.job
        again = Target(kind=TargetKind.GATE, rerun=rerun, external=external)
        if j.compiled is None or j.harness is None or \
                j.stage2_basis is None:
            self._unexpected(c, Target(kind=TargetKind.COMPILE))
            return
        if not self._runner_free(c, again) or \
                not self._charge_rerun(c, rerun, external, again):
            return
        if not rerun:
            j.gate_runs = ()
        j.campaign = None
        j.replay = None
        j.crash_queue = ()
        self._runner_task(c, RunnerInput(
            job_id=j.job_id, harness_ref=j.harness.harness_ref,
            execution_harness_id=j.harness.execution_harness_id,
            step="gate", compiled_ref=j.compiled.compiled_ref,
            gate_repetitions=c.policy.gate_repetitions),
            JobState.S2_GATE, rerun)

    def _gate_finished(self, c: _Call, p: PendingTask,
                       e: ev.RunnerFinished) -> bool:
        """09 §4, the s2_gate rows, over every repetition (01 §3)."""
        j = c.job
        gate = Target(kind=TargetKind.GATE)
        bundles = e.bundle_refs
        if e.state == "ended_unsealed" or not bundles:
            c.reason = f"runner_ended_unsealed:{e.reason or ''}"
            self._goto(c, Target(kind=TargetKind.GATE, rerun=True))
            return True
        wanted = p.runner_input.gate_repetitions if p.runner_input else None
        if len(bundles) != wanted:
            return self._unexpected(c, gate)
        runs = []
        for bundle in bundles:
            if not self.env.stage2.matches_execution(
                    bundle, job_id=j.job_id, task_id=e.task_id):
                c.reason = "gate_execution_mismatch"
                self._block(c, BlockedReason.Q1_EVIDENCE, gate)
                return True
            run = self.env.stage2.judge_gate(
                bundle, plan_ref=j.plan_ref,
                candidate_id=j.candidate.candidate_id,
                compiled=j.compiled, versions=j.judge_versions)
            if run.bundle_ref != bundle:
                # A verdict is used only for the bundle whose provenance
                # was just checked.
                c.reason = "gate_judge_bundle_mismatch"
                self._block(c, BlockedReason.Q1_EVIDENCE, gate)
                return True
            runs.append(run)
            c.verdicts.append(run.q1)
            c.consumed.extend((run.q1.verdict_id, run.m1_verdict_id))
        j.gate_runs = tuple(runs)
        t = None
        rank = None
        for run in runs:
            r, row = self._gate_row(c, run)
            if rank is None or r < rank:
                rank, t = r, row
        if rank < 0:
            c.reason = "unexpected_event"
        if t is None:
            c.reason = "gate_passed"
            self._start_campaign(c)
        else:
            self._goto(c, t)
        return True

    def _gate_row(self, c: _Call, run: GateRun
                  ) -> tuple[int, Target | None]:
        """The 01 §3 gate table for one repetition: its rank (the topmost
        row of all repetitions decides) and where it sends the job; None
        starts the campaign."""
        j = c.job
        gate = Target(kind=TargetKind.GATE)
        q = run.q1
        if q.candidate_id != j.candidate.candidate_id or \
                q.execution_harness_id != j.binding.execution_harness_id:
            return 0, Target(kind=TargetKind.BLOCKED_OPERATOR,
                             reason=BlockedReason.Q1_EVIDENCE, inner=gate)
        if q.status is Q1Status.NOT_REACHED:
            return 1, Target(kind=TargetKind.BLOCKED_OPERATOR,
                             reason=BlockedReason.GATE_REGRESSION, inner=gate)
        if q.status is Q1Status.INCONCLUSIVE:
            if q.reason in ("infra", "loss"):
                return 2, Target(kind=TargetKind.GATE, rerun=True)
            if q.reason in ("evidence", "mapping"):
                return 2, Target(kind=TargetKind.BLOCKED_OPERATOR,
                                 reason=BlockedReason("q1_" + q.reason),
                                 inner=gate)
            g = q.gap_signal
            if q.reason == "unsupported_attribution" and g is not None and \
                    g.gap_class is GapClass.REMOTE_KCOV_ATTRIBUTION and \
                    g.missing_capability_id.startswith(
                        "remote_kcov.context."):
                return 2, Target(kind=TargetKind.BLOCKED_HARNESS_GAP, gap=g,
                                 inner=gate)
            return -1, self._unexpected_target(TargetKind.GATE)
        statuses = [r.status for r in run.rules] + \
            [i.status for i in run.intents]
        if any(st not in M1_STATUSES for st in statuses):
            return -1, self._unexpected_target(TargetKind.GATE)
        if any(r.status == "inconclusive" for r in run.rules):
            return 3, Target(kind=TargetKind.GATE, rerun=True)
        if any(i.targets_baseline_traffic and i.status == "not_applied"
               for i in run.intents):
            return 4, Target(kind=TargetKind.STRATEGY,
                             cause=RepairCause.GATE_NOT_APPLIED,
                             findings=(run.model_dump_json(),),
                             evidence=(run.bundle_ref,))
        return 5, None

    def _start_campaign(self, c: _Call) -> None:
        """The gate passed: a new Stage2Campaign on the job's harness and
        compiled rule set (01 §3)."""
        j = c.job
        j.task_seq += 1
        j.campaign = Campaign(
            campaign_id=f"{j.job_id}.c{j.task_seq}",
            compiled_ref=j.compiled.compiled_ref,
            rule_set_ref=j.compiled.rule_set_ref, binding=j.binding,
            harness_ref=j.harness.harness_ref,
            execution_harness_id=j.harness.execution_harness_id,
            gate_consumed=tuple(c.consumed))
        self._goto(c, Target(kind=TargetKind.CAMPAIGN))

    def _enter_campaign(self, c: _Call, rerun: bool, external: bool) -> None:
        """A new Runner task of the job's campaign (09 §4): its first, or
        one that continues it."""
        j = c.job
        again = Target(kind=TargetKind.CAMPAIGN, rerun=rerun,
                       external=external)
        k = j.campaign
        if k is None or j.compiled is None or \
                j.compiled.compiled_ref != k.compiled_ref:
            self._unexpected(c, Target(kind=TargetKind.COMPILE))
            return
        if not self._runner_free(c, again) or \
                not self._charge_rerun(c, rerun, external, again):
            return
        task_id = self._runner_task(c, RunnerInput(
            job_id=j.job_id, harness_ref=k.harness_ref,
            execution_harness_id=k.execution_harness_id, step="campaign",
            compiled_ref=k.compiled_ref, campaign_id=k.campaign_id),
            JobState.S2_CAMPAIGN, rerun)
        j.bundle_cursors = j.bundle_cursors + (BundleCursor(
            task_id=task_id, campaign_id=k.campaign_id,
            compiled=j.compiled),)

    def _campaign_finished(self, c: _Call, cursor: BundleCursor | None,
                           e: ev.RunnerFinished) -> bool:
        """09 §4: the task's bundles were taken as they were sealed; its
        end continues the campaign."""
        j = c.job
        if cursor is None or cursor.delivered != len(e.bundle_refs):
            return self._unexpected(c, Target(kind=TargetKind.CAMPAIGN))
        if e.state == "ended_unsealed" or not e.bundle_refs:
            c.reason = f"runner_ended_unsealed:{e.reason or ''}"
            self._goto(c, Target(kind=TargetKind.CAMPAIGN, rerun=True))
            return True
        c.reason = "campaign_task_sealed"
        if j.campaign.tally.executions >= c.policy.fuzz_budget_executions:
            self._block(c, BlockedReason.CAMPAIGN_BUDGET_EXHAUSTED,
                        Target(kind=TargetKind.CAMPAIGN))
        else:
            self._goto(c, Target(kind=TargetKind.CAMPAIGN))
        return True

    def _on_runner_bundle_sealed(self, c: _Call,
                                 e: ev.RunnerBundleSealed) -> bool:
        """A campaign bundle (09 §4).  The live campaign's bundles route
        the job; a bundle of a campaign task the job no longer takes is
        judged and kept as a triage item, and its APPLIED crash is routed
        as the late-crash rule says (09 §4)."""
        j = c.job
        cursor = next((x for x in j.bundle_cursors
                       if x.task_id == e.task_id), None)
        if cursor is None or e.index != cursor.delivered:
            return False
        j.bundle_cursors = tuple(
            x.model_copy(update={"delivered": x.delivered + 1})
            if x.task_id == e.task_id else x for x in j.bundle_cursors)
        live = j.state is JobState.S2_CAMPAIGN and \
            self._is_pending(j.pending_task, TaskKind.RUNNER, e.task_id)
        if not self.env.stage2.matches_execution(
                e.bundle_ref, job_id=j.job_id, task_id=e.task_id):
            c.reason = "campaign_execution_mismatch"
            if live:
                self._block(c, BlockedReason.CAMPAIGN_EVIDENCE,
                            Target(kind=TargetKind.CAMPAIGN))
            return True
        seg = self.env.stage2.judge_campaign(
            e.bundle_ref, candidate_id=j.candidate.candidate_id,
            compiled=cursor.compiled)
        if seg.bundle_ref != e.bundle_ref:
            # Never replay or triage a bundle other than the one whose
            # provenance was just checked.
            c.reason = "campaign_judge_bundle_mismatch"
            if live:
                self._block(c, BlockedReason.CAMPAIGN_EVIDENCE,
                            Target(kind=TargetKind.CAMPAIGN))
            return True
        c.consumed.extend((seg.q2_verdict_id, seg.m1_verdict_id))
        if live:
            self._campaign_segment(c, cursor, e.task_id, seg)
        else:
            self._late_segment(c, cursor, e.task_id, seg)
        return True

    @staticmethod
    def _triage(cursor: BundleCursor, task_id: str, seg: CampaignSegment,
                late: bool, routing: str) -> TriageItem:
        return TriageItem(
            campaign_id=cursor.campaign_id, task_id=task_id,
            bundle_ref=seg.bundle_ref, q2_verdict_id=seg.q2_verdict_id,
            q2_status=seg.q2_status, q2_reason=seg.q2_reason,
            m1_verdict_id=seg.m1_verdict_id,
            crash_window_applied=seg.crash_window_applied, late=late,
            attribution_quality=seg.attribution_quality,
            attribution_warnings=seg.attribution_warnings,
            routing=routing)

    @staticmethod
    def _crash(k: Campaign, compiled: CompiledRuleSet,
               seg: CampaignSegment) -> CrashRef:
        return CrashRef(
            bundle_ref=seg.bundle_ref, campaign_id=k.campaign_id,
            compiled=compiled, binding=k.binding, harness_ref=k.harness_ref,
            execution_harness_id=k.execution_harness_id,
            q2_verdict_id=seg.q2_verdict_id, m1_verdict_id=seg.m1_verdict_id)

    def _campaign_segment(self, c: _Call, cursor: BundleCursor,
                          task_id: str, seg: CampaignSegment) -> None:
        """09 §4, the s2_campaign rows, for one sealed bundle of the
        running campaign.  The rows apply in table order."""
        j = c.job
        p = c.policy
        here = Target(kind=TargetKind.CAMPAIGN)
        if seg.q2_status not in Q2_STATUSES:
            self._unexpected(c, here)
            return
        signal = seg.q2_status == "observed"
        applied = signal and bool(seg.crash_window_applied)
        t = j.campaign.tally
        t = t.model_copy(update={
            "segments": t.segments + 1,
            "executions": t.executions + seg.executions,
            "reached_generations":
                t.reached_generations + seg.reached_generations,
            "hypothesis_applied":
                t.hypothesis_applied + seg.hypothesis_applied,
            "hypothesis_not_applied":
                t.hypothesis_not_applied + seg.hypothesis_not_applied,
            "hypothesis_inconclusive":
                t.hypothesis_inconclusive + seg.hypothesis_inconclusive,
            "applied_crashes": t.applied_crashes + int(applied),
            "m1_unevaluated": t.m1_unevaluated + int(
                seg.m1_status == "inconclusive_mapping")})
        j.campaign = j.campaign.model_copy(update={"tally": t})
        # 09 §6: a continued campaign that seals a bundle ends the reruns.
        j.counters = j.counters.model_copy(update={"runtime_retry": 0})
        if applied:
            j.triage = j.triage + (self._triage(cursor, task_id, seg, False,
                                                "replayed"),)
            c.reason = "campaign_applied_crash"
            self._enter_replay(c, self._crash(j.campaign, cursor.compiled,
                                              seg), here)
            return
        if seg.q2_status != "not_observed":
            j.triage = j.triage + (self._triage(cursor, task_id, seg, False,
                                                "none"),)
        findings = (t.model_dump_json(),)
        evidence = (seg.bundle_ref,)
        if t.hypothesis_applied == 0 and \
                t.hypothesis_not_applied >= p.campaign_not_applied_generations:
            c.reason = "campaign_not_applied"
            self._goto(c, Target(kind=TargetKind.STRATEGY,
                                 cause=RepairCause.CAMPAIGN_NOT_APPLIED,
                                 findings=findings, evidence=evidence))
        elif t.applied_crashes == 0 and \
                t.hypothesis_applied >= p.campaign_no_signal_generations:
            c.reason = "campaign_no_signal"
            self._goto(c, Target(kind=TargetKind.STRATEGY,
                                 cause=RepairCause.CAMPAIGN_NO_SIGNAL,
                                 findings=findings, evidence=evidence))
        elif t.hypothesis_inconclusive >= \
                p.campaign_inconclusive_generations:
            c.reason = "campaign_evidence_path"
            self._block(c, BlockedReason.EVIDENCE_PATH, here)
        elif t.executions >= p.fuzz_budget_executions:
            c.reason = "campaign_budget_exhausted"
            self._block(c, BlockedReason.CAMPAIGN_BUDGET_EXHAUSTED, here)
        else:
            c.reason = "campaign_segment"

    def _late_segment(self, c: _Call, cursor: BundleCursor, task_id: str,
                      seg: CampaignSegment) -> None:
        """09 §4 late campaign evidence: a bundle of a campaign task the job
        no longer takes.  It is a triage item and moves no counter.  An
        APPLIED crash still goes to replay and review (01 §12) when the
        job can take it without overriding a person's decision:

        - its campaign is under replay or review: queued, replayed after
          the current review;
        - its campaign is still the job's and the job is in s2_campaign,
          or runs the Mutation Strategy repair that stopped it: that work
          stops and the crash is replayed;
        - otherwise (a waiting state, Stage 1, another rule set, a closed
          job): unrouted, for a person to take further."""
        j = c.job
        c.reason = "late_campaign_bundle"
        applied = seg.q2_status == "observed" and \
            bool(seg.crash_window_applied)
        routing = "none"
        k = j.campaign
        own = k is not None and k.campaign_id == cursor.campaign_id
        p = j.pending_task
        if applied:
            routing = "unrouted"
            if j.state in (JobState.S2_REPLAYING, JobState.CRASH_REVIEW) \
                    and j.replay is not None and \
                    j.replay.crash.campaign_id == cursor.campaign_id:
                routing = "queued"
                j.crash_queue = j.crash_queue + (
                    j.replay.crash.model_copy(update={
                        "bundle_ref": seg.bundle_ref,
                        "q2_verdict_id": seg.q2_verdict_id,
                        "m1_verdict_id": seg.m1_verdict_id}),)
            elif own and j.state is JobState.S2_CAMPAIGN:
                routing = "replayed"
            elif own and j.state is JobState.S2_STRATEGY and \
                    p is not None and p.repair is not None and \
                    p.repair.cause in CAMPAIGN_REPAIRS:
                routing = "replayed"
        j.triage = j.triage + (self._triage(cursor, task_id, seg, True,
                                            routing),)
        if routing == "replayed":
            c.reason = "late_applied_crash"
            resume = Target(kind=TargetKind.CAMPAIGN) \
                if j.state is JobState.S2_CAMPAIGN else \
                self._agent_target(p, charged=True)
            self._enter_replay(c, self._crash(k, cursor.compiled, seg),
                               resume)

    def _enter_replay(self, c: _Call, crash: CrashRef, resume: Target,
                      rerun: bool = False, external: bool = False) -> None:
        """09 §4 s2_replaying: the crash's CrashContextWindow, replayed on
        the identity and rule set it ran with (03-nfs-proxy/05 §25-§29)."""
        j = c.job
        j.replay = Replay(crash=crash, resume=resume)
        again = Target(kind=TargetKind.REPLAY, rerun=rerun,
                       external=external)
        if not self._runner_free(c, again) or \
                not self._charge_rerun(c, rerun, external, again):
            return
        self._runner_task(c, RunnerInput(
            job_id=j.job_id, harness_ref=crash.harness_ref,
            execution_harness_id=crash.execution_harness_id, step="replay",
            compiled_ref=crash.compiled.compiled_ref,
            campaign_id=crash.campaign_id, crash_bundle_ref=crash.bundle_ref),
            JobState.S2_REPLAYING, rerun)

    def _replay_finished(self, c: _Call, e: ev.RunnerFinished) -> bool:
        """09 §4, the s2_replaying rows."""
        j = c.job
        again = Target(kind=TargetKind.REPLAY)
        if e.state == "ended_unsealed" or not e.bundle_ref:
            c.reason = f"runner_ended_unsealed:{e.reason or ''}"
            self._goto(c, Target(kind=TargetKind.REPLAY, rerun=True))
            return True
        crash = j.replay.crash
        if not self.env.stage2.matches_execution(
                e.bundle_ref, job_id=j.job_id, task_id=e.task_id):
            c.reason = "replay_execution_mismatch"
            self._block(c, BlockedReason.REPLAY_EVIDENCE, again)
            return True
        r = self.env.stage2.judge_replay(
            e.bundle_ref, crash_bundle_ref=crash.bundle_ref,
            compiled=crash.compiled)
        c.consumed.append(r.verdict_id)
        j.replay = j.replay.model_copy(update={"outcome": r,
                                               "bundle_ref": e.bundle_ref})
        if r.status == REPLAY_EVIDENCE_REJECTED:
            self._block(c, BlockedReason.REPLAY_EVIDENCE, again)
        elif r.status in REPLAY_STATUSES:
            j.state = JobState.CRASH_REVIEW
            j.state_reason = r.status
            j.resume_point = j.replay.resume
            j.gap = None
            j.gap_proposal_ref = None
        else:
            self._unexpected(c, again)
        return True

    # ------------------------------------------------------------ tasks

    def _start_agent(self, c: _Call, task: AgentTask,
                     repair: RepairInput | None, retry: bool = False) -> None:
        j = c.job
        self._drop_task(c)
        if not retry:
            j.counters = j.counters.model_copy(update={"agent_retry": 0})
        stage2 = {}
        if task is AgentTask.CANDIDATE_ANALYSIS:
            model_policy = c.policy.stage1_agents.candidate_analysis
        elif task is AgentTask.REACHABILITY_PLANNING:
            model_policy = c.policy.stage1_agents.reachability_planning
        elif task is AgentTask.MUTATION_STRATEGY:
            model_policy = c.policy.stage2_agents.mutation_strategy
            stage2 = dict(stage2_input=j.stage2_basis,
                          rule_set_ref=j.rule_set_ref)
        else:
            raise ValueError(f"no model policy for {task}")
        if not stage2:
            self._leave_stage2(j)
            j.fixed = None
        j.pending_task = PendingTask(task_id=self._mint(j),
                                     kind=TaskKind.AGENT,
                                     input_digest=agent_input_digest(
                                         agent_task=task,
                                         model_policy=model_policy,
                                         candidate=j.candidate,
                                         hcap_revision=
                                         j.binding.hcap_revision,
                                         analysis_ref=j.analysis_ref,
                                         plan_ref=j.plan_ref,
                                         repair=repair, **stage2),
                                     agent_task=task,
                                     model_policy=model_policy,
                                     repair=repair)
        j.state = STATE_OF_TASK[task]
        j.state_reason = repair.cause.value if repair else None
        j.resume_point = None
        j.gap = None
        j.gap_proposal_ref = None

    def _enter_running(self, c: _Call, rerun: bool, external: bool) -> None:
        """Every entry into s1_running applies the approval policy of the
        moment (09 §3)."""
        j = c.job
        if j.uncleaned_tasks:
            # 09 §8: no Runner work while an earlier execution may still
            # run, however the job got here (a wait ending, another resume).
            self._block(c, BlockedReason.EXECUTION_CLEANUP,
                        Target(kind=TargetKind.RUNNING, rerun=rerun,
                               external=external))
            return
        if rerun and not external:
            n = j.counters.runtime_retry
            if n >= c.policy.runtime_retry_limit:
                self._block(c, BlockedReason.RUNTIME_RETRY_EXHAUSTED,
                            Target(kind=TargetKind.RUNNING, rerun=True))
                return
            j.counters = j.counters.model_copy(
                update={"runtime_retry": n + 1})
        self._drop_task(c)
        self._leave_stage2(j)
        j.fixed = None
        h = j.harness
        if c.policy.approval_required and \
                h.review_manifest_sha256 not in j.approved_manifests:
            j.pending_task = PendingTask(
                task_id=self._mint(j), kind=TaskKind.HUMAN,
                input_digest=h.review_manifest_sha256)
            j.state = JobState.S1_APPROVAL
        else:
            task_input = RunnerInput(
                job_id=j.job_id, harness_ref=h.harness_ref,
                execution_harness_id=h.execution_harness_id)
            j.pending_task = PendingTask(
                task_id=self._mint(j), kind=TaskKind.RUNNER,
                input_digest=runner_input_digest(task_input))
            j.state = JobState.S1_RUNNING
        j.state_reason = "rerun" if rerun else None
        j.resume_point = None
        j.gap = None
        j.gap_proposal_ref = None

    def _drop_task(self, c: _Call) -> None:
        """The job will not take this task's result.  A Runner task is
        cancelled after commit and the job's next Runner task waits for
        its end (09 §8)."""
        j = c.job
        k = j.fixed
        if k is not None and k.in_flight:
            # 09 §3.1: every attempt in flight, each sent again on resume.
            j.cancelling_tasks = j.cancelling_tasks + tuple(
                a.task_id for a in k.in_flight)
            j.fixed = k.model_copy(update={"in_flight": (), "retry": tuple(
                sorted(k.retry + tuple(a.attempt for a in k.in_flight)))})
        p = j.pending_task
        if p is None:
            return
        if p.kind is TaskKind.RUNNER:
            j.cancelling_tasks = j.cancelling_tasks + (p.task_id,)
        elif p.kind is TaskKind.AGENT:
            c.abandoned = (p.task_id, p.attempt)
        j.pending_task = None

    @staticmethod
    def _mint(j: Job) -> str:
        j.task_seq += 1
        return f"{j.job_id}.t{j.task_seq}"

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _is_pending(p: PendingTask | None, kind: TaskKind, task_id: str,
                    attempt: int | None = None) -> bool:
        return p is not None and p.kind is kind and p.task_id == task_id \
            and (attempt is None or p.attempt == attempt)

    def _usable(self, c: _Call, b: HarnessBinding | None
                ) -> HarnessBinding | None:
        """A binding for another commit or sanitizer is no binding."""
        j = c.job
        commit = j.candidate.kernel_commit if j.candidate else None
        if b is None or b.kernel_commit != commit or \
                b.sanitizer is not c.policy.sanitizer:
            return None
        return b

    @staticmethod
    def _agent_target(p: PendingTask, charged: bool) -> Target:
        kind = AGENT_KINDS[p.agent_task]
        if p.repair is None:
            return Target(kind=kind)
        # A Stage 2 repair names the Stage 1 bundle first, then its own.
        evidence = p.repair.evidence_refs[1:] if \
            p.agent_task is AgentTask.MUTATION_STRATEGY else ()
        return Target(kind=kind, cause=p.repair.cause,
                      findings=p.repair.findings, evidence=evidence,
                      charged=charged)

    def _here(self, j: Job) -> Target:
        """The job's present place as a target, for a resume point."""
        if j.state in AGENT_STATES and j.pending_task is not None:
            return self._agent_target(j.pending_task, charged=True)
        if j.state is JobState.S1_PLANNING:
            return Target(kind=TargetKind.PLANNING)
        if j.state is JobState.S1_ANALYSIS:
            return Target(kind=TargetKind.ANALYSIS)
        if j.state is JobState.S1_REACHED:
            return Target(kind=TargetKind.REACHED)
        if j.state is JobState.S2_STRATEGY:
            return Target(kind=TargetKind.STRATEGY)
        if j.state in RUNNER_STATES:
            return Target(kind=RUNNER_STATES[j.state])
        return Target(kind=TargetKind.RUNNING)
