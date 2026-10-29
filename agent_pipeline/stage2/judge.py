"""``components.Stage2Judge`` over host-published, sealed Stage 2 evidence.

``Stage2Execution`` is the host authority for one bundle: which job, task
and step sealed it, the identity and rule set it ran with, and the
receipts the Q1 and Q2 adapters need.  The authority publisher
(``authority``) builds it from host records only, never from guest bytes.
This judge reads the bundle under that authority and calls the existing
pure kernels; it adds no decision rule of its own:

gate (01 §3)
    Q1 through ``ArtifactQ1Judge``; rule and intent M1 (``m1.evaluate``)
    over the scenario run's program generations; the ambient flags from
    the neutral run (target PCs in its coverage, rules APPLIED in it).
campaign (01 §3, §8.2, §12)
    Q2 through ``ArtifactQ2Judge``; M1 over the crash's CrashContextWindow
    when a signal was observed; and, for each program generation whose
    published coverage hits a target PC of the verified mapping, the
    generation's hypothesis M1 for the campaign counts.
replay (03-nfs-proxy/05 §29)
    ``replay_runner.judge_input`` over the crash bundle's production
    journal and the replay bundle's journal, then ``semantic_replay``.

Like the other judges it is a pure function of its arguments: a bundle
without published authority raises (``UnknownStage2Execution``) so the
Controller retries instead of recording a verdict, storage that cannot be
read raises ``OSError``, and evidence that is present but malformed,
miscorrelated or inconsistent becomes INCONCLUSIVE evidence (rules and
hypotheses INCONCLUSIVE, Q2 by its own table, replay ``evidence_rejected``).

The per-generation reach used for campaign counts is the target-PC test
on the generation's own published coverage.  The full Q1 profile
(counters, context, loss policy) applies to the gate only.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from pydantic import ConfigDict, Field

from ..agent_tasks.mutation import MutationRuleSet
from ..artifacts import ArtifactStore
from ..contracts import (CampaignSegment, CompiledRuleSet, GateRun, IntentM1,
                         JudgeVersions, Q1Result, Record,
                         REPLAY_EVIDENCE_REJECTED, ReplayOutcome, RuleM1, Sha256)
from ..data import canonical_json, load_record
from ..evidence import (EvidenceStore, ExecutionCorrelation, VerifiedBundle)
from ..m1 import (BarrierResults, BarrierStatus, ClosureReason,
                  CrashContextWindow as M1Window, ExposureIntent,
                  ForwardEvent, ForwardOutcome, GenerationClosure,
                  GenerationComplete, HypothesisDefinition, IntentDefinition,
                  JournalIntegrityStatus, JournalIssue, M1Decision,
                  M1JudgeInput, M1JudgeProfile, M1RuleSet, M1Status,
                  MutationEvidence, ProgramGenerationCorrelation,
                  ProgramGenerationExecution, RuleApplication, RuleDefinition,
                  RuleMessageType, aggregate_intent, evaluate as m1_evaluate)
from ..q1 import CandidateTarget, KernelIdentity, TargetPcMapping
from ..q2 import Q2Status
from ..replay_runner import (Barrier, Compatibility as GateCompatibility,
                             PlanError, ReplayPlan, judge_input,
                             invalid_plan_input,
                             parse_crash_context, parse_execprog_barriers,
                             plan_replay)
from ..rule_compiler import CompiledMutationRuleSet
from ..sealed_q1 import ArtifactQ1Judge, PublishedCoverage, TrustedQ1Execution
from ..sealed_q2 import ArtifactQ2Judge, TrustedQ2Execution
from ..semantic_delta import DeltaReadError, GenerationDelta, SealedJournal, SessionDelta
from ..semantic_replay import (InvalidReason, ReplayJudgeInput,
                              ReplayJudgeProfile, evaluate as replay_evaluate)
from .evidence import (CRASH_LOG_ID, CRASH_LOG_TYPE, EXECPROG_TYPE,
                       GENERATION_COVERAGE_PREFIX, GENERATION_COVERAGE_TYPE,
                       GENERATION_EXECUTION_PREFIX, GENERATION_EXECUTION_TYPE,
                       GenerationExecution,
                       HOST_FACTS_ID, HOST_FACTS_TYPE, NEUTRAL_COVERAGE_ID,
                       NEUTRAL_COVERAGE_TYPE, NEUTRAL_EXECPROG_ID,
                       REPLAY_EXECPROG_ID, SCENARIO_EXECPROG_ID,
                       Stage2HostFacts, open_journal)

MAX_WINDOW = 64
UINT64_MAX = 2**64 - 1
#: Evidence that is present but cannot be judged.  OSError (storage) is
#: not here: it propagates so the Controller retries.
_INVALID = (ValueError, TypeError, KeyError, RecursionError, PlanError,
            DeltaReadError)


class Stage2Execution(Record):
    """Host authority for one sealed Stage 2 bundle (01 §11.1).

    ``q1`` (gate) and ``q2`` (campaign) are the receipts the existing
    adapters take.  ``mapping_ref`` is the operator-verified target
    mapping of the bound kernel; ``identity`` is that kernel.  The profile
    references and the window bound are the host's choice when the bundle
    was published, so a replay of the job reads the same ones."""

    model_config = ConfigDict(strict=True, revalidate_instances="always")
    schema_version: Literal["stage2-execution.v1"] = "stage2-execution.v1"
    bundle_ref: Sha256
    step: Literal["gate", "campaign", "replay"]
    index: int = Field(ge=0)
    lease_generation: int = Field(ge=1)
    correlation: ExecutionCorrelation
    candidate: CandidateTarget
    compiled: CompiledRuleSet
    identity: KernelIdentity
    mapping_ref: Sha256
    program_ref: Sha256
    plan_ref: Sha256 | None = None
    q1: TrustedQ1Execution | None = None
    q2: TrustedQ2Execution | None = None
    crash_bundle_ref: Sha256 | None = None
    crash_window_bound: int = Field(ge=1, le=MAX_WINDOW)
    m1_profile_ref: Sha256
    q2_profile_ref: Sha256
    replay_profile_ref: Sha256


@dataclass(frozen=True)
class ReplaySides:
    """A planned replay: its plan, both sealed journals and the judge
    input over them."""

    plan: ReplayPlan
    production: SealedJournal
    replay: SealedJournal
    judge_input: ReplayJudgeInput
    kernel_commit: str
    production_vm_instance_id: str
    replay_vm_instance_id: str


class UnknownStage2Execution(ValueError):
    """No published host authority for the bundle; no verdict is safe."""


def _lineage(**fields) -> str:
    return hashlib.sha256(canonical_json(fields)).hexdigest()


def _barrier_status(name: str, status: int) -> BarrierStatus:
    return BarrierStatus.ACKED if name == "Acked" and status == 0 \
        else BarrierStatus.FAILED


class _Evidence:
    """One verified bundle with its host facts and journal, opened once."""

    def __init__(self, bundle: VerifiedBundle, facts: Stage2HostFacts,
                 journal: SealedJournal | None) -> None:
        self.bundle = bundle
        self.facts = facts
        self.journal = journal

    def text(self, identity: str, artifact_type: str) -> str | None:
        if not any(a.descriptor.identity == identity for a in self.bundle.artifacts):
            return None
        return self.bundle.get(identity, expected_type=artifact_type).decode(
            "utf-8", errors="replace")


class ArtifactStage2Judge:
    """Stage2Judge over an immutable snapshot of published authority."""

    def __init__(self, artifacts: ArtifactStore, *,
                 executions: Mapping[str, Stage2Execution],
                 evidence: EvidenceStore | None = None) -> None:
        checked = {}
        for ref, value in executions.items():
            value = Stage2Execution.model_validate(value)
            if ref != value.bundle_ref:
                raise ValueError("execution key differs from its bundle")
            checked[ref] = value
        self.artifacts = artifacts
        self.evidence = evidence if evidence is not None else EvidenceStore(artifacts)
        self.executions = MappingProxyType(checked)

    # ------------------------------------------------------------ common

    def _execution(self, bundle_ref: str) -> Stage2Execution:
        try:
            return self.executions[bundle_ref]
        except KeyError as exc:
            raise UnknownStage2Execution(
                "bundle has no published Stage 2 authority") from exc

    def matches_execution(self, bundle_ref: str, *, job_id: str,
                          task_id: str) -> bool:
        x = self._execution(bundle_ref)
        return x.correlation.job_id == job_id and \
            x.correlation.task_id == task_id

    def _open(self, x: Stage2Execution, stack: list) -> _Evidence:
        bundle = self.evidence.verify(x.bundle_ref,
                                      expected_correlation=x.correlation)
        facts = Stage2HostFacts.model_validate_json(
            bundle.get(HOST_FACTS_ID, expected_type=HOST_FACTS_TYPE))
        if facts.step != x.step:
            raise ValueError("host facts name another step")
        report = getattr(facts, x.step)
        journal = None
        if report is not None:
            journal, tmp = open_journal(bundle, report.journal_name)
            stack.append(tmp)
        return _Evidence(bundle, facts, journal)

    def _rule_set(self, x: Stage2Execution
                  ) -> tuple[M1RuleSet, CompiledMutationRuleSet, MutationRuleSet]:
        compiled = load_record(self.artifacts, x.compiled.compiled_ref,
                               CompiledMutationRuleSet)
        rule_set = load_record(self.artifacts, x.compiled.rule_set_ref,
                               MutationRuleSet)
        if compiled.rule_set_ref != x.compiled.rule_set_ref:
            raise ValueError("compiled rule set names another rule set")
        intents = {i.intent_id: i for i in rule_set.intents}
        rules = tuple(RuleDefinition(
            rule_id=r.rule_id, intent_id=r.intent_id,
            message_type=RuleMessageType(
                intents[r.intent_id].selector.rpc.message_type))
            for r in compiled.rules)
        members: dict[str, list[str]] = {}
        for r in compiled.rules:
            members.setdefault(r.intent_id, []).append(r.rule_id)
        # An intent with no rule cannot be judged; M1 requires every
        # hypothesis intent to be declared, so it refuses such a set.
        m1 = M1RuleSet(
            candidate_id=x.candidate.candidate_id,
            rule_set_id=compiled.nfsprul1_ref, rules=rules,
            intents=tuple(IntentDefinition(intent_id=i, rule_ids=tuple(ids))
                          for i, ids in members.items()),
            hypotheses=tuple(HypothesisDefinition(
                hypothesis_id=h.hypothesis_id, intent_ids=h.intents)
                for h in rule_set.hypotheses))
        return m1, compiled, rule_set

    def _profile(self, x: Stage2Execution) -> M1JudgeProfile:
        return load_record(self.artifacts, x.m1_profile_ref, M1JudgeProfile)

    def _target_pcs(self, x: Stage2Execution) -> frozenset[int]:
        mapping = load_record(self.artifacts, x.mapping_ref, TargetPcMapping)
        if not mapping.verified or mapping.identity != x.identity or \
                mapping.target != x.candidate:
            raise ValueError("target mapping does not fit this execution")
        return frozenset(mapping.target_pcs)

    @staticmethod
    def _generation_key(identity: str, prefix: str) -> tuple[int, int]:
        suffix = identity.removeprefix(prefix)
        lane_text, separator, generation_text = suffix.partition(".")
        if not separator or not lane_text.isdigit() or \
                not generation_text.isdigit():
            raise ValueError(f"invalid generation artifact {identity!r}")
        lane, generation = int(lane_text), int(generation_text)
        if identity != f"{prefix}{lane}.{generation}":
            raise ValueError(f"non-canonical generation artifact {identity!r}")
        return lane, generation

    def _generation_artifacts(
            self, x: Stage2Execution, ev: _Evidence
            ) -> dict[tuple[int, int], tuple[PublishedCoverage,
                                             GenerationExecution]]:
        """Pair every generation's coverage with its host execution record."""
        coverage: dict[tuple[int, int], PublishedCoverage] = {}
        executions: dict[tuple[int, int], GenerationExecution] = {}
        for item in ev.bundle.artifacts:
            identity, artifact_type = (item.descriptor.identity,
                                       item.descriptor.type)
            if identity.startswith(GENERATION_COVERAGE_PREFIX):
                if artifact_type != GENERATION_COVERAGE_TYPE:
                    raise ValueError("generation coverage has another type")
                key = self._generation_key(identity,
                                           GENERATION_COVERAGE_PREFIX)
                if key in coverage:
                    raise ValueError("duplicate generation coverage")
                coverage[key] = PublishedCoverage.model_validate_json(
                    item.data)
            elif artifact_type == GENERATION_COVERAGE_TYPE:
                raise ValueError("generation coverage without its prefix")
            if identity.startswith(GENERATION_EXECUTION_PREFIX):
                if artifact_type != GENERATION_EXECUTION_TYPE:
                    raise ValueError("generation execution has another type")
                key = self._generation_key(identity,
                                           GENERATION_EXECUTION_PREFIX)
                if key in executions:
                    raise ValueError("duplicate generation execution")
                executions[key] = GenerationExecution.model_validate_json(
                    item.data)
            elif artifact_type == GENERATION_EXECUTION_TYPE:
                raise ValueError("generation execution without its prefix")
        if coverage.keys() != executions.keys():
            raise ValueError("coverage and execution generations differ")
        own = x.correlation
        execution_ids: set[int] = set()
        paired = {}
        for key in sorted(coverage):
            c, a = coverage[key].correlation, executions[key].correlation
            expected = (own.job_id, own.task_id, own.execution_harness_id,
                        own.vm_instance_id, *key)
            if (c.job_id, c.task_id, c.execution_harness_id, c.vm_instance_id,
                    c.lane, c.generation_id) != expected or c != a:
                raise ValueError("generation artifact correlation mismatch")
            if executions[key].execution_id in execution_ids:
                raise ValueError("generation execution ID is reused")
            execution_ids.add(executions[key].execution_id)
            paired[key] = coverage[key], executions[key]
        return paired

    @staticmethod
    def _journal_generation(
            x: Stage2Execution, ev: _Evidence, lane: int, generation: int
            ) -> tuple[SessionDelta, GenerationDelta] | None:
        found = [(session, session.generations[generation])
                 for session in ev.journal.sessions.values()
                 if session.binding.vm_instance_id
                 == x.correlation.vm_instance_id
                 and session.lane_id == lane
                 and generation in session.generations]
        if len(found) > 1:
            raise ValueError("a generation matches two journal sessions")
        return found[0] if found else None

    @staticmethod
    def _execution_valid(attestation: GenerationExecution,
                         generation: GenerationDelta | None) -> bool:
        return generation is not None and \
            attestation.program_digest == generation.program_digest and \
            attestation.activation == "Acked" and \
            attestation.activation_status == 0 and \
            attestation.deactivation == "Acked" and \
            attestation.deactivation_status == 0 and \
            attestation.executed and attestation.lease_cleared

    @staticmethod
    def _a053_generation_valid(
            x: Stage2Execution, session: SessionDelta | None,
            generation: GenerationDelta | None,
            attestation: GenerationExecution) -> bool:
        if x.candidate.candidate_id != "A-053":
            return True
        if session is None or generation is None or \
                attestation.program_sha256 != x.program_ref or \
                session.rejections or session.inconsistent or \
                generation.refusals or generation.summary is None:
            return False
        summary = generation.summary
        if summary.evidence_path_failures != 0 or \
                summary.outside_activation_window != 0 or \
                summary.closure.reason != "drained" or \
                summary.closure.reply_unresolved_count != 0:
            return False
        mutation = False
        for exposure in generation.exposures:
            context = exposure.record_context
            if context is None or context.direction != "c2s" or \
                    context.message_type != "call" or \
                    context.program != 100003 or context.version != 4 or \
                    context.procedure != 1 or exposure.terminal != "complete":
                continue
            for application in exposure.applications:
                if application.rule_id == "r000" and \
                        application.semantic_path == (
                            "nfs4.request.EXCHANGE_ID.args.eia_clientowner."
                            "co_ownerid") and \
                        len(application.original_value) == 32 and \
                        application.mutated_value == "61":
                    mutation = True
        if not mutation:
            return False
        statuses: dict[int, list[int]] = {}
        for reply in generation.protocol_replies:
            context = reply.record_context
            if reply.minor_version != 1 or context.direction != "s2c" or \
                    context.message_type != "reply" or \
                    context.program != 100003 or context.version != 4 or \
                    context.procedure != 1:
                return False
            for operation in reply.operations:
                if operation.opcode in (42, 43, 53, 58):
                    statuses.setdefault(operation.opcode, []).append(
                        operation.status)
        return all(statuses.get(opcode) and not any(statuses[opcode])
                   for opcode in (42, 43, 53, 58))

    @staticmethod
    def _valid_generation(
            x: Stage2Execution, session: SessionDelta | None,
            generation: GenerationDelta | None,
            attestation: GenerationExecution) -> bool:
        return ArtifactStage2Judge._execution_valid(
            attestation, generation) and \
            ArtifactStage2Judge._a053_generation_valid(
                x, session, generation, attestation)

    # ------------------------------------------------------------ M1 window

    @staticmethod
    def _mutation_evidence(x: Stage2Execution, journal: SealedJournal,
                           session: SessionDelta, gen: GenerationDelta,
                           corr: ProgramGenerationCorrelation
                           ) -> MutationEvidence:
        issues = []
        if session.rejections:
            issues.append(JournalIssue.SINK_REJECTION)
        if session.inconsistent:
            issues.append(JournalIssue.INTERNAL_INCONSISTENCY)
        exposures = []
        forwards = []
        for e in gen.exposures:
            exposures.append(ExposureIntent(
                event_seq=e.event_seq, correlation=corr,
                batch_id=str(e.batch_id),
                semantic_signature=hashlib.sha256(canonical_json(
                    [i.model_dump(mode="json") for i in e.signature])).hexdigest(),
                applications=tuple(RuleApplication(rule_id=rule)
                                   for rule, _, _ in e.originals)))
            if e.terminal is not None and e.terminal_seq is not None:
                forwards.append(ForwardEvent(
                    event_seq=e.terminal_seq, correlation=corr,
                    batch_id=str(e.batch_id),
                    outcome=ForwardOutcome(e.terminal)))
        summary = None
        if gen.summary is not None and gen.summary_seq is not None:
            s = gen.summary
            summary = GenerationComplete(
                event_seq=gen.summary_seq, correlation=corr,
                exposure_batch_count=s.exposure_batch_count,
                evidence_path_failures=s.evidence_path_failures,
                summarized_rule_ids=tuple(r.rule_id for r in s.resolver_summary),
                closure=GenerationClosure(
                    reason=ClosureReason(s.closure.reason),
                    drain_bound=s.closure.drain_bound_ms,
                    reply_unresolved_count=s.closure.reply_unresolved_count))
        return MutationEvidence(
            # The session's RULESET names the candidate it was compiled
            # for; another one is an identity mismatch, not this job's.
            candidate_id=session.candidate_id,
            execution_harness_id=x.correlation.execution_harness_id,
            correlation=corr, journal_sha256=journal.manifest_sha256(),
            journal_integrity=JournalIntegrityStatus.VALID,
            exposure_intents=tuple(exposures), forward_events=tuple(forwards),
            generation_complete=summary, last_generation_event_seq=gen.last_seq,
            issues=tuple(issues))

    def _window(self, x: Stage2Execution, journal: SealedJournal,
                entries: list[tuple[Barrier | None,
                                    tuple[SessionDelta, GenerationDelta] | None]],
                *, lane: int, rule_set_id: str) -> M1Window:
        """A CrashContextWindow (01 §8.1) of ``entries`` in order.  An entry
        whose MutationDelta is not in the journal stays in the window with
        unknown journal integrity, so it can never be NOT_APPLIED; it gets
        a generation id no journal can have."""
        vm = x.correlation.vm_instance_id
        generations = []
        for index, (barrier, pair) in enumerate(entries):
            if pair is not None:
                session, gen = pair
                corr = ProgramGenerationCorrelation(
                    vm_instance_id=vm, lane_id=lane, proc_id=0,
                    kcov_generation=gen.kcov_generation,
                    rule_set_id=session.binding.rule_set_id,
                    program_digest=gen.program_digest)
                evidence = self._mutation_evidence(x, journal, session, gen, corr)
                if barrier is not None:
                    barriers = BarrierResults(
                        activation=_barrier_status(barrier.activation,
                                                   barrier.activation_status),
                        deactivation=_barrier_status(barrier.deactivation,
                                                     barrier.deactivation_status))
                else:
                    # The host stored GENERATION_OPEN before the executor
                    # got its ACK; DRAINING likewise for deactivation.
                    barriers = BarrierResults(
                        activation=BarrierStatus.ACKED,
                        deactivation=BarrierStatus.ACKED
                        if gen.draining_seq is not None else BarrierStatus.UNKNOWN)
            else:
                corr = ProgramGenerationCorrelation(
                    vm_instance_id=vm, lane_id=lane, proc_id=0,
                    kcov_generation=UINT64_MAX - index, rule_set_id=rule_set_id,
                    program_digest="0" * 64)
                evidence = MutationEvidence(
                    candidate_id=x.candidate.candidate_id,
                    execution_harness_id=x.correlation.execution_harness_id,
                    correlation=corr, journal_sha256=journal.manifest_sha256(),
                    journal_integrity=JournalIntegrityStatus.UNKNOWN)
                barriers = BarrierResults(activation=BarrierStatus.UNKNOWN,
                                          deactivation=BarrierStatus.UNKNOWN)
            generations.append(ProgramGenerationExecution(
                window_index=index, correlation=corr, barriers=barriers,
                mutation_evidence=evidence))
        return M1Window(bound=len(generations), generations=tuple(generations))

    def _m1(self, x: Stage2Execution, ev: _Evidence, m1_rules: M1RuleSet,
            window: M1Window) -> M1Decision:
        return m1_evaluate(M1JudgeInput(
            candidate_id=x.candidate.candidate_id,
            execution_harness_id=x.correlation.execution_harness_id,
            evidence_manifest_sha256=ev.bundle.manifest_sha256,
            evidence_verified=True, rule_set=m1_rules,
            profile=self._profile(x), crash_context=window))

    def _program_window(self, x: Stage2Execution, ev: _Evidence,
                        execprog_id: str, m1_rules: M1RuleSet
                        ) -> M1Window | None:
        """The program generations one syz-execprog run printed barriers
        for, joined to the journal.  None when the run left no output."""
        text = ev.text(execprog_id, EXECPROG_TYPE)
        if text is None:
            return None
        barriers = parse_execprog_barriers(text)
        if not barriers or len(barriers) > MAX_WINDOW:
            raise ValueError(f"{execprog_id}: {len(barriers)} program barriers")
        vm, lane = x.correlation.vm_instance_id, x.correlation.lane
        entries = []
        for b in barriers:
            pair = None
            if b.executed and len(b.program_digest) == 64:
                pair = ev.journal.find(vm_instance_id=vm, lane_id=lane,
                                       kcov_generation=b.kcov_generation,
                                       program_digest=b.program_digest)
            entries.append((b, pair))
        return self._window(x, ev.journal, entries, lane=lane,
                            rule_set_id=m1_rules.rule_set_id)

    # ------------------------------------------------------------ gate

    def judge_gate(self, bundle_ref: str, *, plan_ref: str,
                   candidate_id: str, compiled: CompiledRuleSet,
                   versions: JudgeVersions) -> GateRun:
        x = self._execution(bundle_ref)
        if x.step != "gate" or x.q1 is None:
            raise UnknownStage2Execution("bundle is not a gate repetition")
        q1 = ArtifactQ1Judge(self.artifacts, receipts={bundle_ref: x.q1},
                             evidence=self.evidence).judge(
            bundle_ref, plan_ref, candidate_id, versions)
        stack: list = []
        try:
            if compiled != x.compiled or plan_ref != x.plan_ref or \
                    candidate_id != x.candidate.candidate_id:
                raise ValueError("request does not match the published gate")
            m1_rules, _, rule_set = self._rule_set(x)
            ev = self._open(x, stack)
            window = self._program_window(x, ev, SCENARIO_EXECPROG_ID,
                                          m1_rules)
            if window is None:
                raise ValueError("the scenario run left no output")
            decision = self._m1(x, ev, m1_rules, window)
            rules, intents = self._rule_vectors(decision, rule_set)
            ambient = self._ambient(x, ev, m1_rules)
            return GateRun(bundle_ref=bundle_ref, q1=q1,
                           m1_verdict_id=decision.verdict_id, rules=rules,
                           intents=intents, ambient=ambient)
        except OSError:
            raise
        except _INVALID as exc:
            return self._invalid_gate(x, q1, compiled, exc)
        finally:
            for tmp in stack:
                tmp.cleanup()

    @staticmethod
    def _rule_vectors(decision: M1Decision, rule_set: MutationRuleSet
                      ) -> tuple[tuple[RuleM1, ...], tuple[IntentM1, ...]]:
        rules = tuple(RuleM1(rule_id=r.rule_id, intent_id=r.intent_id,
                             status=r.status.value)
                      for r in decision.window_rule_results)
        by_intent: dict[str, list[M1Status]] = {}
        for r in decision.window_rule_results:
            by_intent.setdefault(r.intent_id, []).append(r.status)
        baseline = {i.intent_id: i.targets_baseline_traffic
                    for i in rule_set.intents}
        intents = tuple(IntentM1(
            intent_id=intent, status=aggregate_intent(tuple(statuses)).value,
            targets_baseline_traffic=baseline[intent])
            for intent, statuses in sorted(by_intent.items()))
        return rules, intents

    def _invalid_gate(self, x: Stage2Execution, q1: Q1Result,
                      compiled: CompiledRuleSet, exc: BaseException) -> GateRun:
        """Every rule INCONCLUSIVE: the gate reruns (01 §3, row 3)."""
        try:
            record = load_record(self.artifacts, x.compiled.compiled_ref,
                                 CompiledMutationRuleSet)
            rule_set = load_record(self.artifacts, x.compiled.rule_set_ref,
                                   MutationRuleSet)
            pairs = tuple((r.rule_id, r.intent_id) for r in record.rules)
            baseline = {i.intent_id: i.targets_baseline_traffic
                        for i in rule_set.intents}
        except _INVALID:
            pairs, baseline = (), {}
        rules = tuple(RuleM1(rule_id=r, intent_id=i, status="inconclusive")
                      for r, i in pairs)
        intents = tuple(IntentM1(intent_id=i, status="inconclusive",
                                 targets_baseline_traffic=baseline.get(i, True))
                        for i in sorted({i for _, i in pairs}))
        if not rules:
            # Nothing to name: still never a pass.
            rules = (RuleM1(rule_id="unknown", intent_id="unknown",
                            status="inconclusive"),)
        return GateRun(
            bundle_ref=x.bundle_ref, q1=q1,
            m1_verdict_id=_lineage(kind="gate_m1_invalid",
                                   bundle_ref=x.bundle_ref,
                                   compiled=compiled.model_dump(mode="json"),
                                   error=type(exc).__name__),
            rules=rules, intents=intents,
            ambient=("ambient_control_unavailable",))

    def _ambient(self, x: Stage2Execution, ev: _Evidence,
                 m1_rules: M1RuleSet) -> tuple[str, ...]:
        """01 §3 ambient control flags of the neutral run.  They are
        recorded and never change the route."""
        flags: list[str] = []
        try:
            raw = ev.bundle.get(NEUTRAL_COVERAGE_ID,
                                expected_type=NEUTRAL_COVERAGE_TYPE)
            coverage = PublishedCoverage.model_validate_json(raw)
            c, own = coverage.correlation, x.correlation
            if (c.job_id, c.task_id, c.execution_harness_id,
                    c.vm_instance_id) != (own.job_id, own.task_id,
                                          own.execution_harness_id,
                                          own.vm_instance_id):
                raise ValueError("neutral coverage of another execution")
            if self._target_pcs(x) & set(coverage.pcs):
                flags.append("q1_preservation_unverifiable")
            window = self._program_window(x, ev, NEUTRAL_EXECPROG_ID,
                                          m1_rules)
            if window is None:
                raise ValueError("the neutral run left no output")
            decision = self._m1(x, ev, m1_rules, window)
        except OSError:
            raise
        except _INVALID:
            return tuple(flags) + ("ambient_control_unavailable",)
        for r in decision.window_rule_results:
            if r.status is M1Status.APPLIED:
                flags.append(f"ambient_applied:{r.rule_id}")
            elif r.status is M1Status.INCONCLUSIVE:
                flags.append(f"ambient_applied_unknown:{r.rule_id}")
        return tuple(flags)

    # ------------------------------------------------------------ campaign

    def judge_campaign(self, bundle_ref: str, *, candidate_id: str,
                       compiled: CompiledRuleSet) -> CampaignSegment:
        x = self._execution(bundle_ref)
        if x.step != "campaign" or x.q2 is None:
            raise UnknownStage2Execution("bundle is not a campaign segment")
        q2 = ArtifactQ2Judge(self.artifacts, receipts={bundle_ref: x.q2},
                             evidence=self.evidence).judge(
            bundle_ref, x.q2_profile_ref)
        fields = dict(bundle_ref=bundle_ref, q2_verdict_id=q2.verdict_id,
                      q2_status=q2.status.value, q2_reason=q2.reason,
                      attribution_quality=q2.attribution_quality,
                      attribution_warnings=q2.attribution_warnings)
        stack: list = []
        executions = 0
        try:
            if compiled != x.compiled or candidate_id != x.candidate.candidate_id:
                raise ValueError("request does not match the published campaign")
            ev = self._open(x, stack)
            executions = ev.facts.campaign.executions
            m1_rules, _, _ = self._rule_set(x)
            counts, generation_ids = self._generation_counts(x, ev, m1_rules)
            applied: tuple[str, ...] = ()
            window_id = None
            if q2.status is Q2Status.OBSERVED:
                applied, window_id = self._crash_window(x, ev, m1_rules)
            return CampaignSegment(
                **fields, executions=executions,
                m1_verdict_id=_lineage(kind="campaign_m1", window=window_id,
                                       generations=generation_ids),
                crash_window_applied=applied, **counts)
        except OSError:
            raise
        except _INVALID as exc:
            return CampaignSegment(
                **fields, executions=executions,
                m1_verdict_id=_lineage(kind="campaign_m1_invalid",
                                       bundle_ref=bundle_ref,
                                       error=type(exc).__name__),
                reached_generations=0, hypothesis_applied=0,
                hypothesis_not_applied=0, hypothesis_inconclusive=0)
        finally:
            for tmp in stack:
                tmp.cleanup()

    def _generation_counts(self, x: Stage2Execution, ev: _Evidence,
                           m1_rules: M1RuleSet) -> tuple[dict, list[str]]:
        """01 §3, §12: hypothesis M1 of every reached program generation."""
        targets = self._target_pcs(x)
        reached = applied = not_applied = inconclusive = 0
        ids: list[str] = []
        for (lane, generation_id), (coverage, attestation) in \
                self._generation_artifacts(x, ev).items():
            c = coverage.correlation
            if not targets & set(coverage.pcs):
                continue
            pair = self._journal_generation(
                x, ev, lane, generation_id)
            reached += 1
            window = self._window(x, ev.journal, [(None, pair)], lane=c.lane,
                                  rule_set_id=m1_rules.rule_set_id)
            decision = self._m1(x, ev, m1_rules, window)
            valid = self._valid_generation(
                x, pair[0] if pair else None, pair[1] if pair else None,
                attestation)
            ids.append(_lineage(kind="campaign_generation",
                                m1=decision.verdict_id, valid=valid))
            statuses = [h.status for h in decision.window_hypothesis_results]
            if not valid:
                inconclusive += 1
            elif M1Status.APPLIED in statuses:
                applied += 1
            elif statuses and all(s is M1Status.NOT_APPLIED for s in statuses):
                not_applied += 1
            else:
                inconclusive += 1
        return dict(reached_generations=reached, hypothesis_applied=applied,
                    hypothesis_not_applied=not_applied,
                    hypothesis_inconclusive=inconclusive), ids

    def _crash_window(self, x: Stage2Execution, ev: _Evidence,
                      m1_rules: M1RuleSet) -> tuple[tuple[str, ...], str | None]:
        """Rules APPLIED in the crash's CrashContextWindow (01 §8.1).  No
        crash log, or a window joined to no MutationDelta, applies none:
        the signal stays a triage item."""
        log = ev.text(CRASH_LOG_ID, CRASH_LOG_TYPE)
        if log is None:
            return (), None
        window = parse_crash_context(
            log, vm_instance_id=x.correlation.vm_instance_id,
            bound=x.crash_window_bound)
        try:
            plan = plan_replay(ev.journal, window)
        except PlanError:
            return (), None
        entries = []
        for entry, position in zip(window.entries, plan.positions):
            pair = None
            if position.proxy_session_id is not None:
                session = ev.journal.sessions[position.proxy_session_id]
                pair = (session, session.generations[position.kcov_generation])
            entries.append((entry.barrier, pair))
        decision = self._m1(x, ev, m1_rules,
                            self._window(x, ev.journal, entries,
                                         lane=window.lane_id,
                                         rule_set_id=m1_rules.rule_set_id))
        return tuple(r.rule_id for r in decision.window_rule_results
                     if r.status is M1Status.APPLIED), decision.verdict_id

    # ------------------------------------------------------------ replay

    def _replay_executions(self, bundle_ref: str, crash_bundle_ref: str
                           ) -> tuple[Stage2Execution, Stage2Execution,
                                      ReplayJudgeProfile]:
        x = self._execution(bundle_ref)
        crash = self._execution(crash_bundle_ref)
        if x.step != "replay" or crash.step != "campaign":
            raise UnknownStage2Execution("not a replay of a campaign bundle")
        return x, crash, load_record(self.artifacts, x.replay_profile_ref,
                                     ReplayJudgeProfile)

    def _replay_input(self, x: Stage2Execution, crash: Stage2Execution,
                      profile: ReplayJudgeProfile, crash_bundle_ref: str,
                      compiled: CompiledRuleSet, stack: list
                      ) -> tuple[ReplayJudgeInput, ReplaySides | None]:
        """The judge input of a published replay, and its two sides when
        the replay was planned.  The journals stay open until ``stack`` is
        cleaned up."""
        if compiled != x.compiled or compiled != crash.compiled or \
                x.crash_bundle_ref != crash_bundle_ref:
            raise ValueError("request does not match the published replay")
        ev = self._open(x, stack)
        facts = ev.facts
        if facts.plan_error is not None:
            return invalid_plan_input(
                candidate_id=x.candidate.candidate_id,
                production_manifest_sha256=crash_bundle_ref,
                reason=InvalidReason.DELTA_CORRUPT, profile=profile,
                evidence_verified=True), None
        production = self._open(crash, stack)
        log = production.text(CRASH_LOG_ID, CRASH_LOG_TYPE)
        if log is None:
            raise ValueError("the crash bundle has no crash log")
        window = parse_crash_context(
            log, vm_instance_id=crash.correlation.vm_instance_id,
            bound=x.crash_window_bound)
        plan = plan_replay(production.journal, window)
        text = ev.text(REPLAY_EXECPROG_ID, EXECPROG_TYPE) or ""
        compat = facts.compatibility
        inputs = judge_input(
            plan, production.journal, ev.journal,
            replay_vm_instance_id=x.correlation.vm_instance_id,
            replay_lane_id=x.correlation.lane,
            replay_barriers=parse_execprog_barriers(text),
            production_termination=facts.production_end,
            replay_termination=facts.replay.replay_end,
            compatibility=GateCompatibility(compat.ok, compat.reason,
                                            compat.line),
            evidence_verified=True, profile=profile,
            fixture_failed=facts.replay.fixture_failed)
        return inputs, ReplaySides(
            plan=plan, production=production.journal, replay=ev.journal,
            judge_input=inputs, kernel_commit=x.identity.kernel_commit,
            production_vm_instance_id=crash.correlation.vm_instance_id,
            replay_vm_instance_id=x.correlation.vm_instance_id)

    def judge_replay(self, bundle_ref: str, *, crash_bundle_ref: str,
                     compiled: CompiledRuleSet) -> ReplayOutcome:
        x, crash, profile = self._replay_executions(bundle_ref,
                                                    crash_bundle_ref)
        stack: list = []
        try:
            inputs, _ = self._replay_input(x, crash, profile,
                                           crash_bundle_ref, compiled, stack)
            result = replay_evaluate(inputs)
        except OSError:
            raise
        except _INVALID as exc:
            return ReplayOutcome(
                verdict_id=_lineage(kind="replay_invalid", bundle_ref=bundle_ref,
                                    crash_bundle_ref=crash_bundle_ref,
                                    error=type(exc).__name__),
                status=REPLAY_EVIDENCE_REJECTED, reason=type(exc).__name__)
        finally:
            for tmp in stack:
                tmp.cleanup()
        if result.semantic_verdict is None:
            return ReplayOutcome(
                verdict_id=result.verdict_id, status=REPLAY_EVIDENCE_REJECTED,
                reason=",".join(p.value for p in result.invalid_evidence))
        reasons = ",".join(r.value for r in result.invalid_reasons)
        return ReplayOutcome(verdict_id=result.verdict_id,
                             status=result.semantic_verdict.value.lower(),
                             reason=reasons or None)

    @contextmanager
    def replay_sides(self, bundle_ref: str, *, crash_bundle_ref: str,
                     compiled: CompiledRuleSet) -> Iterator[ReplaySides]:
        """The planned sides of a published replay, for the M7 gate
        (03-nfs-proxy/06 §30): the journals are open inside the block.
        An unplanned replay raises ValueError; so does evidence the judge
        would reject."""
        x, crash, profile = self._replay_executions(bundle_ref,
                                                    crash_bundle_ref)
        stack: list = []
        try:
            _, sides = self._replay_input(x, crash, profile,
                                          crash_bundle_ref, compiled, stack)
            if sides is None:
                raise ValueError("the replay was not planned")
            yield sides
        finally:
            for tmp in stack:
                tmp.cleanup()


__all__ = ["ArtifactStage2Judge", "ReplaySides", "Stage2Execution",
           "UnknownStage2Execution"]
