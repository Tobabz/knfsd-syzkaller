"""Bounded, pure M1 decision kernel (01 architecture §7 and §11.1).

The input is a projection of an already sealed evidence bundle.  This module
does not parse a live journal, contact a guest, establish host durability, or
seal artifacts.  The trusted Controller adapter must verify the manifest and
project every committed generation event, rejection, and integrity finding
into these models.  In particular, ``evidence_verified`` is not a guest claim.

M1 answers whether a mutation was applied.  Delivery is reconstructed for
each durable exposure batch and remains a separate result. Before a terminal
summary, missing forwarding evidence yields ``DeliveryState.UNKNOWN`` without
weakening an otherwise valid ``M1Status.APPLIED`` verdict. A terminal summary
requires a forward outcome for every exposure batch.
"""

from __future__ import annotations

import enum
from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .data import canonical_json


MAX_IDENTIFIER_BYTES = 256
MAX_RULES = 256
MAX_INTENTS = 256
MAX_HYPOTHESES = 256
MAX_GENERATIONS = 64
MAX_BATCHES_PER_GENERATION = 4096
MAX_APPLICATIONS_PER_BATCH = 256
MAX_JOURNAL_ISSUES = 256

Identifier = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_IDENTIFIER_BYTES,
        pattern=r"^[^\s\x00-\x1f\x7f]+$",
    ),
]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Count = Annotated[int, Field(ge=0, le=2**64 - 1)]
WindowIndex = Annotated[int, Field(ge=0, lt=MAX_GENERATIONS)]


def _digest(value: object) -> str:
    return sha256(canonical_json(value)).hexdigest()


class _Record(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        validate_default=True,
        revalidate_instances="always",
        allow_inf_nan=False,
    )

    @property
    def digest(self) -> str:
        return _digest(self)


class M1Status(str, enum.Enum):
    APPLIED = "applied"
    NOT_APPLIED = "not_applied"
    INCONCLUSIVE = "inconclusive"


class DeliveryState(str, enum.Enum):
    COMPLETE = "complete"
    FAILED = "failed"
    UNKNOWN = "unknown"


class BarrierStatus(str, enum.Enum):
    ACKED = "acked"
    FAILED = "failed"
    UNKNOWN = "unknown"


class JournalIntegrityStatus(str, enum.Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class RuleMessageType(str, enum.Enum):
    CALL = "call"
    REPLY = "reply"


class ClosureReason(str, enum.Enum):
    DRAINED = "drained"
    REPLY_UNRESOLVED = "reply_unresolved"
    ABORTED = "aborted"


class ForwardOutcome(str, enum.Enum):
    COMPLETE = "complete"
    FAILED = "failed"


class JournalIssue(str, enum.Enum):
    """Host-recorded defects omitted from the minimum event projection."""

    MALFORMED_EVENT = "malformed_event"
    EVENT_CONFLICT = "event_conflict"
    SEQUENCE_VIOLATION = "sequence_violation"
    BATCH_CONFLICT = "batch_conflict"
    CORRELATION_CONFLICT = "correlation_conflict"
    POST_SUMMARY_EVENT = "post_summary_event"
    POST_CLOSE_REJECTION = "post_close_rejection"
    SINK_REJECTION = "sink_rejection"
    INTERNAL_INCONSISTENCY = "internal_inconsistency"


class M1Reason(str, enum.Enum):
    """Stable reasons for rule-level ``INCONCLUSIVE`` results."""

    EVIDENCE_UNVERIFIED = "evidence_unverified"
    EVIDENCE_IDENTITY_MISMATCH = "evidence_identity_mismatch"
    JOURNAL_INTEGRITY_INVALID = "journal_integrity_invalid"
    JOURNAL_INTEGRITY_UNKNOWN = "journal_integrity_unknown"
    CORRELATION_MISMATCH = "correlation_mismatch"
    JOURNAL_CONFLICT = "journal_conflict"
    SEQUENCE_VIOLATION = "sequence_violation"
    POST_SUMMARY_EVENT = "post_summary_event"
    POST_CLOSE_REJECTION = "post_close_rejection"
    INVALID_EVIDENCE = "invalid_evidence"
    INTERNAL_INCONSISTENCY = "internal_inconsistency"
    ACTIVATION_BARRIER_FAILED = "activation_barrier_failed"
    ACTIVATION_BARRIER_UNKNOWN = "activation_barrier_unknown"
    DEACTIVATION_BARRIER_FAILED = "deactivation_barrier_failed"
    DEACTIVATION_BARRIER_UNKNOWN = "deactivation_barrier_unknown"
    GENERATION_COMPLETE_MISSING = "generation_complete_missing"
    GENERATION_COMPLETE_NOT_TERMINAL = "generation_complete_not_terminal"
    GENERATION_COMPLETE_INVALID = "generation_complete_invalid"
    EVIDENCE_PATH_DEGRADED = "evidence_path_degraded"
    CLOSURE_NOT_CLEAN = "closure_not_clean"


class AggregateReason(str, enum.Enum):
    CHILD_INCONCLUSIVE = "child_inconclusive"
    GENERATION_INCONCLUSIVE = "generation_inconclusive"


# ---------------------------------------------------------------- rule-set membership


class RuleDefinition(_Record):
    """The only CompiledMutationRule fields the M1 kernel consumes."""

    rule_id: Identifier
    intent_id: Identifier
    message_type: RuleMessageType


class IntentDefinition(_Record):
    intent_id: Identifier
    rule_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=MAX_RULES)]

    @field_validator("rule_ids")
    @classmethod
    def _canonical_rules(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(values))

    @model_validator(mode="after")
    def _unique_rules(self) -> Self:
        if len(set(self.rule_ids)) != len(self.rule_ids):
            raise ValueError("an intent cannot reference a rule more than once")
        return self


class HypothesisDefinition(_Record):
    hypothesis_id: Identifier
    intent_ids: Annotated[
        tuple[Identifier, ...], Field(min_length=1, max_length=MAX_INTENTS)
    ]
    requirement: Literal["all"] = "all"

    @field_validator("intent_ids")
    @classmethod
    def _canonical_intents(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(values))

    @model_validator(mode="after")
    def _unique_intents(self) -> Self:
        if len(set(self.intent_ids)) != len(self.intent_ids):
            raise ValueError("a hypothesis cannot reference an intent more than once")
        return self


class M1RuleSet(_Record):
    """Canonical M1 projection of a compiled rule set.

    Parent IDs and membership vectors deliberately overlap.  Their exact
    agreement proves that every declared rule has one, and only one, intent;
    the judge never guesses a missing relationship.
    """

    schema_version: Literal["m1-rule-set-v1"] = "m1-rule-set-v1"
    candidate_id: Identifier
    rule_set_id: Identifier
    rules: Annotated[tuple[RuleDefinition, ...], Field(min_length=1, max_length=MAX_RULES)]
    intents: Annotated[
        tuple[IntentDefinition, ...], Field(min_length=1, max_length=MAX_INTENTS)
    ]
    hypotheses: Annotated[
        tuple[HypothesisDefinition, ...], Field(max_length=MAX_HYPOTHESES)
    ] = ()

    @field_validator("rules")
    @classmethod
    def _canonical_rule_definitions(
        cls, values: tuple[RuleDefinition, ...]
    ) -> tuple[RuleDefinition, ...]:
        return tuple(sorted(values, key=lambda value: value.rule_id))

    @field_validator("intents")
    @classmethod
    def _canonical_intent_definitions(
        cls, values: tuple[IntentDefinition, ...]
    ) -> tuple[IntentDefinition, ...]:
        return tuple(sorted(values, key=lambda value: value.intent_id))

    @field_validator("hypotheses")
    @classmethod
    def _canonical_hypothesis_definitions(
        cls, values: tuple[HypothesisDefinition, ...]
    ) -> tuple[HypothesisDefinition, ...]:
        return tuple(sorted(values, key=lambda value: value.hypothesis_id))

    @model_validator(mode="after")
    def _complete_unique_membership(self) -> Self:
        rule_ids = tuple(rule.rule_id for rule in self.rules)
        intent_ids = tuple(intent.intent_id for intent in self.intents)
        hypothesis_ids = tuple(item.hypothesis_id for item in self.hypotheses)
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("duplicate declared rule_id")
        if len(set(intent_ids)) != len(intent_ids):
            raise ValueError("duplicate declared intent_id")
        if len(set(hypothesis_ids)) != len(hypothesis_ids):
            raise ValueError("duplicate declared hypothesis_id")

        declared_rules = {rule.rule_id: rule for rule in self.rules}
        memberships = Counter(
            rule_id for intent in self.intents for rule_id in intent.rule_ids
        )
        if set(memberships) != set(declared_rules):
            raise ValueError("intent membership must reference every and only declared rule")
        if any(count != 1 for count in memberships.values()):
            raise ValueError("every rule must belong to exactly one intent")
        for intent in self.intents:
            for rule_id in intent.rule_ids:
                if declared_rules[rule_id].intent_id != intent.intent_id:
                    raise ValueError("rule parent intent conflicts with intent membership")

        known_intents = set(intent_ids)
        for hypothesis in self.hypotheses:
            if not set(hypothesis.intent_ids).issubset(known_intents):
                raise ValueError("hypothesis references an undeclared intent")
        return self


# ---------------------------------------------------------------- sealed evidence projection


class ProgramGenerationCorrelation(_Record):
    vm_instance_id: Identifier
    lane_id: Count
    proc_id: Count
    kcov_generation: Count
    rule_set_id: Identifier
    program_digest: Digest


class BarrierResults(_Record):
    activation: BarrierStatus
    deactivation: BarrierStatus


class RuleApplication(_Record):
    rule_id: Identifier


class ExposureIntent(_Record):
    """One committed host-journal EXPOSURE_INTENT projection."""

    event_seq: Count
    correlation: ProgramGenerationCorrelation
    batch_id: Identifier
    semantic_signature: Digest
    applications: Annotated[
        tuple[RuleApplication, ...],
        Field(min_length=1, max_length=MAX_APPLICATIONS_PER_BATCH),
    ]

    @field_validator("applications")
    @classmethod
    def _canonical_applications(
        cls, values: tuple[RuleApplication, ...]
    ) -> tuple[RuleApplication, ...]:
        # Multiplicity is meaningful and is intentionally retained.
        return tuple(sorted(values, key=lambda value: value.rule_id))


class ForwardEvent(_Record):
    event_seq: Count
    correlation: ProgramGenerationCorrelation
    batch_id: Identifier
    outcome: ForwardOutcome


class GenerationClosure(_Record):
    reason: ClosureReason
    drain_bound: Count = 0
    reply_unresolved_count: Count = 0


class GenerationComplete(_Record):
    """Minimum GENERATION_COMPLETE facts needed for negative evidence."""

    event_seq: Count
    correlation: ProgramGenerationCorrelation
    exposure_batch_count: Count
    evidence_path_failures: Count
    summarized_rule_ids: Annotated[
        tuple[Identifier, ...], Field(max_length=MAX_RULES)
    ]
    closure: GenerationClosure

    @field_validator("summarized_rule_ids")
    @classmethod
    def _canonical_summaries(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        # Duplicates remain visible to the judge as invalid summary evidence.
        return tuple(sorted(values))


class MutationEvidence(_Record):
    """A bounded semantic projection of one sealed generation journal.

    ``last_generation_event_seq`` comes from the verified full journal, which
    can contain event types intentionally absent from this minimum projection.
    ``issues`` carries host-side rejection/conflict facts that are not accepted
    journal events and therefore cannot be inferred from sequence numbers.
    """

    schema_version: Literal["mutation-evidence-m1-v1"] = "mutation-evidence-m1-v1"
    candidate_id: Identifier
    execution_harness_id: Digest
    correlation: ProgramGenerationCorrelation
    journal_sha256: Digest
    journal_integrity: JournalIntegrityStatus
    exposure_intents: Annotated[
        tuple[ExposureIntent, ...], Field(max_length=MAX_BATCHES_PER_GENERATION)
    ] = ()
    forward_events: Annotated[
        tuple[ForwardEvent, ...], Field(max_length=MAX_BATCHES_PER_GENERATION * 2)
    ] = ()
    generation_complete: GenerationComplete | None = None
    last_generation_event_seq: Count | None = None
    issues: Annotated[
        tuple[JournalIssue, ...], Field(max_length=MAX_JOURNAL_ISSUES)
    ] = ()

    @field_validator("exposure_intents")
    @classmethod
    def _canonical_exposures(
        cls, values: tuple[ExposureIntent, ...]
    ) -> tuple[ExposureIntent, ...]:
        return tuple(sorted(values, key=lambda value: (value.event_seq, value.batch_id)))

    @field_validator("forward_events")
    @classmethod
    def _canonical_forwards(
        cls, values: tuple[ForwardEvent, ...]
    ) -> tuple[ForwardEvent, ...]:
        return tuple(
            sorted(values, key=lambda value: (value.event_seq, value.batch_id, value.outcome.value))
        )

    @field_validator("issues")
    @classmethod
    def _canonical_issues(
        cls, values: tuple[JournalIssue, ...]
    ) -> tuple[JournalIssue, ...]:
        return tuple(sorted(values, key=lambda value: value.value))


class ProgramGenerationExecution(_Record):
    window_index: WindowIndex
    correlation: ProgramGenerationCorrelation
    barriers: BarrierResults
    mutation_evidence: MutationEvidence


class CrashContextWindow(_Record):
    """Host-preserved order for one VM/lane/proc, bounded by job policy."""

    bound: Annotated[int, Field(ge=1, le=MAX_GENERATIONS)]
    generations: Annotated[
        tuple[ProgramGenerationExecution, ...],
        Field(min_length=1, max_length=MAX_GENERATIONS),
    ]

    @field_validator("generations")
    @classmethod
    def _canonical_generations(
        cls, values: tuple[ProgramGenerationExecution, ...]
    ) -> tuple[ProgramGenerationExecution, ...]:
        return tuple(sorted(values, key=lambda value: value.window_index))

    @model_validator(mode="after")
    def _bounded_order(self) -> Self:
        if len(self.generations) > self.bound:
            raise ValueError("CrashContextWindow exceeds its recorded bound")
        indexes = tuple(item.window_index for item in self.generations)
        if indexes != tuple(range(len(indexes))):
            raise ValueError("window_index values must be unique and contiguous from zero")
        scopes = {
            (
                item.correlation.vm_instance_id,
                item.correlation.lane_id,
                item.correlation.proc_id,
            )
            for item in self.generations
        }
        if len(scopes) != 1:
            raise ValueError(
                "CrashContextWindow must remain within one VM/lane/proc scope"
            )
        return self


class M1JudgeProfile(_Record):
    """Versioned policy identity; v1 verdict semantics cannot be weakened."""

    schema_version: Literal["m1-judge-profile-v1"] = "m1-judge-profile-v1"
    name: Identifier
    revision: Identifier
    application_contract: Literal["host-durable-exposure-intent-v1"] = (
        "host-durable-exposure-intent-v1"
    )
    non_application_contract: Literal["clean-terminal-generation-v1"] = (
        "clean-terminal-generation-v1"
    )
    aggregation_contract: Literal["m1-section-7.1-v1"] = "m1-section-7.1-v1"


class M1JudgeInput(_Record):
    schema_version: Literal["m1-judge-input-v1"] = "m1-judge-input-v1"
    candidate_id: Identifier
    execution_harness_id: Digest
    evidence_manifest_sha256: Digest
    evidence_verified: bool
    rule_set: M1RuleSet
    profile: M1JudgeProfile
    crash_context: CrashContextWindow


# ---------------------------------------------------------------- immutable verdict records


class RuleStatusEntry(_Record):
    rule_id: Identifier
    status: M1Status


class IntentStatusEntry(_Record):
    intent_id: Identifier
    status: M1Status


class GenerationStatusEntry(_Record):
    window_index: WindowIndex
    status: M1Status


class RuleM1Result(_Record):
    window_index: WindowIndex
    rule_id: Identifier
    intent_id: Identifier
    status: M1Status
    reason: M1Reason | None
    exposure_batch_ids: Annotated[
        tuple[Identifier, ...], Field(max_length=MAX_BATCHES_PER_GENERATION)
    ] = ()


class BatchDeliveryResult(_Record):
    window_index: WindowIndex
    batch_id: Identifier
    semantic_signature: Digest
    rule_ids: Annotated[
        tuple[Identifier, ...], Field(min_length=1, max_length=MAX_APPLICATIONS_PER_BATCH)
    ]
    exposure_event_seq: Count
    state: DeliveryState
    forward_event_seq: Count | None


class IntentM1Result(_Record):
    window_index: WindowIndex
    intent_id: Identifier
    rule_vector: Annotated[
        tuple[RuleStatusEntry, ...], Field(min_length=1, max_length=MAX_RULES)
    ]
    status: M1Status
    reason: AggregateReason | None


class GenerationHypothesisM1Result(_Record):
    window_index: WindowIndex
    hypothesis_id: Identifier
    intent_vector: Annotated[
        tuple[IntentStatusEntry, ...], Field(min_length=1, max_length=MAX_INTENTS)
    ]
    status: M1Status
    reason: AggregateReason | None


class WindowRuleM1Result(_Record):
    rule_id: Identifier
    intent_id: Identifier
    generation_vector: Annotated[
        tuple[GenerationStatusEntry, ...],
        Field(min_length=1, max_length=MAX_GENERATIONS),
    ]
    status: M1Status
    reason: AggregateReason | None


class WindowHypothesisM1Result(_Record):
    hypothesis_id: Identifier
    generation_vector: Annotated[
        tuple[GenerationStatusEntry, ...],
        Field(min_length=1, max_length=MAX_GENERATIONS),
    ]
    status: M1Status
    reason: AggregateReason | None


class GenerationM1Result(_Record):
    window_index: WindowIndex
    correlation: ProgramGenerationCorrelation
    journal_sha256: Digest
    rule_results: Annotated[
        tuple[RuleM1Result, ...], Field(min_length=1, max_length=MAX_RULES)
    ]
    delivery_results: Annotated[
        tuple[BatchDeliveryResult, ...], Field(max_length=MAX_BATCHES_PER_GENERATION)
    ]
    intent_results: Annotated[
        tuple[IntentM1Result, ...], Field(min_length=1, max_length=MAX_INTENTS)
    ]
    hypothesis_results: Annotated[
        tuple[GenerationHypothesisM1Result, ...], Field(max_length=MAX_HYPOTHESES)
    ]


class M1Decision(_Record):
    schema_version: Literal["m1-decision-v1"] = "m1-decision-v1"
    verdict_id: Digest
    evaluation_input_sha256: Digest
    candidate_id: Identifier
    execution_harness_id: Digest
    evidence_manifest_sha256: Digest
    judge_profile_id: Digest
    rule_set_id: Identifier
    rule_set_ref: Digest
    generation_results: Annotated[
        tuple[GenerationM1Result, ...],
        Field(min_length=1, max_length=MAX_GENERATIONS),
    ]
    window_rule_results: Annotated[
        tuple[WindowRuleM1Result, ...], Field(min_length=1, max_length=MAX_RULES)
    ]
    window_hypothesis_results: Annotated[
        tuple[WindowHypothesisM1Result, ...], Field(max_length=MAX_HYPOTHESES)
    ]


# ---------------------------------------------------------------- exact §7.1 aggregation


def _checked_statuses(statuses: tuple[M1Status, ...], maximum: int) -> None:
    if not statuses:
        raise ValueError("M1 aggregation requires at least one member")
    if len(statuses) > maximum:
        raise ValueError("M1 aggregation exceeds its bound")
    if any(type(status) is not M1Status for status in statuses):
        raise TypeError("M1 aggregation accepts only M1Status members")


def aggregate_intent(statuses: tuple[M1Status, ...]) -> M1Status:
    """Any APPLIED; otherwise all NOT_APPLIED; otherwise INCONCLUSIVE."""

    _checked_statuses(statuses, MAX_RULES)
    if M1Status.APPLIED in statuses:
        return M1Status.APPLIED
    if all(status is M1Status.NOT_APPLIED for status in statuses):
        return M1Status.NOT_APPLIED
    return M1Status.INCONCLUSIVE


def aggregate_generation_hypothesis(statuses: tuple[M1Status, ...]) -> M1Status:
    """Requirement ``all`` within one generation."""

    _checked_statuses(statuses, MAX_INTENTS)
    if all(status is M1Status.APPLIED for status in statuses):
        return M1Status.APPLIED
    if M1Status.NOT_APPLIED in statuses:
        return M1Status.NOT_APPLIED
    return M1Status.INCONCLUSIVE


def aggregate_window_hypothesis(statuses: tuple[M1Status, ...]) -> M1Status:
    """Any generation APPLIED; otherwise all NOT_APPLIED; otherwise unknown."""

    _checked_statuses(statuses, MAX_GENERATIONS)
    if M1Status.APPLIED in statuses:
        return M1Status.APPLIED
    if all(status is M1Status.NOT_APPLIED for status in statuses):
        return M1Status.NOT_APPLIED
    return M1Status.INCONCLUSIVE


def _aggregate_reason(status: M1Status, *, generation: bool = False) -> AggregateReason | None:
    if status is not M1Status.INCONCLUSIVE:
        return None
    return (
        AggregateReason.GENERATION_INCONCLUSIVE
        if generation
        else AggregateReason.CHILD_INCONCLUSIVE
    )


# ---------------------------------------------------------------- evidence validation and judgment


_ISSUE_PRECEDENCE = (
    (JournalIssue.CORRELATION_CONFLICT, M1Reason.CORRELATION_MISMATCH),
    (JournalIssue.POST_SUMMARY_EVENT, M1Reason.POST_SUMMARY_EVENT),
    (JournalIssue.POST_CLOSE_REJECTION, M1Reason.POST_CLOSE_REJECTION),
    (JournalIssue.EVENT_CONFLICT, M1Reason.JOURNAL_CONFLICT),
    (JournalIssue.BATCH_CONFLICT, M1Reason.JOURNAL_CONFLICT),
    (JournalIssue.SEQUENCE_VIOLATION, M1Reason.SEQUENCE_VIOLATION),
    (JournalIssue.MALFORMED_EVENT, M1Reason.INVALID_EVIDENCE),
    (JournalIssue.INTERNAL_INCONSISTENCY, M1Reason.INTERNAL_INCONSISTENCY),
)


@dataclass(frozen=True)
class _GenerationInspection:
    reason: M1Reason | None
    deliveries: tuple[BatchDeliveryResult, ...]
    exposure_batches_by_rule: dict[str, tuple[str, ...]]


def _window_evidence_reason(data: M1JudgeInput) -> M1Reason | None:
    if data.rule_set.candidate_id != data.candidate_id:
        return M1Reason.EVIDENCE_IDENTITY_MISMATCH
    correlations = tuple(item.correlation for item in data.crash_context.generations)
    if any(item.rule_set_id != data.rule_set.rule_set_id for item in correlations):
        return M1Reason.CORRELATION_MISMATCH
    lane_scopes = {
        (item.vm_instance_id, item.lane_id, item.proc_id) for item in correlations
    }
    if len(lane_scopes) != 1:
        return M1Reason.CORRELATION_MISMATCH
    generation_keys = {
        (item.vm_instance_id, item.lane_id, item.proc_id, item.kcov_generation)
        for item in correlations
    }
    if len(generation_keys) != len(correlations):
        return M1Reason.CORRELATION_MISMATCH
    return None


def _closure_shape_valid(closure: GenerationClosure) -> bool:
    if closure.reason is ClosureReason.DRAINED:
        return closure.reply_unresolved_count == 0
    if closure.reason is ClosureReason.REPLY_UNRESOLVED:
        return closure.reply_unresolved_count > 0
    return True


def _clean_for_rule(closure: GenerationClosure, rule: RuleDefinition) -> bool:
    if closure.reason is ClosureReason.DRAINED:
        return True
    if closure.reason is ClosureReason.REPLY_UNRESOLVED:
        return rule.message_type is RuleMessageType.CALL
    return False


def _inspect_generation(
    data: M1JudgeInput,
    execution: ProgramGenerationExecution,
    window_reason: M1Reason | None,
) -> _GenerationInspection:
    evidence = execution.mutation_evidence
    empty = _GenerationInspection(window_reason, (), {})
    if not data.evidence_verified:
        return _GenerationInspection(M1Reason.EVIDENCE_UNVERIFIED, (), {})
    if window_reason is not None:
        return empty
    if (
        evidence.candidate_id != data.candidate_id
        or evidence.execution_harness_id != data.execution_harness_id
    ):
        return _GenerationInspection(M1Reason.EVIDENCE_IDENTITY_MISMATCH, (), {})
    if evidence.correlation != execution.correlation:
        return _GenerationInspection(M1Reason.CORRELATION_MISMATCH, (), {})
    if evidence.journal_integrity is JournalIntegrityStatus.INVALID:
        return _GenerationInspection(M1Reason.JOURNAL_INTEGRITY_INVALID, (), {})
    if evidence.journal_integrity is JournalIntegrityStatus.UNKNOWN:
        return _GenerationInspection(M1Reason.JOURNAL_INTEGRITY_UNKNOWN, (), {})

    issue_set = set(evidence.issues)
    for issue, reason in _ISSUE_PRECEDENCE:
        if issue in issue_set:
            return _GenerationInspection(reason, (), {})

    events: list[tuple[int, str]] = []
    rule_ids = {rule.rule_id for rule in data.rule_set.rules}
    exposures_by_batch: dict[str, ExposureIntent] = {}
    batches_by_rule: dict[str, list[str]] = defaultdict(list)
    for exposure in evidence.exposure_intents:
        if exposure.correlation != execution.correlation:
            return _GenerationInspection(M1Reason.CORRELATION_MISMATCH, (), {})
        if exposure.batch_id in exposures_by_batch:
            return _GenerationInspection(M1Reason.JOURNAL_CONFLICT, (), {})
        application_ids = tuple(item.rule_id for item in exposure.applications)
        if not set(application_ids).issubset(rule_ids):
            return _GenerationInspection(M1Reason.INVALID_EVIDENCE, (), {})
        exposures_by_batch[exposure.batch_id] = exposure
        events.append((exposure.event_seq, "exposure"))
        for rule_id in sorted(set(application_ids)):
            batches_by_rule[rule_id].append(exposure.batch_id)

    forwards_by_batch: dict[str, list[ForwardEvent]] = defaultdict(list)
    for forward in evidence.forward_events:
        if forward.correlation != execution.correlation:
            return _GenerationInspection(M1Reason.CORRELATION_MISMATCH, (), {})
        if forward.batch_id not in exposures_by_batch:
            return _GenerationInspection(M1Reason.JOURNAL_CONFLICT, (), {})
        forwards_by_batch[forward.batch_id].append(forward)
        events.append((forward.event_seq, "forward"))

    if any(len(values) != 1 for values in forwards_by_batch.values()):
        return _GenerationInspection(M1Reason.JOURNAL_CONFLICT, (), {})
    for batch_id, values in forwards_by_batch.items():
        if values[0].event_seq <= exposures_by_batch[batch_id].event_seq:
            return _GenerationInspection(M1Reason.SEQUENCE_VIOLATION, (), {})

    summary = evidence.generation_complete
    if summary is not None:
        if summary.correlation != execution.correlation:
            return _GenerationInspection(M1Reason.CORRELATION_MISMATCH, (), {})
        events.append((summary.event_seq, "summary"))

    sequences = tuple(sequence for sequence, _ in events)
    if len(set(sequences)) != len(sequences):
        return _GenerationInspection(M1Reason.JOURNAL_CONFLICT, (), {})
    if (
        evidence.last_generation_event_seq is not None
        and sequences
        and evidence.last_generation_event_seq < max(sequences)
    ):
        return _GenerationInspection(M1Reason.SEQUENCE_VIOLATION, (), {})

    if summary is not None:
        if any(sequence > summary.event_seq for sequence, kind in events if kind != "summary"):
            return _GenerationInspection(M1Reason.POST_SUMMARY_EVENT, (), {})
        if evidence.last_generation_event_seq != summary.event_seq:
            return _GenerationInspection(M1Reason.GENERATION_COMPLETE_NOT_TERMINAL, (), {})
        summarized = summary.summarized_rule_ids
        if (
            len(set(summarized)) != len(summarized)
            or set(summarized) != rule_ids
            or summary.exposure_batch_count != len(exposures_by_batch)
            # GENERATION_COMPLETE follows a COMPLETE/FAILED for every batch.
            # An open journal prefix may still have unknown delivery instead.
            or forwards_by_batch.keys() != exposures_by_batch.keys()
            or not _closure_shape_valid(summary.closure)
            or (
                JournalIssue.SINK_REJECTION in issue_set
                and summary.evidence_path_failures == 0
            )
        ):
            return _GenerationInspection(M1Reason.GENERATION_COMPLETE_INVALID, (), {})

    deliveries: list[BatchDeliveryResult] = []
    for exposure in evidence.exposure_intents:
        forward_values = forwards_by_batch.get(exposure.batch_id, ())
        forward = forward_values[0] if forward_values else None
        if forward is None:
            state = DeliveryState.UNKNOWN
        elif forward.outcome is ForwardOutcome.COMPLETE:
            state = DeliveryState.COMPLETE
        else:
            state = DeliveryState.FAILED
        deliveries.append(
            BatchDeliveryResult(
                window_index=execution.window_index,
                batch_id=exposure.batch_id,
                semantic_signature=exposure.semantic_signature,
                rule_ids=tuple(sorted({item.rule_id for item in exposure.applications})),
                exposure_event_seq=exposure.event_seq,
                state=state,
                forward_event_seq=forward.event_seq if forward is not None else None,
            )
        )
    return _GenerationInspection(
        None,
        tuple(deliveries),
        {rule_id: tuple(batch_ids) for rule_id, batch_ids in batches_by_rule.items()},
    )


def _barrier_reason(status: BarrierStatus, *, activation: bool) -> M1Reason | None:
    if status is BarrierStatus.ACKED:
        return None
    if activation:
        return (
            M1Reason.ACTIVATION_BARRIER_FAILED
            if status is BarrierStatus.FAILED
            else M1Reason.ACTIVATION_BARRIER_UNKNOWN
        )
    return (
        M1Reason.DEACTIVATION_BARRIER_FAILED
        if status is BarrierStatus.FAILED
        else M1Reason.DEACTIVATION_BARRIER_UNKNOWN
    )


def _judge_rule(
    execution: ProgramGenerationExecution,
    rule: RuleDefinition,
    inspection: _GenerationInspection,
) -> RuleM1Result:
    batches = inspection.exposure_batches_by_rule.get(rule.rule_id, ())
    if inspection.reason is not None:
        return RuleM1Result(
            window_index=execution.window_index,
            rule_id=rule.rule_id,
            intent_id=rule.intent_id,
            status=M1Status.INCONCLUSIVE,
            reason=inspection.reason,
        )
    # A valid durable exposure is positive evidence even when forwarding is
    # failed/unknown or a barrier later fails.
    if batches:
        return RuleM1Result(
            window_index=execution.window_index,
            rule_id=rule.rule_id,
            intent_id=rule.intent_id,
            status=M1Status.APPLIED,
            reason=None,
            exposure_batch_ids=batches,
        )

    activation_reason = _barrier_reason(execution.barriers.activation, activation=True)
    if activation_reason is not None:
        reason = activation_reason
    else:
        reason = _barrier_reason(execution.barriers.deactivation, activation=False)
    evidence = execution.mutation_evidence
    summary = evidence.generation_complete
    if reason is None and summary is None:
        reason = M1Reason.GENERATION_COMPLETE_MISSING
    if reason is None and summary is not None and summary.evidence_path_failures:
        reason = M1Reason.EVIDENCE_PATH_DEGRADED
    if reason is None and summary is not None and not _clean_for_rule(summary.closure, rule):
        reason = M1Reason.CLOSURE_NOT_CLEAN
    return RuleM1Result(
        window_index=execution.window_index,
        rule_id=rule.rule_id,
        intent_id=rule.intent_id,
        status=M1Status.NOT_APPLIED if reason is None else M1Status.INCONCLUSIVE,
        reason=reason,
    )


def evaluate(inputs: M1JudgeInput) -> M1Decision:
    """Judge a bounded CrashContextWindow without I/O or mutable state.

    Type/shape errors and invalid rule membership raise ``ValidationError``.
    Missing, conflicting, corrupt, or miscorrelated evidence yields explicit
    rule-level ``INCONCLUSIVE`` results and can never synthesize NOT_APPLIED.
    """

    data = M1JudgeInput.model_validate(inputs)
    rules = data.rule_set.rules
    intents = data.rule_set.intents
    hypotheses = data.rule_set.hypotheses
    window_reason = _window_evidence_reason(data)

    generation_results: list[GenerationM1Result] = []
    for execution in data.crash_context.generations:
        inspection = _inspect_generation(data, execution, window_reason)
        rule_results = tuple(_judge_rule(execution, rule, inspection) for rule in rules)
        rule_by_id = {result.rule_id: result for result in rule_results}

        intent_results: list[IntentM1Result] = []
        for intent in intents:
            vector = tuple(
                RuleStatusEntry(rule_id=rule_id, status=rule_by_id[rule_id].status)
                for rule_id in intent.rule_ids
            )
            status = aggregate_intent(tuple(item.status for item in vector))
            intent_results.append(
                IntentM1Result(
                    window_index=execution.window_index,
                    intent_id=intent.intent_id,
                    rule_vector=vector,
                    status=status,
                    reason=_aggregate_reason(status),
                )
            )
        intent_by_id = {result.intent_id: result for result in intent_results}

        hypothesis_results: list[GenerationHypothesisM1Result] = []
        for hypothesis in hypotheses:
            vector = tuple(
                IntentStatusEntry(
                    intent_id=intent_id, status=intent_by_id[intent_id].status
                )
                for intent_id in hypothesis.intent_ids
            )
            status = aggregate_generation_hypothesis(tuple(item.status for item in vector))
            hypothesis_results.append(
                GenerationHypothesisM1Result(
                    window_index=execution.window_index,
                    hypothesis_id=hypothesis.hypothesis_id,
                    intent_vector=vector,
                    status=status,
                    reason=_aggregate_reason(status),
                )
            )

        generation_results.append(
            GenerationM1Result(
                window_index=execution.window_index,
                correlation=execution.correlation,
                journal_sha256=execution.mutation_evidence.journal_sha256,
                rule_results=rule_results,
                delivery_results=inspection.deliveries,
                intent_results=tuple(intent_results),
                hypothesis_results=tuple(hypothesis_results),
            )
        )

    generation_tuple = tuple(generation_results)
    window_rule_results: list[WindowRuleM1Result] = []
    for rule in rules:
        vector = tuple(
            GenerationStatusEntry(
                window_index=generation.window_index,
                status=next(
                    result.status
                    for result in generation.rule_results
                    if result.rule_id == rule.rule_id
                ),
            )
            for generation in generation_tuple
        )
        status = aggregate_window_hypothesis(tuple(item.status for item in vector))
        window_rule_results.append(
            WindowRuleM1Result(
                rule_id=rule.rule_id,
                intent_id=rule.intent_id,
                generation_vector=vector,
                status=status,
                reason=_aggregate_reason(status, generation=True),
            )
        )

    window_hypothesis_results: list[WindowHypothesisM1Result] = []
    for hypothesis in hypotheses:
        vector = tuple(
            GenerationStatusEntry(
                window_index=generation.window_index,
                status=next(
                    result.status
                    for result in generation.hypothesis_results
                    if result.hypothesis_id == hypothesis.hypothesis_id
                ),
            )
            for generation in generation_tuple
        )
        status = aggregate_window_hypothesis(tuple(item.status for item in vector))
        window_hypothesis_results.append(
            WindowHypothesisM1Result(
                hypothesis_id=hypothesis.hypothesis_id,
                generation_vector=vector,
                status=status,
                reason=_aggregate_reason(status, generation=True),
            )
        )

    fields = dict(
        schema_version="m1-decision-v1",
        evaluation_input_sha256=data.digest,
        candidate_id=data.candidate_id,
        execution_harness_id=data.execution_harness_id,
        evidence_manifest_sha256=data.evidence_manifest_sha256,
        judge_profile_id=data.profile.digest,
        rule_set_id=data.rule_set.rule_set_id,
        rule_set_ref=data.rule_set.digest,
        generation_results=generation_tuple,
        window_rule_results=tuple(window_rule_results),
        window_hypothesis_results=tuple(window_hypothesis_results),
    )
    identity_fields = {
        **fields,
        "generation_results": tuple(
            item.model_dump(mode="json") for item in generation_tuple
        ),
        "window_rule_results": tuple(
            item.model_dump(mode="json") for item in window_rule_results
        ),
        "window_hypothesis_results": tuple(
            item.model_dump(mode="json") for item in window_hypothesis_results
        ),
    }
    return M1Decision(verdict_id=_digest(identity_fields), **fields)
