"""Pure M1 contract tests; no journal sink or runtime is implemented here."""

from __future__ import annotations

import itertools
from hashlib import sha256

import pytest
from pydantic import ValidationError

from agent_pipeline.m1 import (
    AggregateReason,
    BarrierResults,
    BarrierStatus,
    ClosureReason,
    CrashContextWindow,
    DeliveryState,
    ExposureIntent,
    ForwardEvent,
    ForwardOutcome,
    GenerationClosure,
    GenerationComplete,
    HypothesisDefinition,
    IntentDefinition,
    JournalIntegrityStatus,
    JournalIssue,
    M1JudgeInput,
    M1JudgeProfile,
    M1Reason,
    M1RuleSet,
    M1Status,
    MutationEvidence,
    ProgramGenerationCorrelation,
    ProgramGenerationExecution,
    RuleApplication,
    RuleDefinition,
    RuleMessageType,
    aggregate_generation_hypothesis,
    aggregate_intent,
    aggregate_window_hypothesis,
    evaluate,
)


def digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def replace(record, **changes):
    """Revalidate updates; production callers must not trust model_copy."""

    return type(record).model_validate({**record.model_dump(), **changes})


def correlation(index: int, *, lane_id: int = 4, proc_id: int = 9):
    return ProgramGenerationCorrelation(
        vm_instance_id="vm-1",
        lane_id=lane_id,
        proc_id=proc_id,
        kcov_generation=100 + index,
        rule_set_id="rules-1",
        program_digest=digest(f"program-{index}"),
    )


def rule_set() -> M1RuleSet:
    return M1RuleSet(
        candidate_id="candidate-1",
        rule_set_id="rules-1",
        rules=(
            RuleDefinition(
                rule_id="rule-call", intent_id="intent-call", message_type=RuleMessageType.CALL
            ),
            RuleDefinition(
                rule_id="rule-reply",
                intent_id="intent-reply",
                message_type=RuleMessageType.REPLY,
            ),
        ),
        intents=(
            IntentDefinition(intent_id="intent-call", rule_ids=("rule-call",)),
            IntentDefinition(intent_id="intent-reply", rule_ids=("rule-reply",)),
        ),
        hypotheses=(
            HypothesisDefinition(
                hypothesis_id="hypothesis-all",
                intent_ids=("intent-call", "intent-reply"),
            ),
        ),
    )


def generation(
    index: int,
    *,
    applied: tuple[str, ...] = (),
    outcome: ForwardOutcome | None = None,
    activation: BarrierStatus = BarrierStatus.ACKED,
    deactivation: BarrierStatus = BarrierStatus.ACKED,
    closure: ClosureReason = ClosureReason.DRAINED,
    reply_unresolved_count: int = 0,
    summary: bool = True,
    integrity: JournalIntegrityStatus = JournalIntegrityStatus.VALID,
    evidence_path_failures: int = 0,
    issues: tuple[JournalIssue, ...] = (),
    lane_id: int = 4,
    proc_id: int = 9,
) -> ProgramGenerationExecution:
    corr = correlation(index, lane_id=lane_id, proc_id=proc_id)
    exposures = tuple(
        ExposureIntent(
            event_seq=10 + offset * 3,
            correlation=corr,
            batch_id=f"batch-{index}-{rule_id}",
            semantic_signature=digest(f"signature-{index}-{rule_id}"),
            applications=(RuleApplication(rule_id=rule_id),),
        )
        for offset, rule_id in enumerate(applied)
    )
    forwards = ()
    if outcome is not None:
        forwards = tuple(
            ForwardEvent(
                event_seq=exposure.event_seq + 1,
                correlation=corr,
                batch_id=exposure.batch_id,
                outcome=outcome,
            )
            for exposure in exposures
        )
    summary_seq = 100
    complete = (
        GenerationComplete(
            event_seq=summary_seq,
            correlation=corr,
            exposure_batch_count=len(exposures),
            evidence_path_failures=evidence_path_failures,
            summarized_rule_ids=("rule-call", "rule-reply"),
            closure=GenerationClosure(
                reason=closure,
                drain_bound=50,
                reply_unresolved_count=reply_unresolved_count,
            ),
        )
        if summary
        else None
    )
    evidence = MutationEvidence(
        candidate_id="candidate-1",
        execution_harness_id=digest("harness"),
        correlation=corr,
        journal_sha256=digest(f"journal-{index}"),
        journal_integrity=integrity,
        exposure_intents=exposures,
        forward_events=forwards,
        generation_complete=complete,
        last_generation_event_seq=(
            summary_seq
            if summary
            else max((event.event_seq for event in forwards), default=None)
        ),
        issues=issues,
    )
    return ProgramGenerationExecution(
        window_index=index,
        correlation=corr,
        barriers=BarrierResults(activation=activation, deactivation=deactivation),
        mutation_evidence=evidence,
    )


def judge_input(*generations: ProgramGenerationExecution) -> M1JudgeInput:
    if not generations:
        generations = (generation(0),)
    return M1JudgeInput(
        candidate_id="candidate-1",
        execution_harness_id=digest("harness"),
        evidence_manifest_sha256=digest("manifest"),
        evidence_verified=True,
        rule_set=rule_set(),
        profile=M1JudgeProfile(name="test-profile", revision="1"),
        crash_context=CrashContextWindow(bound=8, generations=generations),
    )


def generation_result(inputs: M1JudgeInput, index: int = 0):
    return evaluate(inputs).generation_results[index]


def rule_result(inputs: M1JudgeInput, rule_id: str, index: int = 0):
    return next(
        result
        for result in generation_result(inputs, index).rule_results
        if result.rule_id == rule_id
    )


@pytest.mark.parametrize(
    "outcome,delivery",
    [
        (ForwardOutcome.COMPLETE, DeliveryState.COMPLETE),
        (ForwardOutcome.FAILED, DeliveryState.FAILED),
        (None, DeliveryState.UNKNOWN),
    ],
)
def test_durable_exposure_is_applied_for_every_delivery_state(outcome, delivery):
    inputs = judge_input(
        generation(
            0,
            applied=("rule-call",),
            outcome=outcome,
            deactivation=BarrierStatus.FAILED,
        )
    )
    result = rule_result(inputs, "rule-call")
    assert result.status is M1Status.APPLIED
    assert result.reason is None
    assert result.exposure_batch_ids == ("batch-0-rule-call",)
    assert generation_result(inputs).delivery_results[0].state is delivery
    assert rule_result(inputs, "rule-reply").reason is M1Reason.DEACTIVATION_BARRIER_FAILED


def test_clean_terminal_generation_is_the_only_not_applied_path():
    result = evaluate(judge_input())
    assert tuple(item.status for item in result.generation_results[0].rule_results) == (
        M1Status.NOT_APPLIED,
        M1Status.NOT_APPLIED,
    )
    assert all(item.reason is None for item in result.generation_results[0].rule_results)
    assert result.generation_results[0].intent_results[0].status is M1Status.NOT_APPLIED
    assert result.generation_results[0].hypothesis_results[0].status is M1Status.NOT_APPLIED


@pytest.mark.parametrize(
    "activation,deactivation,reason",
    [
        (BarrierStatus.FAILED, BarrierStatus.ACKED, M1Reason.ACTIVATION_BARRIER_FAILED),
        (BarrierStatus.UNKNOWN, BarrierStatus.ACKED, M1Reason.ACTIVATION_BARRIER_UNKNOWN),
        (BarrierStatus.ACKED, BarrierStatus.FAILED, M1Reason.DEACTIVATION_BARRIER_FAILED),
        (BarrierStatus.ACKED, BarrierStatus.UNKNOWN, M1Reason.DEACTIVATION_BARRIER_UNKNOWN),
    ],
)
def test_each_missing_barrier_ack_blocks_negative_evidence(activation, deactivation, reason):
    inputs = judge_input(generation(0, activation=activation, deactivation=deactivation))
    assert all(
        (item.status, item.reason) == (M1Status.INCONCLUSIVE, reason)
        for item in generation_result(inputs).rule_results
    )


def test_crash_or_missing_summary_is_inconclusive_without_exposure():
    inputs = judge_input(generation(0, summary=False))
    assert all(
        item.reason is M1Reason.GENERATION_COMPLETE_MISSING
        for item in generation_result(inputs).rule_results
    )


def test_reply_unresolved_closure_is_clean_only_for_call_rules():
    inputs = judge_input(
        generation(
            0,
            closure=ClosureReason.REPLY_UNRESOLVED,
            reply_unresolved_count=1,
        )
    )
    assert rule_result(inputs, "rule-call").status is M1Status.NOT_APPLIED
    reply = rule_result(inputs, "rule-reply")
    assert (reply.status, reply.reason) == (
        M1Status.INCONCLUSIVE,
        M1Reason.CLOSURE_NOT_CLEAN,
    )


def test_aborted_closure_is_dirty_for_every_rule():
    inputs = judge_input(generation(0, closure=ClosureReason.ABORTED))
    assert all(
        (item.status, item.reason)
        == (M1Status.INCONCLUSIVE, M1Reason.CLOSURE_NOT_CLEAN)
        for item in generation_result(inputs).rule_results
    )


def test_evidence_path_failure_blocks_only_negative_claim():
    negative = judge_input(generation(0, evidence_path_failures=1))
    assert all(
        item.reason is M1Reason.EVIDENCE_PATH_DEGRADED
        for item in generation_result(negative).rule_results
    )
    positive = judge_input(
        generation(0, applied=("rule-call",), evidence_path_failures=1)
    )
    assert rule_result(positive, "rule-call").status is M1Status.APPLIED


@pytest.mark.parametrize(
    "integrity,reason",
    [
        (JournalIntegrityStatus.INVALID, M1Reason.JOURNAL_INTEGRITY_INVALID),
        (JournalIntegrityStatus.UNKNOWN, M1Reason.JOURNAL_INTEGRITY_UNKNOWN),
    ],
)
def test_invalid_or_unknown_journal_integrity_fails_closed_even_with_exposure(
    integrity, reason
):
    inputs = judge_input(
        generation(0, applied=("rule-call",), integrity=integrity)
    )
    assert all(item.reason is reason for item in generation_result(inputs).rule_results)
    assert generation_result(inputs).delivery_results == ()


@pytest.mark.parametrize(
    "issue,reason",
    [
        (JournalIssue.MALFORMED_EVENT, M1Reason.INVALID_EVIDENCE),
        (JournalIssue.EVENT_CONFLICT, M1Reason.JOURNAL_CONFLICT),
        (JournalIssue.SEQUENCE_VIOLATION, M1Reason.SEQUENCE_VIOLATION),
        (JournalIssue.POST_SUMMARY_EVENT, M1Reason.POST_SUMMARY_EVENT),
        (JournalIssue.POST_CLOSE_REJECTION, M1Reason.POST_CLOSE_REJECTION),
        (JournalIssue.INTERNAL_INCONSISTENCY, M1Reason.INTERNAL_INCONSISTENCY),
    ],
)
def test_host_recorded_defects_never_become_not_applied(issue, reason):
    inputs = judge_input(generation(0, issues=(issue,)))
    assert all(
        (item.status, item.reason) == (M1Status.INCONCLUSIVE, reason)
        for item in generation_result(inputs).rule_results
    )


def test_ordinary_sink_rejection_degrades_negative_evidence_but_keeps_valid_exposure():
    positive = judge_input(
        generation(
            0,
            applied=("rule-call",),
            evidence_path_failures=1,
            issues=(JournalIssue.SINK_REJECTION,),
        )
    )
    assert rule_result(positive, "rule-call").status is M1Status.APPLIED
    assert (
        rule_result(positive, "rule-reply").reason
        is M1Reason.EVIDENCE_PATH_DEGRADED
    )

    inconsistent = judge_input(
        generation(0, issues=(JournalIssue.SINK_REJECTION,))
    )
    assert all(
        item.reason is M1Reason.GENERATION_COMPLETE_INVALID
        for item in generation_result(inconsistent).rule_results
    )


def test_accepted_event_after_summary_is_detected_from_sequence():
    base = generation(0, applied=("rule-call",))
    evidence = base.mutation_evidence
    late = replace(evidence.exposure_intents[0], event_seq=101)
    evidence = replace(
        evidence,
        exposure_intents=(late,),
        last_generation_event_seq=101,
    )
    inputs = judge_input(replace(base, mutation_evidence=evidence))
    assert all(
        item.reason is M1Reason.POST_SUMMARY_EVENT
        for item in generation_result(inputs).rule_results
    )


def test_nonterminal_summary_cannot_support_any_definitive_verdict():
    base = generation(0, applied=("rule-call",))
    evidence = replace(base.mutation_evidence, last_generation_event_seq=101)
    inputs = judge_input(replace(base, mutation_evidence=evidence))
    assert all(
        item.reason is M1Reason.GENERATION_COMPLETE_NOT_TERMINAL
        for item in generation_result(inputs).rule_results
    )


@pytest.mark.parametrize("defect", ["summary_membership", "summary_count", "closure_shape"])
def test_malformed_terminal_summary_fails_closed(defect):
    base = generation(0)
    complete = base.mutation_evidence.generation_complete
    if defect == "summary_membership":
        complete = replace(complete, summarized_rule_ids=("rule-call",))
    elif defect == "summary_count":
        complete = replace(complete, exposure_batch_count=1)
    else:
        complete = replace(
            complete,
            closure=GenerationClosure(
                reason=ClosureReason.REPLY_UNRESOLVED,
                drain_bound=50,
                reply_unresolved_count=0,
            ),
        )
    evidence = replace(base.mutation_evidence, generation_complete=complete)
    inputs = judge_input(replace(base, mutation_evidence=evidence))
    assert all(
        item.reason is M1Reason.GENERATION_COMPLETE_INVALID
        for item in generation_result(inputs).rule_results
    )


def test_duplicate_batch_and_conflicting_forward_events_fail_closed():
    base = generation(0, applied=("rule-call",), outcome=ForwardOutcome.COMPLETE)
    exposure = base.mutation_evidence.exposure_intents[0]
    duplicate = replace(exposure, event_seq=20)
    evidence = replace(
        base.mutation_evidence,
        exposure_intents=(exposure, duplicate),
        generation_complete=replace(
            base.mutation_evidence.generation_complete, exposure_batch_count=2
        ),
    )
    duplicate_input = judge_input(replace(base, mutation_evidence=evidence))
    assert all(
        item.reason is M1Reason.JOURNAL_CONFLICT
        for item in generation_result(duplicate_input).rule_results
    )

    failed = replace(
        base.mutation_evidence.forward_events[0],
        event_seq=30,
        outcome=ForwardOutcome.FAILED,
    )
    evidence = replace(
        base.mutation_evidence,
        forward_events=(*base.mutation_evidence.forward_events, failed),
    )
    conflict_input = judge_input(replace(base, mutation_evidence=evidence))
    assert all(
        item.reason is M1Reason.JOURNAL_CONFLICT
        for item in generation_result(conflict_input).rule_results
    )


def test_miscorrelated_present_exposure_fails_closed_for_whole_generation():
    base = generation(0, applied=("rule-call",))
    wrong = replace(base.mutation_evidence.exposure_intents[0], correlation=correlation(1))
    evidence = replace(base.mutation_evidence, exposure_intents=(wrong,))
    inputs = judge_input(replace(base, mutation_evidence=evidence))
    assert all(
        item.reason is M1Reason.CORRELATION_MISMATCH
        for item in generation_result(inputs).rule_results
    )


@pytest.mark.parametrize("scope_field", ["lane_id", "proc_id"])
def test_crash_context_cannot_combine_different_lane_or_proc_scopes(scope_field):
    first = generation(0)
    kwargs = {scope_field: 99}
    second = generation(1, **kwargs)
    with pytest.raises(ValidationError):
        CrashContextWindow(bound=8, generations=(first, second))


def test_proc_id_is_required_and_strictly_host_correlation_data():
    values = correlation(0).model_dump()
    values.pop("proc_id")
    with pytest.raises(ValidationError):
        ProgramGenerationCorrelation.model_validate(values)
    with pytest.raises(ValidationError):
        replace(correlation(0), proc_id="9")
    with pytest.raises(ValidationError):
        replace(correlation(0), proc_id=True)


def expected_intent(statuses):
    if M1Status.APPLIED in statuses:
        return M1Status.APPLIED
    if all(item is M1Status.NOT_APPLIED for item in statuses):
        return M1Status.NOT_APPLIED
    return M1Status.INCONCLUSIVE


def expected_generation_hypothesis(statuses):
    if all(item is M1Status.APPLIED for item in statuses):
        return M1Status.APPLIED
    if M1Status.NOT_APPLIED in statuses:
        return M1Status.NOT_APPLIED
    return M1Status.INCONCLUSIVE


def expected_window_hypothesis(statuses):
    if M1Status.APPLIED in statuses:
        return M1Status.APPLIED
    if all(item is M1Status.NOT_APPLIED for item in statuses):
        return M1Status.NOT_APPLIED
    return M1Status.INCONCLUSIVE


@pytest.mark.parametrize(
    "statuses", tuple(itertools.product(tuple(M1Status), repeat=2))
)
def test_section_7_1_aggregation_truth_tables(statuses):
    assert aggregate_intent(statuses) is expected_intent(statuses)
    assert aggregate_generation_hypothesis(statuses) is expected_generation_hypothesis(statuses)
    assert aggregate_window_hypothesis(statuses) is expected_window_hypothesis(statuses)


def test_aggregation_rejects_empty_or_untyped_vectors():
    for aggregate in (
        aggregate_intent,
        aggregate_generation_hypothesis,
        aggregate_window_hypothesis,
    ):
        with pytest.raises(ValueError):
            aggregate(())
        with pytest.raises(TypeError):
            aggregate(("applied",))


def test_intents_applied_in_different_generations_never_form_joint_application():
    inputs = judge_input(
        generation(0, applied=("rule-call",)),
        generation(1, applied=("rule-reply",)),
    )
    result = evaluate(inputs)
    per_generation = tuple(
        item.hypothesis_results[0].status for item in result.generation_results
    )
    assert per_generation == (M1Status.NOT_APPLIED, M1Status.NOT_APPLIED)
    assert result.window_hypothesis_results[0].status is M1Status.NOT_APPLIED
    assert tuple(item.status for item in result.window_rule_results) == (
        M1Status.APPLIED,
        M1Status.APPLIED,
    )


def test_inconclusive_generation_propagates_without_overriding_window_application():
    first = generation(0, summary=False)
    second = generation(1, applied=("rule-call", "rule-reply"))
    result = evaluate(judge_input(first, second))
    assert result.generation_results[0].hypothesis_results[0].status is M1Status.INCONCLUSIVE
    assert result.generation_results[1].hypothesis_results[0].status is M1Status.APPLIED
    window = result.window_hypothesis_results[0]
    assert window.status is M1Status.APPLIED
    assert window.reason is None


def test_inconclusive_child_vectors_keep_stable_aggregate_reasons():
    result = evaluate(
        judge_input(
            generation(
                0,
                applied=("rule-call",),
                closure=ClosureReason.REPLY_UNRESOLVED,
                reply_unresolved_count=1,
            )
        )
    )
    generation_value = result.generation_results[0]
    reply_intent = next(
        item for item in generation_value.intent_results if item.intent_id == "intent-reply"
    )
    assert (reply_intent.status, reply_intent.reason) == (
        M1Status.INCONCLUSIVE,
        AggregateReason.CHILD_INCONCLUSIVE,
    )
    assert generation_value.hypothesis_results[0].reason is AggregateReason.CHILD_INCONCLUSIVE
    assert (
        result.window_hypothesis_results[0].reason
        is AggregateReason.GENERATION_INCONCLUSIVE
    )


def test_rule_membership_must_be_complete_unique_and_consistent():
    rules = rule_set()
    call, reply = rules.rules
    cases = (
        {"intents": (IntentDefinition(intent_id="intent-call", rule_ids=(call.rule_id,)),)},
        {"rules": (replace(call, intent_id="intent-reply"), reply)},
    )
    for changes in cases:
        with pytest.raises(ValidationError):
            replace(rules, **changes)
    with pytest.raises(ValidationError):
        IntentDefinition(
            intent_id="intent-call", rule_ids=(call.rule_id, call.rule_id)
        )


def test_hypothesis_membership_rejects_duplicate_and_unknown_references():
    rules = rule_set()
    with pytest.raises(ValidationError):
        replace(
            rules,
            hypotheses=(
                HypothesisDefinition(
                    hypothesis_id="bad",
                    intent_ids=("intent-call", "intent-call"),
                ),
            ),
        )
    with pytest.raises(ValidationError):
        replace(
            rules,
            hypotheses=(
                HypothesisDefinition(hypothesis_id="bad", intent_ids=("missing",)),
            ),
        )


def test_canonical_ordering_makes_permutations_identical():
    original = generation(
        0,
        applied=("rule-call", "rule-reply"),
        outcome=ForwardOutcome.COMPLETE,
        issues=(),
    )
    evidence = original.mutation_evidence
    permuted_evidence = replace(
        evidence,
        exposure_intents=tuple(reversed(evidence.exposure_intents)),
        forward_events=tuple(reversed(evidence.forward_events)),
        generation_complete=replace(
            evidence.generation_complete,
            summarized_rule_ids=tuple(
                reversed(evidence.generation_complete.summarized_rule_ids)
            ),
        ),
    )
    permuted_generation = replace(original, mutation_evidence=permuted_evidence)
    original_input = judge_input(original)
    rules = original_input.rule_set
    permuted_rules = M1RuleSet(
        candidate_id=rules.candidate_id,
        rule_set_id=rules.rule_set_id,
        rules=tuple(reversed(rules.rules)),
        intents=tuple(reversed(rules.intents)),
        hypotheses=rules.hypotheses,
    )
    permuted_input = replace(
        judge_input(permuted_generation), rule_set=permuted_rules
    )
    assert original_input == permuted_input
    assert evaluate(original_input) == evaluate(permuted_input)
    decision = evaluate(original_input)
    assert tuple(item.rule_id for item in decision.generation_results[0].rule_results) == (
        "rule-call",
        "rule-reply",
    )


def test_generation_order_uses_explicit_contiguous_window_index():
    first, second = generation(0), generation(1)
    window = CrashContextWindow(bound=2, generations=(second, first))
    assert tuple(item.window_index for item in window.generations) == (0, 1)
    with pytest.raises(ValidationError):
        CrashContextWindow(bound=2, generations=(first, replace(second, window_index=2)))
    with pytest.raises(ValidationError):
        CrashContextWindow(bound=1, generations=(first, second))


def test_unverified_manifest_blocks_positive_and_negative_verdicts():
    inputs = replace(
        judge_input(generation(0, applied=("rule-call",))),
        evidence_verified=False,
    )
    result = generation_result(inputs)
    assert all(
        (item.status, item.reason)
        == (M1Status.INCONCLUSIVE, M1Reason.EVIDENCE_UNVERIFIED)
        for item in result.rule_results
    )
    assert result.delivery_results == ()


def test_models_are_strict_deeply_immutable_and_reject_unknown_fields():
    inputs = judge_input()
    records = (
        inputs,
        inputs.rule_set,
        inputs.rule_set.rules[0],
        inputs.rule_set.intents[0],
        inputs.rule_set.hypotheses[0],
        inputs.crash_context,
        inputs.crash_context.generations[0],
        inputs.crash_context.generations[0].mutation_evidence,
        inputs.profile,
    )
    for record in records:
        with pytest.raises(ValidationError):
            replace(record, unknown="rejected")
    with pytest.raises(ValidationError):
        inputs.candidate_id = "other"
    with pytest.raises(ValidationError):
        replace(inputs, evidence_verified=1)
    with pytest.raises(ValidationError):
        replace(correlation(0), lane_id=False)


def test_unvalidated_model_copies_cannot_bypass_evaluation():
    inputs = judge_input()
    evidence = inputs.crash_context.generations[0].mutation_evidence
    unsafe_evidence = evidence.model_copy(update={"journal_integrity": "valid"})
    unsafe_generation = inputs.crash_context.generations[0].model_copy(
        update={"mutation_evidence": unsafe_evidence}
    )
    unsafe_window = inputs.crash_context.model_copy(
        update={"generations": (unsafe_generation,)}
    )
    unsafe_input = inputs.model_copy(update={"crash_context": unsafe_window})
    with pytest.raises(ValidationError):
        evaluate(unsafe_input)


def test_evaluation_identity_binds_profile_manifest_and_full_input():
    inputs = judge_input()
    baseline = evaluate(inputs)
    changed_profile = replace(
        inputs, profile=replace(inputs.profile, revision="2")
    )
    changed_manifest = replace(inputs, evidence_manifest_sha256=digest("other-manifest"))
    assert evaluate(changed_profile).verdict_id != baseline.verdict_id
    assert evaluate(changed_profile).judge_profile_id != baseline.judge_profile_id
    assert evaluate(changed_manifest).verdict_id != baseline.verdict_id
    assert evaluate(changed_manifest).evaluation_input_sha256 != baseline.evaluation_input_sha256
