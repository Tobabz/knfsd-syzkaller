"""Pure M6 comparator tests: the 05 §29 verdict order and oracles §3-§6, §20."""

from __future__ import annotations

from hashlib import sha256

import pytest
from pydantic import ValidationError

from agent_pipeline.semantic_replay import (
    ApplyRefusal, Batch, BatchSignature, Correlation, DeliveryState, DifferenceKind,
    EvidenceProblem, GenerationSummary, InvalidReason, JournalIntegrity, RefusalEvidence,
    ReplayJudgeInput, ReplayJudgeProfile, ReplayPosition, ReplayVerdict, RuleCounts,
    SideGeneration, SignatureItem, Termination, evaluate, refusal_evidence,
)

RULE_SET_ID = sha256(b"rules").hexdigest()
PROFILE = ReplayJudgeProfile(name="replay", revision="1")


def sig(*rules: str) -> BatchSignature:
    return BatchSignature(items=tuple(
        SignatureItem(rule_id=r, semantic_path=f"nfs4.request.SEQUENCE.args.{r}",
                      part="value", kind="replace", count=1) for r in rules))


def summary(batches: int, counts: dict[str, dict[str, int]] | None = None,
            failures: int = 0) -> GenerationSummary:
    counts = counts or {"A": {"resolved": batches}, "B": {"predicate_false": 1}}
    return GenerationSummary(
        evidence_path_failures=failures, exposure_batch_count=batches,
        resolver_summary=tuple(RuleCounts(rule_id=r, counts=tuple(c.items()))
                               for r, c in sorted(counts.items())))


def side(batches: list[BatchSignature], *, vm: str = "vm-0", generation: int = 1,
         digest: str = "a", refusals: tuple[ApplyRefusal, ...] = (),
         summary_: GenerationSummary | None | str = "auto",
         termination: Termination = Termination.CLEAN,
         delivery: DeliveryState = DeliveryState.COMPLETE, **extra) -> SideGeneration:
    if summary_ == "auto":
        summary_ = summary(len(batches))
    return SideGeneration(
        correlation=Correlation(vm_instance_id=vm, lane_id=0, kcov_generation=generation,
                                rule_set_id=RULE_SET_ID,
                                program_digest=sha256(digest.encode()).hexdigest()),
        journal_integrity=extra.pop("integrity", JournalIntegrity.VALID),
        batches=tuple(Batch(signature=s, delivery=delivery) for s in batches),
        apply_refusals=refusals, summary=summary_, termination=termination, **extra)


def judge(*pairs: tuple[SideGeneration | None, SideGeneration | None], **kw) -> object:
    return evaluate(ReplayJudgeInput(
        candidate_id="cand", production_evidence_manifest_sha256="1" * 64,
        replay_evidence_manifest_sha256="2" * 64,
        evidence_verified=kw.pop("verified", True), schema_id="nfs4.1/sha256:" + "0" * 64,
        semantic_runtime_version=1, rule_set_id=RULE_SET_ID, profile=PROFILE,
        invalid_reasons=kw.pop("invalid", ()),
        positions=tuple(ReplayPosition(window_index=i, production=p, replay=r)
                        for i, (p, r) in enumerate(pairs))))


def test_same_multiset_in_another_order_is_equivalent():  # oracle §3
    prod = side([sig("A", "B"), sig("A")])
    repl = side([sig("A"), sig("B", "A")], vm="vm-1", generation=40)
    result = judge((prod, repl))
    assert result.semantic_verdict is ReplayVerdict.EQUIVALENT
    assert result.positions[0].differences == ()
    assert result.positions[0].replay_generation == 40


def test_same_rule_counts_other_grouping_diverges():  # oracle §4
    result = judge((side([sig("A", "B")]), side([sig("A"), sig("B")])))
    assert result.semantic_verdict is ReplayVerdict.DIVERGED
    assert result.positions[0].differences[0].kind is DifferenceKind.BATCH_MULTISET


@pytest.mark.parametrize("replay", [[sig("A"), sig("A"), sig("A")], [sig("A")]])
def test_extra_or_missing_batch_diverges(replay):  # oracle §5
    result = judge((side([sig("A"), sig("A")]), side(replay)))
    assert result.semantic_verdict is ReplayVerdict.DIVERGED


def test_multiplicity_inside_a_batch_counts():
    two = BatchSignature(items=(SignatureItem(rule_id="A", semantic_path="p", part="value",
                                              kind="replace", count=2),))
    split = BatchSignature(items=(
        SignatureItem(rule_id="A", semantic_path="p", part="value", kind="replace", count=1),
        SignatureItem(rule_id="A", semantic_path="p", part="value", kind="replace", count=1)))
    assert two == split  # canonical form merges equal items
    one = BatchSignature(items=(SignatureItem(rule_id="A", semantic_path="p", part="value",
                                              kind="replace", count=1),))
    assert judge((side([two]), side([one]))).semantic_verdict is ReplayVerdict.DIVERGED


@pytest.mark.parametrize("reason", list(InvalidReason))
def test_incompatibility_is_invalid_before_any_comparison(reason):  # oracle §6
    result = judge((side([sig("A")]), side([sig("B")])), invalid=(reason,))
    assert result.semantic_verdict is ReplayVerdict.INVALID
    assert result.invalid_reasons == (reason,)


def test_runtime_transform_unsupported_is_invalid():
    counts = {"A": {"transform_unsupported": 2}}
    repl = side([], summary_=summary(0, counts))
    result = judge((side([], summary_=summary(0, counts)), repl))
    assert result.semantic_verdict is ReplayVerdict.INVALID
    assert result.invalid_reasons == (InvalidReason.TRANSFORM_UNSUPPORTED,)


def test_corrupt_journal_is_invalid():  # oracle §12
    result = judge((side([sig("A")], integrity=JournalIntegrity.CORRUPT), side([sig("A")])))
    assert result.semantic_verdict is ReplayVerdict.INVALID
    assert InvalidReason.DELTA_CORRUPT in result.invalid_reasons


def test_delivery_alone_never_diverges():  # §37, oracle §20 last case
    prod = side([sig("A")], summary_=None, termination=Termination.GUEST_CRASH,
                delivery=DeliveryState.UNKNOWN)
    repl = side([sig("A")], delivery=DeliveryState.FAILED, summary_=summary(1))
    result = judge((prod, repl))
    assert result.semantic_verdict is ReplayVerdict.EQUIVALENT
    assert result.positions[0].production.refusal_evidence is RefusalEvidence.PREFIX_COMPLETE
    assert result.positions[0].replay.forward_complete_multiset == ()


HARD = ApplyRefusal(rule_id="A", refusal="conflict")
HARD_SUMMARY = summary(1, {"A": {"resolved": 1, "conflict": 1}})


def test_hard_refusal_on_either_side_diverges():  # oracle §20
    prod = side([sig("A")], refusals=(HARD,), summary_=HARD_SUMMARY)
    assert judge((prod, side([sig("A")]))).semantic_verdict is ReplayVerdict.DIVERGED
    assert judge((side([sig("A")]), prod)).semantic_verdict is ReplayVerdict.DIVERGED
    # The same hard refusal on both sides is still not equivalent.
    both = judge((prod, side([sig("A")], refusals=(HARD,), summary_=HARD_SUMMARY)))
    assert both.semantic_verdict is ReplayVerdict.DIVERGED


def test_crash_cut_refusal_written_ahead_diverges():  # oracle §20
    prod = side([sig("A")], refusals=(HARD,), summary_=None,
                termination=Termination.GUEST_CRASH, delivery=DeliveryState.UNKNOWN)
    repl = side([sig("A")], summary_=None, termination=Termination.VM_TEARDOWN,
                delivery=DeliveryState.UNKNOWN)
    result = judge((prod, repl))
    assert result.semantic_verdict is ReplayVerdict.DIVERGED
    assert result.positions[0].production.hard_refusals == (HARD,)


def test_two_clean_crash_cut_prefixes_are_equivalent():  # oracle §20
    prod = side([sig("A")], summary_=None, termination=Termination.GUEST_CRASH,
                delivery=DeliveryState.UNKNOWN)
    repl = side([sig("A")], summary_=None, termination=Termination.GUEST_CRASH,
                delivery=DeliveryState.UNKNOWN, integrity=JournalIntegrity.TORN_TAIL)
    assert judge((prod, repl)).semantic_verdict is ReplayVerdict.EQUIVALENT


@pytest.mark.parametrize("dirty", [
    {"sink_rejections": 1}, {"evidence_path_degraded": True}, {"channel_failed": True},
    {"termination": Termination.SINK_STALL}, {"termination": Termination.UNKNOWN},
    {"termination": Termination.CLEAN},
])
def test_unprovable_refusal_absence_is_inconclusive(dirty):  # oracle §20
    termination = dirty.pop("termination", Termination.GUEST_CRASH)
    repl = side([sig("A")], summary_=None, termination=termination,
                delivery=DeliveryState.UNKNOWN, **dirty)
    assert refusal_evidence(repl) is RefusalEvidence.UNKNOWN
    result = judge((side([sig("A")]), repl))
    assert result.semantic_verdict is ReplayVerdict.INCONCLUSIVE
    assert result.positions[0].differences[0].kind is DifferenceKind.REFUSAL_EVIDENCE_UNKNOWN


def test_summary_with_evidence_path_failures_is_inconclusive():
    repl = side([sig("A")], summary_=summary(1, failures=1))
    assert judge((side([sig("A")]), repl)).semantic_verdict is ReplayVerdict.INCONCLUSIVE


def test_divergence_outranks_unknown_refusal_evidence():
    repl = side([sig("B")], summary_=None, termination=Termination.SINK_STALL,
                delivery=DeliveryState.UNKNOWN)
    assert judge((side([sig("A")]), repl)).semantic_verdict is ReplayVerdict.DIVERGED


def test_missing_window_entry_is_never_equivalent():  # 05 §25, oracle §18
    ok = side([sig("A")], generation=1, digest="a")
    result = judge((None, side([], generation=2, digest="b")),
                   (ok, side([sig("A")], generation=3, digest="a")))
    assert result.semantic_verdict is ReplayVerdict.INCONCLUSIVE
    assert result.positions[0].differences[0].kind is DifferenceKind.PRODUCTION_MISSING
    unrun = judge((ok, None))
    assert unrun.semantic_verdict is ReplayVerdict.INCONCLUSIVE
    assert unrun.positions[0].differences[0].kind is DifferenceKind.REPLAY_MISSING


def test_every_position_counts():
    a = side([sig("A")], generation=1, digest="a")
    b = side([], generation=2, digest="b")
    result = judge((a, side([sig("A")], generation=7, digest="a")),
                   (b, side([sig("A")], generation=8, digest="b")))
    assert result.semantic_verdict is ReplayVerdict.DIVERGED
    assert [bool(p.differences) for p in result.positions] == [False, True]


@pytest.mark.parametrize("make, problem", [
    (lambda: ((side([]), side([])), {"verified": False}), EvidenceProblem.EVIDENCE_UNVERIFIED),
    (lambda: ((side([]), side([], digest="other")), {}), EvidenceProblem.CORRELATION_MISMATCH),
    (lambda: ((side([], generation=1), side([])), (side([], generation=1, digest="b"),
                                                   side([], generation=2, digest="b"))),
     EvidenceProblem.CORRELATION_MISMATCH),
    (lambda: ((side([], refusals=(ApplyRefusal(rule_id="A", refusal="no_such"),),
                    summary_=None, termination=Termination.GUEST_CRASH), side([])), {}),
     EvidenceProblem.UNCLASSIFIED_REFUSAL),
    (lambda: ((side([], summary_=summary(0, {"A": {"conflict": 1}})), side([])), {}),
     EvidenceProblem.INTERNAL_INCONSISTENCY),
    (lambda: ((side([sig("A")], summary_=summary(2)), side([])), {}),
     EvidenceProblem.INTERNAL_INCONSISTENCY),
    (lambda: ((side([sig("A")], delivery=DeliveryState.UNKNOWN), side([sig("A")])), {}),
     EvidenceProblem.INTERNAL_INCONSISTENCY),
])
def test_unverifiable_evidence_has_no_verdict(make, problem):  # §29 row 1
    first, second = make()
    if isinstance(second, dict):
        result = judge(first, invalid=(InvalidReason.SCHEMA_UNAVAILABLE,), **second)
    else:
        result = judge(first, second, invalid=(InvalidReason.SCHEMA_UNAVAILABLE,))
    assert result.semantic_verdict is None
    assert problem in result.invalid_evidence


def test_degraded_summary_without_refusal_event_is_not_inconsistent():
    # The sink refused the APPLY_REFUSAL: counted, not written, and degraded.
    repl = side([], summary_=summary(0, {"A": {"conflict": 1}}, failures=1))
    result = judge((side([]), repl))
    assert result.semantic_verdict is ReplayVerdict.DIVERGED
    assert result.positions[0].replay.refusal_evidence is RefusalEvidence.UNKNOWN


def test_profile_table_is_fixed_and_result_is_content_addressed():
    with pytest.raises(ValidationError):
        ReplayJudgeProfile(name="x", revision="1", hard_refusals=("conflict",))
    first = judge((side([sig("A")]), side([sig("A")])))
    again = judge((side([sig("A")]), side([sig("A")])))
    assert first.verdict_id == again.verdict_id
    assert first.verdict_id != judge((side([sig("A")]), side([sig("B")]))).verdict_id
