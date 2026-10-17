"""Bounded, pure M6 replay comparator (05 §28-§39, 06 §29).

The input is a projection of two already sealed evidence bundles: the
production MutationDelta of every `CrashContextWindow` position and the
separate replay journal of the same window replayed in order.  This module
does not read journals, run a guest, or seal anything; `semantic_delta`
projects host journals into these models and the Runner (`replay_runner`)
supplies what only it knows (compatibility gate result, how each side
ended).  ``evidence_verified`` is the trusted Controller adapter's
statement that both manifests and correlations were checked, never a guest
claim.

ReplayResult compares semantic batch composition per window position.  It
is not Q2: an equivalent replay says the recorded rule set was applied to
the same semantic batches again, not that the crash reproduced.
"""

from __future__ import annotations

import enum
from collections import Counter
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .data import canonical_json


MAX_IDENTIFIER_BYTES = 256
MAX_POSITIONS = 64
MAX_BATCHES = 4096
MAX_SIGNATURE_ITEMS = 64
MAX_RULES = 256
MAX_REFUSALS = 256
MAX_INVALID_REASONS = 32

Identifier = Annotated[
    str,
    Field(min_length=1, max_length=MAX_IDENTIFIER_BYTES, pattern=r"^[^\s\x00-\x1f\x7f]+$"),
]
Visible = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[\x21-\x7e]+$")]
Status = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z_]+$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Count = Annotated[int, Field(ge=0, le=2**64 - 1)]
WindowIndex = Annotated[int, Field(ge=0, lt=MAX_POSITIONS)]


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


class ReplayVerdict(str, enum.Enum):
    EQUIVALENT = "REPLAY_EQUIVALENT"
    DIVERGED = "REPLAY_DIVERGED"
    INCONCLUSIVE = "REPLAY_INCONCLUSIVE"
    INVALID = "REPLAY_INVALID"


class RefusalEvidence(str, enum.Enum):
    COMPLETE = "complete"
    PREFIX_COMPLETE = "prefix_complete"
    UNKNOWN = "unknown"


class RefusalClass(str, enum.Enum):
    NORMAL = "normal_non_match"
    HARD = "hard_refusal"
    INCOMPATIBILITY = "incompatibility"


class JournalIntegrity(str, enum.Enum):
    """Of the sealed journal this side was projected from (05 §24)."""

    VALID = "valid"          # every frame complete
    TORN_TAIL = "torn_tail"  # complete prefix + an uncommitted final append
    CORRUPT = "corrupt"      # a complete bad frame, or failed re-admission


class Termination(str, enum.Enum):
    """How the Runner recorded the end of this side's execution."""

    CLEAN = "clean"
    GUEST_CRASH = "guest_crash"
    VM_TEARDOWN = "vm_teardown"
    SINK_STALL = "sink_stall"  # traffic stopped on an unanswered event
    UNKNOWN = "unknown"


class InvalidReason(str, enum.Enum):
    """§29 row 2: comparison is meaningless (from verified evidence)."""

    DELTA_CORRUPT = "delta_corrupt"
    FORMAT_UNSUPPORTED = "format_unsupported"
    RUNTIME_INCOMPATIBLE = "runtime_incompatible"
    SCHEMA_UNAVAILABLE = "schema_unavailable"
    TRANSFORM_UNSUPPORTED = "transform_unsupported"
    RULE_SET_INCOMPATIBLE = "rule_set_incompatible"
    FIXTURE_FAILED = "fixture_failed"


class EvidenceProblem(str, enum.Enum):
    """§29 row 1: no verdict; the attempt is recorded as invalid evidence."""

    EVIDENCE_UNVERIFIED = "evidence_unverified"
    CORRELATION_MISMATCH = "correlation_mismatch"
    INTERNAL_INCONSISTENCY = "internal_inconsistency"
    UNCLASSIFIED_REFUSAL = "unclassified_refusal"


class DifferenceKind(str, enum.Enum):
    BATCH_MULTISET = "batch_multiset"
    HARD_REFUSAL = "hard_refusal"
    REFUSAL_EVIDENCE_UNKNOWN = "refusal_evidence_unknown"
    PRODUCTION_MISSING = "production_missing"
    REPLAY_MISSING = "replay_missing"


class DeliveryState(str, enum.Enum):
    COMPLETE = "complete"
    FAILED = "failed"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------- JudgeProfile(Replay)


NORMAL_NON_MATCH = ("predicate_false", "rpc_selector_miss", "scope_miss", "target_not_found")
HARD_REFUSALS = (
    "apply_precondition_failed",
    "conflict",
    "decode_unavailable",
    "predicate_reference_ambiguous",
    "schema_mismatch",
    "structure_constraint_failed",
    "target_ambiguous",
    "transaction_context_missing",
    "transaction_context_unusable",
    "transform_failed",
)
INCOMPATIBILITIES = ("transform_unsupported",)
# Resolver summary counters that are not refusals at all.
NON_REFUSAL_COUNTS = ("resolved",)


class ReplayJudgeProfile(_Record):
    """JudgeProfile(Replay) v1 (05 §29).  A different table is a new version."""

    schema_version: Literal["replay-judge-profile-v1"] = "replay-judge-profile-v1"
    name: Identifier
    revision: Identifier
    normal_non_match: tuple[Status, ...] = NORMAL_NON_MATCH
    hard_refusals: tuple[Status, ...] = HARD_REFUSALS
    incompatibilities: tuple[Status, ...] = INCOMPATIBILITIES
    verdict_order: Literal["05-section-29-v1"] = "05-section-29-v1"

    @model_validator(mode="after")
    def _v1_table(self) -> Self:
        if (
            self.normal_non_match != NORMAL_NON_MATCH
            or self.hard_refusals != HARD_REFUSALS
            or self.incompatibilities != INCOMPATIBILITIES
        ):
            raise ValueError("replay-judge-profile-v1 classification cannot be changed")
        return self

    def classify(self, status: str) -> RefusalClass | None:
        if status in self.normal_non_match:
            return RefusalClass.NORMAL
        if status in self.hard_refusals:
            return RefusalClass.HARD
        if status in self.incompatibilities:
            return RefusalClass.INCOMPATIBILITY
        return None


# ---------------------------------------------------------------- sealed evidence projection


class Correlation(_Record):
    vm_instance_id: Identifier
    lane_id: Count
    kcov_generation: Count
    rule_set_id: Digest
    program_digest: Digest


class SignatureItem(_Record):
    """One `semantic_signature` entry of an EXPOSURE_INTENT (05 §9)."""

    rule_id: Visible
    semantic_path: Visible
    part: Identifier
    kind: Identifier
    count: Annotated[int, Field(ge=1, le=2**32 - 1)]


class BatchSignature(_Record):
    items: Annotated[
        tuple[SignatureItem, ...], Field(min_length=1, max_length=MAX_SIGNATURE_ITEMS)
    ]

    @field_validator("items")
    @classmethod
    def _canonical(cls, values: tuple[SignatureItem, ...]) -> tuple[SignatureItem, ...]:
        merged: Counter[tuple[str, str, str, str]] = Counter()
        for item in values:
            merged[(item.rule_id, item.semantic_path, item.part, item.kind)] += item.count
        return tuple(
            SignatureItem(rule_id=r, semantic_path=p, part=t, kind=k, count=c)
            for (r, p, t, k), c in sorted(merged.items())
        )


class Batch(_Record):
    signature: BatchSignature
    delivery: DeliveryState


class ApplyRefusal(_Record):
    rule_id: Visible
    refusal: Status


class RuleCounts(_Record):
    rule_id: Visible
    counts: Annotated[tuple[tuple[Status, Count], ...], Field(max_length=64)]

    @field_validator("counts")
    @classmethod
    def _canonical_counts(
        cls, values: tuple[tuple[str, int], ...]
    ) -> tuple[tuple[str, int], ...]:
        return tuple(sorted(values))


class GenerationSummary(_Record):
    """The GENERATION_COMPLETE facts the comparator needs."""

    evidence_path_failures: Count
    exposure_batch_count: Count
    resolver_summary: Annotated[tuple[RuleCounts, ...], Field(max_length=MAX_RULES)]


class SideGeneration(_Record):
    """One side (production or replay) of one window position."""

    correlation: Correlation
    journal_integrity: JournalIntegrity
    batches: Annotated[tuple[Batch, ...], Field(max_length=MAX_BATCHES)] = ()
    apply_refusals: Annotated[tuple[ApplyRefusal, ...], Field(max_length=MAX_REFUSALS)] = ()
    summary: GenerationSummary | None = None
    # Proxy marked its session evidence_path_degraded / the sink recorded a
    # rejection or append failure / the channel failed for this session.
    evidence_path_degraded: bool = False
    sink_rejections: Count = 0
    channel_failed: bool = False
    termination: Termination


class ReplayPosition(_Record):
    window_index: WindowIndex
    # None: the window entry has no MutationDelta / was not executed.
    production: SideGeneration | None
    replay: SideGeneration | None


class ReplayJudgeInput(_Record):
    schema_version: Literal["replay-judge-input-v1"] = "replay-judge-input-v1"
    candidate_id: Identifier
    production_evidence_manifest_sha256: Digest
    replay_evidence_manifest_sha256: Digest
    evidence_verified: bool
    schema_id: Visible
    semantic_runtime_version: Annotated[int, Field(ge=0, le=2**32 - 1)]
    rule_set_id: Digest
    profile: ReplayJudgeProfile
    # From the Runner's compatibility gate and replay execution (§39).
    invalid_reasons: Annotated[
        tuple[InvalidReason, ...], Field(max_length=MAX_INVALID_REASONS)
    ] = ()
    positions: Annotated[
        tuple[ReplayPosition, ...], Field(min_length=1, max_length=MAX_POSITIONS)
    ]

    @field_validator("invalid_reasons")
    @classmethod
    def _canonical_reasons(cls, values: tuple[InvalidReason, ...]) -> tuple[InvalidReason, ...]:
        return tuple(sorted(set(values), key=lambda value: value.value))

    @field_validator("positions")
    @classmethod
    def _ordered(cls, values: tuple[ReplayPosition, ...]) -> tuple[ReplayPosition, ...]:
        ordered = tuple(sorted(values, key=lambda value: value.window_index))
        if tuple(p.window_index for p in ordered) != tuple(range(len(ordered))):
            raise ValueError("window_index values must be unique and contiguous from zero")
        return ordered


# ---------------------------------------------------------------- result records


class SignatureCount(_Record):
    signature_digest: Digest
    signature: BatchSignature
    count: Annotated[int, Field(ge=1)]


class SideResult(_Record):
    correlation: Correlation
    batch_signature_multiset: tuple[SignatureCount, ...]
    forward_complete_multiset: tuple[SignatureCount, ...]
    hard_refusals: tuple[ApplyRefusal, ...]
    refusal_evidence: RefusalEvidence
    delivery: tuple[tuple[DeliveryState, Count], ...]


class Difference(_Record):
    kind: DifferenceKind
    side: Literal["production", "replay", "both"]
    detail: Annotated[str, Field(max_length=512)] = ""


class PositionResult(_Record):
    window_index: WindowIndex
    production_generation: Count | None
    replay_generation: Count | None
    production: SideResult | None
    replay: SideResult | None
    differences: tuple[Difference, ...]


class ReplayResult(_Record):
    schema_version: Literal["replay-result-v1"] = "replay-result-v1"
    verdict_id: Digest
    evaluation_input_sha256: Digest
    candidate_id: Identifier
    production_evidence_manifest_sha256: Digest
    replay_evidence_manifest_sha256: Digest
    judge_profile_id: Digest
    schema_id: Visible
    semantic_runtime_version: int
    rule_set_id: Digest
    # None only when §29 row 1 applies: the attempt is invalid evidence.
    semantic_verdict: ReplayVerdict | None
    invalid_evidence: tuple[EvidenceProblem, ...]
    invalid_reasons: tuple[InvalidReason, ...]
    positions: tuple[PositionResult, ...]


# ---------------------------------------------------------------- judgment


def _multiset(signatures: list[BatchSignature]) -> tuple[SignatureCount, ...]:
    by_digest: dict[str, BatchSignature] = {}
    counts: Counter[str] = Counter()
    for signature in signatures:
        key = signature.digest
        by_digest[key] = signature
        counts[key] += 1
    return tuple(
        SignatureCount(signature_digest=key, signature=by_digest[key], count=counts[key])
        for key in sorted(counts)
    )


def _side_problem(
    data: ReplayJudgeInput, side: SideGeneration
) -> EvidenceProblem | None:
    if side.correlation.rule_set_id != data.rule_set_id:
        return EvidenceProblem.CORRELATION_MISMATCH
    statuses = [refusal.refusal for refusal in side.apply_refusals]
    if side.summary is not None:
        statuses += [s for rule in side.summary.resolver_summary for s, _ in rule.counts]
    for status in statuses:
        if status not in NON_REFUSAL_COUNTS and data.profile.classify(status) is None:
            return EvidenceProblem.UNCLASSIFIED_REFUSAL
    if any(
        data.profile.classify(r.refusal) is RefusalClass.NORMAL for r in side.apply_refusals
    ):
        # Normal non-match is never written ahead (05 §21).
        return EvidenceProblem.INTERNAL_INCONSISTENCY
    if len({(r.rule_id, r.refusal) for r in side.apply_refusals}) != len(side.apply_refusals):
        return EvidenceProblem.INTERNAL_INCONSISTENCY
    if side.summary is not None:
        if side.summary.exposure_batch_count != len(side.batches):
            return EvidenceProblem.INTERNAL_INCONSISTENCY
        if any(b.delivery is DeliveryState.UNKNOWN for b in side.batches):
            # A summary follows a forward outcome for every batch.
            return EvidenceProblem.INTERNAL_INCONSISTENCY
        if (side.summary.evidence_path_failures or side.evidence_path_degraded
                or side.sink_rejections or side.channel_failed):
            # A refusal the sink did not store is an evidence-path failure,
            # which makes this side's refusal evidence unknown instead.
            return None
        written = {r.rule_id for r in side.apply_refusals}
        for rule in side.summary.resolver_summary:
            hard = sum(
                count for status, count in rule.counts
                if data.profile.classify(status) is RefusalClass.HARD
            )
            # A counted hard refusal must have been written ahead, and a
            # written one must be counted (05 §21).
            if (hard > 0) != (rule.rule_id in written):
                return EvidenceProblem.INTERNAL_INCONSISTENCY
    return None


def _evidence_problems(data: ReplayJudgeInput) -> tuple[EvidenceProblem, ...]:
    problems: set[EvidenceProblem] = set()
    if not data.evidence_verified:
        problems.add(EvidenceProblem.EVIDENCE_UNVERIFIED)
    for which in ("production", "replay"):
        sides = [getattr(p, which) for p in data.positions if getattr(p, which) is not None]
        scopes = {(s.correlation.vm_instance_id, s.correlation.lane_id) for s in sides}
        generations = {
            (s.correlation.vm_instance_id, s.correlation.lane_id, s.correlation.kcov_generation)
            for s in sides
        }
        # A window never crosses a VM instance or a lane (01 §8.1), and its
        # generations are distinct.
        if len(scopes) > 1 or len(generations) != len(sides):
            problems.add(EvidenceProblem.CORRELATION_MISMATCH)
        for side in sides:
            problem = _side_problem(data, side)
            if problem is not None:
                problems.add(problem)
    for position in data.positions:
        if position.production is not None and position.replay is not None:
            if position.production.correlation.program_digest != (
                position.replay.correlation.program_digest
            ):
                problems.add(EvidenceProblem.CORRELATION_MISMATCH)
    return tuple(sorted(problems, key=lambda value: value.value))


def refusal_evidence(side: SideGeneration) -> RefusalEvidence:
    """§29 refusal-evidence completeness of one side of one position."""

    dirty = side.evidence_path_degraded or side.sink_rejections or side.channel_failed
    if side.summary is not None:
        if side.summary.evidence_path_failures == 0 and not dirty:
            return RefusalEvidence.COMPLETE
        return RefusalEvidence.UNKNOWN
    if (
        side.journal_integrity is not JournalIntegrity.CORRUPT
        and not dirty
        and side.termination in (Termination.GUEST_CRASH, Termination.VM_TEARDOWN)
    ):
        return RefusalEvidence.PREFIX_COMPLETE
    return RefusalEvidence.UNKNOWN


def _hard_refusals(data: ReplayJudgeInput, side: SideGeneration) -> tuple[ApplyRefusal, ...]:
    found = {
        (r.rule_id, r.refusal)
        for r in side.apply_refusals
        if data.profile.classify(r.refusal) is RefusalClass.HARD
    }
    if side.summary is not None:
        for rule in side.summary.resolver_summary:
            for status, count in rule.counts:
                if count and data.profile.classify(status) is RefusalClass.HARD:
                    found.add((rule.rule_id, status))
    return tuple(ApplyRefusal(rule_id=r, refusal=s) for r, s in sorted(found))


def _incompatible(data: ReplayJudgeInput, side: SideGeneration) -> bool:
    statuses = [(r.refusal, 1) for r in side.apply_refusals]
    if side.summary is not None:
        statuses += [pair for rule in side.summary.resolver_summary for pair in rule.counts]
    return any(
        count and data.profile.classify(status) is RefusalClass.INCOMPATIBILITY
        for status, count in statuses
    )


def _side_result(data: ReplayJudgeInput, side: SideGeneration) -> SideResult:
    delivery = Counter(b.delivery for b in side.batches)
    return SideResult(
        correlation=side.correlation,
        batch_signature_multiset=_multiset([b.signature for b in side.batches]),
        forward_complete_multiset=_multiset(
            [b.signature for b in side.batches if b.delivery is DeliveryState.COMPLETE]
        ),
        hard_refusals=_hard_refusals(data, side),
        refusal_evidence=refusal_evidence(side),
        delivery=tuple((state, delivery[state]) for state in DeliveryState),
    )


def evaluate(inputs: ReplayJudgeInput) -> ReplayResult:
    """Apply the §29 verdict order to a bounded, sealed projection.

    Type and shape errors raise ``ValidationError``.  Unverified, miscorrelated
    or internally inconsistent evidence yields no verdict (row 1); it never
    becomes REPLAY_INVALID or any comparison result.
    """

    data = ReplayJudgeInput.model_validate(inputs)
    problems = _evidence_problems(data)

    invalid = set(data.invalid_reasons)
    positions: list[PositionResult] = []
    diverged = inconclusive = False
    for position in data.positions:
        prod, repl = position.production, position.replay
        prod_result = _side_result(data, prod) if prod is not None else None
        repl_result = _side_result(data, repl) if repl is not None else None
        differences: list[Difference] = []
        for side in (prod, repl):
            if side is None:
                continue
            if side.journal_integrity is JournalIntegrity.CORRUPT:
                invalid.add(InvalidReason.DELTA_CORRUPT)
            if _incompatible(data, side):
                invalid.add(InvalidReason.TRANSFORM_UNSUPPORTED)
        if prod_result is None or repl_result is None:
            # A missing MutationDelta or an unexecuted replay entry is never
            # replaced by a shorter comparison (05 §25).
            inconclusive = True
            if prod_result is None:
                differences.append(Difference(
                    kind=DifferenceKind.PRODUCTION_MISSING, side="production"))
            if repl_result is None:
                differences.append(Difference(
                    kind=DifferenceKind.REPLAY_MISSING, side="replay"))
        else:
            if prod_result.batch_signature_multiset != repl_result.batch_signature_multiset:
                diverged = True
                differences.append(Difference(
                    kind=DifferenceKind.BATCH_MULTISET, side="both",
                    detail=(f"production={sum(c.count for c in prod_result.batch_signature_multiset)}"
                            f" replay={sum(c.count for c in repl_result.batch_signature_multiset)}"
                            " batches")))
        for name, result in (("production", prod_result), ("replay", repl_result)):
            if result is None:
                continue
            if result.hard_refusals:
                diverged = True
                differences.append(Difference(
                    kind=DifferenceKind.HARD_REFUSAL, side=name,
                    detail=" ".join(f"{r.rule_id}:{r.refusal}" for r in result.hard_refusals)[:512]))
            if result.refusal_evidence is RefusalEvidence.UNKNOWN:
                inconclusive = True
                differences.append(Difference(
                    kind=DifferenceKind.REFUSAL_EVIDENCE_UNKNOWN, side=name))
        positions.append(PositionResult(
            window_index=position.window_index,
            production_generation=prod.correlation.kcov_generation if prod else None,
            replay_generation=repl.correlation.kcov_generation if repl else None,
            production=prod_result,
            replay=repl_result,
            differences=tuple(differences),
        ))

    verdict: ReplayVerdict | None
    if problems:
        verdict = None
    elif invalid:
        verdict = ReplayVerdict.INVALID
    elif diverged:
        verdict = ReplayVerdict.DIVERGED
    elif inconclusive:
        verdict = ReplayVerdict.INCONCLUSIVE
    else:
        verdict = ReplayVerdict.EQUIVALENT

    fields = dict(
        evaluation_input_sha256=data.digest,
        candidate_id=data.candidate_id,
        production_evidence_manifest_sha256=data.production_evidence_manifest_sha256,
        replay_evidence_manifest_sha256=data.replay_evidence_manifest_sha256,
        judge_profile_id=data.profile.digest,
        schema_id=data.schema_id,
        semantic_runtime_version=data.semantic_runtime_version,
        rule_set_id=data.rule_set_id,
        semantic_verdict=verdict,
        invalid_evidence=problems,
        invalid_reasons=tuple(sorted(invalid, key=lambda value: value.value)),
        positions=tuple(positions),
    )
    identity = {
        **fields,
        "semantic_verdict": verdict.value if verdict else None,
        "invalid_evidence": [p.value for p in problems],
        "invalid_reasons": [r.value for r in fields["invalid_reasons"]],  # type: ignore[union-attr]
        "positions": [p.model_dump(mode="json") for p in positions],
    }
    return ReplayResult(verdict_id=_digest(identity), **fields)


__all__ = [
    "ApplyRefusal", "Batch", "BatchSignature", "Correlation", "DeliveryState",
    "Difference", "DifferenceKind", "EvidenceProblem", "GenerationSummary",
    "InvalidReason", "JournalIntegrity", "PositionResult", "RefusalClass",
    "RefusalEvidence", "ReplayJudgeInput", "ReplayJudgeProfile", "ReplayPosition",
    "ReplayResult", "ReplayVerdict", "RuleCounts", "SideGeneration", "SideResult",
    "SignatureCount", "SignatureItem", "Termination", "evaluate", "refusal_evidence",
]
