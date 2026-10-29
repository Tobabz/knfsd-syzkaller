"""Pure Q2 sanitizer/crash decision kernel (01 §8.2 and §11.1).

The evaluator consumes facts already bound to a verified evidence manifest by
the Controller-side adapter.  It performs no artifact, filesystem, Runner or
guest I/O.  In particular, candidate association is retained only as triage
metadata and never participates in the Q2 oracle.

``Q2JudgeProfile`` is versioned repository design data.  Its canonical digest
is the judge profile identity, so re-evaluating one immutable evidence bundle
under a changed profile creates a new deterministic decision without changing
the old evidence or decision.
"""

from __future__ import annotations

import enum
import re
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .data import canonical_json
from .evidence import ExecutionCorrelation


Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Text = Annotated[str, Field(min_length=1)]
SignalName = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$"),
]
ConsoleLogCompleteness = Literal["complete", "truncated", "missing"]
VmTermination = Literal["runner_stopped", "guest_crashed", "lost", "unknown"]
NoSignalStatus = Literal["not_observed", "inconclusive"]
AttributionQuality = Literal["exact", "campaign", "ambiguous", "none"]

_LEGACY_ATTRIBUTION_ERRORS = (
    "crash_before_generation_attributed_campaign_execution",
    "report_before_generation_attributed_campaign_execution",
    "uncorrelated_program_results:",
    "foreign_program_execution:",
)


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


class Q2Status(str, enum.Enum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"


# ----------------------------------------------------------- repository policy


class Q2SignalClass(_Record):
    """A report class accepted by Q2 and its profile-defined fatality."""

    name: SignalName
    fatal: bool


class Q2ParseRule(_Record):
    """Ordered regular-expression classification for one manager report.

    ``pattern`` identifies a report of the class.  Every
    ``required_pattern`` must then be present for the report to be complete.
    A primary match missing a required pattern is an unclassified (usually
    truncated) report; evaluation does not fall through to a generic rule.
    Patterns are trusted repository data, while report text is untrusted and
    bounded by the evidence store.
    """

    rule_id: Text
    signal_class: SignalName
    pattern: Text
    required_patterns: tuple[Text, ...] = ()

    @field_validator("pattern")
    @classmethod
    def _valid_pattern(cls, pattern: str) -> str:
        compiled = re.compile(pattern)
        if compiled.search("") is not None:
            raise ValueError("a report pattern must not match empty text")
        return pattern

    @field_validator("required_patterns")
    @classmethod
    def _valid_required_patterns(cls, patterns: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(patterns)) != len(patterns):
            raise ValueError("duplicate required report pattern")
        for pattern in patterns:
            compiled = re.compile(pattern)
            if compiled.search("") is not None:
                raise ValueError("a required report pattern must not match empty text")
        return patterns


class Q2CompletenessRule(_Record):
    """Mandatory lower bounds for a definitive no-signal decision.

    The v1 schema deliberately cannot weaken either requirement.  Future
    profiles may add stricter conditions under a new schema, but no profile
    may turn a missing/truncated console or open window into NOT_OBSERVED.
    """

    require_complete_console_log: Literal[True] = True
    require_closed_collection_window: Literal[True] = True


class Q2TerminationRule(_Record):
    termination: VmTermination
    no_signal_status: NoSignalStatus
    reason: Text | None = None

    @model_validator(mode="after")
    def _reason_shape(self) -> Self:
        if self.no_signal_status == "not_observed":
            if self.termination != "runner_stopped":
                raise ValueError("only runner_stopped can permit NOT_OBSERVED")
            if self.reason is not None:
                raise ValueError("a NOT_OBSERVED termination rule has no reason")
        elif self.reason is None:
            raise ValueError("an inconclusive termination rule requires a reason")
        return self


class Q2JudgeProfile(_Record):
    """Trusted, versioned Q2 repository data; ``digest`` is profile identity."""

    schema_version: Literal["q2-judge-profile-v1"] = "q2-judge-profile-v1"
    name: Text
    revision: Text
    signal_classes: Annotated[tuple[Q2SignalClass, ...], Field(min_length=1)]
    parse_rules: Annotated[tuple[Q2ParseRule, ...], Field(min_length=1)]
    completeness_rule: Q2CompletenessRule = Q2CompletenessRule()
    termination_rules: Annotated[tuple[Q2TerminationRule, ...], Field(min_length=4)]

    @model_validator(mode="after")
    def _consistent_profile(self) -> Self:
        class_names = tuple(item.name for item in self.signal_classes)
        if len(set(class_names)) != len(class_names):
            raise ValueError("duplicate Q2 signal class")
        rule_ids = tuple(item.rule_id for item in self.parse_rules)
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("duplicate Q2 parse rule id")
        referenced = {item.signal_class for item in self.parse_rules}
        if not referenced.issubset(class_names):
            raise ValueError("Q2 parse rule references an unknown signal class")
        if set(class_names) != referenced:
            raise ValueError("every Q2 signal class requires a parse rule")
        terminations = tuple(item.termination for item in self.termination_rules)
        required = {"runner_stopped", "guest_crashed", "lost", "unknown"}
        if len(set(terminations)) != len(terminations) or set(terminations) != required:
            raise ValueError("termination rules must cover each termination exactly once")
        return self


def default_q2_profile() -> Q2JudgeProfile:
    """The default signal taxonomy required by 01 §14 item 11.

    Specific sanitizer and hang headlines precede generic BUG reports.
    Fatality describes the class in this profile and remains
    independent of the observed VM termination.
    """

    classes = (
        Q2SignalClass(name="KASAN", fatal=True),
        Q2SignalClass(name="KMSAN", fatal=True),
        Q2SignalClass(name="UBSAN", fatal=False),
        Q2SignalClass(name="KCSAN", fatal=False),
        Q2SignalClass(name="WARNING", fatal=False),
        Q2SignalClass(name="BUG", fatal=True),
        Q2SignalClass(name="panic", fatal=True),
        Q2SignalClass(name="hang", fatal=True),
    )
    rules = (
        Q2ParseRule(rule_id="kasan", signal_class="KASAN",
                    pattern=r"(?m)\bBUG:\s+KASAN:"),
        # A KASAN-instrumented wild or NULL dereference is reported as a
        # general protection fault followed by this KASAN line.
        Q2ParseRule(rule_id="kasan_wild_access", signal_class="KASAN",
                    pattern=(r"(?m)^KASAN:[ \t]+(?:null-ptr-deref|"
                             r"maybe wild-memory-access)\b")),
        Q2ParseRule(rule_id="kmsan", signal_class="KMSAN",
                    pattern=r"(?m)\bBUG:\s+KMSAN:"),
        Q2ParseRule(rule_id="ubsan", signal_class="UBSAN",
                    pattern=r"(?m)\bUBSAN:"),
        Q2ParseRule(rule_id="kcsan", signal_class="KCSAN",
                    pattern=r"(?m)\bBUG:\s+KCSAN:"),
        Q2ParseRule(rule_id="warning", signal_class="WARNING",
                    pattern=r"(?m)\bWARNING:"),
        Q2ParseRule(
            rule_id="hang", signal_class="hang",
            pattern=(r"(?mi)(?:\bINFO:\s+task\s+.+\s+blocked for more than|"
                     r"\bINFO:[ \t]+rcu(?:_preempt|_sched|_bh|_tasks)?[ \t]+"
                     r"(?:self-)?detected[ \t]+(?:expedited[ \t]+)?stalls?\b|"
                     r"\bwatchdog:\s+BUG:\s+soft lockup)"),
        ),
        # Oops headlines syzkaller's pkg/report also treats as crashes.
        Q2ParseRule(
            rule_id="oops", signal_class="BUG",
            pattern=(r"(?m)(?:\bkernel BUG at\b|"
                     r"\bgeneral protection fault\b|\bOops:|"
                     r"\binvalid opcode:|\bUnable to handle kernel\b)"),
        ),
        Q2ParseRule(rule_id="bug", signal_class="BUG",
                    pattern=r"(?m)\bBUG:"),
        Q2ParseRule(rule_id="panic", signal_class="panic",
                    pattern=r"(?mi)\bKernel panic - not syncing:"),
    )
    return Q2JudgeProfile(
        name="knfsd-q2-sanitizer-signals",
        revision="3",
        signal_classes=classes,
        parse_rules=rules,
        termination_rules=(
            Q2TerminationRule(termination="runner_stopped",
                              no_signal_status="not_observed"),
            Q2TerminationRule(termination="guest_crashed",
                              no_signal_status="inconclusive",
                              reason="guest_crashed_without_report"),
            Q2TerminationRule(termination="lost", no_signal_status="inconclusive",
                              reason="runner_lost"),
            Q2TerminationRule(termination="unknown", no_signal_status="inconclusive",
                              reason="termination_unknown"),
        ),
    )


# -------------------------------------------------------------- evidence input


class Q2CollectionWindow(_Record):
    """Host-stamped collection markers; both are required for a closed window."""

    start_marker: Text | None = None
    end_marker: Text | None = None


class CandidateAssociation(_Record):
    """Optional triage metadata.  Q2 deliberately never reads these fields."""

    candidate_id: Text
    symbol: Text | None = None
    symbol_present: bool | None = None


class ManagerCrashReport(_Record):
    artifact_identity: Text
    report_ref: Digest
    text: str


class Q2Evidence(_Record):
    """Normalized sealed facts supplied by a trusted Controller adapter."""

    execution_harness_id: Digest
    correlation: ExecutionCorrelation
    console_log_ref: Digest | None
    console_log_completeness: ConsoleLogCompleteness
    manager_crash_reports: tuple[ManagerCrashReport, ...]
    vm_termination: VmTermination
    collection_window: Q2CollectionWindow
    internal_errors: tuple[Text, ...] = ()
    candidate_association: CandidateAssociation | None = None
    attribution_quality: AttributionQuality = "none"
    attribution_warnings: tuple[Text, ...] = ()


class Q2Input(_Record):
    schema_version: Literal["q2-input-v1"] = "q2-input-v1"
    evidence_manifest_sha256: Digest
    evidence_verified: bool
    expected_execution_harness_id: Digest
    expected_correlation: ExecutionCorrelation
    evidence: Q2Evidence
    profile: Q2JudgeProfile


# --------------------------------------------------------------------- outputs


class Q2Signal(_Record):
    signal_class: SignalName
    fatal: bool
    report_ref: Digest


class Q2Result(_Record):
    """Compact Q2 result suitable for a future Controller interface."""

    verdict_id: Digest
    execution_harness_id: Digest
    evidence_manifest_sha256: Digest
    judge_profile_id: Digest
    status: Q2Status
    reason: str | None
    signals: tuple[Q2Signal, ...]
    vm_termination: VmTermination
    candidate_association: CandidateAssociation | None = None
    attribution_quality: AttributionQuality = "none"
    attribution_warnings: tuple[Text, ...] = ()


class Q2Decision(_Record):
    """Immutable deterministic verdict and complete evaluation lineage."""

    schema_version: Literal["q2-decision-v1"] = "q2-decision-v1"
    verdict_id: Digest
    evaluation_input_sha256: Digest
    execution_harness_id: Digest
    correlation: ExecutionCorrelation
    evidence_manifest_sha256: Digest
    judge_profile_id: Digest
    status: Q2Status
    reason: str | None
    signals: tuple[Q2Signal, ...]
    vm_termination: VmTermination
    candidate_association: CandidateAssociation | None
    attribution_quality: AttributionQuality = "none"
    attribution_warnings: tuple[Text, ...] = ()
    observations: tuple[Text, ...]

    def as_result(self) -> Q2Result:
        return Q2Result(
            verdict_id=self.verdict_id,
            execution_harness_id=self.execution_harness_id,
            evidence_manifest_sha256=self.evidence_manifest_sha256,
            judge_profile_id=self.judge_profile_id,
            status=self.status,
            reason=self.reason,
            signals=self.signals,
            vm_termination=self.vm_termination,
            candidate_association=self.candidate_association,
            attribution_quality=self.attribution_quality,
            attribution_warnings=self.attribution_warnings,
        )


def evaluate(inputs: Q2Input) -> Q2Decision:
    """Apply the Q2 precedence table without I/O or mutable state.

    Schema violations raise ``pydantic.ValidationError``.  Typed but
    unverified, contradictory or incomplete facts produce an INCONCLUSIVE
    decision.  A classified report wins over ordinary collection
    incompleteness, but never over invalid evidence.
    """

    data = Q2Input.model_validate(inputs)
    evidence, profile = data.evidence, data.profile
    integrity_errors = tuple(
        error for error in evidence.internal_errors
        if not error.startswith(_LEGACY_ATTRIBUTION_ERRORS))
    legacy_warnings = tuple(
        error for error in evidence.internal_errors
        if error.startswith(_LEGACY_ATTRIBUTION_ERRORS))
    attribution_warnings = tuple(dict.fromkeys(
        (*evidence.attribution_warnings, *legacy_warnings)))
    attribution_quality = evidence.attribution_quality
    if attribution_quality == "none" and legacy_warnings:
        attribution_quality = (
            "ambiguous"
            if any(item.startswith("foreign_program_execution:")
                   for item in legacy_warnings)
            else "campaign")

    def decide(status: Q2Status, reason: str | None, diagnostic: str,
               *, signals: tuple[Q2Signal, ...] = ()) -> Q2Decision:
        fields = dict(
            schema_version="q2-decision-v1",
            evaluation_input_sha256=data.digest,
            execution_harness_id=data.expected_execution_harness_id,
            correlation=data.expected_correlation,
            evidence_manifest_sha256=data.evidence_manifest_sha256,
            judge_profile_id=profile.digest,
            status=status,
            reason=reason,
            signals=signals,
            vm_termination=evidence.vm_termination,
            candidate_association=evidence.candidate_association,
            attribution_quality=attribution_quality,
            attribution_warnings=attribution_warnings,
            observations=(diagnostic,),
        )
        identity_fields = {
            **fields,
            "correlation": data.expected_correlation.model_dump(mode="json"),
            "status": status.value,
            "signals": tuple(item.model_dump(mode="json") for item in signals),
            "candidate_association": (
                evidence.candidate_association.model_dump(mode="json")
                if evidence.candidate_association is not None else None
            ),
            "attribution_quality": attribution_quality,
            "attribution_warnings": attribution_warnings,
        }
        return Q2Decision(verdict_id=_digest(identity_fields), **fields)

    def inconclusive(reason: str, diagnostic: str) -> Q2Decision:
        return decide(Q2Status.INCONCLUSIVE, reason, diagnostic)

    # 1. Manifest verification, host authority, correlation and consistency.
    report_ids = tuple(item.artifact_identity for item in evidence.manager_crash_reports)
    if (not data.evidence_verified or integrity_errors
            or evidence.execution_harness_id != data.expected_execution_harness_id
            or evidence.correlation != data.expected_correlation
            or data.expected_correlation.execution_harness_id
            != data.expected_execution_harness_id
            or len(set(report_ids)) != len(report_ids)):
        return inconclusive("invalid_evidence", "unverified_or_inconsistent_evidence")
    if (evidence.collection_window.end_marker is not None
            and evidence.collection_window.start_marker is None):
        return inconclusive("invalid_evidence", "collection_window_marker_order_invalid")
    has_console = evidence.console_log_ref is not None
    if ((evidence.console_log_completeness == "missing" and has_console)
            or (evidence.console_log_completeness != "missing" and not has_console)):
        return inconclusive("invalid_evidence", "console_reference_completeness_conflict")

    # 2. Parse every raw manager report under the selected immutable profile.
    classes = {item.name: item for item in profile.signal_classes}
    signals: list[Q2Signal] = []
    unclassified = False
    for report in evidence.manager_crash_reports:
        classified = False
        for rule in profile.parse_rules:
            if re.search(rule.pattern, report.text) is None:
                continue
            if not all(re.search(pattern, report.text) is not None
                       for pattern in rule.required_patterns):
                unclassified = True
                classified = True  # A partial specific report cannot fall through.
                break
            signal_class = classes[rule.signal_class]
            signals.append(Q2Signal(
                signal_class=signal_class.name,
                fatal=signal_class.fatal,
                report_ref=report.report_ref,
            ))
            classified = True
            break
        if not classified:
            unclassified = True
    if signals:
        return decide(Q2Status.OBSERVED, None, "profile_classified_manager_report",
                      signals=tuple(signals))

    # An existing but unclassifiable report is never equivalent to no report.
    if evidence.manager_crash_reports or unclassified:
        return inconclusive("unclassified_report", "manager_report_not_classified")

    # 3. A definitive miss requires all three independent completion facts.
    if evidence.console_log_completeness == "truncated":
        return inconclusive("console_log_truncated", "console_log_not_complete")
    if evidence.console_log_completeness == "missing":
        return inconclusive("console_log_missing", "console_log_not_complete")
    if evidence.collection_window.start_marker is None:
        return inconclusive("collection_window_not_started",
                            "collection_window_start_marker_absent")
    if evidence.collection_window.end_marker is None:
        return inconclusive("collection_window_open",
                            "collection_window_end_marker_absent")

    termination = next(rule for rule in profile.termination_rules
                       if rule.termination == evidence.vm_termination)
    if termination.no_signal_status == "not_observed":
        return decide(Q2Status.NOT_OBSERVED, None,
                      "complete_closed_runner_stopped_without_report")

    # 4. The profile records the deterministic reason for other terminations.
    return inconclusive(termination.reason or "termination_inconclusive",
                        "termination_does_not_support_no_signal")
