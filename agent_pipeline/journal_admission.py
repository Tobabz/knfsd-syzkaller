"""Pure structural/lifecycle admission and reconstruction of journal prefixes.

No semantic approval, I/O, ACK, activation, replay execution or M1 projection.
Authority is selected independently by the caller, never learned from a guest
event. A prepared next_state is only a value; a future writer must retain the
old state until persistence succeeds and serialize concurrent preparations.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, replace
from hashlib import sha256
from typing import Iterable, Literal

from .journal_events import (
    HARD_REFUSALS, MAX_GENERATIONS, ExposureEvent, GenerationCompleteEvent,
    GenerationCompletePayload, GenerationCorrelation, GenerationDrainingEvent,
    GenerationOpenEvent, JournalEvent, JournalEventError, RecordContext,
    RefusalEvent, ResolverCounts, RuleSnapshot, RulesetEvent, RunCompleteEvent,
    ScalarRule, decode_event, parse_ruleset,
)
from .journal_framing import (
    HEADER, MAX_SEGMENT_BYTES, MAX_SEGMENT_RECORDS, FrameKind, HostSessionBinding,
    JournalFrame,
)

MAX_SESSION_BYTES = MAX_SEGMENT_BYTES
MAX_SESSION_EVENTS = MAX_SEGMENT_RECORDS
MAX_BATCHES = 4096


class AdmissionError(ValueError):
    """A refusal for the future host writer to record, never a success ACK.

    No state is changed on rejection. The caller must preserve the rejection
    as evidence or fail the channel; silently continuing loses integrity facts.
    """

    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


@dataclass(frozen=True)
class HostAuthority:
    """Host-selected inputs, not a claim that semantic approval was performed.

    ``snapshot_bytes`` must be the exact independently selected installed
    snapshot, and ``generations`` the host's permitted correlations. This pure
    constructor cannot authenticate their origin or run the C schema validator.
    The caller must not fill them from the request being admitted.
    """

    session_binding: HostSessionBinding
    snapshot_bytes: bytes
    generations: tuple[GenerationCorrelation, ...]
    snapshot: RuleSnapshot = field(init=False)

    def __post_init__(self) -> None:
        binding = HostSessionBinding.model_validate(self.session_binding)
        snapshot = parse_ruleset(self.snapshot_bytes)
        if binding.rule_set_id != snapshot.rule_set_id:
            raise ValueError("host binding does not name the selected NFSPRUL1 bytes")
        if type(self.generations) is not tuple or len(self.generations) > MAX_GENERATIONS:
            raise ValueError("host generation authority must be a bounded immutable tuple")
        correlations = tuple(GenerationCorrelation.model_validate(c) for c in self.generations)
        ids = set()
        lane_procs: dict[int, int] = {}
        for correlation in correlations:
            if (correlation.vm_instance_id != binding.vm_instance_id
                    or correlation.rule_set_id != binding.rule_set_id):
                raise ValueError("host generation authority differs from session binding")
            if correlation.kcov_generation in ids:
                raise ValueError("host generation IDs must be unique within the session")
            ids.add(correlation.kcov_generation)
            if lane_procs.setdefault(correlation.lane_id, correlation.proc_id) != correlation.proc_id:
                raise ValueError("host lane has conflicting proc identities")
        object.__setattr__(self, "session_binding", binding)
        object.__setattr__(self, "generations", correlations)
        object.__setattr__(self, "snapshot", snapshot)


@dataclass(frozen=True)
class RefusalFact:
    rule_id: str
    refusal: str


@dataclass(frozen=True)
class GenerationState:
    correlation: GenerationCorrelation
    phase: Literal["admitting", "draining", "closed"]
    refusals: tuple[RefusalFact, ...] = ()
    summary: GenerationCompletePayload | None = None


@dataclass(frozen=True)
class BatchState:
    batch_id: str
    correlation: GenerationCorrelation
    final_record_length: int
    application_rule_ids: tuple[str, ...]
    outcome: Literal["complete", "failed"] | None = None


@dataclass(frozen=True)
class AdmissionState:
    """Initialize with initial_state; thereafter use only prepared next states.

    Exact request bytes are retained for byte-identical retransmission, bounded
    across the entire session. Neither state nor next_event_seq is a durability
    certificate. Python object fabrication is outside this trusted API boundary.
    """

    authority: HostAuthority
    requests: tuple[bytes, ...] = ()
    generations: tuple[GenerationState, ...] = ()
    batches: tuple[BatchState, ...] = ()
    framed_bytes: int = 0
    run_complete: bool = False

    @property
    def next_event_seq(self) -> int:
        return len(self.requests)


@dataclass(frozen=True)
class PreparedEvent:
    event: JournalEvent
    request_sha256: str
    duplicate: bool
    next_state: AdmissionState


def initial_state(authority: HostAuthority) -> AdmissionState:
    if type(authority) is not HostAuthority:
        raise TypeError("an independently selected HostAuthority is required")
    return AdmissionState(authority=authority)


def _refuse(code: str, detail: str) -> None:
    raise AdmissionError(code, detail)


def _context(rule: ScalarRule, context: RecordContext, *, exposure: bool) -> None:
    if (rule.direction, rule.backend, rule.client, rule.message_type) != (
            context.direction, context.backend, context.client, context.rpc_message_type):
        _refuse("rule_context_mismatch", "route/message type differs from the exact rule")
    for expected, observed in ((rule.program, context.rpc_program),
                               (rule.version, context.rpc_version),
                               (rule.procedure, context.rpc_procedure),
                               (rule.family, context.protocol_family),
                               (rule.nfs_version, context.nfs_version),
                               (rule.minor_version, context.minor_version)):
        # Refusal can precede decoding or transaction lookup. Known dispatch
        # still must agree; exposure must supply every selected dispatch value.
        if expected is not None and (exposure or observed is not None) and expected != observed:
            _refuse("rule_context_mismatch", "selected dispatch value disagrees or is missing")


def _exposure(event: ExposureEvent, rules: dict[str, ScalarRule]) -> None:
    for application in event.payload.applications:
        rule = rules.get(application.rule_id)
        if rule is None:
            _refuse("unknown_rule", "application not in the exact host snapshot")
        _context(rule, event.payload.record_context, exposure=True)
        target = application.semantic_target
        if (target.semantic_path != rule.target_path
                or application.structure_policy != rule.structure_policy
                or application.mutated_value_snapshot != rule.literal
                or (rule.operation is not None and target.operation != rule.operation)):
            _refuse("rule_evidence_mismatch", "target/policy/literal differs from snapshot")
        # No claim that field_index, operation_index or wire_span names the
        # schema node: that requires the absent schema-aware evidence bridge.


def _generation_summary(event: GenerationCompleteEvent, generation: GenerationState,
                        batches: tuple[BatchState, ...], rule_ids: tuple[str, ...]) -> None:
    summary = event.payload
    owned = tuple(b for b in batches if b.correlation == generation.correlation)
    if any(b.outcome is None for b in owned):
        _refuse("open_batch", "generation summary requires every batch to be forward-closed")
    if summary.exposure_batch_count != len(owned):
        _refuse("summary_mismatch", "exposure count does not match admitted batches")
    if summary.closure.reason != "aborted" and generation.phase != "draining":
        _refuse("generation_phase", "non-aborted closure requires prior draining")
    if tuple(s.rule_id for s in summary.resolver_summary) != rule_ids:
        _refuse("summary_mismatch", "summary must cover every and only snapshot rule")
    applied = Counter(rule for b in owned for rule in b.application_rule_ids)
    refusals = {r.rule_id: r.refusal for r in generation.refusals}
    for item in summary.resolver_summary:
        counts = item.counts
        if counts.resolved < applied[item.rule_id]:
            _refuse("summary_mismatch", "resolved count omits recorded applications")
        hard = any(getattr(counts, name) for name in HARD_REFUSALS)
        if hard != (item.rule_id in refusals):
            _refuse("refusal_summary_mismatch", "hard refusal counts require a first refusal witness")
        if item.rule_id in refusals and not getattr(counts, refusals[item.rule_id]):
            _refuse("refusal_summary_mismatch", "summary omits the recorded refusal kind")


def _run_summary(event: RunCompleteEvent, state: AdmissionState,
                 rule_ids: tuple[str, ...]) -> None:
    if any(g.phase != "closed" for g in state.generations):
        _refuse("open_generation", "RUN_COMPLETE requires all opened generations closed")
    payload = event.payload
    if (payload.batch_count, payload.forward_complete_count, payload.forward_failed_count) != (
            len(state.batches), sum(b.outcome == "complete" for b in state.batches),
            sum(b.outcome == "failed" for b in state.batches)):
        _refuse("summary_mismatch", "run batch/forward totals disagree")
    if tuple(s.rule_id for s in payload.rule_summaries) != rule_ids:
        _refuse("summary_mismatch", "run summary membership differs from snapshot")
    totals = {rule_id: Counter() for rule_id in rule_ids}
    for generation in state.generations:
        for item in generation.summary.resolver_summary:
            totals[item.rule_id].update(item.counts.model_dump())
    for item in payload.rule_summaries:
        for name in ResolverCounts.model_fields:
            if getattr(item.counts, name) != totals[item.rule_id][name]:
                _refuse("summary_mismatch", "run rule totals differ from generation summaries")


def prepare_event(state: AdmissionState, request: bytes) -> PreparedEvent:
    """Check one canonical request and return a candidate immutable next state.

    An identical old request returns the SAME state and duplicate=True, including
    after RUN_COMPLETE. It carries no ACK or append outcome. All other terminal
    requests fail. No exception or successful preparation mutates ``state``.
    """
    try:
        event = decode_event(request)
    except JournalEventError as error:
        raise AdmissionError("malformed_event", str(error)) from error
    authority = state.authority
    if event.session_binding != authority.session_binding:
        _refuse("session_mismatch", "guest binding differs from host-selected session/channel/VM/ruleset")
    digest = sha256(request).hexdigest()
    seq = event.event_seq
    if seq < state.next_event_seq:
        if request == state.requests[seq]:
            return PreparedEvent(event, digest, True, state)
        _refuse("event_conflict", "same sequence has different request bytes")
    if seq != state.next_event_seq:
        _refuse("sequence_violation", "per-session sequence must be contiguous from zero")
    if state.run_complete:
        _refuse("session_closed", "RUN_COMPLETE is final")
    size = state.framed_bytes + HEADER.size + len(request)
    if state.next_event_seq >= MAX_SESSION_EVENTS or size > MAX_SESSION_BYTES:
        _refuse("session_limit", "bounded session storage exceeded")
    if not state.requests:
        if not isinstance(event, RulesetEvent):
            _refuse("ruleset_first", "sequence zero must contain RULESET")
        if bytes.fromhex(event.payload.snapshot_hex) != authority.snapshot_bytes:
            _refuse("ruleset_mismatch", "RULESET must preserve the exact host-selected snapshot")
        return PreparedEvent(event, digest, False,
                             replace(state, requests=(request,), framed_bytes=size))
    if isinstance(event, RulesetEvent):
        _refuse("ruleset_conflict", "a session has one immutable RULESET")

    rules = {r.rule_id: r for r in authority.snapshot.rules}
    rule_ids = tuple(rules)
    generations, batches = state.generations, state.batches
    if isinstance(event, RunCompleteEvent):
        _run_summary(event, state, rule_ids)
    else:
        correlation = event.program_generation_correlation
        if correlation not in authority.generations:
            _refuse("correlation_mismatch", "generation/lane/proc/program differs from host authority")
        generation = next((g for g in generations if g.correlation == correlation), None)
        if isinstance(event, GenerationOpenEvent):
            if generation is not None:
                _refuse("generation_reused", "generation was already bound in this session")
            lane = tuple(g for g in generations if g.correlation.lane_id == correlation.lane_id)
            if any(g.phase == "admitting" for g in lane):
                _refuse("lane_admitting", "another generation still admits CALL on this lane")
            draining = tuple(sorted(g.correlation.kcov_generation for g in lane if g.phase == "draining"))
            if event.payload.draining_generations != draining:
                _refuse("draining_set_mismatch", "OPEN must name the exact draining set on its lane")
            generations += (GenerationState(correlation, "admitting"),)
        else:
            if generation is None:
                _refuse("generation_not_open", "generation needs GENERATION_OPEN first")
            if generation.phase == "closed":
                _refuse("generation_closed", "GENERATION_COMPLETE is final for this binding")
            updated = generation
            if isinstance(event, GenerationDrainingEvent):
                if generation.phase != "admitting":
                    _refuse("generation_phase", "only admitting generations can start draining")
                updated = replace(generation, phase="draining")
            elif isinstance(event, (ExposureEvent, RefusalEvent)):
                if generation.phase == "draining" and event.payload.record_context.rpc_message_type != "reply":
                    _refuse("call_while_draining", "only REPLY evidence may arrive while draining")
                if isinstance(event, ExposureEvent):
                    if any(b.batch_id == event.payload.batch_id for b in batches):
                        _refuse("batch_conflict", "exposure batch IDs are session-unique")
                    if len(batches) >= MAX_BATCHES:
                        _refuse("batch_limit", "bounded session batch count exceeded")
                    _exposure(event, rules)
                    batches += (BatchState(event.payload.batch_id, correlation,
                                            event.payload.output.final_record_length,
                                            tuple(a.rule_id for a in event.payload.applications)),)
                else:
                    rule = rules.get(event.payload.rule_id)
                    if rule is None:
                        _refuse("unknown_rule", "refusal rule not in host snapshot")
                    _context(rule, event.payload.record_context, exposure=False)
                    if any(r.rule_id == rule.rule_id for r in generation.refusals):
                        _refuse("refusal_conflict", "only the first hard refusal per generation/rule is an event")
                    updated = replace(generation, refusals=generation.refusals + (
                        RefusalFact(rule.rule_id, event.payload.refusal),))
            elif isinstance(event, GenerationCompleteEvent):
                _generation_summary(event, generation, batches, rule_ids)
                updated = replace(generation, phase="closed", summary=event.payload)
            else:  # Typed union leaves only FORWARD_COMPLETE / FORWARD_FAILED.
                batch = next((b for b in batches if b.batch_id == event.payload.batch_id), None)
                if batch is None:
                    _refuse("unknown_batch", "forward outcome has no admitted exposure")
                if batch.correlation != correlation:
                    _refuse("batch_correlation_mismatch", "forward outcome belongs to another generation/lane")
                if batch.outcome is not None:
                    _refuse("batch_conflict", "a batch has only one forward outcome")
                if event.event_type == "FORWARD_COMPLETE":
                    if event.payload.forwarded_length != batch.final_record_length:
                        _refuse("forward_length", "full write must equal the complete framed record length")
                    outcome = "complete"
                else:
                    written = event.payload.bytes_written
                    if written is not None and written >= batch.final_record_length:
                        _refuse("forward_length", "failed write cannot claim the full record or more")
                    outcome = "failed"
                batches = tuple(replace(b, outcome=outcome) if b is batch else b for b in batches)
            generations = tuple(updated if g is generation else g for g in generations)
    next_state = replace(state, requests=state.requests + (request,), framed_bytes=size,
                         generations=generations, batches=batches,
                         run_complete=isinstance(event, RunCompleteEvent))
    return PreparedEvent(event, digest, False, next_state)


def reconstruct(authority: HostAuthority, frames: Iterable[JournalFrame]) -> AdmissionState:
    """Revalidate complete event frames using exactly the live prepare path.

    Supply only framing-verified complete records, plus independent host
    authority. Torn-tail policy belongs to the future writer. Rejection frames
    have no typed contract here and fail closed; never silently drop them.
    Duplicate *stored* events are corruption even though request retry is legal.
    This function neither executes semantic replay nor establishes durability.
    """
    state = initial_state(authority)
    for frame in frames:
        if type(frame) is not JournalFrame or frame.kind != FrameKind.JOURNAL_EVENT:
            _refuse("unsupported_record", "reconstruction requires event frames; rejection/ACK cannot be skipped")
        prepared = prepare_event(state, frame.payload)
        if prepared.duplicate:
            _refuse("duplicate_stored_event", "a retransmission must not be appended twice")
        state = prepared.next_state
    return state
