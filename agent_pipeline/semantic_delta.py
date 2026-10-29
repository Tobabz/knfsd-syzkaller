"""M6 semantic Delta reader: a sealed host journal, read only (05 §22-§25).

The production MutationDelta of a generation is not a file of its own: it is
the generation's events in the Runner host journal that `journal_sink`
wrote (RULESET of its Proxy session, GENERATION_OPEN .. GENERATION_COMPLETE,
the batches and refusals in between).  This module opens such a journal
without ever writing to it, re-admits every complete frame through the
sink's own admission rules (so a journal that the sink could not have
written is refused, not interpreted), and projects one generation into the
replay comparator's `SideGeneration`.

Integrity follows §24: an incomplete final append of a segment is an
uncommitted tail and is reported, never read as an event; a complete frame
that fails its hash, a non-canonical record, or an event that fails
re-admission is corruption, and the whole journal is refused.

The segment digests make the immutability check of 05 oracle §13 a byte
comparison: `SealedJournal.manifest()` before and after a replay must match.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Any

from .data import canonical_json, parse_json
from .journal_framing import (
    FrameLimits, HostSessionBinding, JournalFrame, JournalFramingError, read_journal,
)
from .journal_sink import (
    SEGMENT_SUFFIX, SESSION_END_SCHEMA, ApplyRefusalPayload, ExposureIntentPayload,
    ForwardCompletePayload, ForwardFailedPayload, GenerationCompletePayload,
    GenerationOpenPayload, HostJournal, JournalSinkError, NfsCompoundReplyPayload,
    RequestError, ruleset_header,
)
from .semantic_replay import (
    ApplyRefusal, Batch, BatchSignature, Correlation, DeliveryState, GenerationSummary,
    JournalIntegrity, RuleCounts, SideGeneration, SignatureItem, Termination,
)


class DeltaReadError(ValueError):
    """The journal is corrupt or not one the sink could have written."""


@dataclass(frozen=True)
class SegmentInfo:
    name: str
    size: int
    sha256: str
    torn_tail_bytes: int


@dataclass
class ExposureDelta:
    batch_id: int
    event_seq: int
    message_type: str
    signature: tuple[SignatureItem, ...]
    terminal: str | None = None  # complete | failed
    terminal_seq: int | None = None
    #: (rule_id, semantic_path, SHA-256 of original_value) per application:
    #: what M7 compares to show replay ran on other dynamic originals.
    originals: tuple[tuple[str, str, str], ...] = ()
    applications: tuple["ApplicationDelta", ...] = ()
    record_context: object | None = None


@dataclass(frozen=True)
class ApplicationDelta:
    rule_id: str
    semantic_path: str
    kind: str
    part: str
    original_value: str
    mutated_value: str


@dataclass(frozen=True)
class ProtocolOperationDelta:
    index: int
    name: str
    opcode: int
    status: int


@dataclass(frozen=True)
class CompoundReplyDelta:
    event_seq: int
    minor_version: int
    record_context: object
    operations: tuple[ProtocolOperationDelta, ...]


@dataclass
class GenerationDelta:
    kcov_generation: int
    lane_id: int
    program_digest: str
    open_seq: int
    draining_seq: int | None = None
    exposures: list[ExposureDelta] = field(default_factory=list)
    refusals: list[ApplyRefusalPayload] = field(default_factory=list)
    protocol_replies: list[CompoundReplyDelta] = field(default_factory=list)
    summary: GenerationCompletePayload | None = None
    summary_seq: int | None = None
    #: The last event of this generation in the journal, of any type.
    last_seq: int = 0


@dataclass
class SessionDelta:
    binding: HostSessionBinding
    lane_id: int
    rule_set: bytes
    semantic_runtime_version: int
    schema_id: str
    candidate_id: str
    end_reason: str | None = None  # run_complete or the Runner's session-end reason
    rejections: int = 0
    inconsistent: tuple[str, ...] = ()
    generations: dict[int, GenerationDelta] = field(default_factory=dict)


class _ReadOnlyJournal(HostJournal):
    """HostJournal recovery without a writer: nothing here can append."""

    def __init__(self, directory: Path, name: str, *, limits: FrameLimits) -> None:
        self.end_reasons: dict[str, str] = {}
        super().__init__(directory, name, limits=limits)

    def _make_directory(self) -> None:
        if not self.directory.is_dir():
            raise DeltaReadError(f"no journal directory {self.directory}")

    def _append(self, kind: Any, payload: bytes) -> tuple[str, int, bytes]:
        raise JournalSinkError("a sealed journal is read only")

    def _replay(self, journal_id: str, end: int, frame: JournalFrame) -> None:
        super()._replay(journal_id, end, frame)
        value = parse_json(frame.payload)
        if isinstance(value, dict) and value.get("schema_version") == SESSION_END_SCHEMA:
            self.end_reasons.setdefault(value["proxy_session_id"], value["reason"])


class SealedJournal:
    """A host journal opened read only, re-admitted and indexed by generation."""

    def __init__(self, directory: Path, name: str, *,
                 limits: FrameLimits = FrameLimits()) -> None:
        self.directory = Path(directory)
        self.name = name
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise ValueError("invalid journal name")
        self.segments = self._segments(limits)
        if not self.segments:
            raise DeltaReadError(f"no {name} segments in {self.directory}")
        try:
            view = _ReadOnlyJournal(self.directory, name, limits=limits)
        except (JournalFramingError, RequestError, JournalSinkError, KeyError,
                ValueError, TypeError) as error:
            raise DeltaReadError(f"journal fails re-admission: {error}") from error
        self.sessions = self._index(view)
        # The view read the same bytes the digests name: refuse a journal
        # that changed while it was read.
        if self._segments(limits) != self.segments:
            raise DeltaReadError("journal changed while it was read")

    def _segments(self, limits: FrameLimits) -> tuple[SegmentInfo, ...]:
        pattern = re.compile(re.escape(self.name) + r"\.(\d{4})" + re.escape(SEGMENT_SUFFIX))
        if not self.directory.is_dir():
            raise DeltaReadError(f"no journal directory {self.directory}")
        found = []
        for path in sorted(self.directory.iterdir()):
            if not pattern.fullmatch(path.name):
                continue
            data = path.read_bytes()
            try:
                prefix = read_journal(_Bytes(data), limits=limits)
            except JournalFramingError as error:
                raise DeltaReadError(f"{path.name}: {error}") from error
            found.append(SegmentInfo(path.name, len(data), hashlib.sha256(data).hexdigest(),
                                     prefix.torn_tail_bytes))
        return tuple(found)

    @staticmethod
    def _index(view: _ReadOnlyJournal) -> dict[str, SessionDelta]:
        sessions: dict[str, SessionDelta] = {}
        for session_id, state in view._sessions.items():  # noqa: SLF001
            version, schema_id, candidate_id = ruleset_header(state.rule_set)
            end = "run_complete" if state.ended == "run_complete" else (
                view.end_reasons.get(session_id))
            sessions[session_id] = SessionDelta(
                binding=state.binding, lane_id=state.lane_id, rule_set=state.rule_set,
                semantic_runtime_version=version, schema_id=schema_id,
                candidate_id=candidate_id, end_reason=end, rejections=state.rejections,
                inconsistent=tuple(state.inconsistent))
        for event in view.events():
            request = event.request
            session = sessions[request.proxy_session_id]
            payload = request.payload
            if request.event_type in ("RULESET", "RUN_COMPLETE"):
                continue
            g = payload.correlation.kcov_generation  # type: ignore[attr-defined]
            if request.event_type == "GENERATION_OPEN":
                assert isinstance(payload, GenerationOpenPayload)
                session.generations[g] = GenerationDelta(
                    g, payload.correlation.lane_id, payload.correlation.program_digest,
                    request.event_seq, last_seq=request.event_seq)
                continue
            gen = session.generations[g]
            gen.last_seq = max(gen.last_seq, request.event_seq)
            if request.event_type == "GENERATION_DRAINING":
                gen.draining_seq = request.event_seq
            elif request.event_type == "EXPOSURE_INTENT":
                assert isinstance(payload, ExposureIntentPayload)
                gen.exposures.append(ExposureDelta(
                    payload.batch_id, request.event_seq, payload.record_context.message_type,
                    tuple(SignatureItem(rule_id=i.rule_id, semantic_path=i.semantic_path,
                                        part=i.part, kind=i.kind, count=i.count)
                          for i in payload.semantic_signature),
                    originals=tuple(
                        (a.rule_id, a.semantic_path,
                         hashlib.sha256(bytes.fromhex(a.original_value)).hexdigest())
                        for a in payload.applications),
                    applications=tuple(ApplicationDelta(
                        rule_id=a.rule_id, semantic_path=a.semantic_path,
                        kind=a.kind, part=a.part,
                        original_value=a.original_value,
                        mutated_value=a.mutated_value)
                        for a in payload.applications),
                    record_context=payload.record_context))
            elif request.event_type in ("FORWARD_COMPLETE", "FORWARD_FAILED"):
                assert isinstance(payload, (ForwardCompletePayload, ForwardFailedPayload))
                for exposure in gen.exposures:
                    if exposure.batch_id == payload.batch_id:
                        exposure.terminal = ("complete" if request.event_type ==
                                             "FORWARD_COMPLETE" else "failed")
                        exposure.terminal_seq = request.event_seq
            elif request.event_type == "APPLY_REFUSAL":
                assert isinstance(payload, ApplyRefusalPayload)
                gen.refusals.append(payload)
            elif request.event_type == "NFS_COMPOUND_REPLY":
                assert isinstance(payload, NfsCompoundReplyPayload)
                gen.protocol_replies.append(CompoundReplyDelta(
                    event_seq=request.event_seq,
                    minor_version=payload.minor_version,
                    record_context=payload.record_context,
                    operations=tuple(ProtocolOperationDelta(
                        index=op.index, name=op.name, opcode=op.opcode,
                        status=op.status) for op in payload.operations)))
            elif request.event_type == "GENERATION_COMPLETE":
                assert isinstance(payload, GenerationCompletePayload)
                gen.summary = payload
                gen.summary_seq = request.event_seq
        return sessions

    # -- views --

    @property
    def torn_tail(self) -> bool:
        return any(s.torn_tail_bytes for s in self.segments)

    def manifest(self) -> dict[str, Any]:
        """Exact bytes this view read; equal before and after a replay."""
        return {"name": self.name,
                "segments": [{"name": s.name, "sha256": s.sha256, "size": s.size,
                              "torn_tail_bytes": s.torn_tail_bytes}
                             for s in self.segments]}

    def manifest_sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.manifest())).hexdigest()

    def find(self, *, vm_instance_id: str, lane_id: int, kcov_generation: int,
             program_digest: str) -> tuple[SessionDelta, GenerationDelta] | None:
        """The one generation with this host-known identity, or None.

        More than one match is a correlation the host cannot resolve and is
        refused rather than guessed.
        """
        found = [(s, s.generations[kcov_generation]) for s in self.sessions.values()
                 if s.binding.vm_instance_id == vm_instance_id and s.lane_id == lane_id
                 and kcov_generation in s.generations
                 and s.generations[kcov_generation].program_digest == program_digest]
        if len(found) > 1:
            raise DeltaReadError("generation identity matches more than one session")
        return found[0] if found else None

    def side(self, session: SessionDelta, generation: GenerationDelta, *,
             termination: Termination, channel_failed: bool = False) -> SideGeneration:
        """Project one generation into the comparator's evidence model."""
        summary = None
        if generation.summary is not None:
            s = generation.summary
            summary = GenerationSummary(
                evidence_path_failures=s.evidence_path_failures,
                exposure_batch_count=s.exposure_batch_count,
                resolver_summary=tuple(
                    RuleCounts(rule_id=r.rule_id, counts=tuple(sorted(r.counts.items())))
                    for r in s.resolver_summary))
        delivery = {"complete": DeliveryState.COMPLETE, "failed": DeliveryState.FAILED,
                    None: DeliveryState.UNKNOWN}
        return SideGeneration(
            correlation=Correlation(
                vm_instance_id=session.binding.vm_instance_id, lane_id=session.lane_id,
                kcov_generation=generation.kcov_generation,
                rule_set_id=session.binding.rule_set_id,
                program_digest=generation.program_digest),
            journal_integrity=JournalIntegrity.TORN_TAIL if self.torn_tail
            else JournalIntegrity.VALID,
            batches=tuple(Batch(signature=BatchSignature(items=e.signature),
                                delivery=delivery[e.terminal])
                          for e in generation.exposures),
            apply_refusals=tuple(ApplyRefusal(rule_id=r.rule_id, refusal=r.refusal)
                                 for r in generation.refusals),
            summary=summary,
            evidence_path_degraded=bool(session.inconsistent),
            sink_rejections=session.rejections,
            channel_failed=channel_failed,
            termination=termination,
        )


class _Bytes:
    def __init__(self, data: bytes) -> None:
        self._data, self._pos = data, 0

    def read(self, n: int) -> bytes:
        chunk = self._data[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk


__all__ = [
    "ApplicationDelta", "CompoundReplyDelta", "DeltaReadError",
    "ExposureDelta", "GenerationDelta", "ProtocolOperationDelta",
    "SealedJournal", "SegmentInfo", "SessionDelta",
]
