"""M5/S1b host journal sink: event admission, durable append, ACK, recovery.

This is the Runner-owned `(D)` boundary of `05-mutation-delta-replay.md`.
A guest Delta Recorder sends one request frame (NFSPJNL1 kind 1, canonical
JSON) at a time.  The sink checks it against the host-installed session and
the generation/batch state it alone keeps (§6), appends one host frame for
it, and answers only after that append completed:

* accepted: the stored frame is a host journal event (kind 1) holding the
  host-stamped `session_binding`, the exact request digest and the request;
  the answer is the `JournalAck` of §45.
* refused: the stored frame is a host rejection record (kind 2); the answer
  is a kind 2 frame that names the request and the reason.  A rejection is
  never an ACK.

If the append itself fails, nothing is answered and the channel fails: the
guest keeps the record unmutated and the generation's evidence incomplete.

Nothing a guest sends is corrected to a host value.  The host values
(`vm_instance_id`, `channel_id`, `proxy_session_id`, `rule_set_id`, the lane
and the installed rule set bytes) come from `install_session`, which the
Runner calls before the guest starts its Proxy session.  A channel whose
Proxy starts a fresh session each time it starts (a restarted VM after a
quarantined or full session) is installed as a series instead
(`install_session_series`): the host fixes everything but a random suffix of
the session id, and installs each session before admitting its first event.

Failure domain (§11): Proxy crash, guest crash, VM teardown and Runner
restart.  Host OS or storage loss is out of scope unless `fsync=True`.
After a restart the sink re-reads every complete frame, re-validates and
replays them into the same state, and appends to a new segment; a torn tail
is never truncated or reused, so earlier bytes are never rewritten.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import socket
import threading
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .data import canonical_json, parse_json
from .journal_framing import (
    HEADER, MAX_PAYLOAD_BYTES, MAX_SEGMENT_BYTES, MAX_SEGMENT_RECORDS,
    FrameKind, FrameLimits, HostSessionBinding, JournalAck, JournalFrame,
    JournalFramingError, encode_ack, encode_frame, read_journal,
)

REQUEST_SCHEMA = "nfs-proxy-journal-request.v1"
EVENT_SCHEMA = "nfs-proxy-journal-event.v1"
REJECTION_SCHEMA = "nfs-proxy-journal-rejection.v1"
REJECT_RESPONSE_SCHEMA = "nfs-proxy-journal-reject.v1"
INSTALL_SCHEMA = "nfs-proxy-journal-install.v1"
SESSION_END_SCHEMA = "nfs-proxy-journal-session-end.v1"

# A request is stored inside an envelope (binding, digest, schema) that must
# still fit one frame; this much of the frame is kept for that envelope.
ENVELOPE_RESERVE_BYTES = 64 * 1024
MAX_REQUEST_BYTES = MAX_PAYLOAD_BYTES - ENVELOPE_RESERVE_BYTES
CHANNEL_CLOSE_TIMEOUT_S = 5

RULESET_MAGIC = b"NFSPRUL1"
RULESET_MAX_BYTES = 1 << 20
SEMANTIC_RUNTIME_VERSION = 1
SEGMENT_SUFFIX = ".njnl"
UINT64_MAX = 2**64 - 1
UINT32_MAX = 2**32 - 1

_ID = r"^[A-Za-z0-9_.:/-]+$"
_HEX64 = r"^[0-9a-f]{64}$"
# NFSPRUL1 ids and semantic paths: visible ASCII 0x21-0x7e (04 §35).
_VISIBLE = r"^[\x21-\x7e]+$"
_HEX = r"^(?:[0-9a-f]{2})*$"

Uint32 = Annotated[int, Field(ge=0, le=UINT32_MAX)]
Uint64 = Annotated[int, Field(ge=0, le=UINT64_MAX)]
Generation = Annotated[int, Field(ge=1, le=UINT64_MAX)]
Hex64 = Annotated[str, Field(pattern=_HEX64)]
Visible = Annotated[str, Field(min_length=1, max_length=512, pattern=_VISIBLE)]


class JournalSinkError(RuntimeError):
    """The sink cannot record; the channel must fail, evidence is incomplete."""


class _Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True,
                              revalidate_instances="always")


# --- request payloads (guest -> host) ---------------------------------------

class Correlation(_Record):
    """program_generation_correlation without the host-recorded VM id (§2)."""
    kcov_generation: Generation
    lane_id: Uint32
    program_digest: Hex64
    rule_set_id: Hex64


class RecordContext(_Record):
    backend: Annotated[int, Field(ge=0, le=1)]
    client: Annotated[int, Field(ge=0, le=1)]
    connection_id: Annotated[int, Field(ge=1, le=UINT64_MAX)]
    direction: Literal["c2s", "s2c"]
    message_type: Literal["call", "reply"]
    procedure: Uint32
    program: Uint32
    version: Uint32
    xid: Uint32


class RulesetPayload(_Record):
    candidate_id: Visible
    rule_set: Annotated[str, Field(min_length=2, max_length=2 * RULESET_MAX_BYTES,
                                   pattern=_HEX)]
    schema_id: Visible
    semantic_runtime_version: Uint32


class GenerationOpenPayload(_Record):
    correlation: Correlation
    draining_generations: Annotated[list[Generation], Field(max_length=4096)]


class GenerationDrainingPayload(_Record):
    correlation: Correlation


class SignatureItem(_Record):
    count: Annotated[int, Field(ge=1, le=UINT32_MAX)]
    kind: Literal["replace", "insert", "delete", "op_append", "op_prepend"]
    part: Literal["value", "encoded", "length", "count", "discriminant", "padding"]
    rule_id: Visible
    semantic_path: Visible


class ConcreteEdit(_Record):
    data: Annotated[str, Field(max_length=2 * MAX_PAYLOAD_BYTES, pattern=_HEX)]
    flags: Uint32
    offset: Uint32
    original: Annotated[str, Field(max_length=2 * MAX_PAYLOAD_BYTES, pattern=_HEX)]


class Application(_Record):
    concrete_edits: Annotated[list[ConcreteEdit], Field(max_length=128)]
    field_index: Uint32
    kind: Literal["replace", "insert", "delete", "op_append", "op_prepend"]
    mutated_value: Annotated[str, Field(max_length=2 * MAX_PAYLOAD_BYTES, pattern=_HEX)]
    operation_index: Uint32
    original_value: Annotated[str, Field(max_length=2 * MAX_PAYLOAD_BYTES, pattern=_HEX)]
    part: Literal["value", "encoded", "length", "count", "discriminant", "padding"]
    policy: Literal["preserve", "raw"]
    rule_id: Visible
    semantic_path: Visible


class Output(_Record):
    final_record_length: Annotated[int, Field(ge=1, le=UINT32_MAX)]
    output_sha256: Hex64


class ExposureIntentPayload(_Record):
    applications: Annotated[list[Application], Field(min_length=1, max_length=64)]
    batch_id: Uint64
    correlation: Correlation
    output: Output
    record_context: RecordContext
    semantic_signature: Annotated[list[SignatureItem], Field(min_length=1, max_length=64)]


class ApplyRefusalPayload(_Record):
    correlation: Correlation
    record_context: RecordContext
    refusal: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z_]+$")]
    rule_id: Visible


class ForwardCompletePayload(_Record):
    batch_id: Uint64
    correlation: Correlation
    forwarded_length: Annotated[int, Field(ge=1, le=UINT32_MAX)]


class ForwardFailedPayload(_Record):
    batch_id: Uint64
    bytes_written: Uint32
    correlation: Correlation
    reason: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z_]+$")]


class RuleSummary(_Record):
    counts: dict[Annotated[str, Field(pattern=r"^[a-z_]+$", max_length=64)], Uint64]
    rule_id: Visible


class Closure(_Record):
    drain_bound_ms: Uint64
    reason: Literal["drained", "reply_unresolved", "aborted"]
    reply_unresolved_count: Uint64


class GenerationCompletePayload(_Record):
    closure: Closure
    correlation: Correlation
    evidence_path_failures: Uint64
    exposure_batch_count: Uint64
    outside_activation_window: Uint64
    records_seen: Uint64
    resolver_summary: Annotated[list[RuleSummary], Field(max_length=256)]


class RunCompletePayload(_Record):
    batch_count: Uint64
    evidence_path_failures: Uint64
    forward_complete_count: Uint64
    forward_failed_count: Uint64
    generations: Uint64
    outside_activation_window: Uint64


EVENT_PAYLOADS: dict[str, type[_Record]] = {
    "RULESET": RulesetPayload,
    "GENERATION_OPEN": GenerationOpenPayload,
    "GENERATION_DRAINING": GenerationDrainingPayload,
    "EXPOSURE_INTENT": ExposureIntentPayload,
    "APPLY_REFUSAL": ApplyRefusalPayload,
    "FORWARD_COMPLETE": ForwardCompletePayload,
    "FORWARD_FAILED": ForwardFailedPayload,
    "GENERATION_COMPLETE": GenerationCompletePayload,
    "RUN_COMPLETE": RunCompletePayload,
}
SESSION_SCOPED = frozenset({"RULESET", "RUN_COMPLETE"})


class _Envelope(_Record):
    event_seq: Uint64
    event_type: Literal["RULESET", "GENERATION_OPEN", "GENERATION_DRAINING",
                        "EXPOSURE_INTENT", "APPLY_REFUSAL", "FORWARD_COMPLETE",
                        "FORWARD_FAILED", "GENERATION_COMPLETE", "RUN_COMPLETE"]
    payload: dict[str, Any]
    proxy_session_id: Annotated[str, Field(min_length=1, max_length=256, pattern=_ID)]
    rule_set_id: Hex64
    schema_version: Literal["nfs-proxy-journal-request.v1"]


@dataclass(frozen=True)
class JournalRequest:
    """A canonical request: its exact bytes, digest and typed payload."""
    raw: bytes
    sha256: str
    event_seq: int
    event_type: str
    proxy_session_id: str
    rule_set_id: str
    payload: _Record

    def as_json(self) -> dict[str, Any]:
        return parse_json(self.raw)  # type: ignore[return-value]


class RequestError(ValueError):
    """The bytes are not one canonical request; there is no seq to answer."""


def parse_request(raw: bytes) -> JournalRequest:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_REQUEST_BYTES:
        raise RequestError("request payload outside admission bounds")
    try:
        parse_json(raw)
        envelope = _Envelope.model_validate_json(raw)
        payload = EVENT_PAYLOADS[envelope.event_type].model_validate(envelope.payload)
        canonical = canonical_json({
            "event_seq": envelope.event_seq,
            "event_type": envelope.event_type,
            "payload": payload.model_dump(mode="json"),
            "proxy_session_id": envelope.proxy_session_id,
            "rule_set_id": envelope.rule_set_id,
            "schema_version": envelope.schema_version,
        })
    except (ValueError, TypeError, RecursionError, ValidationError) as error:
        raise RequestError(f"invalid request: {error}") from error
    if canonical != raw:
        raise RequestError("request is not in canonical form")
    return JournalRequest(raw, hashlib.sha256(raw).hexdigest(), envelope.event_seq,
                          envelope.event_type, envelope.proxy_session_id,
                          envelope.rule_set_id, payload)


def ruleset_header(blob: bytes) -> tuple[int, str, str]:
    """(semantic_runtime_version, schema_id, candidate_id) of NFSPRUL1 bytes."""
    def string(offset: int, limit: int) -> tuple[str, int]:
        if offset + 4 > len(blob):
            raise ValueError("truncated rule set header")
        n = int.from_bytes(blob[offset:offset + 4], "big")
        end = offset + 4 + n
        if not 1 <= n <= limit or end > len(blob):
            raise ValueError("bad rule set header string")
        value = blob[offset + 4:end]
        if not all(0x21 <= b <= 0x7e for b in value):
            raise ValueError("bad rule set header string")
        pad = (4 - n % 4) % 4
        return value.decode("ascii"), end + pad
    if len(blob) < 12 or blob[:8] != RULESET_MAGIC:
        raise ValueError("not an NFSPRUL1 rule set")
    version = int.from_bytes(blob[8:12], "big")
    schema_id, offset = string(12, 256)
    candidate_id, _ = string(offset, 128)
    return version, schema_id, candidate_id


# --- host state ---------------------------------------------------------------

@dataclass(frozen=True)
class ChannelIdentity:
    """What the host knows about the channel a frame arrived on."""
    vm_instance_id: str
    channel_id: str


@dataclass
class _Batch:
    generation: int
    message_type: str
    final_record_length: int
    terminal: str | None = None


@dataclass
class _Generation:
    lane_id: int
    program_digest: str
    state: str  # admitting | draining | closed


@dataclass
class _Decided:
    request_sha256: str
    response: bytes


# The part of a series session id after the host prefix: "." and a random
# UUID (/proc/sys/kernel/random/uuid in the guest).
_SERIES_SUFFIX = re.compile(
    r"\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_SERIES_PREFIX_MAX = 256 - 37


@dataclass(frozen=True)
class _Series:
    prefix: str
    lane_id: int
    rule_set: bytes


@dataclass
class _Session:
    binding: HostSessionBinding
    lane_id: int
    rule_set: bytes
    next_seq: int = 0
    ruleset_accepted: bool = False
    ended: str | None = None  # run_complete | session_end
    inconsistent: list[str] = field(default_factory=list)
    # Dirty marks RUN_COMPLETE may not seal: rejections recorded for this
    # session on its own channel, and evidence-path failures a generation
    # summary reported.
    rejections: int = 0
    evidence_path_failures: int = 0
    generations: dict[int, _Generation] = field(default_factory=dict)
    batches: dict[int, _Batch] = field(default_factory=dict)
    decided: dict[int, _Decided] = field(default_factory=dict)


@dataclass(frozen=True)
class _Verdict:
    accepted: bool
    reason: str = ""
    # A request at the expected seq consumes it whether accepted or refused.
    consumes_seq: bool = True
    inconsistent: bool = False


def _accept() -> _Verdict:
    return _Verdict(True)


def _refuse(reason: str, *, consumes_seq: bool = True,
            inconsistent: bool = False) -> _Verdict:
    return _Verdict(False, reason, consumes_seq, inconsistent)


def _draining(session: _Session, lane: int) -> list[int]:
    return sorted(g for g, gen in session.generations.items()
                  if gen.lane_id == lane and gen.state == "draining")


def _admit(session: _Session, request: JournalRequest) -> _Verdict:
    """§6 scope table for a request at the session's expected seq."""
    if session.ended is not None:
        return _refuse("session_ended", consumes_seq=False)
    if request.rule_set_id != session.binding.rule_set_id:
        return _refuse("binding_mismatch", consumes_seq=False, inconsistent=True)
    kind, payload = request.event_type, request.payload
    if kind == "RULESET":
        assert isinstance(payload, RulesetPayload)
        if request.event_seq != 0 or session.ruleset_accepted:
            return _refuse("ruleset_not_first")
        blob = bytes.fromhex(payload.rule_set)
        if blob != session.rule_set:
            return _refuse("ruleset_mismatch")
        try:
            header = ruleset_header(blob)
        except ValueError:
            return _refuse("ruleset_mismatch")
        if header != (payload.semantic_runtime_version, payload.schema_id,
                      payload.candidate_id):
            return _refuse("ruleset_mismatch")
        return _accept()
    if not session.ruleset_accepted:
        return _refuse("ruleset_required")
    if kind == "RUN_COMPLETE":
        return _admit_run_complete(session, payload)  # type: ignore[arg-type]
    corr: Correlation = payload.correlation  # type: ignore[attr-defined]
    if corr.lane_id != session.lane_id:
        return _refuse("wrong_lane")
    if corr.rule_set_id != session.binding.rule_set_id:
        return _refuse("correlation_mismatch")
    gen = session.generations.get(corr.kcov_generation)
    if kind == "GENERATION_OPEN":
        assert isinstance(payload, GenerationOpenPayload)
        if gen is not None:
            return _refuse("generation_reused")
        if any(g.lane_id == corr.lane_id and g.state == "admitting"
               for g in session.generations.values()):
            return _refuse("admitting_generation_exists")
        if payload.draining_generations != _draining(session, corr.lane_id):
            return _refuse("draining_set_mismatch")
        return _accept()
    if gen is None:
        return _refuse("generation_not_open")
    if gen.state == "closed":
        return _refuse("generation_closed")
    if corr.program_digest != gen.program_digest:
        return _refuse("correlation_mismatch")
    if kind == "GENERATION_DRAINING":
        return _accept() if gen.state == "admitting" else _refuse("generation_not_admitting")
    if kind in ("EXPOSURE_INTENT", "APPLY_REFUSAL"):
        ctx: RecordContext = payload.record_context  # type: ignore[attr-defined]
        if gen.state == "draining" and ctx.message_type != "reply":
            return _refuse("draining_call_context")
        if kind == "EXPOSURE_INTENT":
            assert isinstance(payload, ExposureIntentPayload)
            if payload.batch_id in session.batches:
                return _refuse("batch_conflict", inconsistent=True)
        return _accept()
    if kind in ("FORWARD_COMPLETE", "FORWARD_FAILED"):
        batch = session.batches.get(payload.batch_id)  # type: ignore[attr-defined]
        if batch is None:
            return _refuse("unknown_batch")
        if batch.generation != corr.kcov_generation:
            return _refuse("batch_generation_mismatch")
        if batch.terminal is not None:
            return _refuse("batch_conflict", inconsistent=True)
        # The terminal names the bytes of the batch's own output (§16-§18).
        if isinstance(payload, ForwardCompletePayload):
            if payload.forwarded_length != batch.final_record_length:
                return _refuse("forward_length_mismatch", inconsistent=True)
        elif payload.bytes_written >= batch.final_record_length:  # type: ignore[attr-defined]
            return _refuse("forward_length_mismatch", inconsistent=True)
        return _accept()
    assert kind == "GENERATION_COMPLETE"
    assert isinstance(payload, GenerationCompletePayload)
    batches = [b for b in session.batches.values() if b.generation == corr.kcov_generation]
    if any(b.terminal is None for b in batches):
        return _refuse("batches_unterminated", inconsistent=True)
    closure = payload.closure
    # Only an abort may close a generation the host never saw draining; a
    # clean drain leaves nothing unresolved (01 §16).
    if gen.state != "draining" and closure.reason != "aborted":
        return _refuse("closure_mismatch", inconsistent=True)
    if closure.reason == "drained" and closure.reply_unresolved_count != 0:
        return _refuse("closure_mismatch", inconsistent=True)
    if payload.exposure_batch_count != len(batches):
        return _refuse("summary_mismatch", inconsistent=True)
    return _accept()


def _admit_run_complete(session: _Session, payload: RunCompletePayload) -> _Verdict:
    """The session's last event: the session is clean, everything it opened
    is closed and terminal, and every count the host can compute agrees.  A
    session with any recorded rejection or evidence-path failure ends through
    the Runner's session end instead (05 §21)."""
    if any(g.state != "closed" for g in session.generations.values()):
        return _refuse("generations_open", inconsistent=True)
    terminals = [b.terminal for b in session.batches.values()]
    if None in terminals:
        return _refuse("batches_unterminated", inconsistent=True)
    if (payload.generations != len(session.generations)
            or payload.batch_count != len(terminals)
            or payload.forward_complete_count != terminals.count("complete")
            or payload.forward_failed_count != terminals.count("failed")):
        return _refuse("summary_mismatch", inconsistent=True)
    if (session.rejections or session.evidence_path_failures
            or payload.evidence_path_failures):
        return _refuse("session_dirty", inconsistent=True)
    return _accept()


def _apply(session: _Session, request: JournalRequest) -> None:
    """State transition of an accepted request (also replayed on restart)."""
    kind, payload = request.event_type, request.payload
    if kind == "RULESET":
        session.ruleset_accepted = True
        return
    if kind == "RUN_COMPLETE":
        session.ended = "run_complete"
        return
    corr: Correlation = payload.correlation  # type: ignore[attr-defined]
    g = corr.kcov_generation
    if kind == "GENERATION_OPEN":
        session.generations[g] = _Generation(corr.lane_id, corr.program_digest, "admitting")
    elif kind == "GENERATION_DRAINING":
        session.generations[g].state = "draining"
    elif kind == "EXPOSURE_INTENT":
        assert isinstance(payload, ExposureIntentPayload)
        session.batches[payload.batch_id] = _Batch(
            g, payload.record_context.message_type, payload.output.final_record_length)
    elif kind == "FORWARD_COMPLETE":
        session.batches[payload.batch_id].terminal = "complete"  # type: ignore[attr-defined]
    elif kind == "FORWARD_FAILED":
        session.batches[payload.batch_id].terminal = "failed"  # type: ignore[attr-defined]
    elif kind == "GENERATION_COMPLETE":
        session.generations[g].state = "closed"
        session.evidence_path_failures += payload.evidence_path_failures  # type: ignore[attr-defined]


# --- stored records -------------------------------------------------------------

def _binding_json(binding: HostSessionBinding) -> dict[str, Any]:
    return binding.model_dump(mode="json")


def _reject_response(journal_id: str, event_seq: int | None, request_sha256: str,
                     reason: str) -> bytes:
    body = {"event_seq": event_seq, "journal_id": journal_id, "reason": reason,
            "request_sha256": request_sha256, "schema_version": REJECT_RESPONSE_SCHEMA}
    return encode_frame(JournalFrame(FrameKind.HOST_REJECTION, canonical_json(body)))


def decode_reject(data: bytes) -> dict[str, Any]:
    """Decode a rejection response frame (does not prove anything was stored)."""
    if len(data) <= HEADER.size:
        raise JournalFramingError("short rejection frame")
    _, _, kind, length, _, _ = HEADER.unpack(data[:HEADER.size])
    if kind != FrameKind.HOST_REJECTION or len(data) != HEADER.size + length:
        raise JournalFramingError("not exactly one rejection frame")
    frames = read_journal(_BytesReader(data)).frames
    value = parse_json(frames[0].payload)
    if not isinstance(value, dict) or value.get("schema_version") != REJECT_RESPONSE_SCHEMA:
        raise JournalFramingError("not a rejection response")
    return value


class _BytesReader:
    def __init__(self, data: bytes) -> None:
        self._data, self._pos = data, 0

    def read(self, n: int) -> bytes:
        chunk = self._data[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk


@dataclass(frozen=True)
class StoredEvent:
    journal_id: str
    end_offset: int
    binding: HostSessionBinding
    request: JournalRequest


@dataclass(frozen=True)
class StoredRejection:
    journal_id: str
    end_offset: int
    vm_instance_id: str
    channel_id: str
    proxy_session_id: str | None
    event_seq: int | None
    event_type: str | None
    request_sha256: str
    reason: str
    consumed: bool
    inconsistent: bool


class HostJournal:
    """Durable, single-writer host journal shared by a Runner's channels.

    Each call to `submit` is answered with the bytes to send back, or raises
    JournalSinkError when it could not record; then that channel must stop.
    """

    def __init__(self, directory: Path, name: str, *, fsync: bool = False,
                 limits: FrameLimits = FrameLimits(),
                 max_total_bytes: int = 1 << 30) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise ValueError("invalid journal name")
        self.directory = Path(directory)
        self.name = name
        self.fsync = fsync
        self.limits = limits
        self.max_total_bytes = max_total_bytes
        self._lock = threading.Lock()
        self._sessions: dict[str, _Session] = {}
        self._series: dict[tuple[str, str], _Series] = {}
        self._events: list[StoredEvent] = []
        self._rejections: list[StoredRejection] = []
        self._fd: int | None = None
        self._failed = False
        self._total = 0
        self._make_directory()
        self._recover()

    def _make_directory(self) -> None:
        """Create the journal directory; with fsync, make every entry this
        created durable in its parent before anything is ACKed."""
        created = []
        path = self.directory.absolute()
        while not path.exists():
            created.append(path)
            path = path.parent
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.fsync:
            for child in created:  # bottom-up: the entry, then its parent's
                self._fsync_dir(child.parent)

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    # -- segments --

    def _segments(self) -> list[tuple[int, Path]]:
        found = []
        pattern = re.compile(re.escape(self.name) + r"\.(\d{4})" + re.escape(SEGMENT_SUFFIX))
        for path in self.directory.iterdir():
            m = pattern.fullmatch(path.name)
            if m:
                found.append((int(m.group(1)), path))
        return sorted(found)

    def _recover(self) -> None:
        index = 0
        for index, path in self._segments():
            journal_id = f"{self.name}.{index:04d}"
            with path.open("rb") as stream:
                prefix = read_journal(stream, limits=self.limits)
            offset = 0
            for frame in prefix.frames:
                offset += HEADER.size + len(frame.payload)
                self._replay(journal_id, offset, frame)
            self._total += path.stat().st_size
        # Never append after a previous process: a torn tail stays as it was.
        self._segment = index + 1 if self._segments() else 0
        self._segment_bytes = 0
        self._segment_records = 0

    def _journal_id(self) -> str:
        return f"{self.name}.{self._segment:04d}"

    def _open_segment(self) -> None:
        path = self.directory / f"{self._journal_id()}{SEGMENT_SUFFIX}"
        self._fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL, 0o644)
        if self.fsync:
            self._fsync_dir(self.directory)

    def _append(self, kind: FrameKind, payload: bytes) -> tuple[str, int, bytes]:
        """Append one complete frame; (journal_id, end offset, frame bytes)."""
        if self._failed:
            raise JournalSinkError("journal writer failed earlier")
        try:
            frame = encode_frame(JournalFrame(kind, payload), limits=self.limits)
        except JournalFramingError as error:
            # Not storable as one frame: fail this channel, keep the server.
            raise JournalSinkError(f"record not storable: {error}") from error
        if len(frame) > self.limits.segment_bytes:
            # Alone in a fresh segment it would still exceed the limit that
            # recovery enforces: an ACK for it could not survive a restart.
            raise JournalSinkError("record not storable: larger than a segment")
        if self._total + len(frame) > self.max_total_bytes:
            raise JournalSinkError("journal storage limit reached")
        if self._fd is not None and (
                self._segment_bytes + len(frame) > self.limits.segment_bytes or
                self._segment_records + 1 > self.limits.records):
            os.close(self._fd)
            self._fd = None
            self._segment += 1
            self._segment_bytes = self._segment_records = 0
        try:
            if self._fd is None:
                self._open_segment()
            assert self._fd is not None
            view = memoryview(frame)
            while view:
                written = os.write(self._fd, view)
                if written <= 0:
                    raise OSError("short journal write")
                view = view[written:]
            if self.fsync:
                os.fsync(self._fd)
        except OSError as error:
            # The segment may now end in a torn frame; no ACK may refer to it.
            self._failed = True
            raise JournalSinkError(f"journal append failed: {error}") from error
        self._segment_bytes += len(frame)
        self._segment_records += 1
        self._total += len(frame)
        return self._journal_id(), self._segment_bytes, frame

    def close(self) -> None:
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    # -- Runner operations --

    @staticmethod
    def _check_install(lane_id: int, rule_set: bytes) -> None:
        if type(rule_set) is not bytes or not 12 <= len(rule_set) <= RULESET_MAX_BYTES:
            raise ValueError("rule set outside bounds")
        ruleset_header(rule_set)
        if type(lane_id) is not int or not 0 <= lane_id <= UINT32_MAX:
            raise ValueError("invalid lane")

    def install_session(self, *, vm_instance_id: str, channel_id: str,
                        proxy_session_id: str, lane_id: int, rule_set: bytes) -> HostSessionBinding:
        """Record the Runner's immutable session before the guest uses it."""
        self._check_install(lane_id, rule_set)
        binding = HostSessionBinding(vm_instance_id=vm_instance_id, channel_id=channel_id,
                                     proxy_session_id=proxy_session_id,
                                     rule_set_id=hashlib.sha256(rule_set).hexdigest())
        with self._lock:
            if proxy_session_id in self._sessions:
                raise ValueError("proxy_session_id already used")
            self._install_locked(binding, lane_id, rule_set)
        return binding

    def _install_locked(self, binding: HostSessionBinding, lane_id: int,
                        rule_set: bytes) -> _Session:
        body = {"lane_id": lane_id, "rule_set": rule_set.hex(),
                "schema_version": INSTALL_SCHEMA, "session_binding": _binding_json(binding)}
        self._append(FrameKind.JOURNAL_EVENT, canonical_json(body))
        session = _Session(binding, lane_id, rule_set)
        self._sessions[binding.proxy_session_id] = session
        return session

    def install_session_series(self, *, vm_instance_id: str, channel_id: str, prefix: str,
                               lane_id: int, rule_set: bytes) -> list[HostSessionBinding]:
        """Let this channel's Proxy start sessions named `prefix.<random UUID>`.

        Each such session is installed with this binding, lane and rule set
        when its first event (RULESET, seq 0) arrives, before that event is
        admitted; the series' earlier sessions on the channel that have not
        ended then end (`superseded`).  A Proxy restart never continues a
        session, and a fresh one is the only way past a quarantined or full
        one.  Returns the recovered sessions of the series, oldest first;
        refuses when any of them differs from this binding.
        """
        self._check_install(lane_id, rule_set)
        if (len(prefix) > _SERIES_PREFIX_MAX
                or not re.fullmatch(_ID, prefix)):
            raise ValueError("invalid session prefix")
        rule_set_id = hashlib.sha256(rule_set).hexdigest()
        with self._lock:
            recovered = []
            for session_id, session in self._sessions.items():
                if not self._in_series(prefix, session_id):
                    continue
                b = session.binding
                if ((b.vm_instance_id, b.channel_id, b.rule_set_id) !=
                        (vm_instance_id, channel_id, rule_set_id)
                        or session.lane_id != lane_id or session.rule_set != rule_set):
                    raise ValueError("recovered session differs from the requested series")
                recovered.append(b)
            self._series[(vm_instance_id, channel_id)] = _Series(prefix, lane_id, rule_set)
            return recovered

    @staticmethod
    def _in_series(prefix: str, session_id: str) -> bool:
        return (session_id.startswith(prefix)
                and _SERIES_SUFFIX.fullmatch(session_id[len(prefix):]) is not None)

    def _install_from_series(self, channel: ChannelIdentity,
                             request: JournalRequest) -> _Session | None:
        """The session a series channel's new Proxy just started, or None."""
        series = self._series.get((channel.vm_instance_id, channel.channel_id))
        if (series is None or request.event_seq != 0 or request.event_type != "RULESET"
                or not self._in_series(series.prefix, request.proxy_session_id)):
            return None
        for session_id, session in list(self._sessions.items()):
            if session.ended is None and self._in_series(series.prefix, session_id):
                self._end_locked(session_id, "superseded")
        binding = HostSessionBinding(
            vm_instance_id=channel.vm_instance_id, channel_id=channel.channel_id,
            proxy_session_id=request.proxy_session_id,
            rule_set_id=hashlib.sha256(series.rule_set).hexdigest())
        return self._install_locked(binding, series.lane_id, series.rule_set)

    def resume_session(self, *, vm_instance_id: str, channel_id: str,
                       proxy_session_id: str, lane_id: int,
                       rule_set: bytes) -> HostSessionBinding | None:
        """The recovered session, when it is exactly this one; None when no
        such session was installed.  A different binding, lane or rule set
        under the same id is refused: a restart never changes a session."""
        with self._lock:
            session = self._sessions.get(proxy_session_id)
            if session is None:
                return None
            b = session.binding
            if ((b.vm_instance_id, b.channel_id, b.rule_set_id) !=
                    (vm_instance_id, channel_id, hashlib.sha256(rule_set).hexdigest())
                    or session.lane_id != lane_id or session.rule_set != rule_set):
                raise ValueError("recovered session differs from the requested one")
            return b

    def end_session(self, proxy_session_id: str, reason: str) -> None:
        """No more events will be accepted (Proxy restart, channel/VM end)."""
        if not re.fullmatch(r"[a-z_]{1,64}", reason):
            raise ValueError("invalid reason")
        with self._lock:
            self._end_locked(proxy_session_id, reason)

    def _end_locked(self, proxy_session_id: str, reason: str) -> None:
        session = self._sessions[proxy_session_id]
        if session.ended is not None:
            return
        body = {"proxy_session_id": proxy_session_id, "reason": reason,
                "schema_version": SESSION_END_SCHEMA}
        self._append(FrameKind.JOURNAL_EVENT, canonical_json(body))
        session.ended = "session_end"

    # -- guest requests --

    def submit(self, channel: ChannelIdentity, raw: bytes) -> bytes:
        with self._lock:
            return self._submit(channel, raw)

    def _reject(self, channel: ChannelIdentity, session_id: str | None,
                request: JournalRequest | None, raw: bytes, reason: str, *,
                consumed: bool = False, inconsistent: bool = False) -> bytes:
        """Record a refusal, then answer it.  `consumed`: the request was at
        the session's expected seq, which it uses up like an accepted one."""
        sha = hashlib.sha256(raw).hexdigest()
        seq = request.event_seq if request else None
        etype = request.event_type if request else None
        body = {"channel_id": channel.channel_id, "consumed": consumed,
                "event_seq": seq, "event_type": etype, "inconsistent": inconsistent,
                "proxy_session_id": session_id, "reason": reason,
                "request_sha256": sha, "schema_version": REJECTION_SCHEMA,
                "vm_instance_id": channel.vm_instance_id}
        journal_id, end, _ = self._append(FrameKind.HOST_REJECTION, canonical_json(body))
        rejection = StoredRejection(journal_id, end, channel.vm_instance_id,
                                    channel.channel_id, session_id, seq, etype,
                                    sha, reason, consumed, inconsistent)
        self._rejections.append(rejection)
        self._count_rejection(rejection)
        return _reject_response(journal_id, seq, sha, reason)

    def _count_rejection(self, rejection: StoredRejection) -> None:
        """Mark the named session dirty when the rejection came over its own
        channel (another channel cannot dirty a session it is not bound to)."""
        session = self._sessions.get(rejection.proxy_session_id or "")
        if session is not None and (rejection.vm_instance_id, rejection.channel_id) == (
                session.binding.vm_instance_id, session.binding.channel_id):
            session.rejections += 1

    def _submit(self, channel: ChannelIdentity, raw: bytes) -> bytes:
        try:
            request = parse_request(raw)
        except RequestError:
            return self._reject(channel, None, None, raw, "malformed_request")
        session = self._sessions.get(request.proxy_session_id)
        if session is None:
            session = self._install_from_series(channel, request)
        if session is None:
            return self._reject(channel, request.proxy_session_id, request, raw,
                                "unknown_session")
        b = session.binding
        if (channel.vm_instance_id, channel.channel_id) != (b.vm_instance_id, b.channel_id):
            return self._reject(channel, request.proxy_session_id, request, raw,
                                "channel_mismatch")
        if request.event_seq < session.next_seq:
            done = session.decided.get(request.event_seq)
            if done is not None and done.request_sha256 == request.sha256:
                return done.response  # retransmission: same answer, no append
            response = self._reject(channel, request.proxy_session_id, request, raw,
                                    "sequence_conflict", inconsistent=True)
            session.inconsistent.append("sequence_conflict")
            return response
        if request.event_seq > session.next_seq:
            response = self._reject(channel, request.proxy_session_id, request, raw,
                                    "sequence_violation", inconsistent=True)
            session.inconsistent.append("sequence_violation")
            return response
        verdict = _admit(session, request)
        if not verdict.accepted:
            response = self._reject(channel, request.proxy_session_id, request, raw,
                                    verdict.reason, consumed=verdict.consumes_seq,
                                    inconsistent=verdict.inconsistent)
            if verdict.inconsistent:
                session.inconsistent.append(verdict.reason)
            if verdict.consumes_seq:
                session.decided[request.event_seq] = _Decided(request.sha256, response)
                session.next_seq += 1
            return response
        body = {"event_seq": request.event_seq, "event_type": request.event_type,
                "request": request.as_json(), "request_sha256": request.sha256,
                "schema_version": EVENT_SCHEMA, "session_binding": _binding_json(b)}
        journal_id, end, frame = self._append(FrameKind.JOURNAL_EVENT, canonical_json(body))
        self._events.append(StoredEvent(journal_id, end, b, request))
        _apply(session, request)
        response = self._ack(journal_id, end, frame, b, request)
        session.decided[request.event_seq] = _Decided(request.sha256, response)
        session.next_seq += 1
        return response

    @staticmethod
    def _ack(journal_id: str, end: int, frame: bytes, binding: HostSessionBinding,
             request: JournalRequest) -> bytes:
        return encode_ack(JournalAck(
            journal_id=journal_id, session_binding=binding, event_seq=request.event_seq,
            request_sha256=request.sha256, record_sha256=hashlib.sha256(frame).hexdigest(),
            committed_end_offset=end))

    # -- restart --

    def _replay(self, journal_id: str, end: int, frame: JournalFrame) -> None:
        """Rebuild state from one stored frame, re-validating its semantics."""
        value = parse_json(frame.payload)
        if canonical_json(value) != frame.payload or not isinstance(value, dict):
            raise JournalFramingError("stored record is not canonical JSON")
        schema = value.get("schema_version")
        wire = encode_frame(frame)
        if frame.kind == FrameKind.JOURNAL_EVENT and schema == INSTALL_SCHEMA:
            binding = HostSessionBinding.model_validate(value["session_binding"])
            blob = bytes.fromhex(value["rule_set"])
            if (set(value) != {"lane_id", "rule_set", "schema_version", "session_binding"}
                    or binding.proxy_session_id in self._sessions
                    or hashlib.sha256(blob).hexdigest() != binding.rule_set_id):
                raise JournalFramingError("invalid stored session install")
            self._sessions[binding.proxy_session_id] = _Session(binding, value["lane_id"], blob)
        elif frame.kind == FrameKind.JOURNAL_EVENT and schema == SESSION_END_SCHEMA:
            session = self._sessions.get(value.get("proxy_session_id"))
            if session is None:
                raise JournalFramingError("session end for an unknown session")
            session.ended = "session_end"
        elif frame.kind == FrameKind.JOURNAL_EVENT and schema == EVENT_SCHEMA:
            request = parse_request(canonical_json(value["request"]))
            binding = HostSessionBinding.model_validate(value["session_binding"])
            session = self._sessions.get(request.proxy_session_id)
            if (session is None or session.binding != binding
                    or value["request_sha256"] != request.sha256
                    or value["event_seq"] != request.event_seq
                    or value["event_type"] != request.event_type
                    or request.event_seq != session.next_seq
                    or not _admit(session, request).accepted):
                raise JournalFramingError("stored event fails admission on recovery")
            _apply(session, request)
            self._events.append(StoredEvent(journal_id, end, binding, request))
            session.decided[request.event_seq] = _Decided(
                request.sha256, self._ack(journal_id, end, wire, binding, request))
            session.next_seq += 1
        elif frame.kind == FrameKind.HOST_REJECTION and schema == REJECTION_SCHEMA:
            rejection = StoredRejection(
                journal_id, end, value["vm_instance_id"], value["channel_id"],
                value["proxy_session_id"], value["event_seq"], value["event_type"],
                value["request_sha256"], value["reason"], value["consumed"],
                value["inconsistent"])
            if type(rejection.consumed) is not bool or type(rejection.inconsistent) is not bool:
                raise JournalFramingError("invalid stored rejection")
            self._rejections.append(rejection)
            self._count_rejection(rejection)
            session = self._sessions.get(rejection.proxy_session_id or "")
            if session is None:
                if rejection.consumed or rejection.inconsistent:
                    raise JournalFramingError("stored rejection names no session")
                return
            if rejection.inconsistent:
                session.inconsistent.append(rejection.reason)
            if rejection.consumed:
                if rejection.event_seq != session.next_seq:
                    raise JournalFramingError("stored rejection out of sequence")
                session.decided[rejection.event_seq] = _Decided(
                    rejection.request_sha256,
                    _reject_response(journal_id, rejection.event_seq,
                                     rejection.request_sha256, rejection.reason))
                session.next_seq += 1
        else:
            raise JournalFramingError("unknown stored record")

    # -- views for tests, sealing and judges --

    def events(self, proxy_session_id: str | None = None) -> list[StoredEvent]:
        with self._lock:
            return [e for e in self._events
                    if proxy_session_id is None or
                    e.request.proxy_session_id == proxy_session_id]

    def rejections(self) -> list[StoredRejection]:
        with self._lock:
            return list(self._rejections)

    def latest_session(self, prefix: str) -> str | None:
        """The last installed session of the series `prefix`."""
        with self._lock:
            found = [i for i in self._sessions if self._in_series(prefix, i)]
            return found[-1] if found else None

    def session_state(self, proxy_session_id: str) -> dict[str, Any]:
        with self._lock:
            s = self._sessions[proxy_session_id]
            return {
                "next_seq": s.next_seq, "ruleset_accepted": s.ruleset_accepted,
                "ended": s.ended, "inconsistent": list(s.inconsistent),
                "rejections": s.rejections,
                "evidence_path_failures": s.evidence_path_failures,
                "generations": {g: v.state for g, v in s.generations.items()},
                "batches": {b: v.terminal for b, v in s.batches.items()},
            }


def delivery_state(events: list[StoredEvent], batch_id: int) -> str:
    """§20 crash-cut state of one batch in a session's stored events."""
    kinds = [e.request.event_type for e in events
             if e.request.event_type in ("EXPOSURE_INTENT", "FORWARD_COMPLETE",
                                         "FORWARD_FAILED")
             and getattr(e.request.payload, "batch_id", None) == batch_id]
    if "EXPOSURE_INTENT" not in kinds:
        return "no_exposure"
    if "FORWARD_COMPLETE" in kinds:
        return "forward_complete"
    if "FORWARD_FAILED" in kinds:
        return "forward_failed"
    return "delivery_unknown"


# --- channel transport --------------------------------------------------------------

def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def serve_channel(sock: socket.socket, journal: HostJournal, channel: ChannelIdentity) -> str:
    """Answer request frames on one connected channel until it ends.

    Returns why the channel ended.  A malformed frame ends the channel: the
    stream cannot be resynchronised.  A recording failure ends it without an
    answer, so the guest never sees a success it did not get.
    """
    while True:
        header = _recv_exact(sock, HEADER.size)
        if not header:
            return "eof"
        if len(header) < HEADER.size:
            return "torn_frame"
        magic, version, kind, length, payload_hash, header_hash = HEADER.unpack(header)
        if (magic != b"NFSPJNL1" or version != 1 or kind != FrameKind.JOURNAL_EVENT
                or not 1 <= length <= MAX_PAYLOAD_BYTES
                or hashlib.sha256(header[:48]).digest() != header_hash):
            return "bad_frame"
        payload = _recv_exact(sock, length)
        if len(payload) < length:
            return "torn_frame"
        if hashlib.sha256(payload).digest() != payload_hash:
            return "bad_frame"
        try:
            response = journal.submit(channel, payload)
        except JournalSinkError:
            return "sink_failed"
        sock.sendall(response)


class ChannelServer:
    """Listen on a Unix socket for one VM's channel (QEMU chardev client).

    Every connection is the same host channel identity: QEMU reconnects the
    same virtio-serial port, never another VM's.
    """

    def __init__(self, path: Path, journal: HostJournal, channel: ChannelIdentity) -> None:
        self.path = Path(path)
        self.journal = journal
        self.channel = channel
        self.ended: list[str] = []
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(self.path))
        self._sock.listen(4)
        self._stop = threading.Event()
        self._connection_lock = threading.Lock()
        self._connection: socket.socket | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self._connection_lock:
                if self._stop.is_set():
                    conn.close()
                    return
                self._connection = conn
            try:
                with conn:
                    conn.settimeout(None)
                    try:
                        self.ended.append(
                            serve_channel(conn, self.journal, self.channel))
                    except OSError:
                        self.ended.append("io_error")
            finally:
                with self._connection_lock:
                    if self._connection is conn:
                        self._connection = None

    def close(self) -> bool:
        """Stop accepting and return whether the serving thread exited."""
        self._stop.set()
        self._sock.close()
        with self._connection_lock:
            connection = self._connection
            if connection is not None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self._thread.join(timeout=CHANNEL_CLOSE_TIMEOUT_S)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        return not self._thread.is_alive()


def main(argv: list[str] | None = None) -> int:
    """Operator entry point: one VM's channel, one installed Proxy session.

    python -m agent_pipeline.journal_sink --dir D --name lane0 --socket S \\
        --vm vm-0 --channel virtio-journal-0 --session ps-1 --lane 0 --rules R

    QEMU connects to S as a chardev client (see tools/nfs-proxy/README.md).
    With --session-prefix P instead of --session, the channel is a series
    (`HostJournal.install_session_series`): every Proxy start uses a new
    session P.<uuid>, as the lane fixture's target mode does.
    Runs until interrupted; the journal stays in D for sealing and judges.
    """
    import argparse
    import signal
    import sys

    parser = argparse.ArgumentParser(prog="python -m agent_pipeline.journal_sink")
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--vm", required=True)
    parser.add_argument("--channel", required=True)
    named = parser.add_mutually_exclusive_group(required=True)
    named.add_argument("--session")
    named.add_argument("--session-prefix")
    parser.add_argument("--lane", type=int, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--fsync", action="store_true")
    args = parser.parse_args(argv)

    journal = HostJournal(args.dir, args.name, fsync=args.fsync)
    session = dict(vm_instance_id=args.vm, channel_id=args.channel,
                   lane_id=args.lane, rule_set=args.rules.read_bytes())
    # A restart (Runner, or QEMU reconnecting) continues the recovered
    # session; it is installed only the first time.
    try:
        if args.session_prefix is not None:
            recovered = journal.install_session_series(prefix=args.session_prefix, **session)
            state = f"series {len(recovered)} recovered session(s)"
            named = f"session_prefix={args.session_prefix}"
        else:
            binding = journal.resume_session(proxy_session_id=args.session, **session)
            state = "installed" if binding is None else "resumed"
            if binding is None:
                binding = journal.install_session(proxy_session_id=args.session, **session)
            named = f"session={binding.proxy_session_id}"
    except ValueError as error:
        journal.close()
        print(f"journal sink refused: {error}", file=sys.stderr, flush=True)
        return 2
    rule_set_id = hashlib.sha256(session["rule_set"]).hexdigest()  # type: ignore[arg-type]
    server = ChannelServer(args.socket, journal, ChannelIdentity(args.vm, args.channel))
    # Before "ready": whoever reads that line may signal at once.
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    print(f"journal sink ready: {state} {named} "
          f"rule_set_id={rule_set_id} socket={args.socket}", flush=True)
    try:
        stop.wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        last = args.session if args.session is not None else journal.latest_session(
            args.session_prefix)
        journal.close()
        if last is None:
            print(f"journal sink stopped: no session channel_ends={server.ended}", flush=True)
        else:
            state = journal.session_state(last)
            print(f"journal sink stopped: session={last} next_seq={state['next_seq']} "
                  f"ended={state['ended']} channel_ends={server.ended}", flush=True)
    return 0


__all__ = [
    "ChannelIdentity", "ChannelServer", "HostJournal", "JournalRequest",
    "JournalSinkError", "RequestError", "StoredEvent", "StoredRejection",
    "decode_reject", "delivery_state", "parse_request", "ruleset_header",
    "serve_channel",
]

if __name__ == "__main__":
    raise SystemExit(main())
