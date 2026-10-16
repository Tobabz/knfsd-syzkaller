"""M5 framing only: bounded host journal recovery and ACK serialization.

Valid frames establish byte integrity, not event admission or durability.
Event payload validation, host binding, persistence and ACK emission belong
to the future host sink. This module performs no writes and emits no ACK.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
import struct
from typing import BinaryIO, Literal

from pydantic import BaseModel, ConfigDict, Field

from .data import canonical_json, parse_json

MAGIC = b"NFSPJNL1"
VERSION = 1
PREFIX = struct.Struct(">8sHHI")
HEADER = struct.Struct(">8sHHI32s32s")
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
MAX_SEGMENT_BYTES = 64 * 1024 * 1024
MAX_SEGMENT_RECORDS = 16384


class FrameKind(IntEnum):
    JOURNAL_EVENT = 1
    HOST_REJECTION = 2
    ACK = 3


class JournalFramingError(ValueError):
    """Corruption or a configured bound prevents recovering this segment."""


@dataclass(frozen=True)
class FrameLimits:
    payload_bytes: int = MAX_PAYLOAD_BYTES
    segment_bytes: int = MAX_SEGMENT_BYTES
    records: int = MAX_SEGMENT_RECORDS

    def __post_init__(self) -> None:
        for name, ceiling in (("payload_bytes", MAX_PAYLOAD_BYTES),
                              ("segment_bytes", MAX_SEGMENT_BYTES),
                              ("records", MAX_SEGMENT_RECORDS)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"invalid {name} limit")


@dataclass(frozen=True)
class JournalFrame:
    kind: FrameKind
    payload: bytes

    def __post_init__(self) -> None:
        if type(self.kind) is not FrameKind:
            raise TypeError("frame kind must be FrameKind")
        if type(self.payload) is not bytes:
            raise TypeError("frame payload must be immutable bytes")
        if not 1 <= len(self.payload) <= MAX_PAYLOAD_BYTES:
            raise JournalFramingError("payload length outside framing bounds")


@dataclass(frozen=True)
class JournalPrefix:
    frames: tuple[JournalFrame, ...]
    complete_bytes: int
    torn_tail_bytes: int


def encode_frame(frame: JournalFrame, *, limits: FrameLimits = FrameLimits()) -> bytes:
    if type(frame) is not JournalFrame or len(frame.payload) > limits.payload_bytes:
        raise JournalFramingError("invalid frame or payload limit exceeded")
    prefix = PREFIX.pack(MAGIC, VERSION, frame.kind, len(frame.payload))
    payload_hash = hashlib.sha256(frame.payload).digest()
    # Check the length against accidental corruption *before* using it
    # to distinguish a short final append from a complete corrupt record.
    header_hash = hashlib.sha256(prefix + payload_hash).digest()
    return prefix + payload_hash + header_hash + frame.payload


def _read(stream: BinaryIO, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = stream.read(count - len(result))
        if type(chunk) is not bytes or len(chunk) > count - len(result):
            raise JournalFramingError("reader must return bounded bytes")
        if not chunk:
            break
        result.extend(chunk)
    return bytes(result)


def _prefix(raw: bytes, limits: FrameLimits) -> None:
    if raw[:8] != MAGIC[:min(8, len(raw))]:
        raise JournalFramingError("invalid journal magic")
    if not VERSION.to_bytes(2, "big").startswith(raw[8:10]):
        raise JournalFramingError("unsupported frame version")
    if not any(kind.to_bytes(2, "big").startswith(raw[10:12]) for kind in FrameKind):
        raise JournalFramingError("unknown frame kind")
    length_prefix = raw[12:16]
    if length_prefix:
        missing = 4 - len(length_prefix)
        smallest = int.from_bytes(length_prefix + b"\0" * missing, "big")
        largest = int.from_bytes(length_prefix + b"\xff" * missing, "big")
        if smallest > limits.payload_bytes or largest < 1:
            raise JournalFramingError("payload length outside framing bounds")


def read_journal(stream: BinaryIO, *, limits: FrameLimits = FrameLimits()) -> JournalPrefix:
    """Read a bounded, finite host segment; never skip a corrupt frame.

    An incomplete final frame is returned as an uncommitted tail. A complete
    bad header/payload is corruption even at EOF. The caller must separately
    validate event schemas, per-session ordering and accepted host bindings.
    Readers must enforce their own I/O deadline; this is not a socket loop.
    """
    frames: list[JournalFrame] = []
    consumed = 0
    while True:
        remaining = limits.segment_bytes - consumed
        # At the exact segment/record limit, probe only one byte to distinguish
        # EOF from an oversized input without allocating another frame.
        if remaining == 0 or len(frames) == limits.records:
            if _read(stream, 1):
                raise JournalFramingError("segment byte or record limit exceeded")
            return JournalPrefix(tuple(frames), consumed, 0)
        header = _read(stream, min(HEADER.size, remaining + 1))
        if len(header) > remaining:
            raise JournalFramingError("segment byte limit exceeded")
        if not header:
            return JournalPrefix(tuple(frames), consumed, 0)
        _prefix(header, limits)
        if len(header) >= 12 and int.from_bytes(header[10:12], "big") == FrameKind.ACK:
            raise JournalFramingError("ACK is not a journal record")
        if len(header) < HEADER.size:
            return JournalPrefix(tuple(frames), consumed, len(header))
        _, _, kind, length, payload_hash, header_hash = HEADER.unpack(header)
        if hashlib.sha256(header[:48]).digest() != header_hash:
            raise JournalFramingError("header integrity mismatch")
        remaining -= HEADER.size
        payload = _read(stream, min(length, remaining + 1))
        if len(payload) > remaining:
            raise JournalFramingError("segment byte limit exceeded")
        if len(payload) < length:
            return JournalPrefix(tuple(frames), consumed, HEADER.size + len(payload))
        if hashlib.sha256(payload).digest() != payload_hash:
            raise JournalFramingError("payload integrity mismatch")
        frames.append(JournalFrame(FrameKind(kind), payload))
        consumed += HEADER.size + length


class _Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True,
                              revalidate_instances="always")


class HostSessionBinding(_Record):
    vm_instance_id: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9_.:/-]+$")
    channel_id: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9_.:/-]+$")
    proxy_session_id: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9_.:/-]+$")
    rule_set_id: str = Field(pattern=r"^[0-9a-f]{64}$")


class JournalAck(_Record):
    """Host reply shape; construction does not prove the append completed.

    A receiver must authenticate the channel and compare the complete binding,
    sequence and request digest against its one outstanding request. Only the
    sink may send this after the referenced host append completed.
    """
    schema_version: Literal["nfs-proxy-journal-ack.v1"] = "nfs-proxy-journal-ack.v1"
    journal_id: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9_.:/-]+$")
    session_binding: HostSessionBinding
    event_seq: int = Field(ge=0, le=2**64 - 1)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    committed_end_offset: int = Field(ge=HEADER.size + 1, le=MAX_SEGMENT_BYTES)


def encode_ack(ack: JournalAck) -> bytes:
    ack = JournalAck.model_validate(ack)
    return encode_frame(JournalFrame(FrameKind.ACK, canonical_json(ack)))


def decode_ack(data: bytes) -> JournalAck:
    """Decode exactly one canonical ACK; this does not verify its authority."""
    if type(data) is not bytes or not HEADER.size < len(data) <= HEADER.size + MAX_PAYLOAD_BYTES:
        raise JournalFramingError("invalid ACK frame length")
    header = data[:HEADER.size]
    _prefix(header, FrameLimits())
    _, _, kind, length, payload_hash, header_hash = HEADER.unpack(header)
    if kind != FrameKind.ACK or len(data) != HEADER.size + length:
        raise JournalFramingError("not exactly one ACK frame")
    if hashlib.sha256(header[:48]).digest() != header_hash:
        raise JournalFramingError("ACK header integrity mismatch")
    payload = data[HEADER.size:]
    if hashlib.sha256(payload).digest() != payload_hash:
        raise JournalFramingError("ACK payload integrity mismatch")
    try:
        parse_json(payload)
        ack = JournalAck.model_validate_json(payload)
        if canonical_json(ack) != payload:
            raise ValueError("noncanonical ACK")
        return ack
    except (ValueError, TypeError, RecursionError) as error:
        raise JournalFramingError("invalid ACK payload") from error
