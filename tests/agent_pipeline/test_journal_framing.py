"""M5 byte-prefix recovery; these tests do not assert host durability."""

import hashlib
import io
import json

import pytest

from agent_pipeline.data import canonical_json
from agent_pipeline.journal_framing import (
    HEADER, MAGIC, PREFIX, VERSION, FrameKind, FrameLimits, HostSessionBinding,
    JournalAck, JournalFrame, JournalFramingError, decode_ack, encode_ack,
    encode_frame, read_journal,
)


def event(payload=b'{"event_type":"RULESET"}'):
    return JournalFrame(FrameKind.JOURNAL_EVENT, payload)


def ack():
    return JournalAck(
        journal_id="segment-1",
        session_binding=HostSessionBinding(
            vm_instance_id="vm-1", channel_id="channel-1",
            proxy_session_id="session-1", rule_set_id="a" * 64),
        event_seq=0, request_sha256="b" * 64, record_sha256="c" * 64,
        committed_end_offset=200)


def test_wire_layout_is_explicit_and_big_endian():
    payload = b"event"
    prefix = bytes.fromhex("4e4653504a4e4c310001000100000005")
    payload_hash = hashlib.sha256(payload).digest()
    wire = encode_frame(event(payload))
    assert HEADER.size == 80
    assert wire == prefix + payload_hash + hashlib.sha256(prefix + payload_hash).digest() + payload


def test_every_final_append_cut_preserves_only_complete_prefix():
    first = event()
    second = JournalFrame(FrameKind.HOST_REJECTION, b'{"reason":"sequence_violation"}')
    prefix, tail = encode_frame(first), encode_frame(second)
    for cut in range(len(tail)):
        result = read_journal(io.BytesIO(prefix + tail[:cut]))
        assert result.frames == (first,)
        assert result.complete_bytes == len(prefix)
        assert result.torn_tail_bytes == cut
    result = read_journal(io.BytesIO(prefix + tail))
    assert result.frames == (first, second)
    assert result.complete_bytes == len(prefix + tail)
    assert result.torn_tail_bytes == 0


@pytest.mark.parametrize("offset", [0, 8, 10, 15, 16, 47, 48, 79, 80, -1])
@pytest.mark.parametrize("suffix", [b"", encode_frame(event(b"next"))])
def test_complete_corruption_is_never_a_recoverable_tail(offset, suffix):
    wire = bytearray(encode_frame(event(b"payload")))
    wire[offset] ^= 1
    with pytest.raises(JournalFramingError):
        read_journal(io.BytesIO(wire + suffix))


def test_changed_length_cannot_hide_later_records_as_torn_tail():
    wire = bytearray(encode_frame(event(b"first")))
    wire[12:16] = (1000).to_bytes(4, "big")
    with pytest.raises(JournalFramingError, match="header integrity"):
        read_journal(io.BytesIO(wire + encode_frame(event(b"later"))))


@pytest.mark.parametrize("offset,value,cut,limit", [
    (8, 1, 9, 4 * 1024 * 1024),
    (10, 1, 11, 4 * 1024 * 1024),
    (12, 1, 13, 4 * 1024 * 1024),
    (13, 65, 14, 4 * 1024 * 1024),
    (14, 1, 15, 128),
])
def test_impossible_partial_fields_are_corruption(offset, value, cut, limit):
    wire = bytearray(encode_frame(event(b"payload")))
    wire[offset] = value
    with pytest.raises(JournalFramingError):
        read_journal(io.BytesIO(wire[:cut]), limits=FrameLimits(payload_bytes=limit))


@pytest.mark.parametrize("kind,length", [(99, 1), (1, 0), (1, 4 * 1024 * 1024 + 1)])
def test_unknown_kind_and_invalid_lengths_fail_before_payload_reads(kind, length):
    header = PREFIX.pack(MAGIC, VERSION, kind, length) + b"\0" * 64

    class HeaderOnly(io.BytesIO):
        def read(self, count=-1):
            assert self.tell() < HEADER.size
            return super().read(count)

    with pytest.raises(JournalFramingError):
        read_journal(HeaderOnly(header))


def test_short_reads_are_not_eof():
    class ShortReads(io.BytesIO):
        def read(self, count=-1):
            return super().read(min(count, 3))

    frame = event()
    assert read_journal(ShortReads(encode_frame(frame))).frames == (frame,)


def test_record_and_segment_limits_do_not_read_another_payload():
    wire = encode_frame(event(b"x"))
    assert read_journal(io.BytesIO(wire), limits=FrameLimits(segment_bytes=len(wire), records=1)).frames
    for limits in (FrameLimits(segment_bytes=len(wire)), FrameLimits(records=1)):
        stream = io.BytesIO(wire * 2)
        with pytest.raises(JournalFramingError, match="limit"):
            read_journal(stream, limits=limits)
        assert stream.tell() == len(wire) + 1
    with pytest.raises(JournalFramingError, match="segment byte limit"):
        read_journal(io.BytesIO(wire), limits=FrameLimits(payload_bytes=1, segment_bytes=80))
    with pytest.raises(JournalFramingError, match="payload length"):
        read_journal(io.BytesIO(encode_frame(event(b"xx"))), limits=FrameLimits(payload_bytes=1))


@pytest.mark.parametrize("changes", [
    {"payload_bytes": 0}, {"records": True}, {"segment_bytes": 64 * 1024 * 1024 + 1},
])
def test_limits_cannot_be_disabled(changes):
    with pytest.raises(ValueError):
        FrameLimits(**changes)


def test_ack_roundtrip_is_distinct_from_journal_evidence():
    value = ack()
    wire = encode_ack(value)
    assert decode_ack(wire) == value
    assert decode_ack(wire).session_binding.proxy_session_id == "session-1"
    with pytest.raises(JournalFramingError, match="not a journal record"):
        read_journal(io.BytesIO(wire))
    with pytest.raises(JournalFramingError):
        decode_ack(wire + b"trailing")
    with pytest.raises(JournalFramingError):
        decode_ack(encode_frame(event()))


@pytest.mark.parametrize("payload", [
    b'{"schema_version":"nfs-proxy-journal-ack.v1","event_seq":0,"event_seq":1}',
    json.dumps(ack().model_dump(mode="json"), indent=2).encode(),
    canonical_json({**ack().model_dump(mode="json"), "event_seq": True}),
    canonical_json({**ack().model_dump(mode="json"), "committed_end_offset": 1}),
    canonical_json({**ack().model_dump(mode="json"), "guest_says_durable": True}),
])
def test_ack_requires_canonical_strict_fields(payload):
    with pytest.raises(JournalFramingError, match="ACK payload"):
        decode_ack(encode_frame(JournalFrame(FrameKind.ACK, payload)))


def test_invalid_model_copy_cannot_be_encoded():
    with pytest.raises(ValueError):
        encode_ack(ack().model_copy(update={"event_seq": -1}))


def test_reader_has_no_repair_or_persistence_side_effects():
    data = encode_frame(event()) + encode_frame(event(b"last"))[:-1]
    stream = io.BytesIO(data)
    result = read_journal(stream)
    assert result.torn_tail_bytes > 0
    assert stream.getvalue() == data
