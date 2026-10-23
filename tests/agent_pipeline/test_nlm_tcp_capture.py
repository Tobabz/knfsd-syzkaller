"""Offline reconstruction must expose ambiguity without promoting evidence."""

import hashlib
import struct

import pytest

from tools import nlm_tcp_capture as capture
from tools.nlm_callback_verify import verify_capture
from tests.agent_pipeline.test_nlm_callback_attribution import call, u32
from tests.agent_pipeline.test_nlm_callback_verify import fixture


def framed(procedure=2, xid=42):
    body = call(procedure, xid)
    return u32(0x80000000 | len(body)) + body


def packet(seq, body=b"", flags=0x10, reverse=False):
    ports = (4050, 50000) if reverse else (50000, 4050)
    ips = (10, 89, 0, 1, 10, 89, 0, 6) if reverse else (10, 89, 0, 6, 10, 89, 0, 1)
    tcp = struct.pack(">HHIIHHHH", *ports, seq % (1 << 32), 0,
                      (5 << 12) | flags, 0, 0, 0) + body
    ip = (bytes.fromhex("4500") + struct.pack(">H", 20 + len(tcp)) +
          bytes.fromhex("0000000040060000") + bytes(ips))
    return bytes(12) + b"\x08\x00" + ip + tcp


def pcap(tmp_path, frames):
    data = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1)
    for index, frame in enumerate(frames):
        data += struct.pack("<IIII", index + 1, 0, len(frame), len(frame)) + frame
    path = tmp_path / "test.pcap"
    path.write_bytes(data)
    return path


def complete(tmp_path, data, *, start=100, chunks=None):
    frames = [packet(start, flags=2), packet(700, flags=0x12, reverse=True)]
    frames += chunks if chunks is not None else [packet(start + 1, data)]
    frames += [packet(start + 1 + len(data), flags=0x11),
               packet(701, flags=0x11, reverse=True)]
    return pcap(tmp_path, frames)


def two_completed_epochs(tmp_path, data):
    frames = []
    for start, reverse_start in ((100, 700), (500, 900)):
        frames += [packet(start, flags=2),
                   packet(reverse_start, flags=0x12, reverse=True),
                   packet(start + 1, data),
                   packet(start + 1 + len(data), flags=0x11),
                   packet(reverse_start + 1, flags=0x11, reverse=True)]
    return pcap(tmp_path, frames)


def issues(result):
    return {issue for stream in result["streams"] for issue in stream["issues"]}


def test_split_reordered_and_coalesced_records(tmp_path):
    data = framed() + framed(10, 43) + framed(15, 44)
    path = complete(tmp_path, data, chunks=[
        packet(118, data[17:]), packet(101, data[:2]), packet(103, data[2:17])])
    result = capture.reconstruct(path)
    assert result["observed_streams_complete"] is True
    assert result["capture_complete"] is False
    assert result["status"] == "diagnostic_only"
    assert [r["procedure"] for r in result["records"]] == [2, 10, 15]
    first = result["records"][0]
    assert first["framed_sha256"] == hashlib.sha256(framed()).hexdigest()
    assert (first["first_packet_index"], first["last_packet_index"]) == (3, 5)


def test_multifragment_keeps_exact_wire_digest(tmp_path):
    body = call(2, 42)
    data = u32(9) + body[:9] + u32(0x80000000 | (len(body) - 9)) + body[9:]
    record = capture.reconstruct(complete(tmp_path, data))["records"][0]
    assert record["framed_sha256"] == hashlib.sha256(data).hexdigest()
    assert record["framed_sha256"] != hashlib.sha256(framed()).hexdigest()
    assert record["framed_length"] == len(data)


def test_sequence_wrap_and_syn_payload(tmp_path):
    data = framed()
    result = capture.reconstruct(complete(tmp_path, data, start=(1 << 32) - 8))
    assert result["observed_streams_complete"]
    assert len(result["records"]) == 1
    result = capture.reconstruct(pcap(tmp_path, [
        packet(100, data, flags=2), packet(101 + len(data), flags=1)]))
    assert len(result["records"]) == 1


@pytest.mark.parametrize("conflict", [False, True])
def test_overlap_is_never_silently_deduplicated(tmp_path, conflict):
    data = framed()
    overlap = (b"x" if conflict else data[10:11]) + data[11:30]
    result = capture.reconstruct(complete(tmp_path, data, chunks=[
        packet(101, data), packet(111, overlap)]))
    assert result["streams"][0]["overlap_observations"] == 1
    if conflict:
        assert result["records"] == []
        assert "conflicting_tcp_overlap" in issues(result)
    else:
        assert result["records"][0]["tcp_overlap_observed"] is True


@pytest.mark.parametrize(("frames", "expected"), [
    ([packet(101, framed())], "stream_start_unobserved"),
    ([packet(101, framed()), packet(100, flags=2)], "syn_after_unanchored_stream"),
    ([packet(100, flags=2), packet(102, framed())], "tcp_sequence_gap"),
    ([packet(100, flags=2), packet(101, framed()[:-1])], "partial_rpc_record"),
    ([packet(100, flags=2), packet(101, framed()), packet(102, flags=1)],
     "fin_sequence_mismatch"),
    ([packet(100, flags=2), packet(101, framed()), packet(101, flags=4)],
     "connection_reset_observed"),
])
def test_incomplete_or_ambiguous_streams(tmp_path, frames, expected):
    result = capture.reconstruct(pcap(tmp_path, frames))
    assert expected in issues(result)
    assert not result["observed_streams_complete"]
    assert result["capture_complete"] is False


def test_tuple_reuse_separates_connections_and_marks_unclosed_epoch(tmp_path):
    data = framed()
    result = capture.reconstruct(pcap(tmp_path, [
        packet(100, flags=2), packet(101, data),
        packet(500, flags=2), packet(501, data)]))
    assert len({r["connection_id"] for r in result["records"]}) == 2
    assert all("connection_reuse_without_close" in s["issues"]
               for s in result["streams"])


def test_duplicate_syn_and_fin_do_not_create_connection(tmp_path):
    data = framed()
    result = capture.reconstruct(pcap(tmp_path, [
        packet(100, flags=2), packet(100, flags=2), packet(101, data),
        packet(101 + len(data), flags=1), packet(101 + len(data), flags=1),
        packet(100, flags=2)]))
    assert len(result["records"]) == 1
    assert "syn_after_close_ambiguous" in issues(result)


def test_closed_connection_reuse(tmp_path):
    data = framed()
    path = complete(tmp_path, data)
    # Append a second capture's packets, not its global header.
    first = path.read_bytes()
    second = complete(tmp_path, data, start=500).read_bytes()
    path.write_bytes(first + second[24:])
    result = capture.reconstruct(path)
    assert result["observed_streams_complete"]
    assert len({r["connection_id"] for r in result["records"]}) == 2


def test_replies_skipped_and_all_records_count_toward_limit(tmp_path, monkeypatch):
    reply = u32(0x8000000c) + u32(42) + u32(1) + u32(0)
    result = capture.reconstruct(complete(tmp_path, reply + framed()))
    assert len(result["records"]) == 1
    assert not issues(result)
    monkeypatch.setattr(capture, "MAX_RECORDS", 1)
    result = capture.reconstruct(complete(tmp_path, reply + framed()))
    assert result["records"] == []
    assert "rpc_record_count_limit" in issues(result)


def test_record_count_budget_applies_across_connection_epochs(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "MAX_RECORDS", 1)
    result = capture.reconstruct(two_completed_epochs(tmp_path, framed()))
    assert len(result["records"]) == 1
    second = [stream for stream in result["streams"]
              if stream["connection_id"] == 2]
    assert any("rpc_record_count_limit" in stream["issues"]
               for stream in second)


def test_record_byte_budget_applies_across_connection_epochs(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "MAX_RECORD_BYTES", len(framed()))
    result = capture.reconstruct(two_completed_epochs(tmp_path, framed()))
    assert len(result["records"]) == 1
    second = [stream for stream in result["streams"]
              if stream["connection_id"] == 2]
    assert any("rpc_record_bytes_limit" in stream["issues"]
               for stream in second)


def test_segment_limit_applies_across_connections(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "MAX_SEGMENTS", 1)
    result = capture.reconstruct(pcap(tmp_path, [
        packet(100, flags=2), packet(101, framed()),
        packet(500, flags=2), packet(501, framed())]))
    assert result["parse_error"] == "stream_segment_limit"
    assert result["records"] == []


@pytest.mark.parametrize(("tail", "expected"), [
    (b"\x80", "partial_rpc_record"),
    (u32(0x80000001) + b"x", "malformed_rpc_record"),
])
def test_prior_record_remains_diagnostic_with_later_stream_issue(tmp_path, tail, expected):
    result = capture.reconstruct(complete(tmp_path, framed() + tail))
    assert len(result["records"]) == 1
    assert expected in issues(result)
    assert not result["observed_streams_complete"]


def test_fragment_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "MAX_FRAGMENTS", 2)
    data = u32(0) * 3 + framed()
    result = capture.reconstruct(complete(tmp_path, data))
    assert "rpc_fragment_limit" in issues(result)
    assert result["records"] == []


@pytest.mark.parametrize(("limit", "value", "expected"), [
    ("MAX_CAPTURE_BYTES", 24, "capture_size_limit"),
    ("MAX_STREAMS", 0, "stream_count_limit"),
    ("MAX_SEGMENTS", 0, "stream_segment_limit"),
    ("MAX_STREAM_BYTES", 8, "stream_sequence_or_size_limit"),
    ("MAX_FRAGMENTS", 0, "rpc_fragment_limit"),
])
def test_bounds(tmp_path, monkeypatch, limit, value, expected):
    monkeypatch.setattr(capture, limit, value)
    result = capture.reconstruct(complete(tmp_path, framed()))
    assert result["parse_error"] == expected or expected in issues(result)
    assert not result["observed_streams_complete"]


def test_truncated_file_invalidates_all_records(tmp_path):
    path = complete(tmp_path, framed())
    path.write_bytes(path.read_bytes()[:-1])
    result = capture.reconstruct(path)
    assert result["parse_error"] == "short_packet"
    assert result["records"] == []


@pytest.mark.parametrize(("change", "expected"), [
    (lambda frame: frame[:12] + b"\x81\x00" + frame[14:],
     "unsupported_vlan_or_ipv6"),
    (lambda frame: frame[:20] + b"\x20\x00" + frame[22:],
     "fragmented_ipv4_packet"),
    (lambda frame: frame[:46] + b"\x10" + frame[47:],
     "short_tcp_header"),
])
def test_unsupported_or_invalid_frames_fail_closed(tmp_path, change, expected):
    result = capture.reconstruct(pcap(tmp_path, [change(packet(100, flags=2))]))
    assert result["parse_error"] == expected
    assert result["records"] == []


def test_incomplete_control_only_direction_is_reported(tmp_path):
    result = capture.reconstruct(pcap(tmp_path, [packet(100, flags=2)]))
    assert len(result["streams"]) == 1
    assert "stream_end_unobserved" in issues(result)
    assert not result["observed_streams_complete"]


def test_reassembled_parse_failure_is_visible_to_verifier(tmp_path):
    journal, _, _ = fixture()
    path = complete(tmp_path, framed())
    path.write_bytes(path.read_bytes()[:-1])
    result = verify_capture(journal, path, "vm", reassemble=True)
    assert result["reassembly"]["parse_error"] == "short_packet"
    assert result["anchors"][0]["reason"] == "backend_lock_missing_or_ambiguous"
    assert result["capture_complete"] is False


def test_mutating_capture_is_rejected(tmp_path, monkeypatch):
    journal, _, _ = fixture()
    path = complete(tmp_path, framed())
    original = capture.reconstruct

    def mutate(source):
        result = original(source)
        source.write_bytes(source.read_bytes() + b"changed")
        return result

    monkeypatch.setattr("tools.nlm_callback_verify.reconstruct", mutate)
    with pytest.raises(ValueError, match="pcap changed during verification"):
        verify_capture(journal, path, "vm", reassemble=True)


def test_verifier_opt_in_preserves_authority_and_overlap_warning(tmp_path):
    journal, _, _ = fixture()
    data = framed()
    journal.events[0].request.payload.output.output_sha256 = hashlib.sha256(data).hexdigest()
    journal.events[0].request.payload.output.final_record_length = len(data)
    journal.events[1].request.payload.forwarded_length = len(data)
    path = complete(tmp_path, data, chunks=[
        packet(101, data[:10]), packet(111, data[10:]), packet(111, data[10:])])
    legacy = verify_capture(journal, path, "vm")
    assert legacy["schema_version"].endswith("v1")
    assert legacy["anchors"][0]["reason"] == "backend_lock_missing_or_ambiguous"
    result = verify_capture(journal, path, "vm", reassemble=True)
    assert result["schema_version"].endswith("v2")
    assert result["anchors"][0]["reason"] == "journal_backend_lock_bytes_observed"
    assert result["anchors"][0]["duplicate_tcp_observations_unresolved"] is True
    assert result["status"] == "diagnostic_only"
    assert result["capture_complete"] is False
    assert "attribution" not in result
