"""Bounded offline TCP/RPC reconstruction for local NLM diagnostics.

Packet ordinals describe this file only. They do not order journal events or
authenticate the VM, capture loss, or remote KCOV ownership.
"""

from __future__ import annotations

import hashlib
import ipaddress
import struct
from dataclasses import dataclass, field
from pathlib import Path

from tools.nlm_callback_attribution import Incomplete, nlm_call

MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_STREAM_BYTES = 4 * 1024 * 1024
MAX_STREAMS = 512
MAX_SEGMENTS = 4096
MAX_RECORDS = 4096
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_FRAGMENTS = 64
NLM_PORTS = frozenset((4045, 4050))


@dataclass
class _Stream:
    endpoints: tuple[str, str, int, int]
    connection: int
    syn: int | None = None
    segments: list = field(default_factory=list)
    fins: set[int] = field(default_factory=set)
    reset: bool = False
    issues: set[str] = field(default_factory=set)


def _packets(path: Path):
    if path.stat().st_size > MAX_CAPTURE_BYTES:
        raise Incomplete("capture_size_limit")
    with path.open("rb") as source:
        header = source.read(24)
        if len(header) != 24 or header[:4] not in (
                b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise Incomplete("requires_classic_pcap")
        endian = "<" if header[0] == 0xd4 else ">"
        major, minor, _, _, snaplen, linktype = struct.unpack(
            endian + "HHiIII", header[4:])
        if (major, minor, linktype) != (2, 4, 1) or not 54 <= snaplen <= 65536:
            raise Incomplete("unsupported_pcap_header")
        used = 24
        ordinal = 0
        while raw := source.read(16):
            ordinal += 1
            if len(raw) != 16:
                raise Incomplete("short_packet_header")
            seconds, micros, size, original = struct.unpack(endian + "IIII", raw)
            used += 16 + size
            if (size != original or size > snaplen or micros >= 1_000_000
                    or used > MAX_CAPTURE_BYTES):
                raise Incomplete("truncated_or_oversized_packet")
            frame = source.read(size)
            if len(frame) != size or size < 14:
                raise Incomplete("short_packet")
            if frame[12:14] in (b"\x81\x00", b"\x88\xa8", b"\x86\xdd"):
                raise Incomplete("unsupported_vlan_or_ipv6")
            if frame[12:14] != b"\x08\x00":
                continue
            ip = frame[14:]
            if len(ip) < 20 or ip[0] >> 4 != 4:
                raise Incomplete("invalid_ipv4_header")
            if ip[9] != 6:
                continue
            ihl = (ip[0] & 15) * 4
            total = int.from_bytes(ip[2:4], "big")
            if ihl < 20 or total < ihl + 20 or total > len(ip):
                raise Incomplete("truncated_ipv4_packet")
            if int.from_bytes(ip[6:8], "big") & 0x3fff:
                raise Incomplete("fragmented_ipv4_packet")
            tcp = ip[ihl:total]
            thl = (tcp[12] >> 4) * 4
            if thl < 20 or thl > len(tcp):
                raise Incomplete("short_tcp_header")
            sport, dport, sequence = struct.unpack_from(">HHI", tcp)
            if sport not in NLM_PORTS and dport not in NLM_PORTS:
                continue
            endpoints = (str(ipaddress.IPv4Address(ip[12:16])),
                         str(ipaddress.IPv4Address(ip[16:20])), sport, dport)
            yield (ordinal, seconds + micros / 1_000_000, endpoints,
                   sequence, tcp[13], tcp[thl:])


def _relative(sequence: int, base: int) -> int:
    # The bounded stream is much smaller than TCP's half sequence space.
    return ((sequence - base + (1 << 31)) % (1 << 32)) - (1 << 31)


def _records(stream: _Stream, record_budget: int, byte_budget: int
             ) -> tuple[list[dict], list[str], int, int, int]:
    issues = sorted(stream.issues)
    if stream.reset:
        issues.append("connection_reset_observed")
    if not stream.fins:
        issues.append("stream_end_unobserved")
    if stream.syn is None:
        return [], issues + ["stream_start_unobserved"], 0, 0, 0
    base = (stream.syn + 1) % (1 << 32)
    segments = sorted((_relative(seq, base), body, ordinal, timestamp)
                      for seq, body, ordinal, timestamp in stream.segments)
    data = bytearray()
    overlaps = 0
    overlap_ranges = []
    for start, body, _, _ in segments:
        end = start + len(body)
        if start < 0 or end > MAX_STREAM_BYTES:
            return [], issues + ["stream_sequence_or_size_limit"], overlaps, 0, 0
        if start > len(data):
            return [], issues + ["tcp_sequence_gap"], overlaps, 0, 0
        shared = min(len(body), len(data) - start)
        if shared:
            overlaps += 1
            overlap_ranges.append((start, start + shared))
            if data[start:start + shared] != body[:shared]:
                return [], issues + ["conflicting_tcp_overlap"], overlaps, 0, 0
        data.extend(body[shared:])
    endings = {_relative(sequence, base) for sequence in stream.fins}
    if endings and endings != {len(data)}:
        return [], issues + ["fin_sequence_mismatch"], overlaps, 0, 0

    records = []
    record_count = 0
    record_bytes = 0
    position = 0
    while position < len(data):
        if record_count >= record_budget:
            return (records, issues + ["rpc_record_count_limit"], overlaps,
                    record_count, record_bytes)
        begin = position
        payload = bytearray()
        for _ in range(MAX_FRAGMENTS):
            if position + 4 > len(data):
                return (records, issues + ["partial_rpc_record"], overlaps,
                        record_count, record_bytes)
            marker = struct.unpack_from(">I", data, position)[0]
            position += 4
            size = marker & 0x7fffffff
            if position + size - begin > MAX_STREAM_BYTES:
                return (records, issues + ["rpc_record_size_limit"], overlaps,
                        record_count, record_bytes)
            if position + size > len(data):
                return (records, issues + ["partial_rpc_record"], overlaps,
                        record_count, record_bytes)
            payload.extend(data[position:position + size])
            position += size
            if marker >> 31:
                break
        else:
            return (records, issues + ["rpc_fragment_limit"], overlaps,
                    record_count, record_bytes)
        framed_length = position - begin
        if record_bytes + framed_length > byte_budget:
            return (records, issues + ["rpc_record_bytes_limit"], overlaps,
                    record_count, record_bytes)
        record_count += 1
        record_bytes += framed_length
        # Replies have a different RPC envelope; they cannot be LOCK anchors.
        if len(payload) >= 8 and struct.unpack_from(">I", payload, 4)[0] == 1:
            continue
        try:
            decoded = nlm_call(payload)
        except Incomplete:
            return (records, issues + ["malformed_rpc_record"], overlaps,
                    record_count, record_bytes)
        if decoded is None:
            continue
        observations = [(ordinal, timestamp) for start, body, ordinal, timestamp
                        in segments if start < position and start + len(body) > begin]
        framed = data[begin:position]
        src, dst, sport, dport = stream.endpoints
        decoded.update(
            src=src, dst=dst, sport=sport, dport=dport,
            tcp_sequence=(base + begin) % (1 << 32),
            connection_id=stream.connection,
            tcp_overlap_observed=any(start < position and end > begin
                                     for start, end in overlap_ranges),
            first_packet_index=min(item[0] for item in observations),
            last_packet_index=max(item[0] for item in observations),
            timestamp=min(item[1] for item in observations),
            framed_length=len(framed),
            framed_sha256=hashlib.sha256(framed).hexdigest())
        records.append(decoded)
    return records, issues, overlaps, record_count, record_bytes


def reconstruct(path: Path) -> dict:
    """Reassemble observed bytes, refusing gaps and conflicting overlaps.

    A SYN anchors record framing. Reused endpoint tuples get distinct local
    connection IDs; these IDs are not VM/session identities. Identical overlap
    observations remain unresolved capture duplication or retransmission.
    """
    streams: dict[tuple, _Stream] = {}
    connections: dict[tuple, tuple[int, dict, bool]] = {}
    next_connection = 0
    total_segments = 0
    try:
        for ordinal, timestamp, endpoints, seq, flags, body in _packets(path):
            src, dst, sport, dport = endpoints
            pair = tuple(sorted(((src, sport), (dst, dport))))
            current = connections.get(pair)
            syn = bool(flags & 2)
            changed_start = (current is not None and syn and
                             endpoints in current[1] and
                             current[1][endpoints] != seq)
            reused_unclosed = changed_start and not current[2]
            if current is None or changed_start:
                if reused_unclosed:
                    for old in streams.values():
                        if old.connection == current[0]:
                            old.issues.add("connection_reuse_without_close")
                next_connection += 1
                current = (next_connection, {}, False)
                connections[pair] = current
            connection, starts, _ = current
            if syn:
                starts[endpoints] = seq
            key = (connection, endpoints)
            if key not in streams:
                if len(streams) >= MAX_STREAMS:
                    raise Incomplete("stream_count_limit")
                streams[key] = _Stream(endpoints, connection)
            stream = streams[key]
            if syn:
                if stream.syn is None and (stream.segments or stream.fins):
                    stream.issues.add("syn_after_unanchored_stream")
                elif stream.fins or stream.reset:
                    stream.issues.add("syn_after_close_ambiguous")
                else:
                    stream.syn = seq
                if reused_unclosed:
                    # The old epoch was not observed closing. A changed ISN
                    # separates bytes, but does not establish a clean restart.
                    stream.issues.add("connection_reuse_without_close")
            if body:
                if total_segments >= MAX_SEGMENTS:
                    raise Incomplete("stream_segment_limit")
                total_segments += 1
                stream.segments.append(((seq + int(syn)) % (1 << 32), body,
                                        ordinal, timestamp))
            if flags & 1:
                stream.fins.add((seq + int(syn) + len(body)) % (1 << 32))
            if flags & 4:
                # A reset terminates both directions of this local connection.
                for other in streams.values():
                    if other.connection == connection:
                        other.reset = True
            if flags & 5:
                directions = [other for other in streams.values()
                              if other.connection == connection]
                if flags & 4 or (len(directions) == 2 and
                                 all(other.fins for other in directions)):
                    connections[pair] = (connection, starts, True)
    except Incomplete as error:
        return {"status": "diagnostic_only", "capture_complete": False,
                "observed_streams_complete": False,
                "parse_error": str(error), "records": [], "streams": []}
    records = []
    reports = []
    total_records = 0
    total_record_bytes = 0
    for stream in streams.values():
        decoded, issues, overlaps, used_records, used_bytes = _records(
            stream, MAX_RECORDS - total_records,
            MAX_RECORD_BYTES - total_record_bytes)
        total_records += used_records
        total_record_bytes += used_bytes
        records.extend(decoded)
        reports.append({"connection_id": stream.connection,
                        "issues": sorted(set(issues)),
                        "nlm_records": len(decoded),
                        "overlap_observations": overlaps})
    return {"status": "diagnostic_only", "capture_complete": False,
            "parse_error": None,
            "observed_streams_complete": bool(reports) and all(
                not report["issues"] for report in reports),
            "records": records, "streams": reports}
