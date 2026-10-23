"""Validate and seal one disposable VM's ordered NLM capture artifacts."""

from __future__ import annotations

import hashlib
import io
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from agent_pipeline.data import canonical_json


EVENT_SCHEMA = "nlm-ordered-capture-events.v1"
MANIFEST_SCHEMA = "nlm-ordered-capture-manifest.v1"
PARSER_VERSION = "bounded_tcp_rpc_reassembly.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ATOM = re.compile(r"[A-Za-z0-9_.-]{1,128}")


@dataclass(frozen=True)
class OrderedEvent:
    sequence: int
    kind: str
    packet_index: int
    timestamp_ns: int
    phase: str
    nonce: str


def _digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _single_line(path: Path, limit: int = 1024) -> str:
    data = path.read_bytes()
    if not data or len(data) > limit or b"\0" in data:
        raise ValueError(f"invalid bounded artifact: {path.name}")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"non-ASCII artifact: {path.name}") from error
    if not text.endswith("\n") or text.count("\n") != 1:
        raise ValueError(f"artifact is not one complete line: {path.name}")
    return text[:-1]


def _fields(path: Path, schema: str, names: frozenset[str]) -> dict[str, int | str]:
    result: dict[str, int | str] = {}
    for item in _single_line(path).split():
        if "=" not in item:
            raise ValueError(f"invalid field in {path.name}")
        key, value = item.split("=", 1)
        if key in result:
            raise ValueError(f"duplicate field in {path.name}: {key}")
        try:
            result[key] = value if key == "schema" else int(value)
        except ValueError as error:
            raise ValueError(f"invalid integer in {path.name}: {key}") from error
    if result.get("schema") != schema:
        raise ValueError(f"unexpected schema in {path.name}")
    if set(result) != {"schema", *names}:
        raise ValueError(f"unexpected fields in {path.name}")
    if any(value < 0 for key, value in result.items()
           if key != "schema" and isinstance(value, int)):
        raise ValueError(f"negative field in {path.name}")
    return result


def parse_event_log(path: Path) -> tuple[str, tuple[OrderedEvent, ...]]:
    data = path.read_bytes()
    if not data or len(data) > 64 * 1024 * 1024 or b"\0" in data:
        raise ValueError("invalid ordered event log")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("non-ASCII ordered event log") from error
    if not data.endswith(b"\n") or not lines:
        raise ValueError("torn ordered event log")
    header = lines[0].split("\t")
    if len(header) != 2 or header[0] != "NLM_CAPTURE_EVENTS_V1" or not _ATOM.fullmatch(
            header[1]):
        raise ValueError("invalid ordered event header")
    events = []
    for expected, line in enumerate(lines[1:]):
        columns = line.split("\t")
        if len(columns) != 6:
            raise ValueError("invalid ordered event")
        sequence, kind, packet_index, timestamp_ns, phase, nonce = columns
        event = OrderedEvent(int(sequence), kind, int(packet_index),
                             int(timestamp_ns), phase, nonce)
        if event.sequence != expected or event.timestamp_ns < 0:
            raise ValueError("non-contiguous ordered event sequence")
        if kind not in ("capture_start", "packet", "marker", "capture_stop",
                        "capture_complete"):
            raise ValueError("unknown ordered event kind")
        if kind == "packet":
            if event.packet_index <= 0 or phase != "-" or nonce != "-":
                raise ValueError("invalid packet event")
        elif kind == "marker":
            if event.packet_index != 0 or not _ATOM.fullmatch(phase) or not _DIGEST.fullmatch(
                    nonce):
                raise ValueError("invalid marker event")
        elif event.packet_index != 0 or phase != "-" or nonce != "-":
            raise ValueError("invalid lifecycle event")
        events.append(event)
    if not events or [event.kind for event in events].count("capture_start") != 1 or (
            [event.kind for event in events].count("capture_stop") != 1) or (
            [event.kind for event in events].count("capture_complete") != 1):
        raise ValueError("missing or duplicate lifecycle event")
    if events[0].kind != "capture_start" or events[-2].kind != "capture_stop" or (
            events[-1].kind != "capture_complete"):
        raise ValueError("reordered lifecycle event")
    packet_indices = [event.packet_index for event in events if event.kind == "packet"]
    if packet_indices != list(range(1, len(packet_indices) + 1)):
        raise ValueError("non-contiguous packet event mapping")
    return header[1], tuple(events)


def _pcap_timestamps(data: bytes) -> tuple[int, ...]:
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("capture exceeds ordered verifier limit")
    result = []
    with io.BytesIO(data) as source:
        header = source.read(24)
        if len(header) != 24 or header[:4] not in (
                b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise ValueError("ordered verifier requires classic pcap")
        endian = "<" if header[0] == 0xd4 else ">"
        major, minor, _, _, snaplen, linktype = struct.unpack(
            endian + "HHiIII", header[4:])
        if (major, minor, linktype) != (2, 4, 1) or not 54 <= snaplen <= 65536:
            raise ValueError("unsupported ordered pcap header")
        while raw := source.read(16):
            if len(raw) != 16:
                raise ValueError("torn ordered pcap packet header")
            seconds, micros, included, original = struct.unpack(
                endian + "IIII", raw)
            if included != original or included > snaplen or micros >= 1_000_000:
                raise ValueError("truncated ordered pcap packet")
            if len(source.read(included)) != included:
                raise ValueError("torn ordered pcap packet")
            result.append(seconds * 1_000_000_000 + micros * 1000)
    return tuple(result)


def validate_markers(events: tuple[OrderedEvent, ...], expected: dict[str, str]
                     ) -> dict[str, int]:
    """Return collector sequences only for exact, unique, ordered nonces."""
    if list(expected) != ["activation_open", "activation_close"]:
        raise ValueError("marker phases must be activation_open then activation_close")
    if any(not _DIGEST.fullmatch(nonce) for nonce in expected.values()) or (
            len(set(expected.values())) != len(expected)):
        raise ValueError("invalid or duplicate expected marker nonce")
    markers = [event for event in events if event.kind == "marker"]
    if len(markers) != len(expected):
        raise ValueError("missing or unexpected marker")
    result = {}
    for event, (phase, nonce) in zip(markers, expected.items(), strict=True):
        if (event.phase, event.nonce) != (phase, nonce):
            raise ValueError("missing, duplicate, or reordered marker")
        result[phase] = event.sequence
    if result["activation_open"] >= result["activation_close"]:
        raise ValueError("empty or reversed activation window")
    return result


def build_manifest(*, vm_instance_id: str, collector: Path, pcap: Path,
                   event_log: Path, stats: Path, complete: Path,
                   journal_manifest_sha256: str,
                   expected_markers: dict[str, str]) -> tuple[dict, tuple[OrderedEvent, ...]]:
    """Bind immutable capture inputs while retaining diagnostic authority."""
    if not _ATOM.fullmatch(vm_instance_id) or not _DIGEST.fullmatch(
            journal_manifest_sha256):
        raise ValueError("invalid manifest identity")
    log_vm, events = parse_event_log(event_log)
    if log_vm != vm_instance_id:
        raise ValueError("ordered event log belongs to another VM")
    marker_sequences = validate_markers(events, expected_markers)
    stats_fields = _fields(
        stats, "nlm-capture-stats.v2",
        frozenset(("captured", "packets", "drops", "events",
                   "ordering_ambiguous")))
    complete_fields = _fields(
        complete, "nlm-capture-complete.v1",
        frozenset(("captured", "events", "ordering_ambiguous")))
    packet_events = [event for event in events if event.kind == "packet"]
    packet_count = len(packet_events)
    with pcap.open("rb") as source:
        pcap_snapshot = source.read(64 * 1024 * 1024 + 1)
    pcap_timestamps = _pcap_timestamps(pcap_snapshot)
    if len(pcap_timestamps) != packet_count or any(
            observed != event.timestamp_ns // 1000 * 1000
            for observed, event in zip(pcap_timestamps, packet_events, strict=True)):
        raise ValueError("pcap packets do not match ordered events")
    if stats_fields.get("captured") != packet_count or complete_fields.get(
            "captured") != packet_count:
        raise ValueError("capture count does not match ordered events")
    if stats_fields.get("events") != len(events) or complete_fields.get(
            "events") != len(events):
        raise ValueError("completion count does not match ordered events")
    if stats_fields["ordering_ambiguous"] not in (0, 1) or complete_fields[
            "ordering_ambiguous"] not in (0, 1):
        raise ValueError("invalid ordering ambiguity field")
    socket_packets = stats_fields["packets"]
    if not isinstance(socket_packets, int):
        raise ValueError("invalid socket packet count")
    all_socket_packets_captured = socket_packets == packet_count
    ordering_ambiguous = (stats_fields.get("ordering_ambiguous") != 0 or
                          complete_fields.get("ordering_ambiguous") != 0 or
                          any(left.timestamp_ns > right.timestamp_ns or (
                              left.timestamp_ns == right.timestamp_ns and
                              {left.kind, right.kind} == {"packet", "marker"})
                              for left, right in zip(events, events[1:])))
    drops = stats_fields.get("drops")
    loss_known_zero = isinstance(drops, int) and drops == 0
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "status": "diagnostic_only",
        "vm_instance_id": vm_instance_id,
        "collector_sha256": _digest(collector),
        "pcap_sha256": hashlib.sha256(pcap_snapshot).hexdigest(),
        "ordered_event_log_sha256": _digest(event_log),
        "capture_stats_sha256": _digest(stats),
        "capture_completion_sha256": _digest(complete),
        "journal_manifest_sha256": journal_manifest_sha256,
        "marker_set_sha256": hashlib.sha256(canonical_json(expected_markers)).hexdigest(),
        "parser_version": PARSER_VERSION,
        "event_schema": EVENT_SCHEMA,
        "packet_count": packet_count,
        "socket_packets": socket_packets,
        "socket_drops": drops,
        "marker_sequences": marker_sequences,
        "ordered_observations_complete": (
            loss_known_zero and all_socket_packets_captured and not ordering_ambiguous),
        "capture_complete": False,
    }
    manifest["manifest_sha256"] = hashlib.sha256(canonical_json(manifest)).hexdigest()
    return manifest, events


def verify_manifest(manifest: dict, *, vm_instance_id: str, collector: Path,
                    pcap: Path, event_log: Path, stats: Path, complete: Path,
                    journal_manifest_sha256: str
                    ) -> tuple[OrderedEvent, ...]:
    """Recompute every binding and reject a changed or extended manifest."""
    if manifest.get("vm_instance_id") != vm_instance_id or manifest.get(
            "journal_manifest_sha256") != journal_manifest_sha256:
        raise ValueError("ordered manifest identity mismatch")
    _, events = parse_event_log(event_log)
    markers = [event for event in events if event.kind == "marker"]
    expected_markers = {event.phase: event.nonce for event in markers}
    rebuilt, rebuilt_events = build_manifest(
        vm_instance_id=vm_instance_id, collector=collector, pcap=pcap,
        event_log=event_log, stats=stats, complete=complete,
        journal_manifest_sha256=journal_manifest_sha256,
        expected_markers=expected_markers)
    if manifest != rebuilt:
        raise ValueError("ordered manifest or bound artifact changed")
    return rebuilt_events
