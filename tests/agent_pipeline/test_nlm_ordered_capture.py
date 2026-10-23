"""Ordered NLM capture artifacts are bounded and fail closed."""

import struct

import pytest

from tools.nlm_ordered_capture import build_manifest, verify_manifest


OPEN = "a" * 64
CLOSE = "b" * 64
JOURNAL = "c" * 64
VM = "vm-run-1"


def _pcap(path, timestamps=(3_000,)):
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65536, 1)
    for timestamp in timestamps:
        frame = bytes(54)
        seconds, nanos = divmod(timestamp, 1_000_000_000)
        data += struct.pack("<IIII", seconds, nanos // 1000, len(frame), len(frame))
        data += frame
    path.write_bytes(data)


def _artifacts(tmp_path, *, vm=VM, markers=None, drops=0, ambiguous=0,
               final_newline=True, packet_timestamp=3_000,
               pcap_timestamp=None):
    collector = tmp_path / "nlm-pcap"
    pcap = tmp_path / "capture.pcap"
    events = tmp_path / "capture.events"
    stats = tmp_path / "capture.stats"
    complete = tmp_path / "capture.complete"
    collector.write_bytes(b"collector")
    _pcap(pcap, (packet_timestamp if pcap_timestamp is None else pcap_timestamp,))
    rows = markers or [
        ("capture_start", 0, 1_000, "-", "-"),
        ("marker", 0, 2_000, "activation_open", OPEN),
        ("packet", 1, packet_timestamp, "-", "-"),
        ("marker", 0, 4_000, "activation_close", CLOSE),
        ("capture_stop", 0, 5_000, "-", "-"),
        ("capture_complete", 0, 6_000, "-", "-"),
    ]
    body = f"NLM_CAPTURE_EVENTS_V1\t{vm}\n" + "".join(
        f"{sequence}\t{kind}\t{packet}\t{timestamp}\t{phase}\t{nonce}\n"
        for sequence, (kind, packet, timestamp, phase, nonce) in enumerate(rows))
    events.write_bytes(body.encode()[:-1] if not final_newline else body.encode())
    stats.write_text(
        "schema=nlm-capture-stats.v2 captured=1 packets=1 "
        f"drops={drops} events={len(rows)} ordering_ambiguous={ambiguous}\n")
    complete.write_text(
        "schema=nlm-capture-complete.v1 captured=1 "
        f"events={len(rows)} ordering_ambiguous={ambiguous}\n")
    return collector, pcap, events, stats, complete


def _build(paths, *, vm=VM, expected=None):
    collector, pcap, events, stats, complete = paths
    return build_manifest(
        vm_instance_id=vm, collector=collector, pcap=pcap, event_log=events,
        stats=stats, complete=complete, journal_manifest_sha256=JOURNAL,
        expected_markers=expected or {
            "activation_open": OPEN, "activation_close": CLOSE})


def test_valid_capture_is_ordered_but_never_promoted(tmp_path):
    manifest, events = _build(_artifacts(tmp_path))
    assert manifest["status"] == "diagnostic_only"
    assert manifest["capture_complete"] is False
    assert manifest["ordered_observations_complete"] is True
    assert manifest["marker_sequences"] == {
        "activation_open": 1, "activation_close": 3}
    assert len(events) == 6


@pytest.mark.parametrize("expected", [
    {"activation_open": OPEN},
    {"activation_open": OPEN, "activation_close": OPEN},
    {"activation_close": CLOSE, "activation_open": OPEN},
])
def test_missing_duplicate_or_reordered_expected_nonce_is_rejected(tmp_path, expected):
    with pytest.raises(ValueError, match="marker|nonce"):
        _build(_artifacts(tmp_path), expected=expected)


def test_reordered_observed_marker_is_rejected(tmp_path):
    rows = [
        ("capture_start", 0, 1_000, "-", "-"),
        ("marker", 0, 2_000, "activation_close", CLOSE),
        ("packet", 1, 3_000, "-", "-"),
        ("marker", 0, 4_000, "activation_open", OPEN),
        ("capture_stop", 0, 5_000, "-", "-"),
        ("capture_complete", 0, 6_000, "-", "-"),
    ]
    with pytest.raises(ValueError, match="reordered marker"):
        _build(_artifacts(tmp_path, markers=rows))


def test_wrong_vm_and_pcap_event_mismatch_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="another VM"):
        _build(_artifacts(tmp_path), vm="vm-run-2")
    mismatch = tmp_path / "mismatch"
    mismatch.mkdir()
    with pytest.raises(ValueError, match="pcap packets"):
        _build(_artifacts(mismatch, pcap_timestamp=4_000))


@pytest.mark.parametrize("target", ["collector", "pcap", "events",
                                      "stats", "complete"])
def test_manifest_rejects_bound_artifact_mutation(tmp_path, target):
    paths = _artifacts(tmp_path)
    manifest, _ = _build(paths)
    selected = paths[["collector", "pcap", "events", "stats",
                      "complete"].index(target)]
    selected.write_bytes(selected.read_bytes() + b"x")
    with pytest.raises(ValueError):
        verify_manifest(
            manifest, vm_instance_id=VM, collector=paths[0], pcap=paths[1],
            event_log=paths[2], stats=paths[3], complete=paths[4],
            journal_manifest_sha256=JOURNAL)


def test_unknown_nonzero_drops_and_ordering_ambiguity_fail_closed(tmp_path):
    dropped = tmp_path / "dropped"
    dropped.mkdir()
    manifest, _ = _build(_artifacts(dropped, drops=1))
    assert manifest["ordered_observations_complete"] is False
    ambiguous = tmp_path / "ambiguous"
    ambiguous.mkdir()
    manifest, _ = _build(_artifacts(ambiguous, ambiguous=1))
    assert manifest["ordered_observations_complete"] is False
    unknown = tmp_path / "unknown"
    unknown.mkdir()
    paths = _artifacts(unknown)
    paths[3].write_text(paths[3].read_text().replace("drops=0", "drops=unknown"))
    with pytest.raises(ValueError, match="invalid integer"):
        _build(paths)
    count = tmp_path / "count"
    count.mkdir()
    paths = _artifacts(count)
    paths[3].write_text(paths[3].read_text().replace("packets=1", "packets=2"))
    manifest, _ = _build(paths)
    assert manifest["ordered_observations_complete"] is False


def test_crossed_event_timestamps_fail_closed_without_collector_flag(tmp_path):
    rows = [
        ("capture_start", 0, 1_000, "-", "-"),
        ("marker", 0, 2_000, "activation_open", OPEN),
        ("packet", 1, 3_000, "-", "-"),
        ("marker", 0, 2_500, "activation_close", CLOSE),
        ("capture_stop", 0, 5_000, "-", "-"),
        ("capture_complete", 0, 6_000, "-", "-"),
    ]
    manifest, _ = _build(_artifacts(tmp_path, markers=rows))
    assert manifest["ordered_observations_complete"] is False


@pytest.mark.parametrize("rows", [
    [
        ("capture_start", 0, 1_000, "-", "-"),
        ("marker", 0, 2_000, "activation_open", OPEN),
        ("packet", 1, 3_000, "-", "-"),
        ("marker", 0, 3_000, "activation_close", CLOSE),
        ("capture_stop", 0, 5_000, "-", "-"),
        ("capture_complete", 0, 6_000, "-", "-"),
    ],
    [
        ("capture_start", 0, 1_000, "-", "-"),
        ("marker", 0, 3_000, "activation_open", OPEN),
        ("packet", 1, 3_000, "-", "-"),
        ("marker", 0, 4_000, "activation_close", CLOSE),
        ("capture_stop", 0, 5_000, "-", "-"),
        ("capture_complete", 0, 6_000, "-", "-"),
    ],
])
def test_equal_packet_marker_timestamps_fail_closed(tmp_path, rows):
    manifest, _ = _build(_artifacts(tmp_path, markers=rows))
    assert manifest["ordered_observations_complete"] is False


def test_torn_event_log_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="torn ordered event log"):
        _build(_artifacts(tmp_path, final_newline=False))
