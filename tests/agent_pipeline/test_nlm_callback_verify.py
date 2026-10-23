"""The journal/pcap comparator reports only unpromoted observations."""

import hashlib
from types import SimpleNamespace as NS

import pytest

from tools.nlm_callback_verify import verify, verify_ordered, verify_ordered_capture
from tools.nlm_ordered_capture import OrderedEvent


def fixture():
    digest = "a" * 64
    corr = NS(lane_id=0, kcov_generation=1, program_digest="b" * 64,
              rule_set_id="c" * 64)
    ctx = NS(route="nlm", direction="c2s", message_type="call",
             program=100021, version=4, procedure=2, backend=0,
             client=1, xid=42)
    exposure = NS(binding=NS(vm_instance_id="vm"), request=NS(
        event_type="EXPOSURE_INTENT", proxy_session_id="session",
        event_seq=2, sha256="d" * 64,
        payload=NS(correlation=corr, batch_id=7, record_context=ctx,
                   output=NS(final_record_length=80, output_sha256=digest))))
    complete = NS(binding=exposure.binding, request=NS(
        event_type="FORWARD_COMPLETE", proxy_session_id="session",
        event_seq=3, payload=NS(correlation=corr, batch_id=7,
                                forwarded_length=80)))
    journal = NS(events=[exposure, complete], torn_tail=False, rejections=[],
                 manifest_sha256=lambda: "e" * 64)
    lock = {"procedure": 2, "dport": 4050, "xid": 42,
            "framed_sha256": digest, "framed_length": 80,
            "src": "10.89.0.6", "dst": "10.89.0.1", "sport": 50000,
            "tcp_sequence": 100, "key_digest": "f" * 64}
    callback = {"procedure": 10, "src": "10.89.0.1", "dst": "10.89.0.6",
                "key_digest": lock["key_digest"]}
    return journal, lock, callback


def decision(journal, observed):
    return verify(journal, observed, "vm", "0" * 64)


def test_exact_bytes_are_observations_only():
    journal, lock, callback = fixture()
    result = decision(journal, [lock, callback])
    assert result["status"] == "diagnostic_only"
    assert result["capture_complete"] is False
    assert result["anchors"][0]["reason"] == "journal_backend_lock_bytes_observed"
    assert result["anchors"][0]["callback_candidate_count_unordered"] == 1
    assert "attribution" not in result


def test_duplicate_packet_vs_distinct_tcp_record():
    journal, lock, _ = fixture()
    same = decision(journal, [lock, lock])["anchors"][0]
    assert same["backend_lock_observations"] == 2
    assert same["backend_lock_unique_tcp_records"] == 1
    assert same["duplicate_tcp_observations_unresolved"] is True
    second = decision(journal, [lock, {**lock, "tcp_sequence": 101}])["anchors"][0]
    assert second["reason"] == "backend_lock_missing_or_ambiguous"
    reused = decision(journal, [{**lock, "connection_id": 1},
                                {**lock, "connection_id": 2}])["anchors"][0]
    assert reused["backend_lock_unique_tcp_records"] == 2
    assert reused["reason"] == "backend_lock_missing_or_ambiguous"


@pytest.mark.parametrize("change", [
    {"framed_sha256": "1" * 64}, {"xid": 43}, {"framed_length": 81},
    {"src": "10.89.0.2"}, {"dst": "10.89.0.5"}, {"dport": 4045},
])
def test_mismatched_or_missing_backend_packet(change):
    journal, lock, _ = fixture()
    result = decision(journal, [{**lock, **change}])
    assert result["anchors"][0]["reason"] == "backend_lock_missing_or_ambiguous"
    assert decision(journal, [])["anchors"][0]["reason"] == (
        "backend_lock_missing_or_ambiguous")


def test_missing_failed_or_wrong_completion():
    journal, lock, _ = fixture()
    complete = journal.events[1]
    for events in ([journal.events[0]],
                   [journal.events[0], NS(binding=complete.binding, request=NS(
                       **{**vars(complete.request), "event_type": "FORWARD_FAILED"}))],
                   [journal.events[0], NS(binding=complete.binding, request=NS(
                       **{**vars(complete.request), "event_seq": 1}))],
                   [journal.events[0], complete, complete]):
        journal.events = events
        assert decision(journal, [lock])["anchors"][0]["reason"] == (
            "missing_or_invalid_forward_complete")


def test_completion_must_share_batch_and_vm_identity():
    journal, lock, _ = fixture()
    complete = journal.events[1]
    complete.request.payload.batch_id = 8
    assert decision(journal, [lock])["anchors"][0]["reason"] == (
        "missing_or_invalid_forward_complete")
    complete.request.payload.batch_id = 7
    complete.binding = NS(vm_instance_id="other-vm")
    assert decision(journal, [lock])["anchors"][0]["reason"] == (
        "missing_or_invalid_forward_complete")


def test_competing_journal_anchor_and_dirty_journal():
    journal, lock, _ = fixture()
    exposure = journal.events[0]
    rival = NS(binding=exposure.binding, request=NS(
        **{**vars(exposure.request), "proxy_session_id": "rival"}))
    journal.events.append(rival)
    assert all(anchor["reason"] == "ambiguous_journal_anchor"
               for anchor in decision(journal, [lock])["anchors"])
    journal.rejections = [object()]
    result = decision(journal, [lock])
    assert not result["journal_clean"] and result["anchors"] == []


def test_torn_journal_tail_refuses_all_anchors():
    journal, lock, _ = fixture()
    journal.torn_tail = True
    result = decision(journal, [lock])
    assert result["journal_limitation"] == "torn journal tail"
    assert result["anchors"] == []


def ordered_fixture(*, late=False, overlap=False):
    journal, lock, callback = fixture()
    lock.update(first_packet_index=1, last_packet_index=1)
    callback.update(first_packet_index=2, last_packet_index=2)
    rows = [
        ("capture_start", 0, "-", "-"),
        ("marker", 0, "activation_open", "a" * 64),
        ("packet", 1, "-", "-"),
    ]
    if late:
        rows.append(("marker", 0, "activation_close", "b" * 64))
        rows.append(("packet", 2, "-", "-"))
    else:
        rows.append(("packet", 2, "-", "-"))
        rows.append(("marker", 0, "activation_close", "b" * 64))
    rows.extend((("capture_stop", 0, "-", "-"),
                 ("capture_complete", 0, "-", "-")))
    events = tuple(OrderedEvent(index, kind, packet, (index + 1) * 1000,
                                phase, nonce)
                   for index, (kind, packet, phase, nonce) in enumerate(rows))
    manifest = {
        "ordered_observations_complete": True,
        "marker_sequences": {
            "activation_open": next(e.sequence for e in events
                                      if e.phase == "activation_open"),
            "activation_close": next(e.sequence for e in events
                                       if e.phase == "activation_close"),
        },
        "pcap_sha256": "0" * 64,
        "manifest_sha256": "1" * 64,
        "journal_manifest_sha256": journal.manifest_sha256(),
    }
    capture = {
        "parse_error": None, "observed_streams_complete": True,
        "streams": [{"overlap_observations": int(overlap), "issues": []}],
        "records": [lock, callback],
    }
    return journal, manifest, events, capture, lock, callback


def test_ordered_unique_callback_matches_diagnostically():
    journal, manifest, events, capture, _, _ = ordered_fixture()
    result = verify_ordered(journal, manifest, events, capture, "vm")
    assert result["status"] == "diagnostic_only"
    assert result["capture_complete"] is False
    assert result["ordered_observations_complete"] is True
    assert result["attribution"] == [{
        "schema_version": "nlm-callback-diagnostic.v1",
        "status": "diagnostic_only", "reason": "matched",
        "session_id": "session", "lane_id": 0, "generation": 1,
        "batch_id": 7,
    }]


def test_ordered_late_callback_stays_unassigned():
    journal, manifest, events, capture, _, _ = ordered_fixture(late=True)
    result = verify_ordered(journal, manifest, events, capture, "vm")
    assert result["attribution"][0]["reason"] == "outside_activation_window"
    assert result["attribution"][0]["generation"] is None


def test_ordered_duplicates_overlap_and_dirty_journal_fail_closed():
    journal, manifest, events, capture, lock, callback = ordered_fixture()
    capture["records"].append(dict(lock))
    assert verify_ordered(journal, manifest, events, capture, "vm")[
        "attribution"][0]["reason"] == "ambiguous_or_unmatched_lock"

    journal, manifest, events, capture, _, callback = ordered_fixture()
    capture["records"].append(dict(callback))
    decisions = verify_ordered(journal, manifest, events, capture, "vm")[
        "attribution"]
    assert {item["reason"] for item in decisions} == {"duplicate_callback"}

    journal, manifest, events, capture, _, _ = ordered_fixture(overlap=True)
    result = verify_ordered(journal, manifest, events, capture, "vm")
    assert result["ordered_observations_complete"] is False
    assert result["attribution"][0]["reason"] == "capture_incomplete"

    journal, manifest, events, capture, _, _ = ordered_fixture()
    journal.rejections = [object()]
    result = verify_ordered(journal, manifest, events, capture, "vm")
    assert result["journal_clean"] is False
    assert result["attribution"][0]["reason"] == "capture_incomplete"


def test_ordered_capture_rejects_replacement_after_manifest_check(
        tmp_path, monkeypatch):
    journal, manifest, events, _, _, _ = ordered_fixture()
    original = b"manifest-bound-pcap"
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(original)
    manifest["pcap_sha256"] = hashlib.sha256(original).hexdigest()

    def verify_then_replace(*args, **kwargs):
        pcap.write_bytes(b"replacement-pcap")
        return events

    monkeypatch.setattr("tools.nlm_callback_verify.verify_manifest",
                        verify_then_replace)
    with pytest.raises(ValueError, match="snapshot does not match manifest"):
        verify_ordered_capture(
            journal, manifest, collector=tmp_path / "collector", pcap=pcap,
            event_log=tmp_path / "events", stats=tmp_path / "stats",
            complete=tmp_path / "complete", vm_instance_id="vm")
