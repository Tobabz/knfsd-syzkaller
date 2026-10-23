"""The journal/pcap comparator reports only unpromoted observations."""

from types import SimpleNamespace as NS

import pytest

from tools.nlm_callback_verify import verify


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
