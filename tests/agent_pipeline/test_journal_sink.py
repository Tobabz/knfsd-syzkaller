"""M5/S1b host journal sink: admission (05 §6, §21), ACK and recovery (§45).

Oracle numbers refer to 05-mutation-delta-replay.md "검증 오라클".
"""

import hashlib
import os
import socket
import threading

import pytest

from agent_pipeline.data import canonical_json
from agent_pipeline.journal_framing import (
    FrameKind, JournalFrame, decode_ack, encode_frame, read_journal,
)
from agent_pipeline.journal_sink import (
    ChannelIdentity, HostJournal, JournalSinkError, decode_reject,
    delivery_state, serve_channel,
)

CHANNEL = ChannelIdentity("vm-1", "nfspj-0")
SESSION = "proxy-1"
LANE = 0
DIGEST = "d" * 64


def xdr_string(s: bytes) -> bytes:
    return len(s).to_bytes(4, "big") + s + b"\0" * ((4 - len(s) % 4) % 4)


def rule_set(candidate=b"cand-1") -> bytes:
    return (b"NFSPRUL1" + (1).to_bytes(4, "big") + xdr_string(b"nfs4.1")
            + xdr_string(candidate) + (0).to_bytes(4, "big"))


RULES = rule_set()
RULE_SET_ID = hashlib.sha256(RULES).hexdigest()


def corr(gen, **kw):
    c = {"kcov_generation": gen, "lane_id": LANE, "program_digest": DIGEST,
         "rule_set_id": RULE_SET_ID}
    c.update(kw)
    return c


def ctx(message_type="call", **kw):
    c = {"backend": 0, "client": 0, "connection_id": 1, "direction": "c2s",
         "message_type": message_type, "procedure": 1, "program": 100003,
         "version": 4, "xid": 7}
    c.update(kw)
    return c


def request(seq, event_type, payload, session=SESSION, rule_set_id=RULE_SET_ID):
    return canonical_json({
        "event_seq": seq, "event_type": event_type, "payload": payload,
        "proxy_session_id": session, "rule_set_id": rule_set_id,
        "schema_version": "nfs-proxy-journal-request.v1"})


def ruleset_payload(blob=RULES):
    return {"candidate_id": "cand-1", "rule_set": blob.hex(), "schema_id": "nfs4.1",
            "semantic_runtime_version": 1}


def exposure(gen, batch, message_type="call"):
    return {
        "applications": [{
            "concrete_edits": [{"data": "00000001", "flags": 1, "offset": 40,
                                "original": "00000000"}],
            "field_index": 3, "kind": "replace", "mutated_value": "00000001",
            "operation_index": 1, "original_value": "00000000", "part": "value",
            "policy": "preserve", "rule_id": "r1",
            "semantic_path": "nfs4.request.OPEN.args.seqid"}],
        "batch_id": batch, "correlation": corr(gen),
        "output": {"final_record_length": 200, "output_sha256": "e" * 64},
        "record_context": ctx(message_type),
        "semantic_signature": [{"count": 1, "kind": "replace", "part": "value",
                                "rule_id": "r1",
                                "semantic_path": "nfs4.request.OPEN.args.seqid"}]}


def summary(gen, reason="drained"):
    return {"closure": {"drain_bound_ms": 5000, "reason": reason,
                        "reply_unresolved_count": 0},
            "correlation": corr(gen), "evidence_path_failures": 0,
            "exposure_batch_count": 1, "outside_activation_window": 0,
            "records_seen": 3,
            "resolver_summary": [{"counts": {"resolved": 1}, "rule_id": "r1"}]}


class Guest:
    """A well-behaved Delta Recorder: one outstanding event, seq in order."""

    def __init__(self, journal, session=SESSION, channel=CHANNEL):
        self.journal, self.session, self.channel, self.seq = journal, session, channel, 0

    def send(self, event_type, payload):
        raw = request(self.seq, event_type, payload, session=self.session)
        self.seq += 1
        return raw, self.journal.submit(self.channel, raw)


def kind(response):
    return FrameKind(int.from_bytes(response[10:12], "big"))


def accepted(response, raw=None):
    assert kind(response) == FrameKind.ACK, decode_reject(response)
    ack = decode_ack(response)
    if raw is not None:
        assert ack.request_sha256 == hashlib.sha256(raw).hexdigest()
    return ack


def refused(response, reason):
    assert kind(response) == FrameKind.HOST_REJECTION
    assert decode_reject(response)["reason"] == reason


@pytest.fixture
def journal(tmp_path):
    j = HostJournal(tmp_path / "journal", "lane0")
    j.install_session(vm_instance_id="vm-1", channel_id="nfspj-0",
                      proxy_session_id=SESSION, lane_id=LANE, rule_set=RULES)
    yield j
    j.close()


def started(journal):
    g = Guest(journal)
    accepted(g.send("RULESET", ruleset_payload())[1])
    return g


def test_ack_names_the_stored_frame_and_host_binding(journal, tmp_path):
    g = Guest(journal)
    raw, response = g.send("RULESET", ruleset_payload())
    ack = accepted(response, raw)
    assert ack.session_binding.vm_instance_id == "vm-1"
    assert ack.session_binding.rule_set_id == RULE_SET_ID
    segment = tmp_path / "journal" / "lane0.0000.njnl"
    data = segment.read_bytes()
    assert ack.committed_end_offset == len(data)
    with open(segment, "rb") as stream:
        frames = read_journal(stream).frames
    last = encode_frame(frames[-1])
    assert hashlib.sha256(last).hexdigest() == ack.record_sha256
    assert data.endswith(last)


def test_ruleset_without_generation_is_accepted_and_must_match_install(journal):
    g = Guest(journal)
    refused(g.send("RULESET", ruleset_payload(rule_set(b"other")))[1], "ruleset_mismatch")
    refused(g.send("RULESET", ruleset_payload())[1], "ruleset_not_first")
    # Nothing generation-scoped is admitted without a durable RULESET.
    refused(g.send("GENERATION_OPEN", {"correlation": corr(1),
                                       "draining_generations": []})[1],
            "ruleset_required")


def test_retransmission_is_re_acked_without_a_second_append(journal, tmp_path):
    """Oracle 16/21: ACK lost, same event resent; applied once."""
    g = started(journal)
    accepted(g.send("GENERATION_OPEN", {"correlation": corr(1),
                                        "draining_generations": []})[1])
    raw, first = g.send("EXPOSURE_INTENT", exposure(1, 0))
    size = (tmp_path / "journal" / "lane0.0000.njnl").stat().st_size
    again = journal.submit(CHANNEL, raw)
    assert again == first
    assert (tmp_path / "journal" / "lane0.0000.njnl").stat().st_size == size
    assert len([e for e in journal.events() if e.request.event_type == "EXPOSURE_INTENT"]) == 1


def test_same_seq_other_payload_is_conflict_and_recorded(journal):
    g = started(journal)
    accepted(g.send("GENERATION_OPEN", {"correlation": corr(1),
                                        "draining_generations": []})[1])
    other = request(1, "GENERATION_OPEN", {"correlation": corr(2), "draining_generations": []})
    refused(journal.submit(CHANNEL, other), "sequence_conflict")
    state = journal.session_state(SESSION)
    assert "sequence_conflict" in state["inconsistent"]
    assert journal.rejections()[-1].reason == "sequence_conflict"


def test_gap_is_sequence_violation(journal):
    started(journal)
    raw = request(5, "GENERATION_OPEN", {"correlation": corr(1), "draining_generations": []})
    refused(journal.submit(CHANNEL, raw), "sequence_violation")
    assert journal.session_state(SESSION)["next_seq"] == 1


def test_stale_session_wrong_channel_and_wrong_lane_are_refused(journal):
    g = started(journal)
    stale = request(0, "RULESET", ruleset_payload(), session="proxy-old")
    refused(journal.submit(CHANNEL, stale), "unknown_session")
    other_vm = request(1, "GENERATION_OPEN", {"correlation": corr(1), "draining_generations": []})
    refused(journal.submit(ChannelIdentity("vm-2", "nfspj-0"), other_vm), "channel_mismatch")
    refused(g.send("GENERATION_OPEN", {"correlation": corr(1, lane_id=3),
                                       "draining_generations": []})[1], "wrong_lane")
    # The wrong-lane request was not turned into a generation.
    assert journal.session_state(SESSION)["generations"] == {}


def test_one_admitting_generation_and_draining_set(journal):
    g = started(journal)
    accepted(g.send("GENERATION_OPEN", {"correlation": corr(1), "draining_generations": []})[1])
    refused(g.send("GENERATION_OPEN", {"correlation": corr(2), "draining_generations": []})[1],
            "admitting_generation_exists")
    accepted(g.send("GENERATION_DRAINING", {"correlation": corr(1)})[1])
    refused(g.send("GENERATION_OPEN", {"correlation": corr(2), "draining_generations": []})[1],
            "draining_set_mismatch")
    accepted(g.send("GENERATION_OPEN", {"correlation": corr(2), "draining_generations": [1]})[1])
    # Draining G keeps its own binding: its REPLY events are G's, not G+1's.
    accepted(g.send("EXPOSURE_INTENT", exposure(1, 0, "reply"))[1])
    accepted(g.send("EXPOSURE_INTENT", exposure(2, 1, "call"))[1])
    assert journal.session_state(SESSION)["generations"] == {1: "draining", 2: "admitting"}


def test_draining_refuses_call_context_and_accepts_reply(journal):
    """Oracle 21: deactivation(G) without G+1."""
    g = started(journal)
    accepted(g.send("GENERATION_OPEN", {"correlation": corr(1), "draining_generations": []})[1])
    accepted(g.send("GENERATION_DRAINING", {"correlation": corr(1)})[1])
    refused(g.send("EXPOSURE_INTENT", exposure(1, 0, "call"))[1], "draining_call_context")
    refusal = {"correlation": corr(1), "record_context": ctx("call"),
               "refusal": "conflict", "rule_id": "r1"}
    refused(g.send("APPLY_REFUSAL", refusal)[1], "draining_call_context")
    accepted(g.send("EXPOSURE_INTENT", exposure(1, 1, "reply"))[1])
    refusal["record_context"] = ctx("reply")
    accepted(g.send("APPLY_REFUSAL", refusal)[1])


def test_batch_lifecycle_and_summary_closure(journal):
    g = started(journal)
    accepted(g.send("GENERATION_OPEN", {"correlation": corr(1), "draining_generations": []})[1])
    refused(g.send("FORWARD_COMPLETE", {"batch_id": 9, "correlation": corr(1),
                                        "forwarded_length": 10})[1], "unknown_batch")
    accepted(g.send("EXPOSURE_INTENT", exposure(1, 0))[1])
    refused(g.send("EXPOSURE_INTENT", exposure(1, 0))[1], "batch_conflict")
    accepted(g.send("GENERATION_DRAINING", {"correlation": corr(1)})[1])
    refused(g.send("GENERATION_COMPLETE", summary(1))[1], "batches_unterminated")
    accepted(g.send("FORWARD_COMPLETE", {"batch_id": 0, "correlation": corr(1),
                                         "forwarded_length": 200})[1])
    refused(g.send("FORWARD_FAILED", {"batch_id": 0, "bytes_written": 0,
                                      "correlation": corr(1), "reason": "x"})[1],
            "batch_conflict")
    accepted(g.send("GENERATION_COMPLETE", summary(1))[1])
    # After the summary, G is closed: its events are refused and recorded.
    refused(g.send("EXPOSURE_INTENT", exposure(1, 5, "reply"))[1], "generation_closed")
    assert journal.rejections()[-1].reason == "generation_closed"
    assert delivery_state(journal.events(SESSION), 0) == "forward_complete"


def test_crash_after_intent_is_delivery_unknown(journal):
    """Oracle 8/15: the intent survives with no forward event."""
    g = started(journal)
    accepted(g.send("GENERATION_OPEN", {"correlation": corr(1), "draining_generations": []})[1])
    accepted(g.send("EXPOSURE_INTENT", exposure(1, 0))[1])
    journal.end_session(SESSION, "vm_teardown")
    assert delivery_state(journal.events(SESSION), 0) == "delivery_unknown"
    refused(g.send("FORWARD_COMPLETE", {"batch_id": 0, "correlation": corr(1),
                                        "forwarded_length": 200})[1], "session_ended")


def test_run_complete_ends_the_session(journal):
    g = started(journal)
    accepted(g.send("RUN_COMPLETE", {"batch_count": 0, "evidence_path_failures": 0,
                                     "forward_complete_count": 0,
                                     "forward_failed_count": 0, "generations": 0,
                                     "outside_activation_window": 0})[1])
    refused(g.send("GENERATION_OPEN", {"correlation": corr(1),
                                       "draining_generations": []})[1], "session_ended")


def test_noncanonical_or_extra_fields_are_malformed(journal):
    raw = request(0, "RULESET", ruleset_payload())
    refused(journal.submit(CHANNEL, raw.replace(b'":', b'": ', 1)), "malformed_request")
    extra = dict(ruleset_payload(), extra=1)
    refused(journal.submit(CHANNEL, request(0, "RULESET", extra)), "malformed_request")
    # A malformed request uses no sequence number.
    assert journal.session_state(SESSION)["next_seq"] == 0


def test_restart_restores_sequence_bindings_and_re_acks(tmp_path):
    """§6 Runner restart, §45 rule 5: replay only complete frames."""
    j = HostJournal(tmp_path / "j", "lane0")
    j.install_session(vm_instance_id="vm-1", channel_id="nfspj-0",
                      proxy_session_id=SESSION, lane_id=LANE, rule_set=RULES)
    g = Guest(j)
    accepted(g.send("RULESET", ruleset_payload())[1])
    accepted(g.send("GENERATION_OPEN", {"correlation": corr(1), "draining_generations": []})[1])
    raw, ack = g.send("EXPOSURE_INTENT", exposure(1, 0))
    refused(g.send("EXPOSURE_INTENT", exposure(1, 0))[1], "batch_conflict")
    j.close()
    # A torn final append (crash mid-write) is left exactly where it is.
    segment = tmp_path / "j" / "lane0.0000.njnl"
    torn = encode_frame(JournalFrame(FrameKind.JOURNAL_EVENT, b'{"x":1}'))[:50]
    with open(segment, "ab") as f:
        f.write(torn)
    before = segment.read_bytes()

    j2 = HostJournal(tmp_path / "j", "lane0")
    assert segment.read_bytes() == before
    assert j2.submit(CHANNEL, raw) == ack
    state = j2.session_state(SESSION)
    assert state["next_seq"] == 4
    assert state["generations"] == {1: "admitting"}
    assert "batch_conflict" in state["inconsistent"]
    g2 = Guest(j2)
    g2.seq = 4
    accepted(g2.send("FORWARD_COMPLETE", {"batch_id": 0, "correlation": corr(1),
                                          "forwarded_length": 200})[1])
    assert (tmp_path / "j" / "lane0.0001.njnl").exists()
    j2.close()


def test_restart_refuses_middle_corruption(tmp_path):
    """Oracle 12: no silent skip."""
    j = HostJournal(tmp_path / "j", "lane0")
    j.install_session(vm_instance_id="vm-1", channel_id="nfspj-0",
                      proxy_session_id=SESSION, lane_id=LANE, rule_set=RULES)
    accepted(Guest(j).send("RULESET", ruleset_payload())[1])
    j.close()
    segment = tmp_path / "j" / "lane0.0000.njnl"
    data = bytearray(segment.read_bytes())
    data[100] ^= 1
    segment.write_bytes(bytes(data))
    with pytest.raises(Exception):
        HostJournal(tmp_path / "j", "lane0")


def test_failed_append_is_never_acked_and_fails_the_writer(journal, monkeypatch):
    """Oracle 7/17: sink cannot record -> no ACK."""
    g = started(journal)
    real = os.write
    calls = {"n": 0}

    def short(fd, data):
        calls["n"] += 1
        if calls["n"] == 1:
            return real(fd, bytes(data[:10]))
        raise OSError("disk gone")
    monkeypatch.setattr(os, "write", short)
    with pytest.raises(JournalSinkError):
        g.send("GENERATION_OPEN", {"correlation": corr(1), "draining_generations": []})
    monkeypatch.setattr(os, "write", real)
    with pytest.raises(JournalSinkError):
        journal.submit(CHANNEL, request(1, "GENERATION_OPEN",
                                        {"correlation": corr(1), "draining_generations": []}))


def test_storage_limit_is_a_channel_failure_not_a_silent_drop(tmp_path):
    j = HostJournal(tmp_path / "j", "lane0", max_total_bytes=3000)
    j.install_session(vm_instance_id="vm-1", channel_id="nfspj-0",
                      proxy_session_id=SESSION, lane_id=LANE, rule_set=RULES)
    g = Guest(j)
    with pytest.raises(JournalSinkError):
        for _ in range(100):
            g.send("RULESET", ruleset_payload())


def test_serve_channel_answers_frames_in_order(journal):
    host, guest = socket.socketpair()
    ended = []
    t = threading.Thread(target=lambda: ended.append(serve_channel(host, journal, CHANNEL)))
    t.start()
    raw = request(0, "RULESET", ruleset_payload())
    guest.sendall(encode_frame(JournalFrame(FrameKind.JOURNAL_EVENT, raw)))
    header = guest.recv(80, socket.MSG_WAITALL)
    length = int.from_bytes(header[12:16], "big")
    body = guest.recv(length, socket.MSG_WAITALL)
    accepted(header + body, raw)
    guest.sendall(b"garbage" * 20)
    t.join(timeout=5)
    guest.close()
    host.close()
    assert ended == ["bad_frame"]


def test_cli_serves_an_installed_session(tmp_path):
    import signal
    import subprocess
    import sys

    rules = tmp_path / "rules.bin"
    rules.write_bytes(RULES)
    sock_path = tmp_path / "s.sock"
    proc = subprocess.Popen(
        [sys.executable, "-m", "agent_pipeline.journal_sink", "--dir", str(tmp_path / "j"),
         "--name", "lane0", "--socket", str(sock_path), "--vm", CHANNEL.vm_instance_id,
         "--channel", CHANNEL.channel_id, "--session", SESSION, "--lane", str(LANE),
         "--rules", str(rules)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().startswith("journal sink ready:")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as guest:
            guest.settimeout(10)
            guest.connect(str(sock_path))
            raw = request(0, "RULESET", ruleset_payload())
            guest.sendall(encode_frame(JournalFrame(FrameKind.JOURNAL_EVENT, raw)))
            header = guest.recv(80, socket.MSG_WAITALL)
            body = guest.recv(int.from_bytes(header[12:16], "big"), socket.MSG_WAITALL)
            accepted(header + body, raw)
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 0, err
    assert "next_seq=1" in out
    reopened = HostJournal(tmp_path / "j", "lane0")
    assert [e.request.event_type for e in reopened.events(SESSION)] == ["RULESET"]
    reopened.close()
