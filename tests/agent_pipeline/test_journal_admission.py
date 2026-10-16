"""Pure admission specification matrix; no writer, ACK or workload is used."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import io

import pytest

from agent_pipeline import journal_admission as admission
from agent_pipeline.data import canonical_json
from agent_pipeline.journal_admission import (
    AdmissionError, HostAuthority, initial_state, prepare_event, reconstruct,
)
from agent_pipeline.journal_events import GenerationCorrelation
from agent_pipeline.journal_framing import (
    HEADER, FrameKind, HostSessionBinding, JournalFrame, encode_frame, read_journal,
)
from tests.agent_pipeline.test_journal_events import (
    binding, context, correlation, event, exposure, snapshot, summaries, summary,
)


def authority(*correlations):
    correlations = correlations or (correlation(), correlation(2), correlation(3, lane=1))
    return HostAuthority(
        HostSessionBinding(**binding()), snapshot(),
        tuple(GenerationCorrelation(**c) for c in correlations))


class Session:
    def __init__(self, host=None):
        self.state = initial_state(host or authority())
        self.frames = []

    def request(self, kind, *, corr=None, payload=None):
        return canonical_json(event(kind, self.state.next_event_seq, corr=corr, payload=payload))

    def add(self, kind, *, corr=None, payload=None):
        raw = self.request(kind, corr=corr, payload=payload)
        prepared = prepare_event(self.state, raw)
        assert not prepared.duplicate
        self.state = prepared.next_state  # Test harness chooses to adopt a value, no persistence claim.
        self.frames.append(JournalFrame(FrameKind.JOURNAL_EVENT, raw))
        return prepared

    def refuse(self, kind, code, *, corr=None, payload=None):
        before = copy.deepcopy(self.state)
        with pytest.raises(AdmissionError) as raised:
            prepare_event(self.state, self.request(kind, corr=corr, payload=payload))
        assert raised.value.code == code
        assert self.state == before


def opened():
    session = Session()
    session.add("RULESET")
    session.add("GENERATION_OPEN")
    return session


def closed():
    session = opened()
    session.add("GENERATION_DRAINING")
    session.add("GENERATION_COMPLETE")
    return session


def test_valid_multigeneration_multilane_drain_and_exact_prefix_reconstruction():
    s = opened()
    s.add("EXPOSURE_INTENT")
    s.add("GENERATION_DRAINING")
    s.add("GENERATION_OPEN", corr=correlation(2), payload={"draining_generations": [1]})
    s.add("GENERATION_OPEN", corr=correlation(3, lane=1))
    assert [g.phase for g in s.state.generations] == ["draining", "admitting", "admitting"]
    s.add("EXPOSURE_INTENT", payload=exposure("batch-2", reply=True))
    s.add("APPLY_REFUSAL", payload=dict(rule_id="reply", refusal="conflict", record_context=context(True)))
    s.add("FORWARD_COMPLETE")
    s.add("FORWARD_FAILED", payload=dict(batch_id="batch-2", reason="closed", bytes_written=3))
    s.add("GENERATION_COMPLETE", payload=summary(2, call={"resolved": 1},
          reply={"resolved": 1, "conflict": 1}, reason="reply_unresolved", unresolved=1))
    s.add("GENERATION_COMPLETE", corr=correlation(2), payload=summary(reason="aborted"))
    s.add("GENERATION_DRAINING", corr=correlation(3, lane=1))
    s.add("GENERATION_COMPLETE", corr=correlation(3, lane=1))
    s.add("RUN_COMPLETE", payload=dict(rule_summaries=summaries({"resolved": 1}, {"resolved": 1, "conflict": 1}),
                                       batch_count=2, forward_complete_count=1, forward_failed_count=1))
    assert s.state.run_complete
    assert all(g.phase == "closed" for g in s.state.generations)
    assert [b.outcome for b in s.state.batches] == ["complete", "failed"]
    state = initial_state(s.state.authority)
    for count, frame in enumerate(s.frames, 1):
        state = prepare_event(state, frame.payload).next_state
        assert reconstruct(s.state.authority, s.frames[:count]) == state
    assert reconstruct(s.state.authority, s.frames) == s.state


def test_prepare_does_not_advance_authority_before_caller_adopts_value():
    state = initial_state(authority())
    raw = canonical_json(event())
    prepared = prepare_event(state, raw)
    assert state.requests == () and state.next_event_seq == 0
    assert prepared.next_state.next_event_seq == 1
    assert prepared.next_state.authority is state.authority
    assert prepared.request_sha256 == hashlib.sha256(raw).hexdigest()
    # Simulated failed append: discard the candidate and retry against old state.
    again = prepare_event(state, raw)
    assert not again.duplicate and again == prepared
    with pytest.raises(FrozenInstanceError):
        prepared.next_state.run_complete = True
    with pytest.raises(FrozenInstanceError):
        state.authority.snapshot_bytes = b"changed"


def test_exact_retransmission_is_distinct_from_same_sequence_conflict():
    s = opened()
    original = s.frames[0].payload
    retried = prepare_event(s.state, original)
    assert retried.duplicate and retried.next_state is s.state
    changed = event("GENERATION_OPEN", 1, payload={"draining_generations": [2]})
    with pytest.raises(AdmissionError, match="event_conflict"):
        prepare_event(s.state, canonical_json(changed))
    assert s.state.next_event_seq == 2


def test_ruleset_first_sequence_zero_no_gaps_or_second_ruleset():
    s = Session()
    s.refuse("GENERATION_OPEN", "ruleset_first")
    with pytest.raises(AdmissionError, match="sequence_violation"):
        prepare_event(s.state, canonical_json(event(seq=1)))
    s.add("RULESET")
    s.refuse("RULESET", "ruleset_conflict")
    with pytest.raises(AdmissionError, match="sequence_violation"):
        prepare_event(s.state, canonical_json(event("GENERATION_OPEN", 2)))
    s.refuse("EXPOSURE_INTENT", "generation_not_open")


@pytest.mark.parametrize("field,value", [("vm_instance_id", "other-vm"),
                                        ("channel_id", "other-channel"),
                                        ("proxy_session_id", "other-session")])
def test_host_session_values_are_compared_never_overwritten(field, value):
    s = Session()
    data = event()
    data["session_binding"][field] = value
    with pytest.raises(AdmissionError, match="session_mismatch"):
        prepare_event(s.state, canonical_json(data))
    assert s.state.authority.session_binding == HostSessionBinding(**binding())
    assert not s.state.requests


def test_different_valid_snapshot_is_not_installed_from_guest():
    s = Session()
    other = snapshot(candidate_id="another-candidate")
    data = event(raw=other)
    data["payload"]["candidate_id"] = "another-candidate"
    with pytest.raises(AdmissionError, match="session_mismatch"):
        prepare_event(s.state, canonical_json(data))
    assert s.state.authority.snapshot_bytes == snapshot()
    with pytest.raises(ValueError, match="does not name"):
        HostAuthority(HostSessionBinding(**binding()), other, ())


@pytest.mark.parametrize("field,value", [("lane_id", 99), ("proc_id", 99),
                                        ("kcov_generation", 99), ("program_digest", "f" * 64)])
def test_host_generation_values_are_compared_even_at_open(field, value):
    s = Session()
    s.add("RULESET")
    wrong = correlation()
    wrong[field] = value
    s.refuse("GENERATION_OPEN", "correlation_mismatch", corr=wrong)
    assert not s.state.generations


@pytest.mark.parametrize("field,value", [("vm_instance_id", "other"), ("rule_set_id", "a" * 64)])
def test_envelope_correlation_must_agree(field, value):
    s = opened()
    wrong = correlation()
    wrong[field] = value
    s.refuse("GENERATION_DRAINING", "malformed_event", corr=wrong)


def test_invalid_authority_is_not_a_mockable_guest_permission_token():
    c = GenerationCorrelation(**correlation())
    for generations in ([c], (c, c), tuple(GenerationCorrelation(**correlation(i)) for i in range(1, 66))):
        with pytest.raises(ValueError):
            HostAuthority(HostSessionBinding(**binding()), snapshot(), generations)
    other = correlation(2)
    other["proc_id"] = 1
    with pytest.raises(ValueError, match="proc identities"):
        authority(correlation(), other)
    other["vm_instance_id"] = "other"
    with pytest.raises(ValueError, match="session binding"):
        authority(other)
    with pytest.raises(TypeError):
        initial_state(lambda *_: True)


def test_generation_reuse_and_exact_draining_set_by_lane():
    s = opened()
    s.refuse("GENERATION_OPEN", "generation_reused")
    s.refuse("GENERATION_OPEN", "lane_admitting", corr=correlation(2))
    s.add("GENERATION_DRAINING")
    s.refuse("GENERATION_DRAINING", "generation_phase")
    s.refuse("GENERATION_OPEN", "draining_set_mismatch", corr=correlation(2))
    s.refuse("GENERATION_OPEN", "draining_set_mismatch", corr=correlation(3, 1),
             payload={"draining_generations": [1]})
    s.add("GENERATION_OPEN", corr=correlation(2), payload={"draining_generations": [1]})
    s.add("GENERATION_COMPLETE")
    s.refuse("GENERATION_OPEN", "generation_reused")


def test_multiple_draining_generations_require_the_whole_set():
    s = Session(authority(correlation(), correlation(2), correlation(3)))
    s.add("RULESET")
    s.add("GENERATION_OPEN")
    s.add("GENERATION_DRAINING")
    s.add("GENERATION_OPEN", corr=correlation(2), payload={"draining_generations": [1]})
    s.add("GENERATION_DRAINING", corr=correlation(2))
    s.refuse("GENERATION_OPEN", "draining_set_mismatch", corr=correlation(3),
             payload={"draining_generations": [2]})
    s.add("GENERATION_OPEN", corr=correlation(3), payload={"draining_generations": [1, 2]})
    assert [g.phase for g in s.state.generations] == ["draining", "draining", "admitting"]


@pytest.mark.parametrize("kind", ["EXPOSURE_INTENT", "APPLY_REFUSAL"])
def test_call_refused_while_draining_even_without_next_generation(kind):
    s = opened()
    s.add("GENERATION_DRAINING")
    s.refuse(kind, "call_while_draining")
    payload = exposure(reply=True) if kind == "EXPOSURE_INTENT" else dict(
        rule_id="reply", refusal="conflict", record_context=context(True))
    s.add(kind, payload=payload)


def test_batch_ids_session_unique_and_cross_generation_outcome_rejected():
    s = opened()
    s.add("EXPOSURE_INTENT")
    s.refuse("EXPOSURE_INTENT", "batch_conflict")
    s.add("GENERATION_OPEN", corr=correlation(3, 1))
    s.refuse("EXPOSURE_INTENT", "batch_conflict", corr=correlation(3, 1))
    s.refuse("FORWARD_COMPLETE", "batch_correlation_mismatch", corr=correlation(3, 1))
    s.refuse("FORWARD_FAILED", "batch_correlation_mismatch", corr=correlation(3, 1))


@pytest.mark.parametrize("kind", ["FORWARD_COMPLETE", "FORWARD_FAILED"])
def test_forward_requires_exposure_and_exactly_one_outcome(kind):
    s = opened()
    s.refuse(kind, "unknown_batch")
    s.add("EXPOSURE_INTENT")
    s.add(kind)
    s.refuse("FORWARD_COMPLETE", "batch_conflict")
    s.refuse("FORWARD_FAILED", "batch_conflict")
    retry = prepare_event(s.state, s.frames[-1].payload)
    assert retry.duplicate and retry.next_state is s.state


@pytest.mark.parametrize("kind,length", [("FORWARD_COMPLETE", 52), ("FORWARD_COMPLETE", 57),
                                        ("FORWARD_FAILED", 56), ("FORWARD_FAILED", 57)])
def test_forwarded_lengths_use_full_framed_record(kind, length):
    s = opened()
    s.add("EXPOSURE_INTENT")
    payload = dict(batch_id="batch-1", forwarded_length=length) if kind == "FORWARD_COMPLETE" else dict(
        batch_id="batch-1", reason="closed", bytes_written=length)
    s.refuse(kind, "forward_length", payload=payload)


@pytest.mark.parametrize("length", [0, 55, None])
def test_failed_forward_can_record_zero_partial_or_unknown_count(length):
    s = opened()
    s.add("EXPOSURE_INTENT")
    s.add("FORWARD_FAILED", payload=dict(batch_id="batch-1", reason="closed", bytes_written=length))
    assert s.state.batches[0].outcome == "failed"


@pytest.mark.parametrize("path,value,code", [
    (("applications", 0, "structure_policy"), "raw", "rule_evidence_mismatch"),
    (("record_context", "backend"), 99, "rule_context_mismatch"),
    (("record_context", "client"), 99, "rule_context_mismatch"),
    (("record_context", "direction"), "S2C", "rule_context_mismatch"),
    (("record_context", "rpc_message_type"), "reply", "rule_context_mismatch"),
    (("record_context", "rpc_program"), 0, "rule_context_mismatch"),
    (("record_context", "rpc_procedure"), None, "rule_context_mismatch"),
    (("record_context", "protocol_family"), None, "rule_context_mismatch"),
    (("record_context", "minor_version"), 2, "rule_context_mismatch"),
])
def test_exposure_compares_rule_facts_derived_from_snapshot(path, value, code):
    s = opened()
    payload = exposure()
    node = payload
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    s.refuse("EXPOSURE_INTENT", code, payload=payload)


def test_unknown_rule_target_and_changed_literal_cannot_use_coherent_bytes_to_bypass_binding():
    s = opened()
    payload = exposure()
    payload["applications"][0]["rule_id"] = "other"
    payload["semantic_signature"][0]["rule_id"] = "other"
    s.refuse("EXPOSURE_INTENT", "unknown_rule", payload=payload)
    payload = exposure()
    payload["applications"][0]["semantic_target"]["semantic_path"] = "other.path"
    payload["semantic_signature"][0]["semantic_path"] = "other.path"
    s.refuse("EXPOSURE_INTENT", "rule_evidence_mismatch", payload=payload)
    payload = exposure()
    payload["applications"][0]["mutated_value_snapshot"]["value"] = 3
    payload["applications"][0]["concrete_edits"][0]["replacement_hex"] = "00000003"
    output = bytes.fromhex(payload["output"]["framed_record_hex"])
    payload["output"]["framed_record_hex"] = (output[:48] + b"\0\0\0\3" + output[52:]).hex()
    s.refuse("EXPOSURE_INTENT", "rule_evidence_mismatch", payload=payload)


def test_refusal_first_witness_known_rule_and_missing_dispatch():
    s = opened()
    payload = dict(rule_id="other", refusal="conflict", record_context=context())
    s.refuse("APPLY_REFUSAL", "unknown_rule", payload=payload)
    payload["rule_id"] = "call"
    payload["refusal"] = "decode_unavailable"
    payload["record_context"].update(rpc_program=None, rpc_version=None, rpc_procedure=None,
                                     protocol_family=None, nfs_version=None, minor_version=None)
    s.add("APPLY_REFUSAL", payload=payload)
    s.refuse("APPLY_REFUSAL", "refusal_conflict", payload=payload)
    s.add("GENERATION_DRAINING")
    s.refuse("GENERATION_COMPLETE", "refusal_summary_mismatch")
    s.add("GENERATION_COMPLETE", payload=summary(call={"decode_unavailable": 1}))


@pytest.mark.parametrize("refusal", ["scope_miss", "target_not_found", "predicate_false", "transform_unsupported"])
def test_apply_refusal_is_not_a_generic_validator_bypass(refusal):
    s = opened()
    s.refuse("APPLY_REFUSAL", "malformed_event", payload=dict(
        rule_id="call", refusal=refusal, record_context=context()))


def test_refusal_summary_requires_witness_and_recorded_kind_but_allows_later_counts():
    s = opened()
    s.add("GENERATION_DRAINING")
    s.refuse("GENERATION_COMPLETE", "refusal_summary_mismatch", payload=summary(call={"conflict": 1}))
    s = opened()
    s.add("APPLY_REFUSAL")
    s.add("GENERATION_DRAINING")
    s.refuse("GENERATION_COMPLETE", "refusal_summary_mismatch", payload=summary(call={"transform_failed": 1}))
    s.add("GENERATION_COMPLETE", payload=summary(call={"conflict": 2, "transform_failed": 3}))


def test_summary_requires_forward_closed_batches_exact_counts_and_resolved_evidence():
    s = opened()
    s.add("EXPOSURE_INTENT")
    s.add("GENERATION_DRAINING")
    payload = summary(1, call={"resolved": 1})
    s.refuse("GENERATION_COMPLETE", "open_batch", payload=payload)
    s.add("FORWARD_FAILED")
    s.refuse("GENERATION_COMPLETE", "summary_mismatch")
    s.refuse("GENERATION_COMPLETE", "summary_mismatch", payload=summary(1))
    missing = copy.deepcopy(payload)
    missing["resolver_summary"].pop()
    s.refuse("GENERATION_COMPLETE", "summary_mismatch", payload=missing)
    s.add("GENERATION_COMPLETE", payload=payload)


@pytest.mark.parametrize("kind", ["GENERATION_DRAINING", "EXPOSURE_INTENT", "APPLY_REFUSAL",
                                 "FORWARD_COMPLETE", "FORWARD_FAILED", "GENERATION_COMPLETE"])
def test_no_generation_events_after_terminal_summary(kind):
    s = closed()
    s.refuse(kind, "generation_closed")
    assert prepare_event(s.state, s.frames[-1].payload).duplicate


def test_aborted_closure_preserves_crash_semantics_and_still_requires_forward_outcomes():
    s = opened()
    s.refuse("GENERATION_COMPLETE", "generation_phase")
    s.add("EXPOSURE_INTENT")
    crashed = reconstruct(s.state.authority, s.frames)
    assert crashed.generations[0].phase == "admitting"
    assert crashed.generations[0].summary is None
    assert crashed.batches[0].outcome is None
    s.refuse("GENERATION_COMPLETE", "open_batch", payload=summary(1, call={"resolved": 1}, reason="aborted"))
    s.add("FORWARD_FAILED", payload=dict(batch_id="batch-1", reason="aborted", bytes_written=None))
    s.add("GENERATION_COMPLETE", payload=summary(1, call={"resolved": 1}, reason="aborted"))
    assert s.state.generations[0].summary.closure.reason == "aborted"


def test_run_complete_exact_totals_finality_and_retry():
    s = opened()
    s.refuse("RUN_COMPLETE", "open_generation")
    s.add("EXPOSURE_INTENT")
    s.add("FORWARD_COMPLETE")
    s.add("GENERATION_DRAINING")
    s.add("GENERATION_COMPLETE", payload=summary(1, call={"resolved": 1}))
    s.refuse("RUN_COMPLETE", "summary_mismatch")
    payload = dict(rule_summaries=summaries(), batch_count=1, forward_complete_count=1, forward_failed_count=0)
    s.refuse("RUN_COMPLETE", "summary_mismatch", payload=payload)
    payload["rule_summaries"] = summaries({"resolved": 1})
    s.add("RUN_COMPLETE", payload=payload)
    s.refuse("GENERATION_OPEN", "session_closed", corr=correlation(2))
    s.refuse("RUN_COMPLETE", "session_closed", payload=payload)
    for frame in s.frames:
        assert prepare_event(s.state, frame.payload).duplicate


def test_session_can_end_without_using_every_authorized_generation():
    s = Session()
    s.add("RULESET")
    s.add("RUN_COMPLETE")
    assert s.state.run_complete and not s.state.generations


def test_cumulative_session_bytes_events_and_batch_bounds(monkeypatch):
    s = Session()
    first = s.request("RULESET")
    second = canonical_json(event("GENERATION_OPEN", 1))
    exact = len(first) + len(second) + HEADER.size * 2
    monkeypatch.setattr(admission, "MAX_SESSION_BYTES", exact)
    s.add("RULESET")
    s.add("GENERATION_OPEN")
    assert s.state.framed_bytes == exact
    s.refuse("GENERATION_DRAINING", "session_limit")
    assert prepare_event(s.state, first).duplicate  # Retry never consumes capacity.
    monkeypatch.setattr(admission, "MAX_SESSION_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(admission, "MAX_SESSION_EVENTS", 2)
    s.refuse("GENERATION_DRAINING", "session_limit")
    monkeypatch.setattr(admission, "MAX_SESSION_EVENTS", 16384)
    monkeypatch.setattr(admission, "MAX_BATCHES", 1)
    s.add("EXPOSURE_INTENT")
    s.refuse("EXPOSURE_INTENT", "batch_limit", payload=exposure("batch-2"))
    s.add("FORWARD_COMPLETE")  # Terminal outcomes still fit at the batch limit.


def test_reconstruction_rejects_duplicate_gaps_foreign_authority_and_unsupported_records():
    s = opened()
    with pytest.raises(AdmissionError, match="duplicate_stored_event"):
        reconstruct(s.state.authority, s.frames + [s.frames[-1]])
    with pytest.raises(AdmissionError, match="sequence_violation"):
        reconstruct(s.state.authority, s.frames[1:])
    wrong = binding()
    wrong["proxy_session_id"] = "other"
    other = HostAuthority(HostSessionBinding(**wrong), snapshot(), ())
    with pytest.raises(AdmissionError, match="session_mismatch"):
        reconstruct(other, s.frames)
    for kind in (FrameKind.HOST_REJECTION, FrameKind.ACK):
        with pytest.raises(AdmissionError, match="unsupported_record"):
            reconstruct(s.state.authority, s.frames + [JournalFrame(kind, b"{}")])


def test_framed_crash_prefix_reconstruction_never_invents_forward_outcome_or_repairs_tail():
    s = opened()
    s.add("EXPOSURE_INTENT")
    prefix = b"".join(encode_frame(f) for f in s.frames)
    tail = encode_frame(JournalFrame(FrameKind.JOURNAL_EVENT, s.request("FORWARD_COMPLETE")))
    for end in (1, HEADER.size - 1, HEADER.size, len(tail) - 1):
        stream = io.BytesIO(prefix + tail[:end])
        parsed = read_journal(stream)
        recovered = reconstruct(s.state.authority, parsed.frames)
        assert recovered == s.state and recovered.batches[0].outcome is None
        assert stream.getvalue() == prefix + tail[:end]
    parsed = read_journal(io.BytesIO(prefix + tail))
    assert reconstruct(s.state.authority, parsed.frames).batches[0].outcome == "complete"
