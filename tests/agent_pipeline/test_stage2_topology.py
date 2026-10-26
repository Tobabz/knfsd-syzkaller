"""HCAP-04 lane-topology campaign checks (#99), without a VM."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent_pipeline.stage2 import topology
from agent_pipeline.stage2.kvm import NfsProxyExecution

PREFIXES = ("tl0-a", "tl1-b")


def record(lane, generation, **fields):
    value = {
        "schema_version": "knfsd-nfs-proxy-execution.v2", "vm": 0,
        "lane": lane, "execution_id": lane * 1000 + generation,
        "campaign": True, "program_sha256": "1" * 64,
        "generation": generation, "program_digest": "2" * 64,
        "activation": "Acked", "activation_status": 0,
        "deactivation": "Acked", "deactivation_status": 0,
        "executed": True, "lease_cleared": True, "hanged": False,
        "error": "", "pcs": (0x1000 + generation,)}
    value.update(fields)
    return NfsProxyExecution.model_validate(value)


def event(lane, generation, *, channel=None, session=None,
          event_type="GENERATION_OPEN"):
    correlation = SimpleNamespace(kcov_generation=generation, lane_id=lane)
    return SimpleNamespace(
        binding=SimpleNamespace(
            channel_id=channel or f"nfsp-journal-{lane}",
            proxy_session_id=session or f"{PREFIXES[lane]}.1"),
        request=SimpleNamespace(event_type=event_type,
                                payload=SimpleNamespace(
                                    correlation=correlation)))


def clean(executions=8):
    records = [record(lane, g) for lane in (0, 1)
               for g in range(1, executions + 1)]
    events = [event(lane, g) for lane in (0, 1)
              for g in range(1, executions + 1)]
    return records, events


def test_clean_lanes_count_every_execution():
    records, events = clean()
    lanes = topology.lane_results(records, events, PREFIXES)
    assert lanes == [{
        "lane": lane, "executions": 8, "attributed_executions": 8,
        "distinct_generations": 8, "proxy_acked_executions": 8,
        "healthy_executions": 8, "journal_generations": 8,
        "generations_missing_from_journal": 0,
        "foreign_journal_events": 0} for lane in (0, 1)]


@pytest.mark.parametrize(("change", "field", "value"), [
    ({"pcs": ()}, "attributed_executions", 7),
    ({"generation": 1}, "distinct_generations", 7),
    ({"deactivation_status": 5}, "proxy_acked_executions", 7),
    ({"activation": "Failed"}, "proxy_acked_executions", 7),
    ({"hanged": True}, "healthy_executions", 7),
    ({"lease_cleared": False}, "healthy_executions", 7),
    ({"error": "lane lost"}, "healthy_executions", 7),
])
def test_one_bad_execution_shows_on_its_lane(change, field, value):
    records, events = clean()
    change = dict(change)
    records[9] = record(1, change.pop("generation", 2), **change)
    lanes = topology.lane_results(records, events, PREFIXES)
    assert lanes[1][field] == value
    assert lanes[0][field] == 8


def test_cross_lane_journal_events_are_foreign():
    records, events = clean()
    # Lane 0's channel carries a lane 1 correlation, lane 1's channel an
    # event of lane 0's series, and lane 1 misses one GENERATION_OPEN.
    events.append(event(1, 3, channel="nfsp-journal-0",
                        session=f"{PREFIXES[0]}.1"))
    events.append(event(1, 4, session=f"{PREFIXES[0]}.2"))
    events.remove(next(e for e in events
                       if e.binding.channel_id == "nfsp-journal-1"
                       and e.request.payload.correlation.kcov_generation == 8))
    lanes = topology.lane_results(records, events, PREFIXES)
    assert lanes[0]["foreign_journal_events"] == 2
    assert lanes[1]["foreign_journal_events"] == 1
    assert lanes[1]["generations_missing_from_journal"] == 1


def test_campaign_waits_for_every_lane():
    records, _ = clean(3)
    assert topology._enough(records, 2, 3)
    assert not topology._enough(records, 2, 4)
    assert not topology._enough(records[:3], 2, 3)
    assert not topology._enough(
        [record(0, 1, campaign=False)] * 3 + records[3:], 2, 3)


def test_program_calls_are_the_corpus_calls():
    program = topology.DEFAULT_PROGRAM.read_bytes()
    calls = topology.program_calls(program)
    assert calls[0] == "syz_open_nfs_lane_profile$client0_knfsd_v41"
    assert len(calls) == len(set(calls))
    assert not any(call.startswith(("syz_nfs_lane_link", "syz_nfsd_"))
                   for call in calls)


def test_empty_rule_set_is_for_the_selection_schema():
    rules = topology.empty_rule_set("4.1")
    assert rules.startswith(b"NFSPRUL1")
    assert b"nfs4.1/" in rules and topology.CANDIDATE_ID.encode() in rules
    with pytest.raises(topology.Stage2StepError):
        topology.empty_rule_set("9")


def test_evidence_types_a_passing_campaign(tmp_path):
    from tests.agent_pipeline.test_materializer import materializer_world
    descriptor = materializer_world(tmp_path).descriptor
    builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
    # The synthetic descriptor has no instrumentation artifact.
    collector = SimpleNamespace(instrumentation_artifact_name="vm-image",
                                vmlinux_artifact_name="kernel")
    records, events = clean()
    result = {"procs": 2, "min_executions_per_lane": 8,
              "manager_exited_unexpectedly": False,
              "crash_signature_count": 0,
              "lanes": topology.lane_results(records, events, PREFIXES)}
    encoded = json.dumps(result).encode()
    evidence = topology.topology_evidence(descriptor, collector, "c" * 64,
                                          result, encoded)
    assert evidence.layout.procs == 2 and evidence.layout.lanes == (0, 1)
    assert evidence.capability_ids == ("HCAP-01", "HCAP-03", "HCAP-04")
    assert evidence.campaign_result_sha256 == hashlib.sha256(
        encoded).hexdigest()
    assert evidence.mapping_identity.vmlinux_sha256 == builds["kernel"]
    result["lanes"][1]["foreign_journal_events"] = 1
    with pytest.raises(ValidationError, match="another lane's events"):
        topology.topology_evidence(descriptor, collector, "c" * 64, result,
                                   json.dumps(result).encode())
    result["lanes"][1]["foreign_journal_events"] = 0
    with pytest.raises(ValidationError, match="private target data"):
        topology.topology_evidence(descriptor, collector, "c" * 64, result,
                                   b'{"pc": "0xffffffff81000000"}')
