#!/usr/bin/env python3
"""Compare re-admitted NLM journal anchors with observed backend LOCK bytes.

Classic pcap does not prove capture completeness, provenance, or event ordering.
This tool therefore never produces Stage 2 evidence or callback ownership.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

from agent_pipeline.data import parse_json
from agent_pipeline.semantic_delta import SealedJournal
from agent_pipeline.stage2.nlm_callback_contract import (
    Activation, Callback, Capture, Lock, attribute,
)
from tools.nlm_callback_attribution import calls
from tools.nlm_ordered_capture import OrderedEvent, verify_manifest
from tools.nlm_tcp_capture import reconstruct


def _key(event):
    payload = event.request.payload
    corr = payload.correlation
    return (event.binding.vm_instance_id, event.request.proxy_session_id,
            corr.lane_id, corr.kcov_generation, corr.program_digest,
            corr.rule_set_id, payload.batch_id)


def verify(journal: SealedJournal, observed: list[dict], vm_instance_id: str,
           pcap_sha256: str) -> dict:
    """Report exact observed byte matches, with no absence or owner claims."""
    result = {
        "schema_version": "nlm-journal-pcap-diagnostic.v1",
        "status": "diagnostic_only",
        "capture_complete": False,
        "capture_limitation": (
            "classic pcap lacks drop counters, VM provenance, TCP reassembly, "
            "and host/journal monotonic ordering"),
        "pcap_sha256": pcap_sha256,
        "journal_manifest_sha256": journal.manifest_sha256(),
        "journal_clean": not journal.torn_tail and not journal.rejections,
        "anchors": [],
    }
    if not result["journal_clean"]:
        result["journal_limitation"] = (
            "torn journal tail" if journal.torn_tail else "journal rejections")
        return result

    exposures = defaultdict(list)
    terminals = defaultdict(list)
    for event in journal.events:
        if event.binding.vm_instance_id != vm_instance_id:
            continue
        kind = event.request.event_type
        if kind == "EXPOSURE_INTENT":
            ctx = event.request.payload.record_context
            if (ctx.route, ctx.direction, ctx.message_type, ctx.program,
                    ctx.version, ctx.procedure, ctx.backend) == (
                    "nlm", "c2s", "call", 100021, 4, 2, 0):
                exposures[_key(event)].append(event)
        elif kind in ("FORWARD_COMPLETE", "FORWARD_FAILED"):
            terminals[_key(event)].append(event)

    backend = [call for call in observed if call["procedure"] == 2
               and call["dport"] == 4050]
    callbacks = [call for call in observed if call["procedure"] == 10]
    for key, group in exposures.items():
        for exposure in group:
            request = exposure.request
            payload = request.payload
            ctx = payload.record_context
            client_ip = f"10.89.{key[2]}.{2 if ctx.client == 0 else 6}"
            server_ip = f"10.89.{key[2]}.1"
            completion = terminals[key]
            forward_ok = (len(completion) == 1 and
                          completion[0].request.event_type == "FORWARD_COMPLETE" and
                          completion[0].request.event_seq > request.event_seq and
                          completion[0].request.payload.forwarded_length ==
                          payload.output.final_record_length)
            matches = [call for call in backend
                       if (call["xid"] == ctx.xid and
                           call["framed_sha256"] == payload.output.output_sha256 and
                           call["framed_length"] == payload.output.final_record_length and
                           call["src"] == client_ip and call["dst"] == server_ip)]
            unique = {(call["src"], call["dst"], call["sport"], call["dport"],
                       call.get("connection_id"), call["tcp_sequence"],
                       call["framed_sha256"])
                      for call in matches}
            competing = sum(1 for other_group in exposures.values()
                            for other in other_group
                            if (other.request.payload.output.output_sha256 ==
                                payload.output.output_sha256 and
                                other.request.payload.record_context.xid == ctx.xid))
            entry = {"journal_request_sha256": request.sha256,
                     "session_id": request.proxy_session_id,
                     "lane_id": key[2], "generation": key[3],
                     "batch_id": key[6], "backend_lock_observations": len(matches),
                     "backend_lock_unique_tcp_records": len(unique)}
            if len(group) != 1 or competing != 1:
                entry["reason"] = "ambiguous_journal_anchor"
            elif not forward_ok:
                entry["reason"] = "missing_or_invalid_forward_complete"
            elif len(unique) != 1:
                entry["reason"] = "backend_lock_missing_or_ambiguous"
            else:
                call = matches[0]
                entry["reason"] = "journal_backend_lock_bytes_observed"
                entry["duplicate_tcp_observations_unresolved"] = (
                    len(matches) > 1 or any(call.get("tcp_overlap_observed", False)
                                            for call in matches))
                entry["callback_candidate_count_unordered"] = sum(
                    cb["key_digest"] == call["key_digest"] and
                    cb["src"] == server_ip and cb["dst"] == client_ip
                    for cb in callbacks)
            result["anchors"].append(entry)
    return result


def verify_capture(journal: SealedJournal, path: Path, vm_instance_id: str,
                   *, reassemble: bool = False) -> dict:
    """Opt-in reconstruction changes parsing, never the evidence authority."""
    def digest():
        with path.open("rb") as source:
            return hashlib.file_digest(source, "sha256").hexdigest()

    before = digest()
    capture = reconstruct(path) if reassemble else None
    observed = capture["records"] if capture is not None else list(
        calls(path, deduplicate=False))
    if before != digest():
        raise ValueError("pcap changed during verification")
    result = verify(journal, observed, vm_instance_id, before)
    if capture is not None:
        result["schema_version"] = "nlm-journal-pcap-diagnostic.v2"
        result["capture_parser"] = "bounded_tcp_rpc_reassembly.v1"
        result["capture_limitation"] = (
            "classic pcap lacks authenticated loss counters, VM provenance, "
            "and host/journal monotonic ordering; reconstructed streams and "
            "RPC decoding are diagnostic observations only")
        result["reassembly"] = {key: value for key, value in capture.items()
                                if key not in ("records", "status", "capture_complete")}
    return result


def _event_sequence(events: tuple[OrderedEvent, ...], record: dict
                    ) -> tuple[int, int]:
    packets = {event.packet_index: event.sequence for event in events
               if event.kind == "packet"}
    first = record.get("first_packet_index")
    last = record.get("last_packet_index")
    if type(first) is not int or type(last) is not int or first > last:
        raise ValueError("RPC record has no valid ordered packet interval")
    try:
        return packets[first], packets[last]
    except KeyError as error:
        raise ValueError("RPC record packet is absent from ordered events") from error


def verify_ordered(journal: SealedJournal, manifest: dict,
                   events: tuple[OrderedEvent, ...], capture: dict,
                   vm_instance_id: str) -> dict:
    """Normalize only re-admitted anchors and return diagnostic attribution."""
    journal_clean = not journal.torn_tail and not journal.rejections
    streams = capture.get("streams", [])
    streams_clean = (capture.get("parse_error") is None
                     and capture.get("observed_streams_complete") is True
                     and all(stream.get("overlap_observations") == 0
                             for stream in streams)
                     and all(not record.get("tcp_overlap_observed", False)
                             for record in capture.get("records", [])))
    ordered_complete = (manifest.get("ordered_observations_complete") is True
                        and journal_clean and streams_clean)
    marker_sequences = manifest["marker_sequences"]
    normalized_capture = Capture(
        vm_instance_id=vm_instance_id,
        capture_sha256=manifest["pcap_sha256"],
        first_sequence=events[0].sequence, last_sequence=events[-1].sequence,
        ordered_observations_complete=ordered_complete)

    exposures = defaultdict(list)
    terminals = defaultdict(list)
    for event in journal.events:
        if event.binding.vm_instance_id != vm_instance_id:
            continue
        kind = event.request.event_type
        if kind == "EXPOSURE_INTENT":
            ctx = event.request.payload.record_context
            if (ctx.route, ctx.direction, ctx.message_type, ctx.program,
                    ctx.version, ctx.procedure, ctx.backend) == (
                    "nlm", "c2s", "call", 100021, 4, 2, 0):
                exposures[_key(event)].append(event)
        elif kind in ("FORWARD_COMPLETE", "FORWARD_FAILED"):
            terminals[_key(event)].append(event)

    records = capture.get("records", [])
    backend = [record for record in records
               if record["procedure"] == 2 and record["dport"] == 4050]
    callbacks = [record for record in records if record["procedure"] == 10]
    locks = []
    anchor_reasons = []
    owners = set()
    for key, group in exposures.items():
        exposure = group[0]
        payload = exposure.request.payload
        ctx = payload.record_context
        client_ip = f"10.89.{key[2]}.{2 if ctx.client == 0 else 6}"
        server_ip = f"10.89.{key[2]}.1"
        completion = terminals[key]
        forward_ok = (len(completion) == 1
                      and completion[0].request.event_type == "FORWARD_COMPLETE"
                      and completion[0].request.event_seq > exposure.request.event_seq
                      and completion[0].request.payload.forwarded_length ==
                      payload.output.final_record_length)
        matches = [record for record in backend
                   if record["xid"] == ctx.xid
                   and record["framed_sha256"] == payload.output.output_sha256
                   and record["framed_length"] == payload.output.final_record_length
                   and record["src"] == client_ip
                   and record["dst"] == server_ip]
        competing = sum(1 for other_group in exposures.values()
                        for other in other_group
                        if other.request.payload.output.output_sha256 ==
                        payload.output.output_sha256
                        and other.request.payload.record_context.xid == ctx.xid)
        if len(group) != 1 or competing != 1:
            anchor_reasons.append("ambiguous_journal_anchor")
            continue
        if not forward_ok:
            anchor_reasons.append("missing_or_invalid_forward_complete")
            continue
        if not matches:
            anchor_reasons.append("backend_lock_missing")
            continue
        anchor_reasons.append("journal_backend_lock_bytes_observed")
        owner = (exposure.request.proxy_session_id, key[2], key[3])
        owners.add(owner)
        for record in matches:
            first, last = _event_sequence(events, record)
            locks.append(Lock(
                vm_instance_id=vm_instance_id, session_id=owner[0],
                lane_id=owner[1], generation=owner[2], batch_id=key[6],
                journal_request_sha256=exposure.request.sha256,
                output_sha256=payload.output.output_sha256,
                forwarded_sha256=record["framed_sha256"],
                forward_complete=True, key_digest=record["key_digest"],
                client_ip=client_ip, server_ip=server_ip,
                first_sequence=first, last_sequence=last))

    activations = tuple(Activation(
        vm_instance_id=vm_instance_id, session_id=session, lane_id=lane,
        generation=generation,
        open_sequence=marker_sequences["activation_open"],
        close_sequence=marker_sequences["activation_close"])
        for session, lane, generation in sorted(owners)) if len(owners) == 1 else ()
    normalized_callbacks = []
    for record in callbacks:
        first, last = _event_sequence(events, record)
        normalized_callbacks.append(Callback(
            vm_instance_id=vm_instance_id, key_digest=record["key_digest"],
            client_ip=record["dst"], server_ip=record["src"],
            first_sequence=first, last_sequence=last))
    decisions = attribute(normalized_capture, activations, tuple(locks),
                          tuple(normalized_callbacks))
    return {
        "schema_version": "nlm-ordered-callback-diagnostic.v1",
        "status": "diagnostic_only",
        "capture_complete": False,
        "ordered_observations_complete": ordered_complete,
        "journal_clean": journal_clean,
        "observed_streams_complete": streams_clean,
        "manifest_sha256": manifest["manifest_sha256"],
        "journal_manifest_sha256": manifest["journal_manifest_sha256"],
        "anchor_reasons": anchor_reasons,
        "lock_observations": len(locks),
        "callback_observations": len(normalized_callbacks),
        "attribution": [decision.model_dump(mode="json")
                        for decision in decisions],
    }


def verify_ordered_capture(journal: SealedJournal, manifest: dict, *,
                           collector: Path, pcap: Path, event_log: Path,
                           stats: Path, complete: Path,
                           vm_instance_id: str) -> dict:
    """Recheck sealed files before interpreting their ordered observations."""
    events = verify_manifest(
        manifest, vm_instance_id=vm_instance_id, collector=collector, pcap=pcap,
        event_log=event_log, stats=stats, complete=complete,
        journal_manifest_sha256=journal.manifest_sha256())
    capture = reconstruct(pcap)
    return verify_ordered(journal, manifest, events, capture, vm_instance_id)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--name", required=True)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--vm-instance-id", required=True)
    parser.add_argument("--reassemble", action="store_true",
                        help="opt in to bounded diagnostic TCP/RPC reconstruction")
    parser.add_argument("--ordered-manifest", type=Path)
    parser.add_argument("--collector", type=Path)
    parser.add_argument("--event-log", type=Path)
    parser.add_argument("--stats", type=Path)
    parser.add_argument("--complete", type=Path)
    args = parser.parse_args()
    journal = SealedJournal(args.journal, args.name)
    ordered = (args.ordered_manifest, args.collector, args.event_log,
               args.stats, args.complete)
    if any(ordered) and not all(ordered):
        parser.error("ordered verification requires all ordered artifact arguments")
    if args.ordered_manifest is not None:
        manifest = parse_json(args.ordered_manifest.read_bytes())
        if not isinstance(manifest, dict):
            parser.error("ordered manifest must be an object")
        result = verify_ordered_capture(
            journal, manifest, collector=args.collector, pcap=args.pcap,
            event_log=args.event_log, stats=args.stats, complete=args.complete,
            vm_instance_id=args.vm_instance_id)
    else:
        result = verify_capture(journal, args.pcap, args.vm_instance_id,
                                reassemble=args.reassemble)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
