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

from agent_pipeline.semantic_delta import SealedJournal
from tools.nlm_callback_attribution import calls
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--name", required=True)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--vm-instance-id", required=True)
    parser.add_argument("--reassemble", action="store_true",
                        help="opt in to bounded diagnostic TCP/RPC reconstruction")
    args = parser.parse_args()
    journal = SealedJournal(args.journal, args.name)
    print(json.dumps(verify_capture(journal, args.pcap, args.vm_instance_id,
                                    reassemble=args.reassemble),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
