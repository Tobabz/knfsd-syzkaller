"""Synthetic Stage 2 host data: NFSPRUL1 bytes, host journals written by a
well-behaved Delta Recorder, syz-execprog barrier lines and syz-manager
crash logs.  Shared by the judge tests and the host command the Stage 2
engine runs in the service test, so both see the same shapes."""

from __future__ import annotations

import hashlib
from pathlib import Path

from agent_pipeline.data import canonical_json
from agent_pipeline.journal_framing import FrameKind
from agent_pipeline.journal_sink import ChannelIdentity, HostJournal, decode_reject

RULE_ID = "r1"


def _xdr(s: bytes) -> bytes:
    return len(s).to_bytes(4, "big") + s + b"\0" * ((4 - len(s) % 4) % 4)


def rules_bytes(candidate_id: str) -> bytes:
    """An NFSPRUL1 rule set naming ``candidate_id`` (no rules: the journal
    sink checks only its header)."""
    return (b"NFSPRUL1" + (1).to_bytes(4, "big") + _xdr(b"nfs4.1")
            + _xdr(candidate_id.encode()) + (0).to_bytes(4, "big"))


def program_digest(n: int) -> str:
    return hashlib.sha256(f"program-{n}".encode()).hexdigest()


class _Guest:
    def __init__(self, journal: HostJournal, channel: ChannelIdentity,
                 session: str, rule_set_id: str) -> None:
        self.journal, self.channel = journal, channel
        self.session, self.rule_set_id, self.seq = session, rule_set_id, 0

    def send(self, event_type: str, payload: dict) -> None:
        raw = canonical_json({
            "event_seq": self.seq, "event_type": event_type,
            "payload": payload, "proxy_session_id": self.session,
            "rule_set_id": self.rule_set_id,
            "schema_version": "nfs-proxy-journal-request.v1"})
        self.seq += 1
        response = self.journal.submit(self.channel, raw)
        kind = FrameKind(int.from_bytes(response[10:12], "big"))
        assert kind == FrameKind.ACK, decode_reject(response)


def write_journal(directory: Path, name: str, *, vm: str, lane: int,
                  candidate_id: str, rules: bytes,
                  generations: list[tuple[int, str, bool]],
                  session: str = "proxy-1") -> list[Path]:
    """One session on ``lane`` whose program generations ``(kcov
    generation, program digest, applied)`` each open, drain and close
    cleanly; an applied one carries one exposure of RULE_ID, forwarded.
    Returns the segment files."""
    rule_set_id = hashlib.sha256(rules).hexdigest()
    journal = HostJournal(directory, name)
    channel = ChannelIdentity(vm, f"nfspj-{lane}")
    journal.install_session(vm_instance_id=vm, channel_id=channel.channel_id,
                            proxy_session_id=session, lane_id=lane,
                            rule_set=rules)
    g = _Guest(journal, channel, session, rule_set_id)
    g.send("RULESET", {"candidate_id": candidate_id, "rule_set": rules.hex(),
                       "schema_id": "nfs4.1", "semantic_runtime_version": 1})
    batches = 0
    for gen, digest, applied in generations:
        corr = {"kcov_generation": gen, "lane_id": lane,
                "program_digest": digest, "rule_set_id": rule_set_id}
        g.send("GENERATION_OPEN", {"correlation": corr,
                                   "draining_generations": []})
        if applied:
            g.send("EXPOSURE_INTENT", _exposure(corr, batches))
        g.send("GENERATION_DRAINING", {"correlation": corr})
        if applied:
            g.send("FORWARD_COMPLETE", {"batch_id": batches,
                                        "correlation": corr,
                                        "forwarded_length": 200})
            batches += 1
        g.send("GENERATION_COMPLETE", {
            "closure": {"drain_bound_ms": 5000, "reason": "drained",
                        "reply_unresolved_count": 0},
            "correlation": corr, "evidence_path_failures": 0,
            "exposure_batch_count": 1 if applied else 0,
            "outside_activation_window": 0, "records_seen": 3,
            "resolver_summary": [{"counts": {"resolved": 1},
                                  "rule_id": RULE_ID}]})
    journal.close()
    return sorted(p for p in Path(directory).iterdir()
                  if p.name.startswith(name + "."))


def _exposure(corr: dict, batch: int) -> dict:
    return {
        "applications": [{
            "concrete_edits": [{"data": "00000001", "flags": 1, "offset": 40,
                                "original": "00000000"}],
            "field_index": 3, "kind": "replace", "mutated_value": "00000001",
            "operation_index": 1, "original_value": "00000000",
            "part": "value", "policy": "preserve", "rule_id": RULE_ID,
            "semantic_path": "nfs4.request.OPEN.args.seqid"}],
        "batch_id": batch, "correlation": corr,
        "output": {"final_record_length": 200, "output_sha256": "e" * 64},
        "record_context": {
            "backend": 0, "client": 0, "connection_id": 1, "direction": "c2s",
            "message_type": "call", "procedure": 1, "program": 100003,
            "version": 4, "xid": 7},
        "semantic_signature": [{"count": 1, "kind": "replace",
                                "part": "value", "rule_id": RULE_ID,
                                "semantic_path":
                                "nfs4.request.OPEN.args.seqid"}]}


def barrier(gen: int, digest: str) -> str:
    return (f"generation={gen} program_digest={digest} activation=Acked/0 "
            "deactivation=Acked/0 executed=true lease_cleared=true")


def execprog_output(*barriers: tuple[int, str]) -> str:
    return "".join(f"2026/10/18 12:00:0{i} nfs proxy barrier: {barrier(g, d)}\n"
                   for i, (g, d) in enumerate(barriers))


def crash_log(lane: int, gen: int, digest: str) -> str:
    """syz-manager's crash log with one finished program of ``lane``."""
    return (
        "last executing test programs:\n\n"
        f"1.0s ago: executing program {lane} (id=1):\n"
        f"nfs-proxy: lane={lane} {barrier(gen, digest)}\n"
        "getpid()\n\n"
        "kernel console output (not intermixed with test programs):\n\n"
        "[  12.0] BUG: KASAN: slab-use-after-free\n")


KASAN_REPORT = (b"BUG: KASAN: slab-use-after-free in nfsd4_target\n"
                b"Write of size 8 at addr ffff0000\n")
