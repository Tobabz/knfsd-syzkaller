"""M5 end to end on the host: the built Proxy in target mode, the real sink.

The Proxy relays NFSv4.1 COMPOUND CALLs between a fake client and a fake
backend on loopback, applies an NFSPRUL1 rule set inside an activated
generation, and records every event on `HostJournal` through
`ChannelServer` before it lets mutated bytes out.  What a guest adds
(virtio-serial instead of a Unix socket, the syzkaller executor instead of
the activation driver here, real knfsd) is the KVM step this test cannot
take.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

from agent_pipeline.journal_sink import (
    ChannelIdentity, ChannelServer, HostJournal, JournalSinkError, delivery_state,
    parse_request,
)

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "tools" / "nfs-proxy" / "src"
SOURCES = [
    "main.c", "proxy.c", "framing.c", "rpc_record.c", "control.c", "delta.c",
    "walk.c", "edit.c", "semantic.c", "resolver.c", "mutation_apply.c",
    "txn.c", "activation.c", "nfs_decode.c", "schema.c", "schema_nfs4.c",
    "schema_nfs3.c", "rpc_decode.c", "rule.c", "target.c", "journal.c",
    "jsonw.c", "sha256.c", "lifecycle.c", "cld.c",
]

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="127.0.0.x aliases and SOCK_SEQPACKET are Linux")

SESSION = "ps-live-1"
VM = "vm-0"
CHANNEL = "virtio-journal-0"
LANE = 0
DIGEST = hashlib.sha256(b"program").digest()
OP_SEQUENCE = 53

#: The events these tests are about: what the Proxy owes the host before it
#: lets a mutated record out and before it ends a session (01 §16).  The
#: Proxy may record further event types; the sink admits them and
#: ``journal.rejections()`` is still checked.  Orders and counts below are
#: over these events only, so a Proxy that records one more kind of event
#: does not break them.
CORE_EVENTS = frozenset({
    "RULESET", "GENERATION_OPEN", "GENERATION_DRAINING", "EXPOSURE_INTENT",
    "APPLY_REFUSAL", "FORWARD_COMPLETE", "FORWARD_FAILED",
    "GENERATION_COMPLETE", "RUN_COMPLETE",
})


def core(events):
    return [e for e in events if e.request.event_type in CORE_EVENTS]


def _xdr_string(s: bytes) -> bytes:
    return struct.pack(">I", len(s)) + s + b"\0" * (-len(s) % 4)


def _schema_id() -> str:
    text = (SRC / "schema_nfs4.c").read_text()
    match = re.search(r'\.schema_id = "(nfs4\.1/sha256:[0-9a-f]{64})"', text)
    assert match, "nfs4.1 schema id not found"
    return match.group(1)


def _rule(rule_id: str, cmp_op: int, rhs: int, value: int) -> bytes:
    """A CALL rule on SEQUENCE.args.sa_slotid: replace with `value` when
    `slotid <cmp_op> rhs` (rule.h, the golden rule's layout)."""
    u32 = lambda v: struct.pack(">I", v)  # noqa: E731
    return b"".join([
        _xdr_string(rule_id.encode()), _xdr_string(b"intent-" + rule_id.encode()),
        u32(0), u32(0), u32(0),                 # c2s, backend 0, client 0
        u32(0), u32(100003), u32(4),            # call, program, version
        u32(1), u32(1),                         # *procedure = COMPOUND
        _xdr_string(b"nfs4"), u32(1), u32(4), u32(1), u32(1),
        u32(1), _xdr_string(b"SEQUENCE"),
        u32(0), _xdr_string(b"nfs4.request.SEQUENCE.args.sa_slotid"), u32(0),
        u32(1), u32(0), _xdr_string(b""), u32(cmp_op), u32(0), u32(1), u32(rhs),
        u32(0), u32(1), u32(0), u32(1), u32(value),   # replace, literal uint
        u32(0),                                 # preserve
        u32(0) * 3, u32(0) * 3,                 # no context dependencies
        u32(0),                                 # all_matches
    ])


def rule_set() -> bytes:
    # r1: slotid > 3 -> 7.  r2: slotid == 6 -> 9, so slotid 6 makes both
    # rules write one field: a conflict, the hard refusal of 05 §29.
    rules = [_rule("r1", 4, 3, 7), _rule("r2", 0, 6, 9)]
    return (b"NFSPRUL1" + struct.pack(">I", 1) + _xdr_string(_schema_id().encode())
            + _xdr_string(b"cand-live") + struct.pack(">I", len(rules)) + b"".join(rules))


def compound_call(xid: int, slotid: int) -> bytes:
    body = struct.pack(">IIIIII", xid, 0, 2, 100003, 4, 1) + struct.pack(">IIII", 0, 0, 0, 0)
    body += _xdr_string(b"") + struct.pack(">II", 1, 1) + struct.pack(">I", OP_SEQUENCE)
    body += b"S" * 16 + struct.pack(">IIII", 1, slotid, slotid, 0)
    return struct.pack(">I", 0x80000000 | len(body)) + body


SLOTID_OFFSET = 4 + 40 + 4 + 8 + 4 + 16 + 4  # marker, RPC header, tag, ..., sequenceid


def compound_reply(xid: int, slotid: int) -> bytes:
    body = struct.pack(">IIIIII", xid, 1, 0, 0, 0, 0)  # accepted, AUTH_NONE, SUCCESS
    body += struct.pack(">I", 0) + _xdr_string(b"") + struct.pack(">I", 1)
    body += struct.pack(">II", OP_SEQUENCE, 0) + b"S" * 16
    body += struct.pack(">IIIII", 1, slotid, slotid, slotid, 0)
    return struct.pack(">I", 0x80000000 | len(body)) + body


def _recv_record(sock: socket.socket) -> bytes:
    def exact(n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data
    marker = exact(4)
    (word,) = struct.unpack(">I", marker)
    return marker + exact(word & 0x7FFFFFFF)


@pytest.fixture(scope="module")
def proxy_binary(tmp_path_factory) -> Path:
    return _build_proxy(tmp_path_factory)


@pytest.fixture(scope="module")
def proxy_binary_faults(tmp_path_factory) -> Path:
    """The Proxy with its test-only fault hook (NFSP_TARGET_FAIL_SUBMIT)."""
    return _build_proxy(tmp_path_factory, "-DNFSP_TARGET_FAULT_INJECT")


_PROXY_BUILDS: dict[tuple[str, ...], Path] = {}


def _build_proxy(tmp_path_factory, *defines: str) -> Path:
    """One build per define set per process: the sanitized build takes ~13 s
    and several modules ask for the same binary (it is only ever executed)."""
    if defines not in _PROXY_BUILDS:
        _PROXY_BUILDS[defines] = _compile_proxy(tmp_path_factory, *defines)
    return _PROXY_BUILDS[defines]


def _compile_proxy(tmp_path_factory, *defines: str) -> Path:
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.fail("a C compiler is required to build the Proxy")
    out = tmp_path_factory.mktemp("proxy") / "nfs-proxy"
    # Sanitized when this compiler can (ASan/UBSan abort on the first error,
    # which fails the run through the exit status).
    sanitize = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    probe = subprocess.run([cc, *sanitize, "-x", "c", "-o", str(out), "-"],
                           input=b"int main(void){return 0;}", capture_output=True)
    flags = sanitize if probe.returncode == 0 else []
    subprocess.run([cc, "-std=c11", "-O1", "-g", "-pthread", *flags, *defines, f"-I{SRC}",
                    "-o", str(out), *[str(SRC / s) for s in SOURCES], "-lm"], check=True)
    return out


def _free_port(ip: str) -> int:
    with socket.socket() as s:
        s.bind((ip, 0))
        return s.getsockname()[1]


class Backend:
    """Fake NFS server: records what arrived and what the journal held then."""

    def __init__(self, journal: HostJournal, reply: bool = True) -> None:
        self.journal = journal
        self.reply = reply
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.20", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.received: list[tuple[bytes, list[str]]] = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            while True:
                try:
                    record = _recv_record(conn)
                except (EOFError, OSError):
                    return
                seen = [e.request.event_type for e in self.journal.events(SESSION)]
                self.received.append((record, seen))
                if self.reply:
                    xid, = struct.unpack(">I", record[4:8])
                    slot, = struct.unpack(">I", record[SLOTID_OFFSET:SLOTID_OFFSET + 4])
                    conn.sendall(compound_reply(xid, slot))

    def close(self) -> None:
        self.sock.close()


class Live:
    def __init__(self, binary: Path, tmp: Path, journal: HostJournal, *, lane: int = LANE,
                 drain_ms: int = 400, reply: bool = True,
                 env: dict[str, str] | None = None) -> None:
        self.tmp = tmp
        self.rules = rule_set()
        self.rule_set_id = hashlib.sha256(self.rules).hexdigest()
        (tmp / "rules.bin").write_bytes(self.rules)
        self.journal = journal
        self.channel = ChannelServer(tmp / "jnl.sock", journal, ChannelIdentity(VM, CHANNEL))
        self.backend = Backend(journal, reply)
        self.listen = _free_port("127.0.0.10")
        other = _free_port("127.0.0.11")
        self.activation_path = tmp / "act.sock"
        self.proc = subprocess.Popen(
            [str(binary), "127.0.0.2", "127.0.0.3", f"127.0.0.10:{self.listen}",
             f"127.0.0.11:{other}", f"127.0.0.20:{self.backend.port}",
             f"127.0.0.21:{_free_port('127.0.0.21')}",
             "--target", str(tmp / "rules.bin"), "--session-id", SESSION,
             "--journal", str(tmp / "jnl.sock"), "--lane", str(lane),
             "--activation", str(self.activation_path), "--drain-bound-ms", str(drain_ms)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                 "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1", **(env or {})})
        line = self.proc.stdout.readline()
        assert line.startswith("relay ready"), line + self.proc.stderr.read()
        self.act = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.act.settimeout(10)
        self.act.connect(str(self.activation_path))
        self.client = socket.socket()
        self.client.settimeout(10)
        self.client.bind(("127.0.0.2", 0))
        self.client.connect(("127.0.0.10", self.listen))

    def request(self, op: int, generation: int) -> int:
        packet = (b"NFSPACT1" + struct.pack(">II", op, 0) + struct.pack(">Q", generation)
                  + DIGEST + self.rule_set_id.encode())
        self.act.send(packet)
        answer = self.act.recv(64)
        assert len(answer) == 24 and answer[:8] == b"NFSPACK1"
        r_op, status, r_gen = struct.unpack(">IIQ", answer[8:])
        assert (r_op, r_gen) == (op, generation)
        return status

    def call(self, xid: int, slotid: int, *, expect_reply: bool = True) -> bytes | None:
        self.client.sendall(compound_call(xid, slotid))
        return _recv_record(self.client) if expect_reply else None

    def all_types(self) -> list[str]:
        return [e.request.event_type for e in self.journal.events(SESSION)]

    def wait_event(self, event_type: str, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if event_type in self.all_types():
                return
            time.sleep(0.02)
        raise AssertionError(f"{event_type} never stored: {self.all_types()}")

    def events(self):
        """The stored events these tests are about (``CORE_EVENTS``)."""
        return core(self.journal.events(SESSION))

    def types(self) -> list[str]:
        return [e.request.event_type for e in self.events()]

    def stop(self) -> str:
        self.client.close()
        self.act.close()
        self.proc.send_signal(signal.SIGTERM)
        out, err = self.proc.communicate(timeout=20)
        assert self.proc.returncode == 0, err
        self.channel.close()
        self.backend.close()
        return out


def _journal(tmp: Path, lane: int = LANE, cls=HostJournal) -> HostJournal:
    journal = cls(tmp / "journal", "lane0")
    journal.install_session(vm_instance_id=VM, channel_id=CHANNEL, proxy_session_id=SESSION,
                            lane_id=lane, rule_set=rule_set())
    return journal


def test_mutation_reaches_peer_only_after_its_exposure_is_stored(proxy_binary, tmp_path):
    journal = _journal(tmp_path)
    live = Live(proxy_binary, tmp_path, journal)
    try:
        # Outside any generation: relayed untouched, no event.
        live.call(10, 5)
        assert live.backend.received[-1][0] == compound_call(10, 5)
        assert live.request(1, 1) == 0
        assert live.types() == ["RULESET", "GENERATION_OPEN"]

        live.call(11, 5)
        record, seen_then = live.backend.received[-1]
        assert struct.unpack(">I", record[SLOTID_OFFSET:SLOTID_OFFSET + 4]) == (7,)
        assert "EXPOSURE_INTENT" in seen_then
        mutated = bytearray(compound_call(11, 5))
        mutated[SLOTID_OFFSET:SLOTID_OFFSET + 4] = struct.pack(">I", 7)
        assert record == bytes(mutated)

        # Both rules write slotid 6: the refusal is stored before the
        # record moves, and the record moves unchanged.
        live.call(12, 6)
        record, seen_then = live.backend.received[-1]
        assert record == compound_call(12, 6)
        assert seen_then.count("APPLY_REFUSAL") == 2
        live.call(13, 6)  # same refusal again: no second event
        assert live.backend.received[-1][0] == compound_call(13, 6)

        assert live.request(2, 1) == 0
        live.wait_event("GENERATION_COMPLETE")
        out = live.stop()
    finally:
        if live.proc.poll() is None:
            live.proc.kill()
    events = live.events()
    types = [e.request.event_type for e in events]
    assert types == ["RULESET", "GENERATION_OPEN", "EXPOSURE_INTENT", "FORWARD_COMPLETE",
                     "APPLY_REFUSAL", "APPLY_REFUSAL", "GENERATION_DRAINING",
                     "GENERATION_COMPLETE", "RUN_COMPLETE"]
    assert journal.rejections() == []
    assert delivery_state(events, 0) == "forward_complete"
    ei = events[2].request.payload
    out_len = len(compound_call(11, 5))
    assert ei.output.final_record_length == out_len
    assert ei.output.output_sha256 == hashlib.sha256(bytes(mutated)).hexdigest()
    assert [a.rule_id for a in ei.applications] == ["r1"]
    assert ei.applications[0].original_value == "00000005"
    assert ei.applications[0].mutated_value == "00000007"
    assert {e.request.payload.rule_id for e in events[4:6]} == {"r1", "r2"}
    assert {e.request.payload.refusal for e in events[4:6]} == {"conflict"}
    summary = events[7].request.payload
    assert summary.closure.reason == "drained"
    assert summary.exposure_batch_count == 1
    assert summary.evidence_path_failures == 0
    counts = {s.rule_id: s.counts for s in summary.resolver_summary}
    assert counts["r1"]["conflict"] == 2 and counts["r2"]["conflict"] == 2
    run = events[8].request.payload
    assert (run.batch_count, run.forward_complete_count, run.generations) == (1, 1, 1)
    assert journal.session_state(SESSION)["ended"] == "run_complete"
    assert "target ruleset=acked" in out and "exposures=1" in out
    assert "run_complete=acked" in out


class _FailsExposure(HostJournal):
    """A sink whose append fails for EXPOSURE_INTENT: no answer, channel ends."""

    def submit(self, channel, raw):  # type: ignore[override]
        if parse_request(raw).event_type == "EXPOSURE_INTENT":
            raise JournalSinkError("append failed")
        return super().submit(channel, raw)


def test_unrecorded_exposure_forwards_the_original(proxy_binary, tmp_path):
    journal = _journal(tmp_path, cls=_FailsExposure)
    live = Live(proxy_binary, tmp_path, journal)
    try:
        assert live.request(1, 1) == 0
        live.call(21, 5)
        assert live.backend.received[-1][0] == compound_call(21, 5)
        # The channel is gone: a deactivation cannot be ACKed.
        assert live.request(2, 1) != 0
        out = live.stop()
    finally:
        if live.proc.poll() is None:
            live.proc.kill()
    assert live.types() == ["RULESET", "GENERATION_OPEN"]
    assert live.channel.ended == ["sink_failed"]
    assert "exposure_lost=1" in out and "channel=failed" in out


def test_refused_open_is_never_acknowledged(proxy_binary, tmp_path):
    journal = _journal(tmp_path, lane=3)  # the host installed another lane
    live = Live(proxy_binary, tmp_path, journal)
    try:
        assert live.request(1, 1) != 0
        live.call(31, 5)  # no generation: untouched
        assert live.backend.received[-1][0] == compound_call(31, 5)
        live.stop()
    finally:
        if live.proc.poll() is None:
            live.proc.kill()
    # The session did not end cleanly: no RUN_COMPLETE, the Runner ends it.
    assert [r.reason for r in journal.rejections()] == ["wrong_lane"]
    assert live.types() == ["RULESET"]


class _FailsRefusal(HostJournal):
    def submit(self, channel, raw):  # type: ignore[override]
        if parse_request(raw).event_type == "APPLY_REFUSAL":
            raise JournalSinkError("append failed")
        return super().submit(channel, raw)


def test_unrecorded_refusal_never_relays_the_record(proxy_binary, tmp_path):
    journal = _journal(tmp_path, cls=_FailsRefusal)
    live = Live(proxy_binary, tmp_path, journal)
    try:
        assert live.request(1, 1) == 0
        live.call(41, 6, expect_reply=False)
        time.sleep(0.5)
        assert live.backend.received == []
        out = live.stop()
    finally:
        if live.proc.poll() is None:
            live.proc.kill()
    assert live.backend.received == []
    assert "refusal_events=2" in out and "held_dropped=1" in out


def test_unanswered_call_closes_at_the_drain_bound(proxy_binary, tmp_path):
    journal = _journal(tmp_path)
    live = Live(proxy_binary, tmp_path, journal, drain_ms=200, reply=False)
    try:
        assert live.request(1, 1) == 0
        live.call(51, 5, expect_reply=False)
        deadline = time.monotonic() + 10
        while not live.backend.received and time.monotonic() < deadline:
            time.sleep(0.02)
        assert live.request(2, 1) == 0
        live.wait_event("GENERATION_COMPLETE")
        live.stop()
    finally:
        if live.proc.poll() is None:
            live.proc.kill()
    summary = [e for e in live.events()
               if e.request.event_type == "GENERATION_COMPLETE"][0].request.payload
    assert summary.closure.reason == "reply_unresolved"
    assert summary.closure.reply_unresolved_count == 1
    assert summary.closure.drain_bound_ms == 200


class _HoldsExposure(HostJournal):
    """A sink that answers EXPOSURE_INTENT only once `release` is set."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.release = threading.Event()
        self.waiting = threading.Event()

    def submit(self, channel, raw):  # type: ignore[override]
        if parse_request(raw).event_type == "EXPOSURE_INTENT":
            self.waiting.set()
            self.release.wait(20)
        return super().submit(channel, raw)


def test_shutdown_drains_owed_events_before_any_run_complete(proxy_binary, tmp_path):
    journal = _journal(tmp_path, cls=_HoldsExposure)
    live = Live(proxy_binary, tmp_path, journal)
    try:
        assert live.request(1, 1) == 0
        live.call(61, 5, expect_reply=False)
        assert journal.waiting.wait(10)
        # Stop while the intent is unanswered: the held record is dropped,
        # and its FORWARD_FAILED can only follow the late ACK.
        live.client.close()
        live.act.close()
        live.proc.send_signal(signal.SIGTERM)
        time.sleep(0.3)
        journal.release.set()
        out, err = live.proc.communicate(timeout=30)
        assert live.proc.returncode == 0, err
        live.channel.close()
        live.backend.close()
    finally:
        journal.release.set()
        if live.proc.poll() is None:
            live.proc.kill()
    assert live.backend.received == []
    assert journal.rejections() == []
    # Generation 1 never closed: the session is not clean, so no RUN_COMPLETE.
    assert live.types() == ["RULESET", "GENERATION_OPEN", "EXPOSURE_INTENT", "FORWARD_FAILED"]
    failed = live.events()[-1].request.payload
    assert (failed.reason, failed.bytes_written) == ("connection_closed", 0)
    assert delivery_state(live.events(), 0) == "forward_failed"
    assert "run_complete=skipped" in out


def test_local_submit_failure_skips_run_complete(proxy_binary_faults, tmp_path):
    """An intent the Proxy could not even queue leaves the channel and the
    host clean, but the session owes evidence it never recorded."""
    journal = _journal(tmp_path)
    live = Live(proxy_binary_faults, tmp_path, journal,
                env={"NFSP_TARGET_FAIL_SUBMIT": "EXPOSURE_INTENT"})
    try:
        assert live.request(1, 1) == 0
        live.call(71, 5)
        # Not recordable: the record goes out unchanged.
        assert live.backend.received[-1][0] == compound_call(71, 5)
        assert live.request(2, 1) == 0
        live.wait_event("GENERATION_COMPLETE")
        out = live.stop()
    finally:
        if live.proc.poll() is None:
            live.proc.kill()
    assert journal.rejections() == []
    assert live.types() == ["RULESET", "GENERATION_OPEN", "GENERATION_DRAINING",
                            "GENERATION_COMPLETE"]
    summary = live.events()[-1].request.payload
    assert (summary.exposure_batch_count, summary.evidence_path_failures) == (0, 1)
    assert journal.session_state(SESSION)["ended"] is None
    assert "evidence_path_failures=1 evidence_path_degraded=1" in out
    assert "run_complete=skipped" in out
