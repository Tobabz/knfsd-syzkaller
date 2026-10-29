"""A loopback harness around the built Proxy in target mode and the real sink.

The Proxy relays NFSv4.1 COMPOUND CALLs between a fake client and a fake
backend on loopback, applies an NFSPRUL1 rule set inside an activated
generation, and records every event on ``HostJournal`` through
``ChannelServer`` before it lets mutated bytes out.  ``delta_durability``
drives it for a Proxy build; ``tests/agent_pipeline/test_journal_live.py``
drives it for the M5 contract.  What a guest adds (virtio-serial instead of
a Unix socket, the syzkaller executor instead of the activation driver
here, real knfsd) is the KVM step this harness cannot take.
"""

from __future__ import annotations

import hashlib
import os
import re
import signal
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

from .journal_sink import ChannelIdentity, ChannelServer, HostJournal

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "tools" / "nfs-proxy" / "src"

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


def rule_set(schema_id: str | None = None) -> bytes:
    # r1: slotid > 3 -> 7.  r2: slotid == 6 -> 9, so slotid 6 makes both
    # rules write one field: a conflict, the hard refusal of 05 §29.
    rules = [_rule("r1", 4, 3, 7), _rule("r2", 0, 6, 9)]
    return (b"NFSPRUL1" + struct.pack(">I", 1)
            + _xdr_string((schema_id or _schema_id()).encode())
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
                 env: dict[str, str] | None = None,
                 schema_id: str | None = None) -> None:
        self.tmp = tmp
        self.rules = rule_set(schema_id)
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


def _journal(tmp: Path, lane: int = LANE, cls=HostJournal,
             schema_id: str | None = None) -> HostJournal:
    journal = cls(tmp / "journal", "lane0")
    journal.install_session(vm_instance_id=VM, channel_id=CHANNEL, proxy_session_id=SESSION,
                            lane_id=lane,
                            rule_set=rule_set(schema_id))
    return journal


