"""Delta durability of one Proxy build, checked without crashing a guest.

M7 asks a semantic subset to show that its mutation record outlives the
guest (06 §30).  That claim rests on two facts about the Proxy build and the
host sink, neither of which depends on the subset:

- the write-ahead ``EXPOSURE_INTENT`` is stored in the host sink before the
  peer receives the mutated bytes;
- a journal that ends abruptly, at any byte after that event was stored,
  still reads back with the exposure and its applications.

``probe`` drives the build in target mode on loopback through the real
``HostJournal`` for the first, then cuts the recorded journal at many byte
offsets and reads every prefix back through ``SealedJournal`` for the
second.  It never touches a guest.  What it cannot show is what a real
kernel death does to data the Proxy still held in the guest: that stays
``natural_crash_reproduction: not_observed`` until a natural crash is
recorded (``semantic_promotion``).

A build this probe cannot drive (it does not start, or does not speak the
rule layout of this repository) raises ``ProbeError``: that is no evidence,
and the build is promoted only through a natural crash.
"""

from __future__ import annotations

import hashlib
import io
import struct
from pathlib import Path

from pydantic import ConfigDict

from .contracts import Record, Sha256
from .journal_framing import encode_frame, read_journal
from .live_probe import (SESSION, SLOTID_OFFSET, Live, _journal,
                         compound_call)
from .journal_sink import SEGMENT_SUFFIX, HostJournal
from .semantic_delta import DeltaReadError, SealedJournal

#: Every frame boundary, one byte either side of it, and every this many
#: bytes in between.
CUT_STRIDE = 61
JOURNAL_NAME = "lane0"


class ProbeError(RuntimeError):
    """The build could not be driven; the probe says nothing about it."""


class DeltaDurabilityCheck(Record):
    """What ``probe`` saw for one Proxy build (the evidence behind
    ``ValidationItem.DELTA_DURABILITY``)."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    schema_version: str = "delta-durability.v1"
    proxy_sha256: Sha256
    registry_digest: Sha256
    #: EXPOSURE_INTENT events the sink stored while the build ran.
    exposures: int
    #: Mutated records the peer received.
    mutated_forwards: int
    #: True when the sink held every one's EXPOSURE_INTENT before the peer
    #: received it.
    intent_before_forward: bool
    #: Journal prefixes read back.
    cuts_checked: int
    #: True when every prefix after the intent frame still holds the
    #: exposure with its applications, none before it holds a forward, and
    #: every prefix read without error.
    prefix_keeps_exposure: bool

    @property
    def passed(self) -> bool:
        return (self.exposures >= 1 and self.mutated_forwards >= 1
                and self.cuts_checked >= 1 and self.intent_before_forward
                and self.prefix_keeps_exposure)

    def problems(self) -> list[str]:
        found = []
        if self.exposures < 1 or self.mutated_forwards < 1:
            found.append("the probe stored no exposure or forwarded no "
                         "mutated record")
        if not self.intent_before_forward:
            found.append("the peer received a mutated record before its "
                         "EXPOSURE_INTENT was stored")
        if self.cuts_checked < 1:
            found.append("no journal prefix was checked")
        if not self.prefix_keeps_exposure:
            found.append("a journal prefix lost an exposure it held, or "
                         "failed to read")
        return found


def _segment(journal_dir: Path) -> Path:
    paths = sorted(journal_dir.glob(f"{JOURNAL_NAME}.*{SEGMENT_SUFFIX}"))
    if len(paths) != 1:
        raise ProbeError(f"expected one journal segment, found {len(paths)}")
    return paths[0]


def _boundaries(data: bytes) -> list[int]:
    """Byte offsets at which a frame ends."""
    prefix = read_journal(io.BytesIO(data))
    if prefix.torn_tail_bytes:
        raise ProbeError("the probe's own journal has a torn tail")
    ends, at = [], 0
    for frame in prefix.frames:
        at += len(encode_frame(frame))
        ends.append(at)
    return ends


def _view(directory: Path, data: bytes):
    directory.mkdir(exist_ok=True)
    for old in directory.iterdir():
        old.unlink()
    (directory / f"{JOURNAL_NAME}.0000{SEGMENT_SUFFIX}").write_bytes(data)
    return SealedJournal(directory, JOURNAL_NAME)


def _exposures(view: SealedJournal) -> tuple[int, int, bool]:
    """Exposures, forwards and whether every exposure names applications."""
    session = view.sessions.get(SESSION)
    exposures = [e for g in (session.generations.values() if session else ())
                 for e in g.exposures]
    return (len(exposures), sum(e.terminal is not None for e in exposures),
            all(e.applications for e in exposures))


def probe(proxy: Path, *, proxy_sha256: str, registry_digest: str,
          schema_id: str, workdir: Path,
          journal_cls: type[HostJournal] = HostJournal
          ) -> DeltaDurabilityCheck:
    """Run ``proxy`` against the real sink and cut its journal.
    ``journal_cls`` lets a test stand in a sink that misbehaves."""
    if hashlib.sha256(proxy.read_bytes()).hexdigest() != proxy_sha256:
        raise ProbeError("the binary is not the build being checked")
    workdir.mkdir(parents=True, exist_ok=True)
    journal = _journal(workdir, cls=journal_cls, schema_id=schema_id)
    try:
        live = Live(proxy, workdir, journal, schema_id=schema_id)
    except (AssertionError, OSError) as error:
        journal.close()
        raise ProbeError(f"the Proxy did not start: {error}") from error
    try:
        try:
            live.call(10, 5)                       # outside a generation
            if live.request(1, 1) != 0:
                raise ProbeError("the Proxy refused to open a generation")
            live.call(11, 5)                       # mutated by rule r1
            live.call(12, 6)                       # both rules: a refusal
            if live.request(2, 1) != 0:
                raise ProbeError("the Proxy refused to close a generation")
            live.wait_event("GENERATION_COMPLETE")
            live.stop()
        except (AssertionError, OSError, EOFError, struct.error) as error:
            raise ProbeError(f"the Proxy did not follow the probe: "
                             f"{error}") from error
    except ProbeError:
        journal.close()
        raise
    finally:
        if live.proc.poll() is None:
            live.proc.kill()
    exposures = [e for e in journal.events(SESSION)
                 if e.request.event_type == "EXPOSURE_INTENT"]
    mutated = [(record, seen) for record, seen in live.backend.received
               if _is_mutated(record)]
    ordered = bool(mutated) and all("EXPOSURE_INTENT" in seen
                                    for _, seen in mutated)
    journal.close()

    data = _segment(workdir / "journal").read_bytes()
    ends = _boundaries(data)
    cuts = sorted({c for end in ends for c in (end - 1, end, end + 1)
                   if ends[0] <= c <= len(data)}
                  | set(range(ends[0], len(data) + 1, CUT_STRIDE)))
    scratch = workdir / "cut"
    seen: list[tuple[int, int, int, bool]] = []
    kept = True
    for cut in cuts:
        try:
            count, forwards, named = _exposures(_view(scratch, data[:cut]))
        except DeltaReadError:
            kept = False
            continue
        seen.append((cut, count, forwards, named))
    first = next((cut for cut, count, _, _ in seen if count), None)
    if first is None:
        kept = False
    for cut, count, forwards, named in seen:
        if first is not None and cut >= first and not (count and named):
            kept = False
        if (first is None or cut < first) and forwards:
            kept = False
    return DeltaDurabilityCheck(
        proxy_sha256=proxy_sha256, registry_digest=registry_digest,
        exposures=len(exposures), mutated_forwards=len(mutated),
        intent_before_forward=ordered, cuts_checked=len(seen),
        prefix_keeps_exposure=kept)


def _is_mutated(record: bytes) -> bool:
    """The probe's rules rewrite SEQUENCE.sa_slotid 5 to 7."""
    slot, = struct.unpack(">I", record[SLOTID_OFFSET:SLOTID_OFFSET + 4])
    return slot == 7


__all__ = ["DeltaDurabilityCheck", "ProbeError", "probe"]
