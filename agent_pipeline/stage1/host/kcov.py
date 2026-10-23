"""Pure parsing of a lane run into the Q1 capture records.

Inputs are what the guest prints: the ``sunrpc_fuzz`` debugfs ``*_stats``
files (one ``name value`` per line, dumped as ``== <path>`` sections) before
and after the program, the ``phase4_state`` generation list at the start of
the window, and the ``cover_prog<N>.extra`` remote coverage file written by
``syz-execprog -coverfile``.  Nothing here runs a VM, so every
mapping from guest text to a record field is unit-tested.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from ...data import canonical_json
from ...q1 import (CounterDelta, ExecutionCorrelation, GenerationCounters,
                   KernelIdentity, RemoteKcovObservation)
from ...sealed_q1 import PublishedCoverage

#: The window every counter delta is measured over: from the execprog gate
#: (the machine check has finished, the program has not started) to after
#: the drain period.  The machine check runs its own extra-coverage request,
#: which opens a generation of its own; the gate keeps it out of the window.
WINDOW = "generation-plus-drain"

#: GenerationCounters field -> (stats file, counter, how it is read).
#: ``delta`` is after minus before; ``after`` is the drain snapshot.
GENERATION_SOURCES = {
    "generation_begin": ("phase4_stats", "generation_begin", "delta"),
    "generation_aborted": ("phase4_stats", "generation_aborted", "delta"),
    "remote_start_ok": ("phase5_stats", "remote_start_ok", "delta"),
    "aggregate_published": ("phase6_stats", "aggregate_published", "delta"),
    "scratch_overflow": ("phase6_stats", "scratch_overflow", "delta"),
    "merge_truncation": ("phase6_stats", "aggregate_merge_truncated", "delta"),
    "outstanding_tokens": ("phase4_stats", "outstanding_tokens", "after"),
    "remote_refs": ("phase6_stats", "remote_refs", "after"),
}

_SECTION = re.compile(r"^== .*/([A-Za-z0-9_]+)$")
_COUNTER = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*) (-?[0-9]+)$")
_PC = re.compile(r"^0x([0-9a-fA-F]+)$")

STATS_COMMAND = ("for f in /sys/kernel/debug/sunrpc_fuzz/*_stats; do "
                 "echo \"== $f\"; cat \"$f\"; done")
STATE_COMMAND = "cat /sys/kernel/debug/sunrpc_fuzz/phase4_state"
#: Generation states that no longer collect or drain coverage.
SETTLED_STATES = {"ABORTED", "COMMITTED", "DEAD"}

Stats = dict[str, dict[str, int]]


def parse_stats(text: str) -> Stats:
    """``== /sys/kernel/debug/sunrpc_fuzz/phase4_stats`` sections of
    ``name value`` lines.  Lines with more fields (state dumps) are not
    counters and are skipped."""
    stats: Stats = {}
    current: dict[str, int] | None = None
    for line in text.splitlines():
        line = line.strip()
        if m := _SECTION.match(line):
            current = stats.setdefault(m.group(1), {})
        elif current is not None and (m := _COUNTER.match(line)):
            current[m.group(1)] = int(m.group(2))
    return stats


def generation_counters(before: Stats, after: Stats) -> GenerationCounters:
    """A counter missing on either side is unknown (None), never zero."""
    values: dict[str, int | None] = {}
    for name, (section, counter, mode) in GENERATION_SOURCES.items():
        a = after.get(section, {}).get(counter)
        b = before.get(section, {}).get(counter)
        if mode == "after":
            values[name] = a if a is not None and a >= 0 else None
        elif a is None or b is None or a < b:
            values[name] = None
        else:
            values[name] = a - b
    return GenerationCounters(**values)


def counter_deltas(before: Stats, after: Stats,
                   window: str = WINDOW) -> tuple[CounterDelta, ...]:
    """Every counter present on both sides that did not go down.  A name
    found in one stats file is used bare (``lane_owner_failed``); a name in
    several files is qualified by its file (``phase5_stats.remote_refs``)."""
    owners: dict[str, list[str]] = {}
    for section, counters in after.items():
        for name in counters:
            owners.setdefault(name, []).append(section)
    out = []
    for section in sorted(after):
        for name, a in sorted(after[section].items()):
            b = before.get(section, {}).get(name)
            if b is None or a < b:
                continue
            label = name if len(owners[name]) == 1 else f"{section}.{name}"
            out.append(CounterDelta(counter=label, window=window, value=a - b))
    return tuple(out)


def unsettled_generations(state: str) -> list[str]:
    """``phase4_state`` lines (``owner 1 state COMMITTED outstanding_tokens 0
    object_refs 1 active_roots 0 ... generation 7``) of generations that are
    still open or draining.  The window may only start when this is empty:
    otherwise an earlier generation's work lands in the program's deltas."""
    busy = []
    for line in state.splitlines():
        fields = line.split()
        if not fields:
            continue
        pairs = dict(zip(fields[::2], fields[1::2]))
        if (pairs.get("state") not in SETTLED_STATES
                or pairs.get("outstanding_tokens") != "0"
                or pairs.get("active_roots") != "0"):
            busy.append(line.strip())
    return busy


def parse_cover_pcs(text: str) -> set[int]:
    """One ``0x...`` PC per line, as ``syz-execprog -coverfile`` writes
    them: already the call-site address of the coverage callback."""
    pcs = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _PC.match(line)
        if m is None:
            raise ValueError(f"not a coverage PC line: {line[:80]!r}")
        pc = int(m.group(1), 16)
        if pc <= 0 or pc >= 2 ** 64:
            raise ValueError(f"coverage PC out of range: {line[:80]!r}")
        pcs.add(pc)
    return pcs


def lane_state_ok(text: str) -> bool:
    """``lane_id 0 lane_epoch 1 valid 1 unhealthy 0 owner 1``."""
    fields = text.split()
    pairs = dict(zip(fields[::2], fields[1::2]))
    return pairs.get("valid") == "1" and pairs.get("unhealthy") == "0"


@dataclass
class LaneRun:
    """What the collector learned from one boot.  Booleans default to the
    failing value: a step that never ran did not succeed."""

    boot_ok: bool = False
    fixture_ok: bool = False
    lane_ok: bool = False
    runner_completed: bool = False
    collection_started: bool = False
    collection_completed: bool = False
    extra_present: bool = False
    stats_before: Stats | None = None
    stats_after: Stats | None = None
    pcs: set[int] = field(default_factory=set)
    runtime_errors: list[str] = field(default_factory=list)


def capture_records(run: LaneRun, *, candidate_id: str,
                    identity: KernelIdentity,
                    correlation: ExecutionCorrelation,
                    trace_mode: str) -> tuple[bytes, bytes]:
    """The canonical ``reachability`` observation and ``coverage`` bytes."""
    coverage = canonical_json(PublishedCoverage(
        correlation=correlation, pcs=tuple(sorted(run.pcs))))
    if run.stats_before is not None and run.stats_after is not None:
        generation = generation_counters(run.stats_before, run.stats_after)
        deltas = counter_deltas(run.stats_before, run.stats_after)
    else:
        generation, deltas = GenerationCounters(), ()
    # The .extra file is the generation-bound remote coverage the executor
    # published for this program; one begin and one publication in the
    # window tie it to a single generation.
    attributed = (run.extra_present and generation.generation_begin == 1
                  and generation.aggregate_published == 1)
    observation = RemoteKcovObservation(
        candidate_id=candidate_id, identity=identity, correlation=correlation,
        boot_ok=run.boot_ok, fixture_ok=run.fixture_ok, lane_ok=run.lane_ok,
        runner_completed=run.runner_completed,
        collection_started=run.collection_started,
        collection_completed=run.collection_completed,
        generation_attributed=attributed, channel="remote_kcov",
        lane_trace_mode=trace_mode,
        coverage_artifacts=(hashlib.sha256(coverage).hexdigest(),),
        published_pcs=tuple(sorted(run.pcs)),
        generation=generation, counter_deltas=deltas,
        runtime_errors=tuple(run.runtime_errors))
    return canonical_json(observation), coverage
