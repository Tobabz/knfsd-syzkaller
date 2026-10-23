"""The host's KVM slots (09 §8, #81 R4, R6).

A slot is one backend resource lock, ``<resource_key>/kvm-<i>``: the
``ProcessSupervisor`` lets one execution own it at a time.  The Runner
runs one worker per slot, and every engine (Stage 1 runs, fixed attempts,
replays, Stage 2 leases) takes its resource key from the same pool, so
the host never runs more guests than it has slots for.

The slot count is computed on each host when the Runner starts, from its
CPUs and memory, so one configuration scales across machines.
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class SlotPolicy:
    """One guest's size and what the host keeps for itself."""

    vm_cpus: int
    vm_memory_mb: int
    reserve_cpus: int = 2
    reserve_memory_mb: int = 4096
    #: An upper bound, None for none.
    max_slots: int | None = None

    def __post_init__(self) -> None:
        if self.vm_cpus < 1 or self.vm_memory_mb < 1:
            raise ValueError("a guest needs at least one CPU and some memory")
        if self.reserve_cpus < 0 or self.reserve_memory_mb < 0:
            raise ValueError("a reserve cannot be negative")
        if self.max_slots is not None and self.max_slots < 1:
            raise ValueError("max_slots must be at least 1")

    def count(self, cpus: int, memory_mb: int) -> int:
        """``min((cpus - reserve) // vm_cpus, (memory - reserve) //
        vm_memory)``, at least 1 and at most ``max_slots``."""
        n = min((cpus - self.reserve_cpus) // self.vm_cpus,
                (memory_mb - self.reserve_memory_mb) // self.vm_memory_mb)
        n = max(1, n)
        return n if self.max_slots is None else min(n, self.max_slots)


def host_cpus() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count() or 1


def host_memory_mb(meminfo: Path = Path("/proc/meminfo")) -> int:
    """``MemTotal`` in MiB."""
    for line in meminfo.read_text().splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) // 1024
    raise ValueError("MemTotal missing from /proc/meminfo")


@contextmanager
def resource(pool: SlotPool | None, fixed: str) -> Iterator[str]:
    """A free slot of ``pool``, or ``fixed`` without one."""
    if pool is None:
        yield fixed
    else:
        with pool.slot() as key:
            yield key


class SlotPool:
    """Thread-safe: ``slot()`` blocks until one is free and yields its
    resource key."""

    def __init__(self, resource_key: str, count: int) -> None:
        if count < 1:
            raise ValueError("a pool needs at least one slot")
        self.keys = tuple(f"{resource_key}/kvm-{i}" for i in range(count))
        self._free = list(self.keys)
        self._ready = threading.Condition()

    @classmethod
    def for_host(cls, resource_key: str, policy: SlotPolicy) -> SlotPool:
        return cls(resource_key, policy.count(host_cpus(), host_memory_mb()))

    @property
    def count(self) -> int:
        return len(self.keys)

    @contextmanager
    def slot(self) -> Iterator[str]:
        with self._ready:
            while not self._free:
                self._ready.wait()
            key = self._free.pop(0)
        try:
            yield key
        finally:
            with self._ready:
                self._free.append(key)
                self._ready.notify()
