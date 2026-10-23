"""#81 R4, R6: the host-proportional KVM slot pool."""

from __future__ import annotations

import threading
import time

import pytest

from agent_pipeline.runner.slots import (SlotPolicy, SlotPool, host_memory_mb,
                                         resource)


@pytest.mark.parametrize(("cpus", "memory", "expected"), [
    (32, 128 * 1024, 7),       # (32-2)//4 = 7, (131072-4096)//4096 = 31
    (64, 32 * 1024, 7),        # memory bound: (32768-4096)//4096 = 7
    (4, 8192, 1),              # never fewer than one
    (2, 1024, 1),
])
def test_slot_count_follows_host_cores_and_memory(cpus, memory, expected):
    policy = SlotPolicy(vm_cpus=4, vm_memory_mb=4096)
    assert policy.count(cpus, memory) == expected


def test_max_slots_caps_the_count():
    assert SlotPolicy(vm_cpus=1, vm_memory_mb=1024, max_slots=3) \
        .count(64, 1 << 20) == 3
    with pytest.raises(ValueError):
        SlotPolicy(vm_cpus=0, vm_memory_mb=1024)


def test_meminfo_is_read_in_mib(tmp_path):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal:       16384000 kB\nMemFree: 1 kB\n")
    assert host_memory_mb(meminfo) == 16000


def test_a_pool_hands_out_each_slot_once():
    pool = SlotPool("host", 2)
    assert pool.keys == ("host/kvm-0", "host/kvm-1")
    with pool.slot() as a, pool.slot() as b:
        assert {a, b} == set(pool.keys)
        taken = []

        def third():
            with pool.slot() as key:
                taken.append(key)

        t = threading.Thread(target=third)
        t.start()
        time.sleep(0.05)
        assert taken == []           # waits for a free slot
    t.join(5)
    assert taken and taken[0] in pool.keys


def test_without_a_pool_the_fixed_key_is_used():
    with resource(None, "lane") as key:
        assert key == "lane"
    pool = SlotPool("lane", 1)
    with resource(pool, "lane") as key:
        assert key == "lane/kvm-0"
