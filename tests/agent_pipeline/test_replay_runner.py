"""S1c CrashContextWindow parsing from a syz-manager crash log (patch 0024)."""

from __future__ import annotations

import pytest

from agent_pipeline.replay_runner import PlanError, parse_crash_context, parse_execprog_barriers

# The exact line pkg/rpcserver's TestNfsProxyContextLine pins (patch 0024).
GO_LINE = ("nfs-proxy: lane=1 generation=7 program_digest=abcd"
           " activation=Acked/0 deactivation=Acked/0 executed=true lease_cleared=true")

LOG = f"""\
some header
last executing test programs:

3.1s ago: executing program 0 (id=1):
nfs-proxy: lane=0 generation=3 program_digest=00 activation=Acked/0 deactivation=Acked/0 executed=true lease_cleared=true
getpid()

2.5s ago: executing program 1 (id=2):
{GO_LINE}
r0 = getuid()
close(r0)

1.1s ago: executing program 32 (id=3):
nfs-proxy: lane=1 generation=8 program_digest=ef activation=Acked/0 deactivation=NoAnswer/4294967295 executed=true lease_cleared=false
gettid()

0s ago: executing program 1 (id=4):
getppid()

kernel console output (not intermixed with test programs):

[  12.0] BUG: KASAN: slab-use-after-free
executing program 9 (id=99):
"""


def test_window_is_the_lane_in_execution_order():
    window = parse_crash_context(LOG, vm_instance_id="vm-0", bound=8)
    assert window.lane_id == 1  # the most recently started program's lane
    assert [e.exec_id for e in window.entries] == [2, 3, 4]
    assert [e.window_index for e in window.entries] == [0, 1, 2]
    first, hung, running = window.entries
    assert first.barrier.kcov_generation == 7 and first.barrier.program_digest == "abcd"
    assert first.program == "r0 = getuid()\nclose(r0)\n"
    # Hanged: the printed proc is synthetic; the lane comes from the context line.
    assert (hung.printed_proc, hung.lane_id) == (32, 1)
    assert hung.barrier.deactivation == "NoAnswer" and not hung.barrier.lease_cleared
    # Still running at the crash: no barrier, its lane is the printed proc.
    assert running.barrier is None and running.lane_id == 1


def test_bound_and_lane_choice():
    window = parse_crash_context(LOG, vm_instance_id="vm-0", bound=2)
    assert [e.exec_id for e in window.entries] == [3, 4]
    window = parse_crash_context(LOG, vm_instance_id="vm-0", bound=2, lane_id=0)
    assert [e.exec_id for e in window.entries] == [1]
    with pytest.raises(PlanError):
        parse_crash_context(LOG, vm_instance_id="vm-0", bound=2, lane_id=5)
    with pytest.raises(PlanError):
        parse_crash_context("no programs here", vm_instance_id="vm-0", bound=2)


def test_malformed_context_line_is_refused():
    bad = LOG.replace("generation=3 program_digest=00", "generation=x program_digest=00")
    with pytest.raises(PlanError):
        parse_crash_context(bad, vm_instance_id="vm-0", bound=8)


def test_execprog_barriers_in_order():
    out = ("2026/10/17 12:00:00 executed programs: 0\n"
           f"2026/10/17 12:00:01 nfs proxy barrier: {GO_LINE.split(' ', 2)[2]}\n"
           "2026/10/17 12:00:02 nfs proxy barrier: generation=8 program_digest=abcd"
           " activation=Refused/2 deactivation=None/0 executed=false lease_cleared=true\n")
    barriers = parse_execprog_barriers(out)
    assert [(b.kcov_generation, b.executed) for b in barriers] == [(7, True), (8, False)]
    assert barriers[1].activation == "Refused" and barriers[1].activation_status == 2


# The exact shape patch 0024's Collect() emits for a hung program: the
# Note() record stays in the ring (printed proc = lane, no context line) and
# Hanged() appends a second record with a synthetic proc, the lane and the
# barrier, stamped at hang time.
HUNG_LOG = """\
last executing test programs:

5.0s ago: executing program 1 (id=41):
nfs-proxy: lane=1 generation=6 program_digest=aa activation=Acked/0 deactivation=Acked/0 executed=true lease_cleared=true
getpid()

4.0s ago: executing program 1 (id=42):
gettid()

2.0s ago: executing program 32 (id=42):
nfs-proxy: lane=1 generation=7 program_digest=bb activation=Acked/0 deactivation=NoAnswer/4294967295 executed=true lease_cleared=false
gettid()

1.0s ago: executing program 1 (id=43):
getppid()

kernel console output (not intermixed with test programs):
"""


def test_hung_program_is_one_execution():
    window = parse_crash_context(HUNG_LOG, vm_instance_id="vm-0", bound=8)
    assert [e.exec_id for e in window.entries] == [41, 42, 43]
    hung = window.entries[1]
    assert (hung.printed_proc, hung.lane_id) == (32, 1)
    assert hung.barrier.kcov_generation == 7 and hung.barrier.deactivation == "NoAnswer"
    assert hung.program == "gettid()\n"
    # The bound counts executions, not log records.
    assert [e.exec_id for e in parse_crash_context(
        HUNG_LOG, vm_instance_id="vm-0", bound=2).entries] == [42, 43]


def test_duplicate_records_that_disagree_are_refused():
    with pytest.raises(PlanError):
        parse_crash_context(HUNG_LOG.replace("gettid()\n\n1.0s", "getuid()\n\n1.0s"),
                            vm_instance_id="vm-0", bound=8)
