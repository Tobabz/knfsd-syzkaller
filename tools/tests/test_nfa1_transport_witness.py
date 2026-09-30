"""Focused integration and parser regressions for the NF-A1 witness."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
ENV_DIR = Path(os.environ.get("KOOV_ENV_DIR", str(ROOT / "env")))
HELPER = ROOT / "bundle/corpus/nfs-normal/nfa1-transport-witness.py"
RETAINED_LOG = Path(
    "/home/idealinsane/attr-scenario-evidence/NORMAL-B05-CORPUS-20260928/"
    "remote_on/trial_01/executor.log"
)
RETAINED_TRACE = Path(
    "/home/idealinsane/normal-flow-evidence/NF-A1-COPY-20260928/"
    "remote_on/trial_01/nfa1-transport-trace.txt"
)
TOKEN = "a1b2c3d4e5f6"
XPRT = "0xffff888012340000"
RQST = "0xffff888099990000"


def _load_helper():
    spec = importlib.util.spec_from_file_location("nfa1_transport_witness", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nfa1 = _load_helper()


def _trace(records: list[tuple[int, int, str, str]], *, loss: bool = False) -> str:
    rows = [(1, 0, "tracing_mark_write", f"nfa1-begin-{TOKEN}"),
            *records,
            (1, 0, "tracing_mark_write", f"nfa1-end-{TOKEN}")]
    lines = [f" task-{pid} [{cpu:03d}] d..2 {1 + index / 100:.6f}: {event}: {body}\n"
             for index, (pid, cpu, event, body) in enumerate(rows)]
    written = len(rows) + int(loss)
    return f"# entries-in-buffer/entries-written: {len(rows)}/{written}   #P:8\n" + "".join(lines)


def _pair(kind: str, *, xprt: str = XPRT, rqst: str = RQST,
          client: str = "10.0.0.2:999", flags: str = "DATA",
          service: str = "nfsd", pid: int | None = None,
          cpu: int | None = None) -> list[tuple[int, int, str, str]]:
    worker = kind in {"dequeue", "process"}
    pid = pid if pid is not None else (202 if worker else 101)
    cpu = cpu if cpu is not None else (5 if worker else 3)
    dynamic = f"xprt={xprt}"
    if worker:
        dynamic = f"rqst={rqst} {dynamic}"
    built = {
        "ready": ("svcsock_data_ready", f"addr={client} result=0 flags={flags}"),
        "enqueue": ("svc_xprt_enqueue",
                    f"server=10.0.0.1:2049 client={client} flags={flags}"),
        "dequeue": ("svc_xprt_dequeue",
                    f"server=10.0.0.1:2049 client={client} flags={flags} wakeup-us=1 qtime-us=1"),
        "process": ("svc_process",
                    f"addr={client} xid=0x1 service={service} vers=4 proc=COMPOUND"),
    }[kind]
    return [(pid, cpu, f"{kind}_{TOKEN}", dynamic), (pid, cpu, *built)]


def _valid_records() -> list[tuple[int, int, str, str]]:
    return [*_pair("ready"), *_pair("enqueue"),
            *_pair("dequeue", flags="BUSY|DATA"), *_pair("process")]


def test_accepts_endpoint_request_correlated_lossless_nfsd_chain() -> None:
    verdict = nfa1.witness_trace(_trace(_valid_records()))
    assert verdict["assert"] is True
    assert verdict["matched_xprt"] == XPRT
    assert all(verdict["checks"].values())


def test_accepts_literal_guest_slice_with_out_of_scope_callback_process() -> None:
    records = _valid_records()
    records[4:4] = [
        (2703, 4, "svc_process",
         "addr=(null) xid=0xc060f825 service=NFSv4 callback vers=1 proc=COMPOUND")
    ]
    verdict = nfa1.witness_trace(_trace(records))
    assert verdict["assert"] is True
    assert verdict["checks"]["context_pairs_complete"] is True
    assert verdict["out_of_scope_backchannel_process"] == 1


def test_rejects_unmatched_forechannel_nfsd_process() -> None:
    records = [
        *_valid_records(),
        (2703, 4, "svc_process",
         "addr=10.0.0.2:999 xid=0xc060f825 service=nfsd vers=4 proc=COMPOUND"),
    ]
    verdict = nfa1.witness_trace(_trace(records))
    assert verdict["assert"] is False
    assert verdict["checks"]["context_pairs_complete"] is False
    assert verdict["out_of_scope_backchannel_process"] == 0


def test_rejects_dynamic_process_paired_with_callback_semantic() -> None:
    records = _valid_records()
    records[-1] = (
        202, 5, "svc_process",
        "addr=(null) xid=0xc060f825 service=NFSv4 callback vers=1 proc=COMPOUND",
    )
    verdict = nfa1.witness_trace(_trace(records))
    assert verdict["assert"] is False
    assert verdict["checks"]["context_pairs_complete"] is True
    assert verdict["out_of_scope_backchannel_process"] == 0


def test_full_retained_guest_trace_replays_as_direct_witness() -> None:
    verdict = nfa1.witness_trace(RETAINED_TRACE.read_text())
    assert verdict["assert"] is True
    assert verdict["checks"]["context_pairs_complete"] is True
    assert verdict["out_of_scope_backchannel_process"] == 10
    assert verdict["matched_xprt"] == "0xffff888110b24000"
    assert verdict["event_counts"] == {
        "ready": 275, "enqueue": 262, "dequeue": 216,
        "process": 75, "svc_process": 85,
    }


@pytest.mark.parametrize(
    ("records", "failed_check"),
    [
        ([*_pair("ready"), *_pair("enqueue", xprt="0xffff8880dead0000"),
          *_pair("dequeue", flags="BUSY|DATA"), *_pair("process")],
         "correlated_xprt_chain"),
        ([*_pair("ready"), *_pair("dequeue", flags="BUSY|DATA"),
          *_pair("enqueue"), *_pair("process")], "correlated_xprt_chain"),
        ([*_pair("ready"), *_pair("enqueue"),
          *_pair("dequeue", rqst="0xffff888011110000", flags="BUSY|DATA"),
          *_pair("process")], "correlated_xprt_chain"),
        ([*_pair("ready"), *_pair("enqueue", flags="BUSY|DATA"),
          *_pair("dequeue", flags="BUSY|DATA"), *_pair("process")],
         "correlated_xprt_chain"),
        ([*_pair("ready"), *_pair("enqueue"),
          *_pair("dequeue", client="10.0.0.99:888", flags="BUSY|DATA"),
          *_pair("process", client="10.0.0.99:888")], "correlated_xprt_chain"),
        ([*_pair("ready"), *_pair("enqueue"),
          *_pair("dequeue", flags="BUSY|DATA"), *_pair("process", service="nfs")],
         "nfsd_svc_process"),
    ],
)
def test_rejects_broken_identity_sequence_flags_endpoint_or_service(
        records: list[tuple[int, int, str, str]], failed_check: str) -> None:
    verdict = nfa1.witness_trace(_trace(records))
    assert verdict["assert"] is False
    assert verdict["checks"][failed_check] is False


def test_rejects_trace_loss() -> None:
    verdict = nfa1.witness_trace(_trace(_valid_records(), loss=True))
    assert verdict["assert"] is False
    assert verdict["checks"]["trace_lossless"] is False


def test_rejects_recycled_pointer_across_closed_old_peer() -> None:
    records = [
        *_pair("ready", flags="CLOSE", client="10.0.0.2:999"),
        *_pair("enqueue", flags="CLOSE|DATA", client="10.0.0.2:999"),
        *_pair("dequeue", rqst="0xffff888011110000", flags="BUSY|CLOSE|DATA",
               client="10.0.0.2:999", pid=201),
        *_pair("enqueue", client="10.0.0.99:888", pid=203, cpu=6),
        *_pair("dequeue", flags="BUSY|DATA", client="10.0.0.99:888"),
        *_pair("process", client="10.0.0.99:888"),
    ]
    verdict = nfa1.witness_trace(_trace(records))
    assert verdict["assert"] is False
    assert verdict["checks"]["correlated_xprt_chain"] is False


def test_accepts_exact_normal_tcp_receive_reenqueue_before_process() -> None:
    records = [
        *_pair("ready", flags="TEMP"),
        *_pair("enqueue"),
        *_pair("dequeue", flags="BUSY|DATA"),
        *_pair("enqueue", pid=202, cpu=5),
        *_pair("process"),
    ]
    verdict = nfa1.witness_trace(_trace(records))
    assert verdict["assert"] is True
    assert verdict["event_counts"]["enqueue"] == 2
    assert verdict["matched_xprt"] == XPRT


def test_rejects_exact_22_entry_interleaved_recycled_pointer_trace() -> None:
    other = "0xffff888012341111"
    records = [
        (101, 3, f"ready_{TOKEN}", f"xprt={XPRT}"),
        (101, 3, "svcsock_data_ready", "addr=10.0.0.2:999 result=0 flags=TEMP"),
        (101, 3, f"enqueue_{TOKEN}", f"xprt={XPRT}"),
        (101, 3, "svc_xprt_enqueue",
         "server=10.0.0.1:2049 client=10.0.0.2:999 flags=DATA"),
        (201, 5, f"dequeue_{TOKEN}",
         f"rqst=0xffff888011110000 xprt={XPRT}"),
        (404, 7, f"enqueue_{TOKEN}", f"xprt={other}"),
        (404, 7, "svc_xprt_enqueue",
         "server=10.0.0.1:2049 client=10.0.0.8:888 flags=BUSY|DATA"),
        (201, 5, "svc_xprt_dequeue",
         "server=10.0.0.1:2049 client=10.0.0.2:999 flags=BUSY|CLOSE|DATA"),
        (203, 6, f"enqueue_{TOKEN}", f"xprt={XPRT}"),
        (404, 7, f"enqueue_{TOKEN}", f"xprt={other}"),
        (404, 7, "svc_xprt_enqueue",
         "server=10.0.0.1:2049 client=10.0.0.8:888 flags=BUSY|DATA"),
        (203, 6, "svc_xprt_enqueue",
         "server=10.0.0.1:2049 client=10.0.0.2:999 flags=DATA"),
        (202, 5, f"dequeue_{TOKEN}", f"rqst={RQST} xprt={XPRT}"),
        (202, 5, "svc_xprt_dequeue",
         "server=10.0.0.1:2049 client=10.0.0.2:999 flags=BUSY|DATA"),
        (202, 5, f"enqueue_{TOKEN}", f"xprt={XPRT}"),
        (404, 7, f"enqueue_{TOKEN}", f"xprt={other}"),
        (404, 7, "svc_xprt_enqueue",
         "server=10.0.0.1:2049 client=10.0.0.8:888 flags=BUSY|DATA"),
        (202, 5, "svc_xprt_enqueue",
         "server=10.0.0.1:2049 client=10.0.0.2:999 flags=DATA"),
        (202, 5, f"process_{TOKEN}", f"rqst={RQST} xprt={XPRT}"),
        (202, 5, "svc_process",
         "addr=10.0.0.2:999 xid=0x1 service=nfsd vers=4 proc=COMPOUND"),
    ]
    trace = _trace(records)
    assert trace.startswith("# entries-in-buffer/entries-written: 22/22")
    verdict = nfa1.witness_trace(trace)
    assert verdict["assert"] is False
    assert verdict["checks"]["context_pairs_complete"] is True
    assert verdict["checks"]["correlated_xprt_chain"] is False


def test_arm_owns_second_subscriber_for_static_call_dispatch(tmp_path: Path) -> None:
    calls = []
    vm = SimpleNamespace(guest=lambda stage, command: calls.append((stage, command)))
    plan = nfa1.NFATransportPlan(tmp_path)
    plan.before_workload(vm, "on")
    command = calls[0][1]
    assert 'CONFIG_HAVE_STATIC_CALL_INLINE' not in command
    assert 'D="$T/instances/nfa1_' in command
    assert command.count("sunrpc/svcsock_data_ready") >= 2
    assert command.count("sunrpc/svc_xprt_dequeue") >= 2
    assert 'echo 1 > "$D/events/$e/enable"' in command


def test_copy_contract_accepts_actual_retained_executor_log() -> None:
    reach = nfa1._load_reach()
    assert (reach.EXPECTED_CALLS, reach.CONFLICT_CALL) == (11, -1)
    result = reach.validate_executor_log(RETAINED_LOG.read_text(), executions=10, procs=2)
    assert result["call_count"] == 110
    assert result["calls_per_execution"] == 11
    assert result["expected_lock_conflicts"] == 0


def test_literal_nested_cli_help_loads_shared_runner() -> None:
    result = subprocess.run(
        ["/usr/bin/python3", str(HELPER), "--help"], cwd=ROOT,
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "--workload" in result.stdout


def test_literal_preflight_reports_ready_not_runtime_pass(tmp_path: Path) -> None:
    output = tmp_path / "evidence"
    command = [
        "/usr/bin/python3", str(HELPER),
        "--kernel", str(ENV_DIR / "images/kcsan/bzImage"),
        "--image", str(ENV_DIR / "images/bookworm-kcov-fresh-v1.raw"),
        "--ssh-key", str(ROOT / "artifacts/bookworm.id_rsa"),
        "--deps-tar", str(ROOT / "bundle/src/guest-deps.tar.gz"),
        "--vmlinux", str(ENV_DIR / "images/kcsan/vmlinux"),
        "--lane-fixture", str(ROOT / "bundle/corpus/nfs-normal/ab-lane-fixture-v42.sh"),
        "--workload", str(ROOT / "bundle/corpus/nfs-normal/async-copy-v42-tcp.prog"),
        "--syz-executor", str(ENV_DIR / "syzkaller/bin/linux_amd64/syz-executor"),
        "--syz-execprog", str(ENV_DIR / "syzkaller/bin/linux_amd64/syz-execprog"),
        "--mode", "on", "--trials", "1", "--executions", "10",
        "--sample-every", "10", "--procs", "2", "--cpus", "8",
        "--memory", "8192", "--output", str(output), "--preflight",
    ]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                            check=False)
    assert result.returncode == 0, result.stderr
    assert f"NF-A1 READY: {output}" in result.stdout
    assert "NF-A1 PASS:" not in result.stdout
    assert not output.exists()
